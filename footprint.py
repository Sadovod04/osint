"""Проверка собственного цифрового следа (OSINT self-check).

По заданным данным (e-mail, username, телефон, имя+фамилия) собирает то, что
доступно из ОТКРЫТЫХ источников, и пишет единый отчёт в .txt (перезаписывается
при каждом запуске).

Использует, если установлены:
  * maigret  — username по тысячам сайтов   (pip install maigret)
  * holehe   — на каких сервисах зарегана почта (pip install holehe)
Плюс собственные проверки: gravatar, HaveIBeenPwned (нужен ключ), разбор
телефона (phonenumbers), генерация поисковых запросов (Google dorks).

Сетевые запросы выполняются ТОЛЬКО с флагом --online.
Инструмент — для проверки СВОИХ данных или авторизованного пентеста.

Примеры:
    python footprint.py --email me@example.com --username mynick --online
    python footprint.py --phone "+7 999 123-45-67" --name "Иван Иванов"
    python footprint.py --email me@example.com --online --hibp-key "$HIBP_KEY" --out me.txt
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

UA = "Mozilla/5.0 (footprint-self-check; +local script)"
SITES_FILE = Path(__file__).with_name("sites.json")
DELETION_FILE = Path(__file__).with_name("deletion_links.json")
DEFAULT_OUT = Path(__file__).with_name("footprint_report.txt")

# Крупные брокеры данных / people-search — ссылки на самостоятельный opt-out.
_DATA_BROKERS = [
    ("Spokeo", "https://www.spokeo.com/optout"),
    ("BeenVerified", "https://www.beenverified.com/app/optout/search"),
    ("Whitepages", "https://www.whitepages.com/suppression-requests"),
    ("Intelius", "https://www.intelius.com/opt-out/"),
    ("PeopleFinders", "https://www.peoplefinders.com/opt-out"),
    ("Radaris", "https://radaris.com/page/how-to-remove"),
    ("MyLife", "https://www.mylife.com/ccpa/index.pubview"),
    ("PeekYou", "https://www.peekyou.com/about/contact/optout/"),
    ("TruePeopleSearch", "https://www.truepeoplesearch.com/removal"),
    ("FastPeopleSearch", "https://www.fastpeoplesearch.com/removal"),
    ("Google 'Результаты о вас'", "https://myactivity.google.com/results-about-you"),
]


# --- Таймер (живой отсчёт в терминале с момента запуска) -----------------

class Ticker:
    """Печатает [ЧЧ:ММ:СС] <фаза> в stderr, обновляясь раз в секунду."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.phase = "старт"
        self._stop = threading.Event()
        self._thr: threading.Thread | None = None
        self._t0 = 0.0
        self._tty = sys.stderr.isatty()

    @staticmethod
    def _fmt(sec: float) -> str:
        s = int(sec)
        return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"

    def _loop(self):
        last_line = 0.0
        while not self._stop.wait(1.0):
            el = time.monotonic() - self._t0
            if self._tty:
                sys.stderr.write(f"\r\033[K[{self._fmt(el)}] {self.phase}")
                sys.stderr.flush()
            elif el - last_line >= 20:          # в файл/пайп — строкой раз в 20с
                last_line = el
                sys.stderr.write(f"[{self._fmt(el)}] {self.phase}\n")
                sys.stderr.flush()

    def start(self):
        if not self.enabled:
            return
        self._t0 = time.monotonic()
        self._thr = threading.Thread(target=self._loop, daemon=True)
        self._thr.start()

    def set(self, phase: str):
        self.phase = phase
        if self.enabled and self._tty:
            el = time.monotonic() - self._t0
            sys.stderr.write(f"\r\033[K[{self._fmt(el)}] {phase}")
            sys.stderr.flush()

    def stop(self):
        if not self.enabled or not self._thr:
            return
        self._stop.set()
        self._thr.join(timeout=2)
        el = time.monotonic() - self._t0
        sys.stderr.write(f"\r\033[K[{self._fmt(el)}] завершено за {self._fmt(el)}\n")
        sys.stderr.flush()


# --- HTTP -----------------------------------------------------------------

def http_get(url: str, timeout: float = 8.0, headers: dict | None = None):
    """Возвращает (status_code, body_text). При ошибке сети — (None, "")."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(200_000).decode(resp.headers.get_content_charset() or "utf-8", "replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return None, ""


# --- Внешние инструменты (maigret / holehe) --------------------------------

_NOISE = ("%|", "it/s]", "BTC Donations", "palenath",
          "github.com/megadose/holehe", "\x1b[H\x1b[J", "[H[J")


def _clean(text: str) -> str:
    import re
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)  # ANSI-коды
    lines = [ln.rstrip() for ln in text.splitlines()
             if ln.strip() and not any(n in ln for n in _NOISE)]
    return "\n".join(lines) or "(пустой вывод)"


def run_external(cmd: list[str], timeout: float) -> str | None:
    """Запускает внешний CLI. None — не установлен; строка — очищенный вывод."""
    if shutil.which(cmd[0]) is None:
        return None
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return f"(таймаут {timeout:.0f}s — увеличь --ext-timeout)"
    except OSError as e:
        return f"(ошибка запуска: {e})"
    out = (p.stdout or "").strip() or (p.stderr or "").strip()
    return _clean(out)


def maigret_scan(usernames: list[str], timeout: float, full: bool = False,
                 proxy: str | None = None, permute: bool = False,
                 top_sites: int = 500, site_timeout: int = 10,
                 workers: int = 4) -> str | None:
    """Гоняет maigret по каждому нику ОТДЕЛЬНЫМ процессом и параллельно —
    так N ников идут одновременно, а не в очередь (главное ускорение).
      * top_sites   — сколько самых популярных сайтов (игнор при full)
      * site_timeout — таймаут одного HTTP внутри maigret
      * timeout     — общий потолок на один процесс maigret
    """
    import tempfile
    if shutil.which("maigret") is None:
        return None

    def one(user: str) -> str:
        # --folderoutput уводит файловые отчёты в /tmp, чтобы не мусорить в папке
        cmd = ["maigret", user, "--no-progressbar", "--no-recursion",
               "--timeout", str(site_timeout), "--retries", "1", "--no-color",
               "--folderoutput", tempfile.gettempdir()]
        if full:
            cmd.append("-a")  # весь список сайтов (~3300)
        elif top_sites:
            cmd += ["--top-sites", str(top_sites)]
        if permute:
            cmd.append("--permute")  # перестановки/склейки частей ника
        if proxy:
            cmd += ["--proxy", proxy]
        return run_external(cmd, timeout) or ""

    if len(usernames) == 1:
        return one(usernames[0]) or "(пустой вывод)"

    parts: list[str] = []
    with cf.ThreadPoolExecutor(max_workers=min(workers, len(usernames))) as ex:
        for user, out in zip(usernames, ex.map(one, usernames)):
            if out.strip():
                parts.append(f"# {user}\n{out}")
    return "\n".join(parts) if parts else "(пустой вывод)"


# --- Варианты ника ------------------------------------------------------

_TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


def _translit(s: str) -> str:
    return "".join(_TRANSLIT.get(ch, ch) for ch in s.lower())


def username_variants(username: str | None, name: str | None,
                      email: str | None, limit: int) -> list[str]:
    """Генерит правдоподобные варианты ника из ника / имени / почты."""
    import re
    out: list[str] = []

    def push(x: str):
        x = x.strip().lower()
        if x and x not in out and 2 <= len(x) <= 30:
            out.append(x)

    if username:
        push(username)
        push(username.rstrip("0123456789"))
    if email:
        lp = email.split("@")[0].lower()
        push(lp)
        push(lp.rstrip("0123456789"))
        push(re.sub(r"[._\-]", "", lp))
    if name:
        parts = [_translit(p) for p in re.split(r"\s+", name.strip()) if p]
        parts = [re.sub(r"[^a-z]", "", p) for p in parts if p]
        if len(parts) >= 2:
            a, b = parts[0], parts[1]
            for v in (a + b, b + a, f"{a}.{b}", f"{b}.{a}", f"{a}_{b}",
                      f"{b}_{a}", f"{a[0]}{b}", f"{b[0]}{a}"):
                push(v)
        for p in parts:
            push(p)
    return out[:limit]


def holehe_scan(email: str, timeout: float) -> str | None:
    return run_external(["holehe", email, "--only-used", "--no-color"], timeout)


# --- E-mail: gravatar + HIBP ---------------------------------------------

def gravatar(email: str, timeout: float) -> dict:
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    status, _ = http_get(f"https://www.gravatar.com/avatar/{h}?d=404", timeout)
    exists = status == 200
    out = {"hash": h, "has_public_avatar": exists,
           "avatar_url": f"https://www.gravatar.com/avatar/{h}" if exists else None,
           "profile": None}
    if exists:
        st, body = http_get(f"https://www.gravatar.com/{h}.json", timeout)
        if st == 200 and body:
            try:
                out["profile"] = json.loads(body)
            except json.JSONDecodeError:
                pass
    return out


def hibp(email: str, api_key: str, timeout: float) -> dict:
    if not api_key:
        return {"checked": False, "reason": "нет --hibp-key"}
    acct = urllib.parse.quote(email, safe="")
    status, body = http_get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{acct}?truncateResponse=true",
        timeout, headers={"hibp-api-key": api_key},
    )
    if status == 404:
        return {"checked": True, "breached": False, "breaches": []}
    if status == 200:
        try:
            names = [b.get("Name") for b in json.loads(body)]
        except json.JSONDecodeError:
            names = []
        out = {"checked": True, "breached": True, "breaches": names}
        ps, pb = http_get(
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{acct}",
            timeout, headers={"hibp-api-key": api_key},
        )
        if ps == 200:
            try:
                out["pastes"] = [f"{p.get('Source')}:{p.get('Id')}" for p in json.loads(pb)]
            except json.JSONDecodeError:
                pass
        return out
    return {"checked": True, "error": f"HTTP {status}"}


# --- Встроенный username-скан (fallback, если нет maigret) ---------------

def _load_sites() -> list[dict]:
    try:
        return json.loads(SITES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def _check_site(site: dict, username: str, timeout: float) -> dict:
    url = site["url"].format(u=urllib.parse.quote(username))
    status, body = http_get(url, timeout)
    found = None
    if status is not None:
        if site.get("check") == "text":
            found = status == 200 and site.get("absent", "") not in body
        else:
            found = status == 200
    return {"site": site["name"], "url": url, "status": status, "found": found}


def username_scan(username: str, timeout: float, workers: int) -> list[dict]:
    sites = _load_sites()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_check_site, s, username, timeout) for s in sites]
        return [f.result() for f in futs]


# --- Телефон -----------------------------------------------------------

_CC = {"7": "Россия/Казахстан", "1": "США/Канада", "44": "Великобритания",
       "49": "Германия", "33": "Франция", "380": "Украина", "375": "Беларусь",
       "998": "Узбекистан", "996": "Киргизия", "992": "Таджикистан"}


def _analyze_phone_basic(raw: str) -> dict:
    digits = "".join(c for c in raw if c.isdigit())
    if raw.strip().startswith("8") and len(digits) == 11:
        digits = "7" + digits[1:]
    country = None
    for code, name in sorted(_CC.items(), key=lambda x: -len(x[0])):
        if digits.startswith(code):
            country = name
            break
    return {"parsed": True, "library": "basic",
            "e164": "+" + digits if digits else None,
            "valid": None, "country": country, "carrier": None,
            "line_type": "UNKNOWN"}


def analyze_phone(raw: str) -> dict:
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, number_type, PhoneNumberType
    except ImportError:
        res = _analyze_phone_basic(raw)
        res["reason"] = "точнее с пакетом: pip install phonenumbers"
        return res
    try:
        num = phonenumbers.parse(raw, "RU")
    except phonenumbers.NumberParseException as e:
        return {"parsed": False, "reason": str(e)}
    types = {v: k for k, v in vars(PhoneNumberType).items() if isinstance(v, int)}
    return {"parsed": True, "library": "phonenumbers",
            "valid": phonenumbers.is_valid_number(num),
            "e164": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164),
            "country": geocoder.description_for_number(num, "ru") or None,
            "carrier": carrier.name_for_number(num, "ru") or None,
            "line_type": types.get(number_type(num), "UNKNOWN")}


# --- Поисковые запросы ------------------------------------------------

def build_queries(email=None, username=None, phone=None, name=None) -> dict:
    q: dict[str, list[str]] = {}
    if email:
        q["email"] = [f'"{email}"',
                      f'"{email}" (site:pastebin.com OR site:github.com OR site:trello.com)']
    if username:
        q["username"] = [f'"{username}"',
                         f'intext:"{username}" (site:vk.com OR site:t.me OR site:reddit.com)']
    if phone:
        digits = "".join(c for c in phone if c.isdigit())
        if phone.strip().startswith("8") and len(digits) == 11:
            digits = "7" + digits[1:]
        variants = {phone, digits, f"+{digits}"}
        if len(digits) == 11:
            variants.add(f"+{digits[0]} ({digits[1:4]}) {digits[4:7]}-{digits[7:9]}-{digits[9:]}")
        q["phone"] = [f'"{v}"' for v in sorted(variants)]
    if name:
        q["name"] = [f'"{name}"',
                     f'"{name}" (site:linkedin.com OR site:vk.com OR site:facebook.com OR site:ok.ru)',
                     f'"{name}" (резюме OR CV OR vc.ru OR habr.com OR hh.ru)',
                     f'"{name}" filetype:pdf',
                     f'"{name}" (телефон OR почта OR "дата рождения" OR адрес)']
    _ENGINES = {
        "google": "https://www.google.com/search?q=",
        "bing": "https://www.bing.com/search?q=",
        "ddg": "https://duckduckgo.com/?q=",
        "yandex": "https://yandex.ru/search/?text=",
    }
    links = {k: {eng: [base + urllib.parse.quote(s) for s in v]
                 for eng, base in _ENGINES.items()}
             for k, v in q.items()}
    return {"dorks": q, "links": links, "engines": list(_ENGINES)}


# --- Wayback Machine: что осталось в архиве ------------------------------

def wayback_lookup(url: str, timeout: float) -> dict | None:
    """Есть ли у archive.org снимок этого URL. None — снимков нет."""
    api = "http://archive.org/wayback/available?url=" + urllib.parse.quote(url, safe="")
    st, body = http_get(api, timeout)
    if st != 200 or not body:
        return None
    try:
        snap = (json.loads(body).get("archived_snapshots") or {}).get("closest")
    except json.JSONDecodeError:
        return None
    if not snap or not snap.get("available"):
        return None
    return {"url": url, "snapshot": snap.get("url"), "timestamp": snap.get("timestamp")}


def wayback_scan(urls: list[str], timeout: float, workers: int) -> list[dict]:
    out: list[dict] = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(lambda u: wayback_lookup(u, timeout), urls):
            if res:
                out.append(res)
    return out


# --- Разведка своего домена (crt.sh + DNS + Wayback) -------------------

def _clean_domain(raw: str) -> str:
    d = re.sub(r"^[a-z]+://", "", raw.strip().lower())
    return d.split("/")[0].strip(".")


def domain_recon(domain: str, timeout: float) -> dict:
    domain = _clean_domain(domain)
    res: dict = {"domain": domain}

    st, body = http_get(
        f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json", timeout)
    subs: set[str] = set()
    if st == 200 and body:
        try:
            for row in json.loads(body):
                for n in str(row.get("name_value", "")).splitlines():
                    n = n.strip().lstrip("*.").lower()
                    if n.endswith(domain):
                        subs.add(n)
        except json.JSONDecodeError:
            pass
    res["subdomains"] = sorted(subs)

    try:
        import socket
        res["dns_a"] = sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None)})
    except OSError:
        res["dns_a"] = []

    for path in ("robots.txt", "security.txt", ".well-known/security.txt", "sitemap.xml"):
        s, _ = http_get(f"https://{domain}/{path}", timeout)
        if s == 200:
            res.setdefault("exposed_files", []).append(f"https://{domain}/{path}")

    wb = wayback_lookup(f"http://{domain}", timeout)
    res["wayback"] = wb
    return res


# --- Найденные аккаунты + куда идти удалять ------------------------------

def parse_found_accounts(r: dict) -> list[dict]:
    """Собирает из вывода maigret/holehe/встроенного скана список
    {service, url, source} — реально существующие аккаунты.
    source: 'email' (holehe) | 'nick' (maigret) | 'scan' (встроенный)."""
    import re
    found: list[dict] = []
    seen: set = set()

    def add(service: str, url: str, source: str):
        key = (service.lower(), url)
        if key not in seen:
            seen.add(key)
            found.append({"service": service, "url": url, "source": source})

    mg = r.get("maigret")
    if isinstance(mg, str):
        for ln in mg.splitlines():
            m = re.match(r"^\[\+\]\s+(.+?):\s+(https?://\S+)", ln.strip())
            if m:
                add(m.group(1).strip(), m.group(2).strip(), "nick")

    ho = r.get("holehe")
    if isinstance(ho, str):
        for ln in ho.splitlines():
            m = re.match(r"^\[\+\]\s+([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})\s*$", ln.strip(), re.I)
            if m:
                dom = m.group(1).lower()
                add(dom, f"https://{dom}", "email")

    for row in r.get("username_scan", []):
        if row.get("found"):
            add(row["site"], row["url"], "scan")

    return found


def _load_deletion_map() -> dict:
    try:
        raw = json.loads(DELETION_FILE.read_text(encoding="utf-8"))
        return {k.lower(): v for k, v in raw.items()}
    except (OSError, json.JSONDecodeError):
        return {}


def deletion_hint(service: str, dmap: dict) -> str:
    """URL страницы удаления/настроек аккаунта для сервиса, либо поисковый запрос."""
    s = service.lower().strip()
    root = s.split("//")[-1].split("/")[0].replace("www.", "")
    base = root.split(".")[0]
    for key in (s, root, base):
        if key in dmap:
            return dmap[key]
    # нестрогое совпадение — только по длинным ключам, чтобы "x" не цеплял "xbox"
    for k, v in dmap.items():
        if len(k) >= 5 and (k in base or base in k):
            return v
    q = urllib.parse.quote(f"как удалить аккаунт {service}")
    return f"(нет в базе) https://www.google.com/search?q={q}"


# --- VK: публичная видимость СВОЕГО профиля ---------------------------

def vk_self_visibility(token: str, timeout: float) -> dict:
    """Что твой собственный VK-профиль показывает наружу. Только свой аккаунт:
    user_id берётся из токена."""
    def call(method: str, **params) -> dict:
        params.update(access_token=token, v="5.199")
        url = f"https://api.vk.com/method/{method}?{urllib.parse.urlencode(params)}"
        _, body = http_get(url, timeout)
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {}

    me = call("users.get", fields="screen_name,bdate,city,country,contacts,"
              "site,personal,universities,schools,career,relatives,connections")
    if "error" in me:
        return {"ok": False, "error": me["error"].get("error_msg", "ошибка VK API")}
    resp = me.get("response") or []
    if not resp:
        return {"ok": False, "error": "пустой ответ users.get (проверь токен)"}
    u = resp[0]
    uid = u["id"]

    exposed = {k: u[k] for k in ("bdate", "site", "mobile_phone", "home_phone",
                                 "skype", "instagram", "twitter", "facebook")
               if u.get(k)}
    if u.get("city"):
        exposed["city"] = u["city"].get("title")

    groups = call("groups.get", user_id=uid, extended=1, count=1000, fields="name")
    g = groups.get("response") or {}
    friends = call("friends.get", user_id=uid, count=0)
    f = friends.get("response") or {}

    return {
        "ok": True,
        "id": uid,
        "screen_name": u.get("screen_name"),
        "name": f"{u.get('first_name', '')} {u.get('last_name', '')}".strip(),
        "exposed_fields": exposed,
        "groups_count": g.get("count"),
        "groups": [it.get("name") for it in g.get("items", []) if it.get("name")],
        "friends_count": f.get("count"),
    }


# --- Оркестрация -----------------------------------------------------

def run(args, tk: "Ticker | None" = None) -> dict:
    if tk is None:
        tk = Ticker(enabled=False)
    r: dict = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "input": {k: v for k, v in dict(email=args.email, username=args.username,
                                        phone=args.phone, name=args.name).items() if v},
    }
    if args.phone:
        tk.set("разбор телефона")
        r["phone_analysis"] = analyze_phone(args.phone)
    r["search_queries"] = build_queries(args.email, args.username, args.phone, args.name)

    if not args.online:
        r["note"] = "Сетевые проверки выключены. Добавь --online."
        return r

    if args.email:
        tk.set("gravatar + HIBP")
        r["gravatar"] = gravatar(args.email, args.timeout)
        r["hibp"] = hibp(args.email, args.hibp_key or "", args.timeout)
        tk.set("holehe (регистрация почты на сервисах)")
        r["holehe"] = holehe_scan(args.email, args.ext_timeout)
    variants = username_variants(args.username, args.name, args.email, args.max_variants)
    if args.variants:
        for v in args.variants.split(","):
            v = v.strip().lower()
            if v and v not in variants:
                variants.append(v)
    if variants:
        r["username_variants"] = variants
        mode = "полный список ~3300" if args.full else f"топ-{args.top_sites}"
        tk.set(f"maigret [{mode}, {len(variants)} ников параллельно"
               f"{', +permute' if args.permute else ''}]")
        r["maigret"] = maigret_scan(variants, args.ext_timeout, full=args.full,
                                    proxy=args.proxy, permute=args.permute,
                                    top_sites=args.top_sites,
                                    site_timeout=args.site_timeout,
                                    workers=args.maigret_workers)
        if r["maigret"] is None:  # maigret не установлен — свой скан по первому нику
            tk.set("встроенный username-скан")
            r["username_scan"] = username_scan(variants[0], args.timeout, args.workers)
    if args.vk_token:
        tk.set("VK — видимость профиля")
        r["vk_self"] = vk_self_visibility(args.vk_token, args.timeout)

    # сводим всё найденное в чек-лист удаления (группируем по сервису)
    accs = sorted(parse_found_accounts(r), key=lambda a: (a["service"].lower(), a["url"]))
    dmap = _load_deletion_map()
    for acc in accs:
        acc["delete_via"] = deletion_hint(acc["service"], dmap)
    r["found_accounts"] = accs

    # Wayback: архивные копии найденных профилей (+ своего сайта)
    wb_urls = [a["url"] for a in accs][:40]
    if args.site:
        wb_urls.append(f"http://{_clean_domain(args.site)}")
    if wb_urls:
        tk.set(f"Wayback ({len(wb_urls)} url)")
        r["wayback"] = wayback_scan(wb_urls, args.timeout, args.workers)

    if args.site:
        tk.set(f"домен {args.site} — crt.sh, DNS")
        r["domain"] = domain_recon(args.site, args.timeout)

    return r


# --- Рендер отчёта --------------------------------------------------

def render_report(r: dict) -> str:
    L: list[str] = []
    add = L.append
    add("ЦИФРОВОЙ СЛЕД — ОТЧЁТ")
    add(f"Сгенерирован: {r['generated_at']}")
    add("Вход: " + ", ".join(f"{k}={v}" for k, v in r["input"].items()))
    add("=" * 60)

    accs = r.get("found_accounts") or []
    by_email = [a for a in accs if a.get("source") == "email"]
    by_nick = [a for a in accs if a.get("source") == "nick"]
    by_scan = [a for a in accs if a.get("source") == "scan"]
    pa = r.get("phone_analysis") or {}
    g = r.get("gravatar") or {}
    h = r.get("hibp") or {}

    def _table(rows: list[dict]):
        w = max((len(a["service"]) for a in rows), default=0)
        for a in rows:
            add(f"  [+] {a['service']:<{w}}  {a['url']}")

    # --- СВОДКА -------------------------------------------------------
    add("\n[СВОДКА]")
    add(f"  Аккаунтов:  {len(accs)}   "
        f"(по нику: {len(by_nick)}, по почте: {len(by_email)}"
        + (f", встроенный скан: {len(by_scan)}" if by_scan else "") + ")")
    if pa:
        add("  Телефон:    " + (
            f"{pa.get('e164') or '—'} — {pa.get('carrier') or '?'}, "
            f"{pa.get('country') or '?'}, {pa.get('line_type')}"
            if pa.get("parsed") else f"не разобран ({pa.get('reason')})"))
    if h:
        if not h.get("checked"):
            add(f"  Утечки:     не проверялись ({h.get('reason')})")
        elif h.get("breached"):
            add(f"  Утечки:     {len(h.get('breaches') or [])} (HIBP) — см. ниже")
        elif "error" in h:
            add(f"  Утечки:     ошибка HIBP ({h['error']})")
        else:
            add("  Утечки:     не найдено (HIBP)")
    if g:
        add(f"  Gravatar:   {'публичный профиль есть' if g.get('has_public_avatar') else 'нет'}")

    # --- ГДЕ ЗАРЕГИСТРИРОВАНА ПОЧТА --------------------------------
    if "holehe" in r or by_email:
        email = r["input"].get("email", "")
        add(f"\n[ПО E-MAIL]  {email}   (holehe — механика «восстановить пароль»)")
        if r.get("holehe") is None:
            add("  holehe не установлен: pipx install holehe")
        elif by_email:
            _table(by_email)
        else:
            add("  регистраций не найдено")

    # --- ГДЕ ЕСТЬ АККАУНТ ПО НИКУ ---------------------------------
    if "maigret" in r or by_nick:
        add("\n[ПО НИКУ]   (maigret)")
        if r.get("username_variants"):
            add(f"  варианты: {', '.join(r['username_variants'])}")
        if r.get("maigret") is None:
            add("  maigret не установлен: pipx install maigret")
        elif by_nick:
            _table(by_nick)
        else:
            add("  аккаунтов не найдено")

    if "username_scan" in r:
        add("\n[ВСТРОЕННЫЙ СКАН]  (fallback без maigret, ~20 сайтов)")
        hit = [row for row in r["username_scan"] if row.get("found")]
        noans = [row for row in r["username_scan"] if row.get("found") is None]
        _table([{"service": row["site"], "url": row["url"]} for row in hit])
        for row in noans:
            add(f"  [?] {row['site']:<14}  {row['url']}  (не ответил)")

    # --- ЧЕК-ЛИСТ УДАЛЕНИЯ ---------------------------------------
    if accs:
        add(f"\n[ЧЕК-ЛИСТ УДАЛЕНИЯ]  {len(accs)} шт.  (сверь каждую ссылку глазами)")
        for i, a in enumerate(accs, 1):
            add(f"  {i:>2}. {a['service']}  ({a.get('source', '?')})")
            add(f"      профиль:  {a['url']}")
            add(f"      удалить:  {a.get('delete_via', '—')}")

    if pa:
        add("\n[ТЕЛЕФОН]")
        if pa.get("parsed"):
            add(f"  E.164:    {pa.get('e164') or '—'}")
            add(f"  Валиден:  {pa.get('valid')}")
            add(f"  Страна:   {pa.get('country') or '—'}")
            add(f"  Оператор: {pa.get('carrier') or '—'}")
            add(f"  Тип:      {pa.get('line_type')}   (движок: {pa.get('library')})")
            if pa.get("reason"):
                add(f"  прим.: {pa['reason']}")
        else:
            add(f"  не разобран: {pa.get('reason')}")

    if h:
        add("\n[УТЕЧКИ — HaveIBeenPwned]")
        if not h.get("checked"):
            add(f"  пропущено: {h.get('reason')}")
        elif "error" in h:
            add(f"  ошибка: {h['error']}")
        elif h["breached"]:
            add(f"  найдено в {len(h['breaches'])} утечках:")
            for name in h["breaches"]:
                add(f"    - {name}")
            if h.get("pastes"):
                add(f"  в пастах ({len(h['pastes'])}): {', '.join(h['pastes'][:15])}")
        else:
            add("  не найдено")

    if g and (g.get("has_public_avatar") or g.get("profile")):
        add("\n[GRAVATAR]")
        if g.get("avatar_url"):
            add(f"  {g['avatar_url']}")
        if g.get("profile"):
            e = (g["profile"].get("entry") or [{}])[0]
            add(f"  Имя в профиле: {e.get('displayName') or '—'}")
            add(f"  Профиль: {e.get('profileUrl') or '—'}")

    vk = r.get("vk_self")
    if vk:
        add("\n[VK — публичная видимость ТВОЕГО профиля]")
        if not vk.get("ok"):
            add(f"  ошибка: {vk.get('error')}")
        else:
            add(f"  Профиль: vk.com/{vk.get('screen_name') or ('id' + str(vk['id']))}"
                f"  ({vk.get('name')})")
            ef = vk.get("exposed_fields") or {}
            add(f"  Открытые поля: {', '.join(f'{k}={v}' for k, v in ef.items()) or 'нет'}")
            add(f"  Друзей видно: {vk.get('friends_count')}")
            add(f"  Групп видно:  {vk.get('groups_count')}")
            for name in (vk.get("groups") or [])[:60]:
                add(f"    - {name}")
            if vk.get("groups_count", 0) > 60:
                add(f"    … ещё {vk['groups_count'] - 60}")
            add("  Закрыть: vk.com/settings?act=privacy  (подписки, друзья, поля)")

    wb = r.get("wayback")
    if wb is not None:
        add(f"\n[WAYBACK — архивные копии, остаются после удаления]  ({len(wb)})")
        for row in wb:
            ts = row.get("timestamp", "")
            ts = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
            add(f"  {ts}  {row['url']}")
            add(f"            {row['snapshot']}")
        if not wb:
            add("  архивных копий не найдено")
        add("  Удаление из архива: https://help.archive.org/help/how-do-i-request-to-remove-something-from-archive-org/")

    dom = r.get("domain")
    if dom:
        add(f"\n[DOMAIN — {dom['domain']}]")
        add(f"  A-записи: {', '.join(dom.get('dns_a') or []) or '—'}")
        subs = dom.get("subdomains") or []
        add(f"  Поддомены (crt.sh): {len(subs)}")
        for s in subs[:50]:
            add(f"    - {s}")
        if len(subs) > 50:
            add(f"    … ещё {len(subs) - 50}")
        for f in dom.get("exposed_files") or []:
            add(f"  открыто: {f}")
        if dom.get("wayback"):
            add(f"  wayback: {dom['wayback']['snapshot']}")

    sq = r.get("search_queries") or {}
    if sq.get("dorks"):
        add("\n[ПОИСКОВЫЕ ЗАПРОСЫ]  (скопируй строку в любой поисковик)")
        for cat, items in sq["dorks"].items():
            add(f"  {cat}:")
            for s in items:
                add(f"    {s}")

    add("\n[КАК УДАЛЯТЬ — ОБЩЕЕ]")
    add("  - Аккаунты выше: залогинься → настройки → удалить/деактивировать.")
    add("  - Пароли из [УТЕЧКИ]: смени везде, где повторял; включи 2FA.")
    add("  - Убрать из выдачи Google: https://support.google.com/websearch/troubleshooter/9685456")
    add("  - Убрать из выдачи Яндекса: https://yandex.ru/support/webmaster/removed-pages/remove-url.html")
    add("  - Каталог ссылок на удаление аккаунтов: https://justdeleteme.xyz")
    add("  - Выгрузить, что о тебе знает сервис: https://justgetmydata.com")

    add("\n[БРОКЕРЫ ДАННЫХ — opt-out]  (агрегаторы, торгующие профилями)")
    for name, link in _DATA_BROKERS:
        add(f"  - {name}: {link}")

    if "note" in r:
        add(f"\n{r['note']}")
    add("")
    return "\n".join(L)


# --- CLI ------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Проверка собственного цифрового следа (OSINT self-check).")
    p.add_argument("--email")
    p.add_argument("--username")
    p.add_argument("--phone")
    p.add_argument("--name", help="Имя и фамилия одной строкой.")
    p.add_argument("--online", action="store_true", help="Разрешить сетевые запросы.")
    p.add_argument("--full", action="store_true",
                   help="maigret по всему списку сайтов (~3300, дольше).")
    p.add_argument("--variants", help="Доп. варианты ника через запятую.")
    p.add_argument("--max-variants", dest="max_variants", type=int, default=6,
                   help="Сколько авто-вариантов ника генерить (из имени/почты).")
    p.add_argument("--permute", action="store_true",
                   help="maigret перебирает перестановки/склейки переданных ников (медленно, шумно).")
    p.add_argument("--top-sites", dest="top_sites", type=int, default=500,
                   help="maigret: сколько самых популярных сайтов (по умолч. 500; "
                        "ставь 100–150 для быстрого прогона). Игнорируется при --full.")
    p.add_argument("--site-timeout", dest="site_timeout", type=int, default=10,
                   help="Таймаут одного HTTP-запроса внутри maigret, сек (по умолч. 10).")
    p.add_argument("--maigret-workers", dest="maigret_workers", type=int, default=4,
                   help="Сколько вариантов ника гнать через maigret одновременно (по умолч. 4).")
    p.add_argument("--site", help="Твой домен — разведка: crt.sh, DNS, Wayback.")
    p.add_argument("--proxy", help="Прокси для maigret, напр. socks5://127.0.0.1:9050")
    p.add_argument("--hibp-key", dest="hibp_key", help="API-ключ HaveIBeenPwned.")
    p.add_argument("--vk-token", dest="vk_token",
                   help="access_token ВК — покажет публичную видимость ТВОЕГО профиля.")
    p.add_argument("--out", default=str(DEFAULT_OUT),
                   help=f"Файл отчёта .txt (перезаписывается). По умолчанию: {DEFAULT_OUT.name}")
    p.add_argument("--timeout", type=float, default=8.0, help="Таймаут одного HTTP-запроса.")
    p.add_argument("--ext-timeout", dest="ext_timeout", type=float, default=900.0,
                   help="Таймаут maigret/holehe целиком, сек (для --full ставь больше).")
    p.add_argument("--workers", type=int, default=10)
    p.add_argument("--json", action="store_true", help="Также вывести JSON в stdout.")
    p.add_argument("--no-timer", dest="no_timer", action="store_true",
                   help="Не показывать таймер [ЧЧ:ММ:СС] в терминале.")
    args = p.parse_args(argv)

    if not any([args.email, args.username, args.phone, args.name, args.vk_token]):
        p.error("нужен хотя бы один из --email/--username/--phone/--name/--vk-token")

    tk = Ticker(enabled=not args.no_timer)
    tk.start()
    try:
        result = run(args, tk)
    finally:
        tk.stop()
    report = render_report(result)

    out_path = Path(args.out)
    out_path.write_text(report, encoding="utf-8")  # перезапись при каждом запуске

    print(report)
    print(f"\n>>> Отчёт записан (перезаписан): {out_path}")
    if args.json:
        print("\n--- JSON ---")
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

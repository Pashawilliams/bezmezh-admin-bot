#!/usr/bin/env python3
"""
Админ-бот сайта БЕЗ МЕЖ (Telegram).

- Пользуются только OWNER_ID и админы; остальных молча игнорирует.
- Правит data/site.json и коммитит в GitHub через REST API —
  сайт на Pages обновляется сам.
- Только стандартная библиотека Python, без зависимостей.
- Заявки с сайта прилетают через ntfy-мост (без переписки с посетителями).
- Чисто завершается после MAX_RUNTIME секунд, Actions его перезапускает.
"""
import json
import os
import sys
import time
import base64
import hashlib
import hmac
import signal
import logging
import datetime as dt
import urllib.request
import urllib.parse
import urllib.error
import re
import threading

BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()


def _parse_admin_id(val, fallback=7906546417):
    if not val:
        return fallback
    digits = "".join(ch for ch in str(val) if ch.isdigit())
    try:
        return int(digits) if digits else fallback
    except Exception:
        return fallback


OWNER_ID = _parse_admin_id(os.environ.get("ADMIN_ID", "7906546417"))
ADMIN_ID = OWNER_ID  # kept for backwards compat (owner chat)
NTFY = "https://ntfy.sh/"
GH_TOKEN = os.environ.get("GH_TOKEN", "").strip()
GH_REPO = os.environ.get("GH_REPO", "Pashawilliams/bez-mezh-site")
GH_BRANCH = os.environ.get("GH_BRANCH", "main")
DATA_PATH = "data/site.json"
STATE_PATH = "bot/state.json"
SITE_URL = os.environ.get("SITE_URL", "http://bez-mezh.pp.ua/")
try:
    MAX_RUNTIME = int(os.environ.get("MAX_RUNTIME") or str(5 * 3600 + 20 * 60))  # 5h20m
except Exception:
    MAX_RUNTIME = 19200
STATE_SECRET = os.environ.get("STATE_SECRET", "").strip()
START = time.time()

API = f"https://api.telegram.org/bot{BOT_TOKEN}/"
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("bot")

# ----------------------------------------------------------------- HTTP helpers

def http(url, data=None, headers=None, method=None, timeout=60):
    body = None
    h = {"User-Agent": "site-admin-bot"}
    if headers:
        h.update(headers)
    if data is not None:
        body = json.dumps(data).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "{}")


def tg(method, **params):
    try:
        return http(API + method, params)
    except urllib.error.HTTPError as e:
        try:
            err = e.read().decode()
        except Exception:
            err = str(e)
        log.warning("tg %s failed: %s", method, err[:300])
        return {"ok": False, "error": err}
    except Exception as e:
        log.warning("tg %s error: %s", method, e)
        return {"ok": False, "error": str(e)}


CTX = threading.local()


def cur_chat():
    return getattr(CTX, "chat", None) or OWNER_ID


def _clip(text, limit=3900):
    text = str(text)
    if len(text) <= limit:
        return text
    cut = re.sub(r"&[A-Za-z0-9#]*$", "", text[:limit])
    return cut + "\u2026"


def _plain(text):
    t = re.sub(r"<[^>]*>", "", str(text))
    return t.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#039;", "'").replace("&amp;", "&")


def send(text, kb=None, chat_id=None, parse="HTML"):
    text = _clip(text)
    p = {"chat_id": chat_id or cur_chat(), "text": text, "parse_mode": parse, "disable_web_page_preview": True}
    if kb:
        p["reply_markup"] = kb
    r = tg("sendMessage", **p)
    if not r.get("ok") and parse == "HTML":
        p2 = {"chat_id": p["chat_id"], "text": _clip(_plain(text)), "disable_web_page_preview": True}
        if kb:
            p2["reply_markup"] = kb
        r = tg("sendMessage", **p2)
    return r


def edit(msg_id, text, kb=None, chat_id=None):
    text = _clip(text)
    p = {"chat_id": chat_id or cur_chat(), "message_id": msg_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    if kb:
        p["reply_markup"] = kb
    r = tg("editMessageText", **p)
    if r.get("ok"):
        return
    if "not modified" in str(r.get("error", "")):
        return
    send(text, kb, chat_id)


def ikb(rows):
    return {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in rows]}


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

# ----------------------------------------------------------------- GitHub storage

GH_H = {"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github+json"} if GH_TOKEN else {"Accept": "application/vnd.github+json"}


def default_state():
    return {"leads": [], "log": [], "admins": [], "chats": {}, "banned": [], "dialogs": {}}


def _state_fallback(src=None):
    st = default_state()
    if isinstance(src, dict):
        st["offset"] = src.get("offset", 0)
        st["bridge_since"] = src.get("bridge_since") or "5m"
        st["admins"] = src.get("admins") or []
        st["banned"] = src.get("banned") or []
    return st


def _state_key():
    return hashlib.pbkdf2_hmac(
        "sha256",
        STATE_SECRET.encode("utf-8"),
        b"bezmezh-bot-state-v1",
        200_000,
        dklen=32,
    )


def _xor_stream(data, key, nonce):
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        out.extend(hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(a ^ b for a, b in zip(data, out))


def encrypt_state(obj):
    """Encrypt bot runtime state before writing it to the public repo.

    This keeps leads private if GitHub Actions secret STATE_SECRET is set.
    The offset fields remain public so the bot can avoid replay storms even if
    the secret is temporarily missing.
    """
    payload = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    key = _state_key()
    nonce = os.urandom(16)
    ct = _xor_stream(payload, key, nonce)
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return {
        "_encrypted": "state.v1",
        "_note": "Encrypted Telegram bot state. Do not edit manually. Secret: GitHub Actions STATE_SECRET.",
        "offset": obj.get("offset", 0),
        "bridge_since": obj.get("bridge_since") or "5m",
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "tag": base64.b64encode(tag).decode(),
        "updated_at": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def decrypt_state(obj):
    if not isinstance(obj, dict):
        return default_state()
    if obj.get("_encrypted") != "state.v1":
        return obj
    fallback = _state_fallback(obj)
    if not STATE_SECRET:
        log.warning("bot state is encrypted, but STATE_SECRET is not configured; using public offsets only")
        return fallback
    try:
        key = _state_key()
        nonce = base64.b64decode(obj.get("nonce") or "")
        ct = base64.b64decode(obj.get("ciphertext") or "")
        tag = base64.b64decode(obj.get("tag") or "")
        expected = hmac.new(key, nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("state authentication failed")
        plain = _xor_stream(ct, key, nonce)
        state = json.loads(plain.decode("utf-8"))
        return state if isinstance(state, dict) else fallback
    except Exception:
        log.exception("cannot decrypt bot state; using public offsets only")
        return fallback


def public_state(obj):
    """Redacted state safe to keep in a public repository.

    Without STATE_SECRET, active leads live only in bot memory until the
    current GitHub Actions run ends. This is intentional: a public repo must not
    contain client names, phones, messages, or attachments.
    """
    return {
        "_state": "public-redacted-v1",
        "_note": "Sensitive leads/logs are intentionally not stored in the public repository. Set GitHub Actions secret STATE_SECRET to persist encrypted full bot state.",
        "offset": obj.get("offset", 0),
        "bridge_since": obj.get("bridge_since") or "5m",
        "admins": obj.get("admins") or [],
        "banned": obj.get("banned") or [],
        "leads": [],
        "log": [],
        "chats": {},
        "dialogs": {},
    }


def state_for_repo(obj):
    return encrypt_state(obj) if STATE_SECRET else public_state(obj)


class Store:
    def __init__(self):
        self.data = None
        self.sha = None
        self.state = default_state()
        self.state_sha = None
        self._lock = threading.Lock()

    def load(self):
        loaded = False
        if GH_TOKEN:
            for attempt in range(4):
                try:
                    r = http(f"https://api.github.com/repos/{GH_REPO}/contents/{DATA_PATH}?ref={GH_BRANCH}", headers=GH_H)
                    if r.get("sha") and r.get("content"):
                        self.sha = r["sha"]
                        self.data = json.loads(base64.b64decode(r["content"]).decode("utf-8"))
                        loaded = True
                        break
                except Exception as e:
                    log.warning("attempt %d fetching %s from GitHub API failed: %s", attempt + 1, DATA_PATH, e)
                    if attempt < 3:
                        time.sleep(2 + attempt)
                        continue

        # Fallback to raw.githubusercontent.com
        if not loaded:
            try:
                raw_url = f"https://raw.githubusercontent.com/{GH_REPO}/{GH_BRANCH}/{DATA_PATH}"
                req = urllib.request.Request(raw_url, headers={"User-Agent": "site-admin-bot"})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    self.data = json.loads(resp.read().decode("utf-8"))
                    loaded = True
                    log.info("loaded %s via raw fallback", DATA_PATH)
            except Exception as e:
                log.warning("raw fallback load failed: %s", e)

        if not loaded or not isinstance(self.data, dict):
            self.data = {"site": {"name": "БЕЗ МЕЖ"}, "routes": [], "reviews": [], "faq": [], "contacts": {}}

        loaded_state = False
        if GH_TOKEN:
            try:
                r = http(f"https://api.github.com/repos/{GH_REPO}/contents/{STATE_PATH}?ref={GH_BRANCH}", headers=GH_H)
                if r.get("sha") and r.get("content"):
                    self.state_sha = r["sha"]
                    raw_state = json.loads(base64.b64decode(r["content"]).decode("utf-8"))
                    self.state = decrypt_state(raw_state)
                    loaded_state = True
            except Exception as e:
                log.debug("cannot load state via API: %s", e)

        if not loaded_state:
            try:
                raw_state_url = f"https://raw.githubusercontent.com/{GH_REPO}/{GH_BRANCH}/{STATE_PATH}"
                req = urllib.request.Request(raw_state_url, headers={"User-Agent": "site-admin-bot"})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    raw_state = json.loads(resp.read().decode("utf-8"))
                    self.state = decrypt_state(raw_state)
            except Exception:
                self.state_sha = None
                self.state = default_state()

        if not isinstance(self.state, dict):
            self.state = default_state()
        for k, v in (("leads", []), ("log", []), ("admins", []), ("chats", {}), ("banned", []), ("dialogs", {})):
            self.state.setdefault(k, v)
        if isinstance(self.data, dict):
            self.data.setdefault("managers", [])
        return self.data

    def _put(self, path, obj, sha, msg):
        content = base64.b64encode(json.dumps(obj, ensure_ascii=False, indent=2).encode()).decode()
        body = {"message": msg, "content": content, "branch": GH_BRANCH}
        if sha:
            body["sha"] = sha
        if not GH_TOKEN:
            log.warning("GH_TOKEN is missing, cannot write %s to GitHub", path)
            return None
        for attempt in range(3):
            try:
                r = http(f"https://api.github.com/repos/{GH_REPO}/contents/{path}", body, GH_H, method="PUT")
                if r.get("content") and r["content"].get("sha"):
                    return r["content"]["sha"]
            except urllib.error.HTTPError as e:
                err_text = ""
                try:
                    err_text = e.read().decode()
                except Exception:
                    pass
                log.warning("gh put %s failed (attempt %d): %s %s", path, attempt + 1, e.code, err_text[:200])
                if e.code in (409, 422):
                    try:
                        cur = http(f"https://api.github.com/repos/{GH_REPO}/contents/{path}?ref={GH_BRANCH}", headers=GH_H)
                        body["sha"] = cur.get("sha")
                    except Exception:
                        pass
                elif e.code == 403:
                    log.warning("GitHub token lacks write permissions for %s", path)
                    break
                time.sleep(1 + attempt)
            except Exception as e:
                log.warning("gh put %s error: %s", path, e)
                time.sleep(1 + attempt)
        return None

    def save(self, msg):
        self.data["updated_at"] = dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._lock:
            self.sha = self._put(DATA_PATH, self.data, self.sha, f"admin-bot: {msg}")
        self.state.setdefault("log", []).append({"t": self.data["updated_at"], "msg": msg})
        self.state["log"] = self.state["log"][-200:]
        self.save_state(silent=True)

    _lock = threading.Lock()

    def save_state(self, silent=False):
        try:
            with self._lock:
                self.state_sha = self._put(STATE_PATH, state_for_repo(self.state), self.state_sha, "admin-bot: state")
        except Exception as e:
            log.warning("state save failed: %s", e)
            if not silent:
                raise


store = Store()
pending = {}  # chat_id -> {"action":..., ...}
state_dirty = {"flag": False}


def _aid(a):
    try:
        return int((a or {}).get("id"))
    except Exception:
        return None


def _idx(v, n):
    try:
        i = int(v)
    except Exception:
        return None
    return i if 0 <= i < n else None


def _stars(r):
    try:
        return "\u2605" * max(1, min(5, int(str(r.get("stars", 5)).strip()[0])))
    except Exception:
        return "\u2605" * 5


def admin_ids():
    ids = [OWNER_ID] + [_aid(a) for a in store.state.get("admins", [])]
    return list(dict.fromkeys(i for i in ids if i is not None))


def is_admin(uid):
    return uid in admin_ids()


def is_owner(uid):
    return uid == OWNER_ID


def broadcast(text, kb=None):
    for uid in admin_ids():
        send(text, kb, chat_id=uid)


def mark_dirty():
    state_dirty["flag"] = True

# ----------------------------------------------------------------- UI

def main_menu():
    d = store.data
    st = store.state
    new_leads = sum(1 for l in st.get("leads", []) if not l.get("done"))
    m = "🔴 Техработы" if d["site"].get("maintenance") else "🟢 Онлайн"
    an = d["site"].get("announcement", {})
    return ikb([
        [(f"📥 Заявки{' · '+str(new_leads) if new_leads else ''}", "leads")],
        [("🛣 Маршруты", "routes:0"), ("💶 Цены", "pricing"), ("⭐ Отзывы", "reviews"), ("❓ FAQ", "faq")],
        [("🏠 Главная", "hero"), ("👤 Менеджеры", "managers")],
        [(("📢 Объявление ✓" if an.get("enabled") else "📢 Объявление"), "announce"), (m, "maint")],
        [("👥 Админы", "admins"), ("📊 Журнал", "stats")],
        [("📣 Рассылка", "cast"), ("🌐 Сайт", "open")],
    ])


def show_main(msg_id=None):
    d = store.data
    txt = (f"<b>БЕЗ МЕЖ · панель</b>\n"
           f"🛣 {len(d['routes'])} · ⭐ {len(d['reviews'])} · ❓ {len(d['faq'])}\n"
           f"<i>обновлено {esc((d.get('updated_at','') or '')[5:16].replace('T',' '))}</i>")
    if msg_id:
        edit(msg_id, txt, main_menu())
    else:
        send(txt, main_menu())


PAGE = 10


def routes_view(page, msg_id=None):
    rs = store.data["routes"]
    total = len(rs)
    page = max(0, min(page, (total - 1) // PAGE))
    rows = []
    for i in range(page * PAGE, min(total, (page + 1) * PAGE)):
        r = rs[i]
        eye = "" if r.get("visible", True) else "🚫 "
        _pc = price_for(r['from'], r['to'])
        rows.append([(f"{eye}{r['from']} → {r['to']} · {(str(_pc['uah']) + ' ₴ · ' + str(_pc['hours']) + ' ч') if _pc else '—'}", f"route:{i}")])
    nav = []
    if page > 0:
        nav.append(("◀️", f"routes:{page-1}"))
    nav.append((f"{page+1}/{(total-1)//PAGE+1}", "noop"))
    if (page + 1) * PAGE < total:
        nav.append(("▶️", f"routes:{page+1}"))
    rows.append(nav)
    rows.append([("➕ Маршрут", "route_add"), ("💶 Тариф / курс", "pricing")])
    rows.append([("⬅️ Меню", "main")])
    txt = f"<b>Маршруты</b> · {total}"
    if msg_id:
        edit(msg_id, txt, ikb(rows))
    else:
        send(txt, ikb(rows))


def route_view(i, msg_id=None):
    if not (0 <= i < len(store.data["routes"])):
        return routes_view(0, msg_id)
    _r = store.data["routes"][i]
    _pc = price_for(_r["from"], _r["to"], "comfort"); _pl = price_for(_r["from"], _r["to"], "lux")
    _auto = (f"\n🕒 В пути ~{_pc['hours']} ч · Comfort (08:00) €{_pc['eur']} ≈ {_pc['uah']} ₴ · Lux (18:00) €{_pl['eur']} ≈ {_pl['uah']} ₴" if (_pc and _pl) else "\n⚠️ Время в пути ещё не рассчитано (💶 Цены → Пересчитать)")
    r = store.data["routes"][i]
    vis = "🚫 Скрыть" if r.get("visible", True) else "✅ Показать"
    txt = (f"<b>{esc(r['from'])} → {esc(r['to'])}</b>\n"
           f"💰 Цена: автоматически по времени в пути" + _auto +
           (f"\n🔖 {esc(r['badge'])}" if r.get('badge') else "") + ("" if r.get('visible', True) else "\n🚫 скрыто"))
    kb = ikb([
        [("💶 Тариф и курс", "pricing")],
        [("🔖 Бейдж", f"rset:{i}:badge"), (vis, f"rtoggle:{i}")],
        [("🗑 Удалить", f"rdel:{i}"), ("⬅️ Назад", f"routes:{i//PAGE}")],
    ])
    if msg_id:
        edit(msg_id, txt, kb)
    else:
        send(txt, kb)


def reviews_view(msg_id=None):
    rows = [[(f"{(r.get('name') or '?')[:40]} · {r.get('date','')} · {_stars(r)}", f"review:{i}")] for i, r in enumerate(store.data["reviews"][:40])]
    rows.append([("➕ Добавить отзыв", "review_add"), ("⬅️ Меню", "main")])
    txt = "<b>Отзывы</b>\n" + "\n\n".join(f"<b>{esc(r.get('name') or '?')}</b> ({esc(r.get('date',''))}): {esc((r.get('text') or '')[:120])}…" for r in store.data["reviews"])
    (edit if msg_id else send)(*((msg_id, txt, ikb(rows)) if msg_id else (txt, ikb(rows))))


def faq_view(msg_id=None):
    rows = [[(f"{i+1}. {(f.get('q') or '?')[:40]}", f"faqi:{i}")] for i, f in enumerate(store.data["faq"][:40])]
    rows.append([("➕ Добавить вопрос", "faq_add"), ("⬅️ Меню", "main")])
    txt = "<b>FAQ</b> (первый вопрос показывается большой карточкой):\n\n" + "\n".join(f"{i+1}. {esc(f.get('q') or '?')}" for i, f in enumerate(store.data["faq"]))
    (edit if msg_id else send)(*((msg_id, txt, ikb(rows)) if msg_id else (txt, ikb(rows))))


def contacts_view(msg_id=None):
    c = store.data["contacts"]
    txt = (f"<b>Контакты</b>\nТелефон: {esc(c.get('phone',''))} (показ: {esc(c.get('phone_display',''))})\n"
           f"Telegram: {esc(c.get('telegram',''))}\nWhatsApp: {esc(c.get('whatsapp',''))}\nПодпись: {esc(c.get('support_note',''))}")
    kb = ikb([
        [("📱 Телефон", "cset:phone"), ("✈️ Telegram", "cset:telegram")],
        [("💬 WhatsApp", "cset:whatsapp"), ("📝 Подпись в шапке", "cset:support_note")],
        [("👤 Менеджеры", "managers"), ("⬅️ Меню", "main")],
    ])
    (edit if msg_id else send)(*((msg_id, txt, kb) if msg_id else (txt, kb)))


def _mgr_fmt(m):
    d = "".join(ch for ch in m.get("phone", "") if ch.isdigit())
    ph = f"+{d[:3]} {d[3:5]} {d[5:8]} {d[8:10]} {d[10:]}".strip() if len(d) == 12 else m.get("phone", "")
    return f"<b>{esc(m.get('name',''))}</b> — {esc(ph)}\n<i>{esc(m.get('role',''))}</i>"


def managers_view(msg_id=None):
    ms = store.data.setdefault("managers", [])
    txt = "<b>👤 Менеджеры</b>\nПоказываются в разделе «Контакты», в футере, в мобильном меню и в окне выбора «кому написать/позвонить».\n\n"
    txt += "\n\n".join(f"{i+1}. {_mgr_fmt(m)}" for i, m in enumerate(ms)) if ms else "<i>Список пуст — на сайте показываются менеджеры по умолчанию.</i>"
    rows = [[(f"{i+1}. {m.get('name','')}", f"mgr:{i}")] for i, m in enumerate(ms)]
    rows.append([("➕ Добавить менеджера", "mgr_add")])
    rows.append([("📞 Общие контакты", "contacts"), ("⬅️ Меню", "main")])
    (edit if msg_id else send)(*((msg_id, txt, ikb(rows)) if msg_id else (txt, ikb(rows))))


def manager_view(i, msg_id=None):
    ms = store.data.get("managers", [])
    if i >= len(ms):
        return managers_view(msg_id)
    m = ms[i]
    txt = (f"{_mgr_fmt(m)}\nTelegram: {esc(m.get('telegram','') or 'авто (по номеру)')}\nWhatsApp: {esc(m.get('whatsapp','') or 'авто (по номеру)')}")
    kb = ikb([
        [("✏️ Имя", f"mset:{i}:name"), ("✏️ Должность", f"mset:{i}:role")],
        [("📱 Телефон", f"mset:{i}:phone"), ("✈️ Telegram", f"mset:{i}:telegram"), ("💬 WhatsApp", f"mset:{i}:whatsapp")],
        [("⬆️ Выше", f"mup:{i}"), ("🗑 Удалить", f"mdel:{i}"), ("⬅️ Назад", "managers")],
    ])
    (edit if msg_id else send)(*((msg_id, txt, kb) if msg_id else (txt, kb)))


def _parse_manager(text, m=None):
    m = dict(m or {})
    lines = [l.strip() for l in text.split("\n") if l.strip()]
    if len(lines) < 2:
        raise ValueError("format")
    m["name"] = lines[0]
    d = "".join(ch for ch in lines[1] if ch.isdigit())
    if len(d) < 10:
        raise ValueError("phone")
    m["phone"] = "+" + d
    m["role"] = lines[2] if len(lines) > 2 else m.get("role") or "Менеджер з перевезень"
    m["telegram"] = lines[3] if len(lines) > 3 else m.get("telegram") or f"https://t.me/+{d}"
    m["whatsapp"] = lines[4] if len(lines) > 4 else m.get("whatsapp") or f"https://wa.me/{d}"
    return m


# ----------------------------------------------------------------- pricing (time-based)
CITY_COORDS = {
    "Івано-Франківськ": (24.7111, 48.9226),
    "Ізмаїл": (28.84, 45.35),
    "Інгольштадт": (11.4259, 48.7433),
    "Ірпінь": (30.25, 50.521),
    "Їглава": (15.591, 49.3961),
    "Алмере": (5.2194, 52.3705),
    "Амстердам": (4.9041, 52.3676),
    "Антверпен": (4.4025, 51.2194),
    "Бердичів": (28.602, 49.899),
    "Берлін": (13.405, 52.52),
    "Бонн": (7.0982, 50.7374),
    "Бориспіль": (30.955, 50.352),
    "Братислава": (17.1077, 48.1486),
    "Бреда": (4.7683, 51.5719),
    "Бреїла": (27.9575, 45.2692),
    "Брно": (16.6068, 49.1951),
    "Бровари": (30.7909, 50.5111),
    "Броди": (25.1478, 50.0827),
    "Брюгге": (3.2247, 51.2093),
    "Брюссель": (4.3517, 50.8503),
    "Будапешт": (19.0402, 47.4979),
    "Бухарест": (26.1025, 44.4268),
    "Біла Церква": (30.116, 49.795),
    "Білефельд": (8.5325, 52.0302),
    "Варшава": (21.0122, 52.2297),
    "Вроцлав": (17.0385, 51.1079),
    "Вюрцбург": (9.9534, 49.7913),
    "Відень": (16.3738, 48.2082),
    "Вінниця": (28.4682, 49.2331),
    "Гаага": (4.3007, 52.0705),
    "Галац": (28.008, 45.4353),
    "Ганновер": (9.732, 52.3759),
    "Гент": (3.7214, 51.0543),
    "Градець-Кралове": (15.8258, 50.2104),
    "Дніпро": (35.0462, 48.4647),
    "Дортмунд": (7.4653, 51.5136),
    "Дрезден": (13.7373, 51.0504),
    "Дрогобич": (23.506, 49.352),
    "Дубно": (25.735, 50.3938),
    "Дюссельдорф": (6.7735, 51.2277),
    "Ейндговен": (5.4697, 51.4416),
    "Ерфурт": (11.0299, 50.9848),
    "Ессен": (7.0116, 51.4556),
    "Жешув": (21.999, 50.0413),
    "Житомир": (28.6587, 50.2547),
    "Запоріжжя": (35.1396, 47.8388),
    "Захонь": (22.176, 48.405),
    "Звягель": (27.62, 50.59),
    "КПП Могилів-Подільський": (27.7861, 48.4433),
    "Калуш": (24.367, 49.043),
    "Кам'янець-Подільський": (26.58, 48.68),
    "Кам'янське": (34.6021, 48.511),
    "Карлові Вари": (12.8712, 50.2317),
    "Кассель": (9.4797, 51.3127),
    "Катовіце": (19.0238, 50.2649),
    "Кельн": (6.9603, 50.9375),
    "Кишинів": (28.8638, 47.0105),
    "Київ": (30.5234, 50.4501),
    "Ковель": (24.709, 51.215),
    "Коломия": (25.04, 48.53),
    "Конотоп": (33.2, 51.24),
    "Коростень": (28.64, 50.95),
    "Краків": (19.945, 50.0647),
    "Кременчук": (33.4204, 49.068),
    "Кривий Ріг": (33.3919, 47.9105),
    "Кропивницький": (32.2623, 48.5079),
    "Лейпциг": (12.3731, 51.3397),
    "Лозова": (36.317, 48.889),
    "Луцьк": (25.3254, 50.7472),
    "Львів": (24.0297, 49.8397),
    "Льовен": (4.7005, 50.8796),
    "Льєж": (5.5734, 50.6452),
    "Люблін": (22.5684, 51.2465),
    "Мадрид": (-3.7038, 40.4168),
    "Мапп Угринів": (24.0289, 50.5772),
    "Медика": (22.932, 49.804),
    "Миколаїв": (31.9946, 46.975),
    "Монс": (3.9523, 50.4542),
    "Мукачево": (22.7139, 48.4414),
    "Мюнстер": (7.6261, 51.9607),
    "Мюнхен": (11.582, 48.1351),
    "Мілан": (9.19, 45.4642),
    "Намюр": (4.8719, 50.4674),
    "Неймеген": (5.8528, 51.8426),
    "Нововолинськ": (24.163, 50.733),
    "Ньїредьхаза": (21.717, 47.955),
    "Нюрнберг": (11.0767, 49.4521),
    "Ніжин": (31.886, 51.048),
    "Нікополь": (34.3964, 47.5712),
    "Одеса": (30.7233, 46.4825),
    "Олександрія": (33.12, 48.67),
    "Оломоуц": (17.2509, 49.5938),
    "Острава": (18.2625, 49.8209),
    "Павлоград": (35.87, 48.52),
    "Паланка": (29.67, 46.414),
    "Пардубице": (15.7812, 50.0343),
    "Париж": (2.3522, 48.8566),
    "Пассау": (13.4319, 48.5662),
    "Первомайськ": (30.85, 48.044),
    "Перемишль": (22.767, 49.785),
    "Пльзень": (13.3736, 49.7384),
    "Познань": (16.9252, 52.4064),
    "Полтава": (34.5514, 49.5883),
    "Прага": (14.4378, 50.0755),
    "Прилуки": (32.387, 50.593),
    "Рава-Руська": (23.6223, 50.241),
    "Роттердам": (4.4777, 51.9244),
    "Рівне": (26.2516, 50.6199),
    "Самар": (35.23, 48.63),
    "Сміла": (31.872, 49.237),
    "Стрий": (23.856, 49.262),
    "Суми": (34.7981, 50.9077),
    "Теплиці": (13.8246, 50.6407),
    "Тернопіль": (25.5948, 49.5535),
    "Тілбург": (5.0913, 51.5555),
    "Ужгород": (22.2879, 48.6208),
    "Ульм": (9.9876, 48.4011),
    "Умань": (30.221, 48.748),
    "Утрехт": (5.1214, 52.0907),
    "Франкфурт-на-Майні": (8.6821, 50.1109),
    "Харків": (36.2304, 49.9935),
    "Хемніц": (12.9214, 50.8278),
    "Херсон": (32.6169, 46.6354),
    "Хмельницький": (26.9871, 49.4229),
    "Хорол": (33.271, 49.7868),
    "Червоноград": (24.23, 50.39),
    "Черкаси": (32.0598, 49.4444),
    "Чернівці": (25.9358, 48.2921),
    "Чернігів": (31.2893, 51.4982),
    "Чеське-Будейовіце": (14.4743, 48.9747),
    "Чоп": (22.2093, 48.4297),
    "Чорноморськ": (30.657, 46.301),
    "Шарлеруа": (4.4446, 50.4108),
    "Шегині": (22.9589, 49.7966),
    "Шостка": (33.48, 51.863),
    "Штутгарт": (9.1829, 48.7758),
}


def geocode(name):
    if name in CITY_COORDS:
        return CITY_COORDS[name]
    try:
        q = urllib.parse.quote(name)
        r = http(f"https://nominatim.openstreetmap.org/search?q={q}&format=json&limit=1", headers={"User-Agent": "bezmezh-admin-bot"})
        if r:
            return (float(r[0]["lon"]), float(r[0]["lat"]))
    except Exception as e:
        log.warning("geocode %s: %s", name, e)
    return None


def road_hours(frm, to):
    """Driving time by road graph (OSRM / OpenStreetMap). Returns (hours, km) or None."""
    a, b = geocode(frm), geocode(to)
    if not a or not b:
        return None
    try:
        r = http(f"https://router.project-osrm.org/route/v1/driving/{a[0]},{a[1]};{b[0]},{b[1]}?overview=false", headers={"User-Agent": "bezmezh-admin-bot"})
        rt = r["routes"][0]
        return rt["duration"] / 3600.0, rt["distance"] / 1000.0
    except Exception as e:
        log.warning("osrm %s-%s: %s", frm, to, e)
        return None


def pricing_cfg():
    p = store.data.setdefault("pricing", {})
    p.setdefault("currency", "UAH"); p.setdefault("eur_rate", 51.8); p.setdefault("rate_auto", True); p.setdefault("extra_hours", 3)
    p.setdefault("tiers", [[6,8,90,120],[8,10,100,140],[10,12,130,170],[12,14,140,180],[14,16,150,190],[16,18,160,200],[18,20,160,200],[20,22,170,210],[22,24,180,220],[24,27,190,230],[27,30,200,240],[30,33,210,250],[33,36,210,250],[36,39,220,260],[39,42,230,270],[42,45,240,280],[45,999,250,290]])
    p.setdefault("discounts", [{"label": "Пенсіонерам", "pct": 10}, {"label": "Дітям", "pct": 15}])
    try:
        _tiers_ok = isinstance(p.get("tiers"), list) and sum(1 for _row in p["tiers"] if isinstance(_row, (list, tuple)) and len(_row) >= 4) >= 2
    except Exception:
        _tiers_ok = False
    if not _tiers_ok:
        p.pop("tiers", None)
        p.setdefault("tiers", [[6,8,90,120],[8,10,100,140],[10,12,130,170],[12,14,140,180],[14,16,150,190],[16,18,160,200],[18,20,160,200],[20,22,170,210],[22,24,180,220],[24,27,190,230],[27,30,200,240],[30,33,210,250],[33,36,210,250],[36,39,220,260],[39,42,230,270],[42,45,240,280],[45,999,250,290]])
    try:
        p["eur_rate"] = float(p.get("eur_rate", 51.8))
        assert 1 < p["eur_rate"] < 1000
    except Exception:
        p["eur_rate"] = 51.8
    try:
        p["extra_hours"] = float(p.get("extra_hours", 3))
    except Exception:
        p["extra_hours"] = 3
    return p


def price_for(frm, to, cls="comfort"):
    p = pricing_cfg()
    dur = store.data.get("durations", {})
    k = dur.get(f"{frm}|{to}") or dur.get(f"{to}|{frm}")
    if not isinstance(k, dict):
        return None
    try:
        h = float(k["hours"])
    except Exception:
        return None
    t = None
    for row in p["tiers"]:
        try:
            if len(row) >= 4 and row[0] <= h < row[1]:
                t = row; break
        except Exception:
            continue
    if t is None:
        t = p["tiers"][0] if h < p["tiers"][0][0] else p["tiers"][-1]
    eur = t[3] if cls == "lux" else t[2]
    return {"hours": h, "eur": eur, "uah": int(round(eur * float(p["eur_rate"]) / 50) * 50), "open": t[1] >= 999}


def recalc_durations(only_missing=False):
    p = pricing_cfg()
    dur = store.data.setdefault("durations", {})
    pairs = sorted({(r["from"], r["to"]) for r in store.data["routes"]})
    done = 0; failed = []
    for f, t in pairs:
        key = f"{f}|{t}"
        if only_missing and key in dur:
            continue
        rev = dur.get(f"{t}|{f}")
        if rev and only_missing:
            dur[key] = dict(rev); done += 1; continue
        res = road_hours(f, t)
        if res:
            dur[key] = {"hours": round(res[0] + float(p["extra_hours"]), 1), "km": int(round(res[1])), "src": "osrm"}
            done += 1
        else:
            failed.append(key)
        time.sleep(0.6)
    return done, failed


def fetch_eur_rate():
    try:
        r = http("https://bank.gov.ua/NBUStatService/v1/statdirectory/exchange?valcode=EUR&json")
        return float(r[0]["rate"])
    except Exception as e:
        log.warning("nbu: %s", e)
        return None


def pricing_view(msg_id=None):
    p = pricing_cfg()
    dur = store.data.get("durations", {})
    tiers = "\n".join(f"{a}–{'' if b >= 999 else b}{'+' if b >= 999 else ''} ч: €{c} / €{d}" for a, b, c, d in p["tiers"])
    disc = ", ".join(f"{x['label']} −{x['pct']}%" for x in p["discounts"])
    txt = (f"<b>💶 Цены по времени в пути</b>\n"
           f"Курс: €1 = {float(p['eur_rate']):.2f} ₴ ({'авто НБУ' if p.get('rate_auto', True) else 'вручную'})\n"
           f"Надбавка ко времени с карты: +{p['extra_hours']} ч\n"
           f"Рассчитано маршрутов: {len(dur)} из {len({(r['from'], r['to']) for r in store.data['routes']})}\n"
           f"Скидки: {esc(disc)}\n\n<b>Тариф (Comfort / Lux):</b>\n<code>{tiers}</code>")
    kb = ikb([
        [("🔄 Пересчитать время (все)", "pr_recalc_all"), ("➕ Только новые", "pr_recalc_new")],
        [("💱 Курс вручную", "pr_rate"), (("💱 Авто-курс ✓" if p.get("rate_auto", True) else "💱 Авто-курс ✗"), "pr_rate_auto")],
        [("⏱ Надбавка часов", "pr_extra"), ("🎁 Скидки", "pr_disc")],
        [("📋 Тариф (таблица)", "pr_tiers"), ("⬅️ Меню", "main")],
    ])
    (edit if msg_id else send)(*((msg_id, txt[:4000], kb) if msg_id else (txt[:4000], kb)))


def hero_view(msg_id=None):
    h = store.data["hero"]
    a = store.data["advantages"]
    txt = (f"<b>Главный экран</b>\nЗаголовок: {esc(h.get('title',''))}\n\nПодзаголовок: {esc(h.get('subtitle',''))}\n\n"
           f"<b>Преимущества</b> ({len(a)}):\n" + "\n".join(f"{i+1}. {esc(x)}" for i, x in enumerate(a)))
    kb = ikb([
        [("✏️ Заголовок", "hset:title"), ("✏️ Подзаголовок", "hset:subtitle")],
        [("📋 Преимущества (список)", "adv_set"), ("⬅️ Меню", "main")],
    ])
    (edit if msg_id else send)(*((msg_id, txt, kb) if msg_id else (txt, kb)))


def announce_view(msg_id=None):
    a = store.data["site"].setdefault("announcement", {"enabled": False, "text": "", "link": ""})
    txt = (f"<b>Объявление</b> (полоска сверху сайта)\nСтатус: {'🟢 включено' if a.get('enabled') else '⚪️ выключено'}\n"
           f"Текст: {esc(a.get('text') or '—')}\nСсылка: {esc(a.get('link') or '—')}")
    kb = ikb([
        [("✏️ Текст", "aset:text"), ("🔗 Ссылка", "aset:link")],
        [("🔁 Вкл/выкл", "atoggle"), ("⬅️ Меню", "main")],
    ])
    (edit if msg_id else send)(*((msg_id, txt, kb) if msg_id else (txt, kb)))


def stats_view(msg_id=None):
    st = store.state
    logs = st.get("log", [])[-10:]
    leads = st.get("leads", [])
    try:
        from zoneinfo import ZoneInfo
        _off = dt.datetime.now(ZoneInfo("Europe/Kyiv")).utcoffset() or dt.timedelta(0)
    except Exception:
        _off = dt.timedelta(0)
    _now = dt.datetime.utcnow() + _off
    today = _now.strftime("%Y-%m-%d")
    week_ago = _now - dt.timedelta(days=7)
    n_today = n_week = n_open = 0
    by_kind = {}
    for _l in leads:
        try:
            _d = dt.datetime.fromisoformat((_l.get("t") or "")[:19])
        except Exception:
            continue
        if (_l.get("t") or "")[:10] == today:
            n_today += 1
        if _d >= week_ago:
            n_week += 1
        if not _l.get("done"):
            n_open += 1
        _k = _l.get("kind") or "?"
        by_kind[_k] = by_kind.get(_k, 0) + 1
    kinds = ", ".join(f"{k}: {v}" for k, v in sorted(by_kind.items(), key=lambda x: -x[1])[:6])
    txt = (f"<b>Журнал</b>\n📥 {len(leads)} заявок · 👥 {len(admin_ids())} админов\n"
           f"📊 Сегодня: {n_today} · 7 дней: {n_week} · необработано: {n_open}\n" + (f"<i>{esc(kinds)}</i>\n" if kinds else "") + f"⏱ бот работает {int((time.time()-START)/60)} мин\n\n" + ("\n".join(f"• {esc(l['t'][5:16].replace('T',' '))} {esc(l['msg'])}" for l in logs) or "—"))
    kb = ikb([[("♻️ Перечитать данные", "reload"), ("💾 Бэкап", "backup")], [("⬅️ Меню", "main")]])
    (edit if msg_id else send)(*((msg_id, txt, kb) if msg_id else (txt, kb)))

def admins_view(msg_id=None):
    me = cur_chat()
    rows = []
    txt = f"<b>Администраторы</b>\n👑 Владелец: <code>{OWNER_ID}</code>\n"
    for a in store.state.get("admins", []):
        txt += f"• {esc(a.get('name',''))} — <code>{a['id']}</code>\n"
        if is_owner(me):
            rows.append([(f"🗑 {a.get('name','')} ({a['id']})", f"admin_del:{a['id']}")])
    if not store.state.get("admins"):
        txt += "Дополнительных администраторов нет.\n"
    if is_owner(me):
        rows.append([("➕ Добавить администратора", "admin_add")])
    else:
        txt += "\n<i>Добавлять/удалять админов может только владелец.</i>"
    rows.append([("⬅️ Меню", "main")])
    (edit if msg_id else send)(*((msg_id, txt, ikb(rows)) if msg_id else (txt, ikb(rows))))


KINDS = {"booking": "🎫 Бронирование рейса", "manager": "📞 Связь с менеджером", "callback": "📞 Обратный звонок", "payment": "💳 Оплата картой",
         "delivery": "📦 Доставка посылки", "transfer": "🚐 Трансфер", "review": "⭐ Новый отзыв", "form": "📝 Форма"}


FIELD_RU = {"Імʼя": "Имя", "Телефон": "Телефон", "Маршрут": "Маршрут", "Звідки": "Откуда", "Куди": "Куда", "Дата рейсу": "Дата рейса", "Дата": "Дата", "Дата відправлення": "Дата отправления", "Час відправлення": "Время отправления", "Пасажирів": "Пассажиры", "Тип посилки": "Тип посылки", "Email": "Email", "Відгук": "Отзыв", "Крок": "Шаг", "Клас": "Класс", "Дорослі": "Взрослые", "Діти": "Дети до 16", "Пенсіонери": "Пенсионеры", "Ціна квитка": "Цена билета", "Знижка": "Скидка", "Загальна ціна": "Итого"}
FIELD_RU["\u0406\u043c\u044f"] = "Имя"


def _norm_key(k):
    if isinstance(k, str):
        for _a in ("\u02bc", "\u2019", "\u2018", "\u0060", "\u0027"):
            k = k.replace(_a, "")
    return k


def fmt_lead(ev):
    lead = ev.get("lead") or {}
    fields = lead.get("fields") or {}
    if not fields:  # legacy payload
        for k, label in (("name", "Имя"), ("phone", "Телефон"), ("direction", "Маршрут"), ("date", "Дата"), ("time", "Время"), ("price_text", "Цена"), ("email", "Email")):
            if lead.get(k):
                fields[label] = lead[k]
    lines = [f"📥 <b>Новая заявка · {esc(KINDS.get(lead.get('type'), lead.get('type') or 'форма'))}</b>", ""]
    order = ["Імʼя", "Телефон", "Маршрут", "Звідки", "Куди", "Дата рейсу", "Дата", "Дата відправлення", "Час відправлення", "Пасажирів", "Дорослі", "Діти", "Пенсіонери", "Клас", "Ціна квитка", "Знижка", "Загальна ціна", "Тип посилки", "Email", "Відгук", "Крок"]
    seen = set()
    for k in order + [k for k in fields if k not in order]:
        if k in fields and k not in seen and fields[k]:
            seen.add(k)
            lines.append(f"▫️ {esc(FIELD_RU.get(k, FIELD_RU.get(_norm_key(k), k)))}: <b>{esc(fields[k])}</b>")
    ctx = lead.get("context") or {}
    if ctx:
        lines.append("")
        for k, v in ctx.items():
            lines.append(f"▪️ {esc(k)}: {esc(v)}")
    phone = fields.get("Телефон") or lead.get("phone")
    if phone:
        digits = "".join(ch for ch in str(phone) if ch.isdigit())
        if len(digits) >= 10:
            lines.append("")
            lines.append(f"📲 <a href=\"https://wa.me/{digits}\">WhatsApp</a> · <a href=\"https://t.me/+{digits}\">Telegram</a> · <code>+{digits}</code>")
    lines.append(f"<i>{esc((ev.get('page') or '').replace('https://', '')[:70])} · {esc((ev.get('ts') or '')[:16].replace('T', ' '))}</i>")
    return "\n".join(lines)


def _new_lid():
    return base64.urlsafe_b64encode(os.urandom(6)).decode()


def _lead_by_ref(ref):
    ls = store.state.get("leads", [])
    for i, l in enumerate(ls):
        if l.get("lid") == ref:
            return i, l
    try:
        i = int(ref)
        if 0 <= i < len(ls):
            return i, ls[i]
    except Exception:
        pass
    return None, None


def on_bridge_event(ev):
    kind = ev.get("kind")
    if kind == "lead":
        _l = ev.get("lead") or {}
        _f = _l.get("fields") or {}
        if not _f and not any(_l.get(k) for k in ("name", "phone", "direction", "date", "time", "price_text", "email")):
            log.warning("bridge: empty lead event, skipped")
            return
        _summary = ", ".join(f"{k}: {v}" for k, v in _f.items()) if _f else json.dumps(_l, ensure_ascii=False)
        _entry = {"t": ev.get("ts") or dt.datetime.utcnow().isoformat(), "kind": KINDS.get(_l.get("type"), _l.get("type") or ""), "text": _summary[:700], "fields": _f, "type": _l.get("type") or "", "done": False, "rem": 0,
                  "lid": _new_lid()}
        store.state.setdefault("leads", []).append(_entry)
        store.state["leads"] = store.state["leads"][-200:]
        mark_dirty()
        if (_l.get("type") or "") == "review":
            rows = [[("✅ Опубликовать", f"revpub:{_entry['lid']}"), ("❌ Отклонить", f"revrej:{_entry['lid']}")]]
        else:
            rows = [[("✅ Обработано", f"lead_done:{_entry['lid']}")]]
        broadcast(fmt_lead(ev), ikb(rows))




def reminder_loop(stop):
    while not stop["flag"]:
        try:
            time.sleep(1800)
            if stop["flag"]:
                break
            now = dt.datetime.utcnow()
            for i, _l in enumerate(store.state.get("leads", [])):
                try:
                    if _l.get("done") or (_l.get("rem") or 0) >= 3:
                        continue
                    _t = dt.datetime.fromisoformat((_l.get("t") or "")[:19])
                    if (now - _t).total_seconds() < 1800:
                        continue
                    _l["rem"] = (_l.get("rem") or 0) + 1
                    broadcast(f"⏰ <b>Напоминание</b>: заявка {_l.get('kind') or ''} без обработки уже {int((now-_t).total_seconds()/60)} мин.\n\n{esc((_l.get('text') or '')[:400])}",
                              ikb([[("✅ Обработано", f"lead_done:{_l.get('lid') or i}")]]))
                except Exception:
                    continue
            try:
                _p = pricing_cfg()
                _last = float(store.state.get("rate_fetched") or 0)
                if _p.get("rate_auto", True) and time.time() - _last > 6 * 3600:
                    _r = fetch_eur_rate()
                    if _r:
                        _p["eur_rate"] = round(_r, 2)
                        store.state["rate_fetched"] = time.time()
                        store.save("pricing auto rate")
            except Exception:
                log.exception("auto rate failed")
            mark_dirty()
        except Exception:
            log.exception("reminder loop failed")


def bridge_listener(stop):
    """Subscribe to ntfy inbox topic (JSON stream) and dispatch events."""
    topic = store.data.get("bridge", {}).get("inbox")
    if not topic:
        log.warning("bridge inbox not configured")
        return
    since = store.state.get("bridge_since") or "5m"
    try:
        seen = set((store.state.get("bridge_seen") or [])[-50:])
    except Exception:
        seen = set()
    errs = 0
    while not stop["flag"]:
        try:
            req = urllib.request.Request(NTFY + topic + "/json?since=" + urllib.parse.quote(str(since)), headers={"User-Agent": "site-admin-bot"})
            with urllib.request.urlopen(req, timeout=90) as r:
                for raw in r:
                    if stop["flag"]:
                        break
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        d = json.loads(raw.decode())
                    except Exception:
                        continue
                    if d.get("event") != "message":
                        continue
                    mid = d.get("id") or ""
                    if mid and mid in seen:
                        since = mid
                        store.state["bridge_since"] = since
                        continue
                    if mid:
                        seen.add(mid)
                        store.state["bridge_seen"] = sorted(seen)[-50:]
                    since = mid or since
                    store.state["bridge_since"] = since
                    mark_dirty()
                    try:
                        ev = json.loads(d.get("message") or "{}")
                    except Exception:
                        ev = {"kind": "raw", "text": d.get("message")}
                    try:
                        on_bridge_event(ev)
                    except Exception:
                        log.exception("bridge event failed")
            errs = 0
        except Exception as e:
            errs += 1
            log.warning("bridge stream error: %s", e)
            if errs >= 3:
                since = "5m"
                errs = 0
            time.sleep(5)


# ----------------------------------------------------------------- handlers

def ask(action, prompt, **extra):
    pending[cur_chat()] = dict(action=action, ts=time.time(), **extra)
    send(prompt, ikb([[("✖️ Отмена", "cancel")]]))


def handle_callback(cq):
    data = cq.get("data", "")
    msg_id = cq["message"]["message_id"]
    tg("answerCallbackQuery", callback_query_id=cq["id"])
    if data == "noop":
        return
    if data == "cancel":
        pending.pop(cur_chat(), None)
        return show_main(msg_id)
    if data == "main":
        return show_main(msg_id)
    if data == "open":
        return send(f"🌐 {SITE_URL}?v={int(time.time())}")
    if data == "reload":
        try:
            store.load()
        except Exception as e:
            log.warning("reload failed: %s", e)
            return send("❌ Не удалось обновить данные.", main_menu())
        tg("answerCallbackQuery", callback_query_id=cq["id"], text="Данные обновлены")
        return show_main(msg_id)
    if data == "backup":
        CTX.chat = cur_chat()
        return handle_text("/backup")
    if data.startswith("routes:"):
        return routes_view(int(data.split(":")[1]), msg_id)
    if data.startswith("route:"):
        return route_view(int(data.split(":")[1]), msg_id)
    if data.startswith("rtoggle:"):
        i = _idx(data.split(":")[1], len(store.data["routes"]))
        if i is None:
            return routes_view(0, msg_id)
        r = store.data["routes"][i]
        r["visible"] = not r.get("visible", True)
        store.save(f"route {r['from']}→{r['to']} visible={r['visible']}")
        return route_view(i, msg_id)
    if data.startswith("rdel:"):
        i = _idx(data.split(":")[1], len(store.data["routes"]))
        if i is None:
            return routes_view(0, msg_id)
        r = store.data["routes"].pop(i)
        store.save(f"delete route {r['from']}→{r['to']}")
        return routes_view(0, msg_id)
    if data.startswith("rset:"):
        _, i, field = data.split(":")
        names = {"price": "Цена, грн:", "old_price": "Старая цена (0 — убрать):", "badge": "Бейдж (напр. ХІТ) или «-»:"}
        i = _idx(i, len(store.data["routes"]))
        if i is None or field not in names:
            return routes_view(0, msg_id)
        return ask("rset", names[field], i=i, field=field)
    if data == "route_add":
        return ask("route_add", "Формат: <code>Київ - Варшава</code>. Время в пути и цена рассчитаются автоматически.")
    if data == "bulk":
        return edit(msg_id, "Изменить <b>все</b> цены на:", ikb([[("−10%", "bulkp:-10"), ("−5%", "bulkp:-5"), ("+5%", "bulkp:5"), ("+10%", "bulkp:10")], [("✏️ Другой %", "bulk_ask"), ("⬅️ Назад", "routes:0")]]))
    if data == "bulk_ask":
        return ask("bulk", "Процент, напр. <code>+7</code> или <code>-3</code>")
    if data.startswith("bulkp:"):
        pct = float(data.split(":")[1])
        for r in store.data["routes"]:
            for k in ("price", "old_price"):
                try:
                    v = float(r.get(k) or 0)
                except Exception:
                    continue
                if v > 0:
                    r[k] = int(round(v * (1 + pct / 100) / 100.0) * 100)
        store.save(f"bulk prices {pct:+.0f}%")
        tg("answerCallbackQuery", callback_query_id=cq["id"], text=f"Готово: {pct:+.0f}%")
        return routes_view(0, msg_id)
    if data.startswith("radj:"):
        _, i, dlt = data.split(":")
        i = _idx(i, len(store.data["routes"]))
        if i is None:
            return routes_view(0, msg_id)
        r = store.data["routes"][i]
        r["price"] = max(0, (r.get("price") or 0) + int(dlt))
        store.save(f"route {r['from']}→{r['to']} price={r['price']}")
        return route_view(i, msg_id)
    if data == "reviews":
        return reviews_view(msg_id)
    if data.startswith("review:"):
        i = _idx(data.split(":")[1], len(store.data["reviews"]))
        if i is None:
            return reviews_view(msg_id)
        r = store.data["reviews"][i]
        kb = ikb([[("🗑 Удалить", f"revdel:{i}"), ("⬅️ Меню", "main")], [("⬅️ Назад", "reviews")]])
        return edit(msg_id, f"<b>{esc(r.get('name') or '?')}</b> · {esc(r.get('date',''))} · {_stars(r)}\n\n{esc(r.get('text') or '')}", kb)
    if data.startswith("revdel:"):
        i = _idx(data.split(":")[1], len(store.data["reviews"]))
        if i is None:
            return reviews_view(msg_id)
        r = store.data["reviews"].pop(i)
        store.save(f"delete review {r['name']}")
        return reviews_view(msg_id)
    if data == "review_add":
        return ask("review_add", "4 строки:\n<code>Имя\n12.09.2026\n5\nТекст</code>")
    if data == "faq":
        return faq_view(msg_id)
    if data.startswith("faqi:"):
        i = _idx(data.split(":")[1], len(store.data["faq"]))
        if i is None:
            return faq_view(msg_id)
        f = store.data["faq"][i]
        kb = ikb([[("✏️ Вопрос", f"faqset:{i}:q"), ("✏️ Ответ", f"faqset:{i}:a")], [("⬆️ Сделать первым", f"faqtop:{i}"), ("🗑 Удалить", f"faqdel:{i}")], [("⬅️ Назад", "faq")]])
        return edit(msg_id, f"<b>{esc(f.get('q') or '?')}</b>\n\n{esc(f.get('a') or '')}", kb)
    if data.startswith("faqset:"):
        _, i, field = data.split(":")
        i = _idx(i, len(store.data["faq"]))
        if i is None or field not in ("q", "a"):
            return faq_view(msg_id)
        return ask("faqset", "Введите " + ("новый вопрос:" if field == "q" else "новый ответ:"), i=i, field=field)
    if data.startswith("faqtop:"):
        i = _idx(data.split(":")[1], len(store.data["faq"]))
        if i is None:
            return faq_view(msg_id)
        f = store.data["faq"].pop(i)
        store.data["faq"].insert(0, f)
        store.save("faq reorder")
        return faq_view(msg_id)
    if data.startswith("faqdel:"):
        i = _idx(data.split(":")[1], len(store.data["faq"]))
        if i is None:
            return faq_view(msg_id)
        store.data["faq"].pop(i)
        store.save("delete faq")
        return faq_view(msg_id)
    if data == "faq_add":
        return ask("faq_add", "2 строки:\n<code>Вопрос?\nОтвет.</code>")
    if data == "managers":
        return managers_view(msg_id)
    if data.startswith("mgr:"):
        i = _idx(data.split(":")[1], len(store.data.get("managers", [])))
        return manager_view(i if i is not None else 0, msg_id)
    if data == "mgr_add":
        return ask("mgr_add", "Пришлите данные менеджера (каждое с новой строки):\n<code>Имя\n+380XXXXXXXXX\nДолжность (необязательно)\nСсылка Telegram (необязательно)\nСсылка WhatsApp (необязательно)</code>\n\nПример:\n<code>Олексій\n+380966973130\nМенеджер з перевезень\nhttps://t.me/pereviznyk_support</code>")
    if data.startswith("mset:"):
        _, i, field = data.split(":")
        hints = {"name": "Новое имя:", "role": "Новая должность:", "phone": "Номер: <code>+380XXXXXXXXX</code>", "telegram": "Ссылка t.me/… или «auto»", "whatsapp": "Ссылка wa.me/… или «auto»"}
        i = _idx(i, len(store.data.get("managers", [])))
        if i is None or field not in hints:
            return managers_view(msg_id)
        return ask("mset", hints[field], i=i, field=field)
    if data.startswith("mup:"):
        i = _idx(data.split(":")[1], len(store.data.get("managers", [])))
        if i is None:
            return managers_view(msg_id)
        ms = store.data["managers"]
        if i > 0:
            ms[i-1], ms[i] = ms[i], ms[i-1]
            store.save("managers reorder")
        return managers_view(msg_id)
    if data.startswith("mdel:"):
        i = int(data.split(":")[1])
        ms = store.data["managers"]
        if i < len(ms):
            m = ms.pop(i)
            store.save(f"delete manager {m.get('name','')}")
        return managers_view(msg_id)
    if data == "pricing":
        return pricing_view(msg_id)
    if data in ("pr_recalc_all", "pr_recalc_new"):
        edit(msg_id, "⏳ Считаю время в пути по дорожному графу (OSRM)… это может занять до минуты.")
        def _job(only_new=(data == "pr_recalc_new")):
            CTX.chat = cur_chat_val
            try:
                done, failed = recalc_durations(only_missing=only_new)
                store.save(f"durations recalculated ({done})")
                send(f"✅ Обновлено {done} маршрутов." + (f"\n⚠️ Не удалось: {', '.join(failed)}" if failed else ""))
                pricing_view()
            except Exception as e:
                log.exception("recalc")
                send(f"❌ Ошибка: {esc(str(e))}")
        cur_chat_val = cur_chat()
        threading.Thread(target=_job, daemon=True).start()
        return
    if data == "pr_rate":
        return ask("pr_rate", "Курс евро в гривнах, напр. <code>51.8</code> (это выключит авто-курс):")
    if data == "pr_rate_auto":
        p = pricing_cfg()
        p["rate_auto"] = not p.get("rate_auto", True)
        if p["rate_auto"]:
            r = fetch_eur_rate()
            if r:
                p["eur_rate"] = round(r, 2)
        store.save("pricing rate_auto")
        return pricing_view(msg_id)
    if data == "pr_extra":
        return ask("pr_extra", "Сколько часов добавлять ко времени с карты (граница, остановки)? Напр. <code>3</code>")
    if data == "pr_disc":
        return ask("pr_disc", "Скидки — каждая с новой строки в формате <code>Название 10</code>:\n<code>Пенсіонерам 10\nДітям 15</code>")
    if data == "pr_tiers":
        return ask("pr_tiers", "Тариф — каждая строка: <code>от до comfort lux</code> (часы и € без символов). Последняя строка с «до» = 999 означает «и больше».\nПример:\n<code>6 8 90 120\n8 10 100 140\n…\n45 999 250 290</code>")
    if data == "contacts":
        return contacts_view(msg_id)
    if data.startswith("cset:"):
        field = data.split(":")[1]
        hints = {"phone": "Номер: <code>+380XXXXXXXXX</code>", "telegram": "Ссылка t.me/…", "whatsapp": "Ссылка wa.me/… или «auto»", "support_note": "Подпись в шапке:"}
        return ask("cset", hints[field], field=field)
    if data == "hero":
        return hero_view(msg_id)
    if data.startswith("hset:"):
        return ask("hset", "Новый текст:", field=data.split(":")[1])
    if data == "adv_set":
        return ask("adv_set", "Преимущества — каждое с новой строки:")
    if data == "announce":
        return announce_view(msg_id)
    if data.startswith("aset:"):
        return ask("aset", "Текст объявления:" if data.endswith("text") else "Ссылка или «-»:", field=data.split(":")[1])
    if data == "atoggle":
        a = store.data["site"].setdefault("announcement", {"enabled": False, "text": "", "link": ""})
        a["enabled"] = not a.get("enabled")
        store.save(f"announcement enabled={a['enabled']}")
        return announce_view(msg_id)
    if data == "maint":
        s = store.data["site"]
        s["maintenance"] = not s.get("maintenance")
        store.save(f"maintenance={s['maintenance']}")
        return show_main(msg_id)
    if data == "stats":
        return stats_view(msg_id)
    if data == "admins":
        return admins_view(msg_id)
    if data == "cast":
        pending[cur_chat()] = dict(action="cast", ts=time.time())
        return send("Текст рассылки всем админам:", ikb([[("✖️ Отмена", "cancel")]]))
    if data == "cast_yes":
        p = pending.pop(cur_chat(), {}) or {}
        if p.get("action") != "cast_ok" or not p.get("text"):
            return show_main(msg_id)
        n = 0
        for uid in admin_ids():
            try:
                if send("📣 <b>Рассылка</b>\n\n" + esc(p["text"]), chat_id=uid).get("ok"):
                    n += 1
            except Exception:
                pass
        return edit(msg_id, f"✅ Разослано админам: {n}.", ikb([[("⬅️ Меню", "main")]]))
    if data == "cast_no":
        pending.pop(cur_chat(), None)
        return show_main(msg_id)
    if data == "admin_add":
        if not is_owner(cur_chat()):
            return send("Только владелец может добавлять администраторов.")
        return ask("admin_add", "<code>ID Имя</code>, напр. <code>123456789 Елена</code>\n(ID — через @userinfobot; админ должен нажать /start в боте)")
    if data.startswith("admin_del:"):
        if not is_owner(cur_chat()):
            return send("Только владелец может удалять администраторов.")
        uid = int(data.split(":")[1])
        store.state["admins"] = [a for a in store.state.get("admins", []) if _aid(a) != uid]
        store.save_state(silent=True)
        send("Ваш доступ администратора отозван.", chat_id=uid)
        return admins_view(msg_id)

    if data == "leads_clear":
        store.state["leads"] = []
        mark_dirty(); store.save_state(silent=True)
        return stats_view(msg_id)

    if data.startswith("lead_done:"):
        ref = data.split(":")[1]
        _di, _dl = _lead_by_ref(ref)
        if _dl is not None:
            _dl["done"] = True; mark_dirty()
        try:
            old = cq["message"].get("text") or ""
            edit(msg_id, esc(old) + "\n\n✅ <b>Обработано</b>", ikb([[("↩️ Вернуть", f"lead_undo:{ref}")]]))
        except Exception:
            pass
        return
    if data.startswith("lead_undo:"):
        ref = data.split(":")[1]
        _ui, _ul = _lead_by_ref(ref)
        if _ul is not None:
            _ul["done"] = False; mark_dirty()
        return edit(msg_id, "Заявка возвращена в работу.", ikb([[("✅ Обработано", f"lead_done:{ref}")]]))
    if data.startswith("revpub:"):
        ref = data.split(":")[1]
        _ri, _rl = _lead_by_ref(ref)
        if _rl is None or _rl.get("type") != "review":
            try:
                edit(msg_id, "⚠️ Заявка уже недоступна.", None)
            except Exception:
                pass
            return
        if _rl.get("pub"):
            try:
                edit(msg_id, "✅ Этот отзыв уже опубликован.", None)
            except Exception:
                pass
            return
        if True:
            _f = {_norm_key(_k): _v for _k, _v in (_rl.get("fields") or {}).items()}
            try:
                stars = max(1, min(5, int(str(_f.get("\u041e\u0446\u0456\u043d\u043a\u0430") or _f.get("Оценка") or "5").strip()[0])))
            except Exception:
                stars = 5
            t = _rl.get("t") or ""
            day = (t[8:10] + "." + t[5:7] + "." + t[:4]) if len(t) >= 10 and t[4:5] == "-" else t[:10]
            r = {"name": str(_f.get("\u0406\u043c\u044f") or _f.get("Имя") or "Гость").strip() or "Гость",
                 "date": day, "text": str(_f.get("\u0412\u0456\u0434\u0433\u0443\u043a") or _f.get("Отзыв") or "").strip(), "stars": stars}
            store.data["reviews"].insert(0, r)
            store.save(f"publish review {r['name']}")
            _rl["done"] = True; _rl["pub"] = True; mark_dirty()
        try:
            edit(msg_id, "✅ Отзыв опубликован на сайте.", None)
        except Exception:
            pass
        return

    if data.startswith("revrej:"):
        ref = data.split(":")[1]
        _ji, _jl = _lead_by_ref(ref)
        if _jl is not None:
            _jl["done"] = True; mark_dirty()
        try:
            edit(msg_id, "❌ Отзыв отклонён.", None)
        except Exception:
            pass
        return
    if data == "leads":
        leads = store.state.get("leads", [])[-10:]
        def _fmt(l):
            try:
                d = json.loads(l.get("text") or "")
                if isinstance(d, dict):
                    return ", ".join(f"{k}: {v}" for k, v in d.items() if v and k not in ("path", "title"))
            except Exception:
                pass
            return l.get("text") or ""
        def _when(l):
            t = str(l.get("t") or "")
            return t[5:16].replace("T", " ") if len(t) >= 16 else t
        txt = "<b>Заявки</b> · последние 10\n\n" + ("\n\n".join(f"{'✅' if l.get('done') else '🆕'} {esc(_when(l))} {esc(l.get('kind',''))}\n{esc(_fmt(l))[:300]}" for l in leads) or "Пока нет")
        rows = []
        for l in leads:
            if not l.get("done") and l.get("lid"):
                rows.append([(f"✅ {l.get('kind') or 'Заявка'}", f"lead_done:{l['lid']}")])
        rows = rows[-8:]
        rows.append([("🗑 Очистить", "leads_clear"), ("⬅️ Меню", "main")])
        return edit(msg_id, txt, ikb(rows))


def num(s):
    s = str(s).replace(" ", "").replace("грн", "").replace(",", ".")
    return int(float(s))


def handle_text(text):
    p = pending.pop(cur_chat(), None)
    if text.startswith("/cancel"):
        return show_main()
    if text.startswith("/start") or text.startswith("/menu") or text.startswith("/admin"):
        return show_main()
    if text.startswith("/help"):
        return send("Команды:\n/menu — панель\n/site — ссылка на сайт\n/admins — администраторы\n/backup — выгрузить site.json\n/cancel — отменить ввод")
    if text.startswith("/site"):
        return send(f"🌐 {SITE_URL}")
    if text.startswith("/admins"):
        return admins_view()
    if text.startswith("/backup"):
        content = json.dumps(store.data, ensure_ascii=False, indent=2).encode()
        boundary = "----botb"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n{cur_chat()}\r\n"
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"site.json\"\r\nContent-Type: application/json\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
        req = urllib.request.Request(API + "sendDocument", data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        try:
            urllib.request.urlopen(req, timeout=60).read()
        except Exception as e:
            log.warning("backup failed: %s", e)
            return send("❌ Не удалось отправить бэкап.")
        return
    if not p:
        # free text from admin = treat as note/lead
        store.state.setdefault("leads", []).append({"t": dt.datetime.utcnow().isoformat(), "text": text, "kind": "📝 Заметка", "fields": {}, "type": "note", "done": False, "rem": 0, "lid": _new_lid()})
        store.state["leads"] = store.state["leads"][-100:]
        store.save_state(silent=True)
        return send("📝 Сохранено как заметку", main_menu())

    a = p["action"]
    try:
        if a == "cast":
            if not text.strip():
                return send("❌ Пустое сообщение. Введите текст или /cancel")
            pending[cur_chat()] = dict(action="cast_ok", text=text.strip(), ts=time.time())
            return send(f"Разослать {len(admin_ids())} админам?\n\n{esc(text.strip())}",
                        ikb([[("✅ Разослать", "cast_yes"), ("✖️ Отмена", "cast_no")]]))
        if a == "admin_add":
            parts = text.strip().split(None, 1)
            uid = int(parts[0])
            name = parts[1].strip() if len(parts) > 1 else str(uid)
            if uid == OWNER_ID:
                return send("Это ваш собственный ID — вы и так владелец.")
            if any(_aid(x) == uid for x in store.state.get("admins", [])):
                return send("Такой администратор уже есть.")
            store.state["admins"].append({"id": uid, "name": name, "added": dt.datetime.utcnow().isoformat()})
            store.save_state(silent=True)
            r = send(f"✅ Вы добавлены администратором сайта. Нажмите /menu", chat_id=uid)
            if not r.get("ok"):
                send("⚠️ Не удалось написать новому админу — он должен сначала нажать /start в боте. Доступ уже выдан.")
            return admins_view()
        if a == "rset":
            _rs = store.data["routes"]
            if not (0 <= p.get("i", -1) < len(_rs)):
                return routes_view(0)
            r = _rs[p["i"]]
            if p["field"] == "badge":
                r["badge"] = "" if text.strip() in ("-", "—") else text.strip()[:20]
            else:
                v = num(text)
                r[p["field"]] = v if v > 0 else None
            store.save(f"route {r['from']}→{r['to']} {p['field']}={r.get(p['field'])}")
            return route_view(p["i"])
        if a == "route_add":
            rx = text.replace("–", "-").replace("—", "-")
            parts = [x.strip() for x in rx.split(" - ")] if " - " in rx else [x.strip() for x in rx.split("-")]
            if len(parts) < 2 or not parts[0] or not parts[1]:
                raise ValueError("format")
            frm, to = parts[0], parts[1]
            if any(r.get("from") == frm and r.get("to") == to for r in store.data["routes"]):
                send("⚠️ Такой маршрут уже есть.")
                return routes_view(len(store.data["routes"]) // PAGE)
            r = {"from": frm, "to": to, "price": None, "old_price": None, "slug": "", "visible": True}
            store.data["routes"].append(r)
            try:
                store.save(f"add route {frm}→{to}")
            except Exception:
                store.data["routes"].pop()
                raise
            chat = cur_chat()
            send("⏳ Маршрут добавлен, считаю время в пути…")
            def _job(frm=frm, to=to, chat=chat):
                CTX.chat = chat
                try:
                    res = road_hours(frm, to)
                    if res:
                        store.data.setdefault("durations", {})[f"{frm}|{to}"] = {"hours": round(res[0] + float(pricing_cfg()["extra_hours"]), 1), "km": int(round(res[1])), "src": "osrm"}
                        store.save(f"durations +{frm}→{to}")
                    _pc = price_for(frm, to)
                    send(f"✅ В пути ~{_pc['hours']} ч → Comfort {_pc['uah']} ₴" if _pc else "✅ Добавлено, но время в пути не удалось рассчитать (проверьте названия городов).")
                    routes_view(len(store.data["routes"]) // PAGE)
                except Exception as e:
                    log.exception("route_add job")
                    send(f"❌ Ошибка: {esc(str(e))}")
            threading.Thread(target=_job, daemon=True).start()
            return
        if a == "bulk":
            pct = float(text.replace("%", "").replace("+", "").strip())
            for r in store.data["routes"]:
                for k in ("price", "old_price"):
                    try:
                        v = float(r.get(k) or 0)
                    except Exception:
                        continue
                    if v > 0:
                        r[k] = int(round(v * (1 + pct / 100) / 100.0) * 100)
            store.save(f"bulk prices {pct:+.1f}%")
            return routes_view(0)
        if a == "review_add":
            lines = [l for l in text.split("\n") if l.strip()]
            if len(lines) < 4:
                raise ValueError("format")
            r = {"name": lines[0].strip(), "date": lines[1].strip(), "stars": max(1, min(5, int(lines[2].strip()[0]))), "text": " ".join(lines[3:]).strip()}
            store.data["reviews"].insert(0, r)
            store.save(f"add review {r['name']}")
            return reviews_view()
        if a == "faqset":
            if not (0 <= p.get("i", -1) < len(store.data["faq"])) or p.get("field") not in ("q", "a"):
                return faq_view()
            store.data["faq"][p["i"]][p["field"]] = text.strip()
            store.save("edit faq")
            return faq_view()
        if a == "faq_add":
            lines = [l for l in text.split("\n") if l.strip()]
            if len(lines) < 2:
                raise ValueError("format")
            store.data["faq"].append({"q": lines[0].strip(), "a": " ".join(lines[1:]).strip()})
            store.save("add faq")
            return faq_view()
        if a == "mgr_add":
            m = _parse_manager(text)
            store.data.setdefault("managers", []).append(m)
            store.save(f"add manager {m['name']}")
            return managers_view()
        if a == "mset":
            ms = store.data.get("managers", [])
            if not (0 <= p.get("i", -1) < len(ms)):
                return managers_view()
            m = ms[p["i"]]
            v = text.strip()
            f = p["field"]
            d = "".join(ch for ch in m.get("phone", "") if ch.isdigit())
            if f == "phone":
                d = "".join(ch for ch in v if ch.isdigit())
                if len(d) < 10:
                    raise ValueError("phone")
                m["phone"] = "+" + d
                if not m.get("whatsapp") or "wa.me" in m.get("whatsapp", ""):
                    m["whatsapp"] = "https://wa.me/" + d
                if not m.get("telegram") or "t.me/+" in m.get("telegram", ""):
                    m["telegram"] = "https://t.me/+" + d
            elif f == "telegram" and v.lower() == "auto":
                m["telegram"] = "https://t.me/+" + d
            elif f == "whatsapp" and v.lower() == "auto":
                m["whatsapp"] = "https://wa.me/" + d
            else:
                m[f] = v
            store.save(f"manager {m['name']} {f}")
            return manager_view(p["i"])
        if a == "pr_rate":
            v = float(text.strip().replace(",", "."))
            if not (20 < v < 200):
                raise ValueError("rate")
            p = pricing_cfg(); p["eur_rate"] = round(v, 2); p["rate_auto"] = False
            store.save("pricing rate"); return pricing_view()
        if a == "pr_extra":
            v = float(text.strip().replace(",", "."))
            p = pricing_cfg(); old = float(p.get("extra_hours", 3)); p["extra_hours"] = v
            for k, d_ in store.data.get("durations", {}).items():
                d_["hours"] = round(d_["hours"] - old + v, 1)
            store.save("pricing extra_hours"); return pricing_view()
        if a == "pr_disc":
            items = []
            for line in text.split("\n"):
                parts = line.strip().rsplit(" ", 1)
                if len(parts) == 2 and parts[1].replace("%", "").isdigit():
                    items.append({"label": parts[0].strip(), "pct": int(parts[1].replace("%", ""))})
            if not items:
                raise ValueError("disc")
            pricing_cfg()["discounts"] = items
            store.save("pricing discounts"); return pricing_view()
        if a == "pr_tiers":
            rows = []
            for line in text.split("\n"):
                nums = [float(x) for x in line.replace("€", "").replace(",", ".").split()]
                if len(nums) == 4:
                    rows.append([int(nums[0]) if nums[0].is_integer() else nums[0], int(nums[1]) if nums[1].is_integer() else nums[1], int(nums[2]), int(nums[3])])
            rows.sort(key=lambda r: r[0])
            for w in rows:
                if w[1] <= w[0] or w[0] < 0 or w[2] <= 0 or w[3] <= 0:
                    raise ValueError("tiers")
            if len(rows) < 2:
                raise ValueError("tiers")
            pricing_cfg()["tiers"] = rows
            store.save("pricing tiers"); return pricing_view()
        if a == "cset":
            c = store.data["contacts"]
            v = text.strip()
            if p["field"] == "phone":
                digits = "".join(ch for ch in v if ch.isdigit())
                if len(digits) < 10:
                    raise ValueError("phone")
                c["phone"] = "+" + digits
                c["phone_display"] = f"+{digits[:3]} {digits[3:5]} {digits[5:8]} {digits[8:10]} {digits[10:]}".strip()
                if not c.get("whatsapp") or "wa.me" in c.get("whatsapp", ""):
                    c["whatsapp"] = "https://wa.me/" + digits
            elif p["field"] == "whatsapp" and v.lower() == "auto":
                c["whatsapp"] = "https://wa.me/" + "".join(ch for ch in c["phone"] if ch.isdigit())
            else:
                c[p["field"]] = v
            store.save(f"contacts {p['field']}")
            return contacts_view()
        if a == "hset":
            store.data["hero"][p["field"]] = text.strip()
            store.save(f"hero {p['field']}")
            return hero_view()
        if a == "adv_set":
            store.data["advantages"] = [l.strip() for l in text.split("\n") if l.strip()][:12]
            store.save("advantages")
            return hero_view()
        if a == "aset":
            an = store.data["site"].setdefault("announcement", {"enabled": False, "text": "", "link": ""})
            an[p["field"]] = "" if text.strip() in ("-", "—") else text.strip()
            if p["field"] == "text" and an["text"]:
                an["enabled"] = True
            store.save("announcement")
            return announce_view()
    except Exception as e:
        log.exception("handle_text")
        send("❌ Не вышло. Проверьте формат и попробуйте ещё раз.", main_menu())


def handle_update(u):
    msg = u.get("message") or u.get("edited_message")
    cq = u.get("callback_query")
    frm = (msg or cq or {}).get("from", {})
    uid = frm.get("id")
    if not is_admin(uid):
        return  # ignore everyone else silently
    CTX.chat = uid
    _pp = pending.get(uid)
    if _pp and "ts" in _pp and time.time() - _pp.get("ts", 0) > 1800:
        pending.pop(uid, None)
    if frm.get("first_name") and uid == OWNER_ID and store.state.get("owner_name") != frm.get("first_name"):
        store.state["owner_name"] = frm.get("first_name"); mark_dirty()
    try:
        if cq:
            return handle_callback(cq)
        if msg:
            text = msg.get("text") or ""
            if text.startswith("/"):
                return handle_text(text)
            if cur_chat() in pending:
                return handle_text(text) if text else send("Жду текст.")
            if text:
                return handle_text(text)
            return send("Пришлите текст или нажмите /menu.", main_menu())
    finally:
        CTX.chat = None

# ----------------------------------------------------------------- main loop

def main():
    if not BOT_TOKEN:
        log.error("BOT_TOKEN is not configured! Sleeping before exit.")
        time.sleep(60)
        return
    try:
        tg("deleteWebhook", drop_pending_updates=False)
    except Exception as e:
        log.warning("deleteWebhook failed: %s", e)
    try:
        store.load()
    except Exception as e:
        log.exception("store.load() error: %s", e)
    try:
        tg("setMyCommands", commands=[
            {"command": "menu", "description": "Админ-панель"},
            {"command": "site", "description": "Ссылка на сайт"},
            {"command": "admins", "description": "Администраторы"},
            {"command": "backup", "description": "Выгрузить site.json"},
            {"command": "cancel", "description": "Отменить ввод"},
        ])
    except Exception as e:
        log.warning("setMyCommands failed: %s", e)
    offset = store.state.get("offset", 0)
    log.info("started; admin=%s repo=%s runtime=%ss state_mode=%s", ADMIN_ID, GH_REPO, MAX_RUNTIME, "encrypted" if STATE_SECRET else "redacted")
    if not STATE_SECRET:
        log.warning("STATE_SECRET is not set; leads are kept only in memory and redacted in bot/state.json")
    stop = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *a: stop.__setitem__("flag", True))
    threading.Thread(target=bridge_listener, args=(stop,), daemon=True).start()
    threading.Thread(target=reminder_loop, args=(stop,), daemon=True).start()
    last_state_save = time.time()
    while not stop["flag"] and time.time() - START < MAX_RUNTIME:
        try:
            r = http(API + "getUpdates", {"offset": offset, "timeout": 40, "allowed_updates": ["message", "callback_query"]}, timeout=60)
            for u in r.get("result", []):
                offset = u["update_id"] + 1
                try:
                    handle_update(u)
                except Exception:
                    log.exception("update failed")
        except Exception as e:
            log.warning("poll error: %s", e)
            time.sleep(3)
        if time.time() - last_state_save > 300 and (store.state.get("offset") != offset or state_dirty["flag"]):
            store.state["offset"] = offset
            store.save_state(silent=True)
            state_dirty["flag"] = False
            last_state_save = time.time()
    stop["flag"] = True
    store.state["offset"] = offset
    store.save_state(silent=True)
    log.info("runtime limit reached, exiting for restart")


if __name__ == "__main__":
    main()

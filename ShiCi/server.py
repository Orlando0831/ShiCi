#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
拾词 (Vocabulary Ledger) — backend server with accounts & multi-device sync.

Pure standard library (http.server + sqlite3 + csv + json + hashlib) — NO third-party deps.
Serves the frontend (vocab-app.html) at "/" and a REST API under "/api/*".

Accounts:
    POST /api/auth/register {username,password} -> {token,user}
    POST /api/auth/login    {username,password} -> {token,user}
    POST /api/auth/logout   (Bearer token)      -> {ok}
    GET  /api/auth/me       (Bearer token)      -> {user}
All data endpoints require a Bearer token and are scoped to that account, so any
device that logs into the same account sees the same data (multi-device sync).

Run:
    python server.py                 # localhost only, port 8000
    HOST=0.0.0.0 python server.py    # also reachable from other devices on the LAN
    PORT=9000 python server.py       # custom port

Data is persisted in vocab.db (SQLite) next to this file.
Each account may store at most WORD_LIMIT (20000) word/phrase pairs.
"""
import json
import sqlite3
import os
import io
import csv
import re
import time
import hmac
import hashlib
import secrets
import threading
import datetime
import socket
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "vocab.db")
HTML_PATH = os.path.join(BASE, "vocab-app.html")
WORD_LIMIT = 20000
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))

# Static PWA assets served for "Add to Home Screen" on iOS / Android.
STATIC_ASSETS = {
    "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json; charset=utf-8"),
    "/sw.js": ("sw.js", "text/javascript; charset=utf-8"),
    "/apple-touch-icon.png": ("apple-touch-icon.png", "image/png"),
    "/icon-192.png": ("icon-192.png", "image/png"),
    "/icon-512.png": ("icon-512.png", "image/png"),
    "/icon-1024.png": ("icon-1024.png", "image/png"),
}

PBKDF2_ROUNDS = 200000
SESSION_TTL_MS = 30 * 24 * 3600 * 1000        # 30 days

_lock = threading.Lock()                       # serialises writes (single-file SQLite)

# ----------------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id             TEXT PRIMARY KEY,
  username       TEXT NOT NULL,
  username_lower TEXT NOT NULL UNIQUE,
  pw_salt        TEXT NOT NULL,
  pw_hash        TEXT NOT NULL,
  created_at     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token      TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS sheets(
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  date       INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS items(
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  sheet_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  en       TEXT NOT NULL,
  zh       TEXT NOT NULL,
  FOREIGN KEY(sheet_id) REFERENCES sheets(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS reviews(
  id       TEXT PRIMARY KEY,
  user_id  TEXT NOT NULL,
  date     INTEGER NOT NULL,
  total    INTEGER NOT NULL,
  correct  INTEGER NOT NULL,
  accuracy INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS review_items(
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  review_id TEXT NOT NULL,
  position  INTEGER NOT NULL,
  zh        TEXT NOT NULL,
  en        TEXT NOT NULL,
  answer    TEXT,
  correct   INTEGER NOT NULL,
  FOREIGN KEY(review_id) REFERENCES reviews(id) ON DELETE CASCADE
);
"""

# Created AFTER migrate() so an upgraded (pre-account) DB has user_id before it is indexed.
INDEXES = """
CREATE INDEX IF NOT EXISTS idx_sheets_user   ON sheets(user_id);
CREATE INDEX IF NOT EXISTS idx_items_sheet   ON items(sheet_id);
CREATE INDEX IF NOT EXISTS idx_reviews_user  ON reviews(user_id);
CREATE INDEX IF NOT EXISTS idx_ritems_review ON review_items(review_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
"""


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _table_exists(c, name):
    return c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _has_column(c, table, col):
    return any(r["name"] == col for r in c.execute("PRAGMA table_info(%s)" % table).fetchall())


def migrate(c):
    """Pre-account databases lack sheets/reviews.user_id. Add the column so queries
    keep working (legacy rows stay until claimed). No-op on fresh databases."""
    for tbl in ("sheets", "reviews"):
        if _table_exists(c, tbl) and not _has_column(c, tbl, "user_id"):
            c.execute("ALTER TABLE %s ADD COLUMN user_id TEXT" % tbl)


def init_db():
    conn = connect()
    try:
        conn.executescript(SCHEMA)      # tables (skipped if they already exist)
        migrate(conn)                   # add user_id to pre-account tables BEFORE indexing it
        conn.executescript(INDEXES)
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now_ms(),))
        conn.commit()
    finally:
        conn.close()


@contextmanager
def ro():
    """Read-only connection (auto-closed)."""
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def tx():
    """Write transaction: serialised, committed on success, always closed."""
    conn = connect()
    try:
        with _lock:
            with conn:           # commit / rollback
                yield conn
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# Generic helpers
# ----------------------------------------------------------------------------
def now_ms():
    return int(time.time() * 1000)


def gen_id():
    return format(now_ms(), "x") + os.urandom(4).hex()


# ----------------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------------
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ROUNDS)
    return salt, dk.hex()


def verify_password(password, salt, expected_hex):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ROUNDS)
    return hmac.compare_digest(dk.hex(), expected_hex)


def new_session(c, user_id):
    token = secrets.token_urlsafe(32)
    now = now_ms()
    c.execute("INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
              (token, user_id, now, now + SESSION_TTL_MS))
    return token


def get_bearer(headers):
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def user_from_token(token):
    if not token:
        return None
    with ro() as c:
        row = c.execute(
            "SELECT s.user_id AS uid, s.expires_at AS exp, u.username AS username "
            "FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=?", (token,)).fetchone()
    if not row:
        return None
    if row["exp"] < now_ms():
        with tx() as c:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
        return None
    return {"id": row["uid"], "username": row["username"]}


# ----------------------------------------------------------------------------
# Data helpers (all scoped to a user_id)
# ----------------------------------------------------------------------------
def word_count(c, user_id):
    return c.execute(
        "SELECT COUNT(*) AS n FROM items i JOIN sheets s ON i.sheet_id=s.id WHERE s.user_id=?",
        (user_id,)).fetchone()["n"]


def clean_items(raw):
    """Keep only rows where BOTH en and zh are non-empty (trimmed)."""
    out = []
    for it in (raw or []):
        if not isinstance(it, dict):
            continue
        en = (it.get("en") or "").strip()
        zh = (it.get("zh") or "").strip()
        if en and zh:
            out.append({"en": en, "zh": zh})
    return out


def insert_items(c, sid, items):
    for pos, it in enumerate(items):
        c.execute("INSERT INTO items(sheet_id,position,en,zh) VALUES(?,?,?,?)",
                  (sid, pos, it["en"], it["zh"]))


def owns_sheet(c, user_id, sid):
    row = c.execute("SELECT user_id FROM sheets WHERE id=?", (sid,)).fetchone()
    return bool(row) and row["user_id"] == user_id


def sheet_dict(c, sid):
    s = c.execute("SELECT id,date FROM sheets WHERE id=?", (sid,)).fetchone()
    if not s:
        return None
    items = c.execute("SELECT en,zh FROM items WHERE sheet_id=? ORDER BY position", (sid,)).fetchall()
    return {"id": s["id"], "date": s["date"],
            "items": [{"en": i["en"], "zh": i["zh"]} for i in items]}


def fetch_sheets(c, user_id):
    rows = c.execute("SELECT id,date,updated_at FROM sheets WHERE user_id=? ORDER BY date DESC, created_at DESC",
                     (user_id,)).fetchall()
    res = []
    for s in rows:
        items = c.execute("SELECT en,zh FROM items WHERE sheet_id=? ORDER BY position", (s["id"],)).fetchall()
        res.append({"id": s["id"], "date": s["date"], "updatedAt": s["updated_at"],
                    "items": [{"en": i["en"], "zh": i["zh"]} for i in items]})
    return res


def fetch_reviews(c, user_id):
    rows = c.execute("SELECT * FROM reviews WHERE user_id=? ORDER BY date DESC", (user_id,)).fetchall()
    res = []
    for r in rows:
        items = c.execute("SELECT zh,en,answer,correct FROM review_items WHERE review_id=? ORDER BY position",
                          (r["id"],)).fetchall()
        res.append({"id": r["id"], "date": r["date"], "total": r["total"],
                    "correct": r["correct"], "accuracy": r["accuracy"],
                    "items": [{"zh": i["zh"], "en": i["en"], "answer": i["answer"],
                               "correct": bool(i["correct"])} for i in items]})
    return res


def parse_date(val):
    """Best-effort parse of a date value -> epoch ms, or None."""
    if val is None:
        return None
    if isinstance(val, (int, float)) and val > 0:
        v = int(val)
        return v if v > 10 ** 12 else v * 1000      # secs -> ms
    s = str(val).strip()
    if not s:
        return None
    nums = re.findall(r"\d+", s)
    if len(nums) >= 3:
        try:
            y, mo, d = int(nums[0]), int(nums[1]), int(nums[2])
            return int(datetime.datetime(y, mo, d).timestamp() * 1000)
        except Exception:
            return None
    if s.isdigit():
        v = int(s)
        return v if v > 10 ** 12 else v * 1000
    return None


# ----------------------------------------------------------------------------
# Import / Export (scoped to a user)
# ----------------------------------------------------------------------------
def parse_csv_words(text):
    """CSV text -> [{'en','zh','date'(ms|None)}]."""
    text = text.lstrip("﻿")
    reader = csv.reader(io.StringIO(text))
    rows = [r for r in reader if any((cell or "").strip() for cell in r)]
    if not rows:
        return []
    header_markers = {"english", "chinese", "en", "zh", "英文", "中文",
                      "word", "translation", "date", "日期", "录入日期"}
    first = [(c or "").strip().lower() for c in rows[0]]
    if any(h in header_markers for h in first):
        rows = rows[1:]
    words = []
    for r in rows:
        en = r[0].strip() if len(r) > 0 else ""
        zh = r[1].strip() if len(r) > 1 else ""
        dt = parse_date(r[2]) if len(r) > 2 else None
        if en and zh:
            words.append({"en": en, "zh": zh, "date": dt})
    return words


def parse_json_payload(text):
    """Returns ('backup', dict) for a full backup, or ('words', list) for a word list."""
    data = json.loads(text)
    if isinstance(data, dict) and "sheets" in data:
        return "backup", data
    if isinstance(data, list):
        words = []
        for it in data:
            if isinstance(it, dict):
                en = (it.get("en") or it.get("english") or "").strip()
                zh = (it.get("zh") or it.get("chinese") or "").strip()
                if en and zh:
                    words.append({"en": en, "zh": zh, "date": parse_date(it.get("date"))})
        return "words", words
    raise ValueError("无法识别的 JSON 结构")


def group_words_by_date(words):
    """Group a flat word list into (date_ms, [items]) buckets, preserving order."""
    buckets, order = {}, []
    now = now_ms()
    for w in words:
        key = w.get("date") or now
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append({"en": w["en"], "zh": w["zh"]})
    return [(k, buckets[k]) for k in order]


def insert_groups(c, user_id, groups, remaining):
    """Insert (date_ms, items) groups for a user while respecting remaining capacity.
    Returns (imported, skipped)."""
    imported, skipped = 0, 0
    for date_ms, items in groups:
        items = clean_items(items)
        if not items:
            continue
        if remaining <= 0:
            skipped += len(items)
            continue
        take, rest = items[:remaining], items[remaining:]
        sid = gen_id()
        t = now_ms()
        c.execute("INSERT INTO sheets(id,user_id,date,created_at,updated_at) VALUES(?,?,?,?,?)",
                  (sid, user_id, int(date_ms), t, t))
        insert_items(c, sid, take)
        imported += len(take)
        remaining -= len(take)
        skipped += len(rest)
    return imported, skipped


def insert_review(c, user_id, r):
    rid = gen_id()
    total = int(r.get("total") or 0)
    correct = int(r.get("correct") or 0)
    if r.get("accuracy") is not None:
        acc = int(r.get("accuracy"))
    else:
        acc = round(correct / total * 100) if total else 0
    date = int(r.get("date") or now_ms())
    c.execute("INSERT INTO reviews(id,user_id,date,total,correct,accuracy) VALUES(?,?,?,?,?,?)",
              (rid, user_id, date, total, correct, acc))
    for pos, it in enumerate(r.get("items", [])):
        c.execute("INSERT INTO review_items(review_id,position,zh,en,answer,correct) VALUES(?,?,?,?,?,?)",
                  (rid, pos, (it.get("zh") or ""), (it.get("en") or ""),
                   (it.get("answer") or ""), 1 if it.get("correct") else 0))


def do_import(user_id, payload):
    fmt = (payload.get("format") or "").lower()
    data = payload.get("data")
    mode = (payload.get("mode") or "merge").lower()
    if not data or not str(data).strip():
        return 400, {"error": "导入内容为空"}

    kind, backup, words = "words", None, []
    try:
        if fmt == "json":
            kind, parsed = parse_json_payload(data)
            if kind == "backup":
                backup = parsed
            else:
                words = parsed
        else:
            words = parse_csv_words(data)
    except Exception as e:
        return 400, {"error": "解析失败：" + str(e)}

    if kind != "backup" and not words:
        return 400, {"error": "未发现可导入的词条（每行需有英文与中文）"}

    with tx() as c:
        if mode == "replace":
            c.execute("DELETE FROM sheets WHERE user_id=?", (user_id,))      # cascades items
            if kind == "backup":
                c.execute("DELETE FROM reviews WHERE user_id=?", (user_id,))  # cascades review_items
        remaining = WORD_LIMIT - word_count(c, user_id)

        if kind == "backup":
            groups = []
            for s in backup.get("sheets", []):
                groups.append((int(s.get("date") or now_ms()), s.get("items")))
            imported, skipped = insert_groups(c, user_id, groups, remaining)
            for r in backup.get("reviews", []):
                insert_review(c, user_id, r)
        else:
            imported, skipped = insert_groups(c, user_id, group_words_by_date(words), remaining)

        wc = word_count(c, user_id)
    return 200, {"imported": imported, "skipped": skipped, "wordCount": wc, "limit": WORD_LIMIT}


def export_csv(user_id):
    buf = io.StringIO()
    buf.write("﻿")                               # BOM so Excel shows UTF-8 CJK
    w = csv.writer(buf)
    w.writerow(["English", "Chinese", "Date"])
    with ro() as c:
        rows = c.execute(
            "SELECT i.en, i.zh, s.date FROM items i JOIN sheets s ON i.sheet_id=s.id "
            "WHERE s.user_id=? ORDER BY s.date DESC, i.position", (user_id,)).fetchall()
        for r in rows:
            d = datetime.datetime.fromtimestamp(r["date"] / 1000).strftime("%Y-%m-%d")
            w.writerow([r["en"], r["zh"], d])
    return buf.getvalue().encode("utf-8")


def export_json(user_id):
    with ro() as c:
        data = {"app": "拾词", "version": 2, "exportedAt": now_ms(), "limit": WORD_LIMIT,
                "sheets": fetch_sheets(c, user_id), "reviews": fetch_reviews(c, user_id)}
    return json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")


# ----------------------------------------------------------------------------
# Two-way sync (offline-first clients)
# ----------------------------------------------------------------------------
def _sheets_with_meta(c, user_id):
    rows = c.execute("SELECT id,date,updated_at FROM sheets WHERE user_id=?", (user_id,)).fetchall()
    out = {}
    for s in rows:
        items = c.execute("SELECT en,zh FROM items WHERE sheet_id=? ORDER BY position", (s["id"],)).fetchall()
        out[s["id"]] = {"id": s["id"], "date": s["date"], "updatedAt": s["updated_at"],
                        "items": [{"en": i["en"], "zh": i["zh"]} for i in items]}
    return out


def _insert_review_full(c, user_id, r):
    """Insert a review preserving its (client) id; used by sync merge."""
    rid = r.get("id") or gen_id()
    total = int(r.get("total") or 0)
    correct = int(r.get("correct") or 0)
    acc = int(r["accuracy"]) if r.get("accuracy") is not None else (round(correct / total * 100) if total else 0)
    date = int(r.get("date") or now_ms())
    c.execute("INSERT INTO reviews(id,user_id,date,total,correct,accuracy) VALUES(?,?,?,?,?,?)",
              (rid, user_id, date, total, correct, acc))
    for pos, it in enumerate(r.get("items", [])):
        c.execute("INSERT INTO review_items(review_id,position,zh,en,answer,correct) VALUES(?,?,?,?,?,?)",
                  (rid, pos, (it.get("zh") or ""), (it.get("en") or ""),
                   (it.get("answer") or ""), 1 if it.get("correct") else 0))


def do_sync(user_id, payload):
    """Merge a client's full local state with the server's stored state and return the result.
    Sheets: union by id, last-write-wins by updatedAt; ids in deletedSheetIds are removed.
    Reviews: union by id (append-only). Per-account 20000-pair cap is enforced on the result."""
    client_sheets = payload.get("sheets") or []
    client_reviews = payload.get("reviews") or []
    deleted = set(payload.get("deletedSheetIds") or [])

    with tx() as c:
        merged = {sid: s for sid, s in _sheets_with_meta(c, user_id).items() if sid not in deleted}
        for cs in client_sheets:
            sid = cs.get("id")
            if not sid or sid in deleted:
                continue
            items = clean_items(cs.get("items"))
            if not items:
                continue
            up = int(cs.get("updatedAt") or cs.get("date") or now_ms())
            if sid not in merged or up >= int(merged[sid]["updatedAt"]):
                merged[sid] = {"id": sid, "date": int(cs.get("date") or now_ms()),
                               "updatedAt": up, "items": items}

        srv_rev_ids = set(r["id"] for r in fetch_reviews(c, user_id))
        new_reviews = [r for r in client_reviews if r.get("id") and r["id"] not in srv_rev_ids]

        # enforce the per-account cap, keeping the most-recent sheets
        ordered = sorted(merged.values(), key=lambda s: s["date"], reverse=True)
        kept, total = [], 0
        for s in ordered:
            if total >= WORD_LIMIT:
                break
            its = s["items"][:WORD_LIMIT - total]
            kept.append({"id": s["id"], "date": s["date"], "updatedAt": s["updatedAt"], "items": its})
            total += len(its)

        c.execute("DELETE FROM sheets WHERE user_id=?", (user_id,))     # cascades items
        now = now_ms()
        for s in kept:
            c.execute("INSERT INTO sheets(id,user_id,date,created_at,updated_at) VALUES(?,?,?,?,?)",
                      (s["id"], user_id, int(s["date"]), now, int(s["updatedAt"])))
            insert_items(c, s["id"], s["items"])
        for r in new_reviews:
            _insert_review_full(c, user_id, r)

        out = {"sheets": fetch_sheets(c, user_id), "reviews": fetch_reviews(c, user_id),
               "wordCount": word_count(c, user_id), "limit": WORD_LIMIT, "syncedAt": now}
    return out


# ----------------------------------------------------------------------------
# HTTP handler
# ----------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "ShiCi/2.0"

    def log_message(self, *args):
        pass                                            # quiet

    # -- low level --
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send(self, status, body=b"", ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        return json.loads(raw.decode("utf-8")) if raw else {}

    def _auth(self):
        """Returns the user dict, or sends 401 and returns None."""
        user = user_from_token(get_bearer(self.headers))
        if not user:
            self._json(401, {"error": "未登录或登录状态已过期，请重新登录"})
            return None
        return user

    def _guard(self, fn):
        try:
            fn()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            try:
                self._json(500, {"error": "服务器内部错误"})
            except Exception:
                pass

    # -- verbs --
    def do_OPTIONS(self):
        self._send(204)

    def do_GET(self):
        self._guard(self._get)

    def do_POST(self):
        self._guard(self._post)

    def do_PUT(self):
        self._guard(self._put)

    def do_DELETE(self):
        self._guard(self._delete)

    # -- routing --
    def _get(self):
        u = urlparse(self.path)
        path = u.path
        if path in ("/", "/index.html", "/vocab-app.html"):
            return self._serve_html()
        if path == "/favicon.ico":
            return self._send(204)
        if path in STATIC_ASSETS:
            fname, ctype = STATIC_ASSETS[path]
            return self._serve_asset(fname, ctype)
        if path == "/api/health":
            return self._json(200, {"ok": True})
        if path == "/api/auth/me":
            user = self._auth()
            if not user:
                return
            return self._json(200, {"user": user})
        if path == "/api/state":
            user = self._auth()
            if not user:
                return
            with ro() as c:
                return self._json(200, {"sheets": fetch_sheets(c, user["id"]),
                                        "reviews": fetch_reviews(c, user["id"]),
                                        "wordCount": word_count(c, user["id"]), "limit": WORD_LIMIT})
        if path == "/api/export":
            user = self._auth()
            if not user:
                return
            q = parse_qs(u.query)
            fmt = (q.get("format", ["json"])[0]).lower()
            stamp = datetime.datetime.now().strftime("%Y%m%d")
            if fmt == "csv":
                return self._send(200, export_csv(user["id"]), "text/csv; charset=utf-8",
                                  {"Content-Disposition": 'attachment; filename="vocab_%s.csv"' % stamp})
            return self._send(200, export_json(user["id"]), "application/json; charset=utf-8",
                              {"Content-Disposition": 'attachment; filename="vocab_backup_%s.json"' % stamp})
        return self._json(404, {"error": "not found"})

    def _post(self):
        path = urlparse(self.path).path
        try:
            body = self._read_body()
        except Exception:
            return self._json(400, {"error": "无效的 JSON 请求体"})
        if path == "/api/auth/register":
            return self._register(body)
        if path == "/api/auth/login":
            return self._login(body)
        if path == "/api/auth/logout":
            return self._logout()
        user = self._auth()
        if not user:
            return
        if path == "/api/sheets":
            return self._create_sheet(user, body)
        if path == "/api/reviews":
            return self._create_review(user, body)
        if path == "/api/import":
            status, resp = do_import(user["id"], body)
            return self._json(status, resp)
        if path == "/api/sync":
            return self._json(200, do_sync(user["id"], body))
        return self._json(404, {"error": "not found"})

    def _put(self):
        m = re.match(r"^/api/sheets/([^/]+)$", urlparse(self.path).path)
        if not m:
            return self._json(404, {"error": "not found"})
        user = self._auth()
        if not user:
            return
        try:
            body = self._read_body()
        except Exception:
            return self._json(400, {"error": "无效的 JSON 请求体"})
        return self._update_sheet(user, m.group(1), body)

    def _delete(self):
        m = re.match(r"^/api/sheets/([^/]+)$", urlparse(self.path).path)
        if not m:
            return self._json(404, {"error": "not found"})
        user = self._auth()
        if not user:
            return
        return self._delete_sheet(user, m.group(1))

    # -- auth handlers --
    def _register(self, body):
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        if not username or len(username) > 32:
            return self._json(400, {"error": "用户名需为 1–32 个字符"})
        if not isinstance(password, str) or len(password) < 4:
            return self._json(400, {"error": "密码至少需要 4 位"})
        salt, h = hash_password(password)
        uid = gen_id()
        with tx() as c:
            taken = c.execute("SELECT 1 FROM users WHERE username_lower=?", (username.lower(),)).fetchone()
            if taken:
                result = (409, {"error": "该用户名已被注册"})
            else:
                c.execute("INSERT INTO users(id,username,username_lower,pw_salt,pw_hash,created_at) "
                          "VALUES(?,?,?,?,?,?)", (uid, username, username.lower(), salt, h, now_ms()))
                token = new_session(c, uid)
                result = (201, {"token": token, "user": {"id": uid, "username": username}})
        return self._json(*result)

    def _login(self, body):
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        with ro() as c:
            u = c.execute("SELECT * FROM users WHERE username_lower=?", (username.lower(),)).fetchone()
        if not u or not verify_password(password, u["pw_salt"], u["pw_hash"]):
            return self._json(401, {"error": "用户名或密码错误"})
        with tx() as c:
            token = new_session(c, u["id"])
        return self._json(200, {"token": token, "user": {"id": u["id"], "username": u["username"]}})

    def _logout(self):
        token = get_bearer(self.headers)
        if token:
            with tx() as c:
                c.execute("DELETE FROM sessions WHERE token=?", (token,))
        return self._json(200, {"ok": True})

    # -- data handlers (scoped to user) --
    def _serve_html(self):
        try:
            with open(HTML_PATH, "rb") as f:
                body = f.read()
        except FileNotFoundError:
            return self._send(404, "vocab-app.html not found", "text/plain; charset=utf-8")
        return self._send(200, body, "text/html; charset=utf-8")

    def _serve_asset(self, fname, ctype):
        try:
            with open(os.path.join(BASE, fname), "rb") as f:
                body = f.read()
        except FileNotFoundError:
            return self._json(404, {"error": "asset not found"})
        return self._send(200, body, ctype, {"Cache-Control": "public, max-age=86400"})

    def _create_sheet(self, user, body):
        items = clean_items(body.get("items"))
        if not items:
            return self._json(400, {"error": "请至少输入一行完整的词条（英文 + 中文）"})
        date = int(body["date"]) if body.get("date") else now_ms()
        with tx() as c:
            cur = word_count(c, user["id"])
            if cur + len(items) > WORD_LIMIT:
                result = (409, {"error": "已达到 %d 组上限，本次还可添加 %d 组"
                                % (WORD_LIMIT, max(0, WORD_LIMIT - cur)),
                                "wordCount": cur, "limit": WORD_LIMIT,
                                "remaining": max(0, WORD_LIMIT - cur)})
            else:
                sid = gen_id()
                t = now_ms()
                c.execute("INSERT INTO sheets(id,user_id,date,created_at,updated_at) VALUES(?,?,?,?,?)",
                          (sid, user["id"], date, t, t))
                insert_items(c, sid, items)
                result = (201, {"sheet": sheet_dict(c, sid), "wordCount": word_count(c, user["id"]),
                                "limit": WORD_LIMIT})
        return self._json(*result)

    def _update_sheet(self, user, sid, body):
        items = clean_items(body.get("items"))
        if not items:
            return self._json(400, {"error": "请至少保留一行完整的词条（英文 + 中文）"})
        with tx() as c:
            if not owns_sheet(c, user["id"], sid):
                result = (404, {"error": "该录入单不存在"})
            else:
                existing = c.execute("SELECT COUNT(*) AS n FROM items WHERE sheet_id=?",
                                     (sid,)).fetchone()["n"]
                others = word_count(c, user["id"]) - existing
                if others + len(items) > WORD_LIMIT:
                    result = (409, {"error": "已达到 %d 组上限，无法保存这么多词条" % WORD_LIMIT,
                                    "wordCount": others + existing, "limit": WORD_LIMIT})
                else:
                    c.execute("DELETE FROM items WHERE sheet_id=?", (sid,))
                    insert_items(c, sid, items)
                    c.execute("UPDATE sheets SET updated_at=? WHERE id=?", (now_ms(), sid))
                    result = (200, {"sheet": sheet_dict(c, sid), "wordCount": word_count(c, user["id"]),
                                    "limit": WORD_LIMIT})
        return self._json(*result)

    def _delete_sheet(self, user, sid):
        with tx() as c:
            if not owns_sheet(c, user["id"], sid):
                result = (404, {"error": "该录入单不存在"})
            else:
                c.execute("DELETE FROM sheets WHERE id=?", (sid,))
                result = (200, {"wordCount": word_count(c, user["id"]), "limit": WORD_LIMIT})
        return self._json(*result)

    def _create_review(self, user, body):
        items = body.get("items") or []
        total = int(body.get("total") or len(items))
        correct = int(body.get("correct") or 0)
        if total <= 0:
            return self._json(400, {"error": "复习记录为空"})
        if body.get("accuracy") is not None:
            acc = int(body.get("accuracy"))
        else:
            acc = round(correct / total * 100) if total else 0
        date = int(body["date"]) if body.get("date") else now_ms()
        rid = gen_id()
        with tx() as c:
            c.execute("INSERT INTO reviews(id,user_id,date,total,correct,accuracy) VALUES(?,?,?,?,?,?)",
                      (rid, user["id"], date, total, correct, acc))
            for pos, it in enumerate(items):
                c.execute("INSERT INTO review_items(review_id,position,zh,en,answer,correct) VALUES(?,?,?,?,?,?)",
                          (rid, pos, (it.get("zh") or ""), (it.get("en") or ""),
                           (it.get("answer") or ""), 1 if it.get("correct") else 0))
        review = {"id": rid, "date": date, "total": total, "correct": correct, "accuracy": acc,
                  "items": [{"zh": (it.get("zh") or ""), "en": (it.get("en") or ""),
                             "answer": (it.get("answer") or ""), "correct": bool(it.get("correct"))}
                            for it in items]}
        return self._json(201, {"review": review})


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    init_db()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print("=" * 60)
    print("  拾词 backend is running (accounts enabled)")
    print("  Local:      http://localhost:%d/" % PORT)
    if HOST == "0.0.0.0":
        print("  LAN:        http://%s:%d/   (other devices on same Wi-Fi)" % (local_ip(), PORT))
    else:
        print("  (Set HOST=0.0.0.0 to allow other devices on your Wi-Fi to sync.)")
    print("  Database:   %s" % DB_PATH)
    print("  Per-account word limit: %d pairs" % WORD_LIMIT)
    print("  Press Ctrl+C to stop.")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping...")
        httpd.shutdown()


if __name__ == "__main__":
    main()

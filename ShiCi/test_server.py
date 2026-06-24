#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated test suite for the 拾词 backend (server.py).

Pure standard library (unittest + urllib) — NO third-party deps.
Spins the real server on a temp SQLite DB and exercises every endpoint:
auth (register/login/logout/me/expiry), per-account data isolation,
CRUD, the 20000-pair cap, reviews, and CSV/JSON import/export.

Run:
    python test_server.py            # verbose
    python test_server.py -v
"""
import os
import sys
import json
import time
import tempfile
import threading
import unittest
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server  # noqa: E402

PORT = 8137
ORIGIN = "http://127.0.0.1:%d" % PORT
_httpd = None


# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------
def setUpModule():
    global _httpd
    server.DB_PATH = os.path.join(tempfile.gettempdir(), "vocab_test_%d.db" % os.getpid())
    if os.path.exists(server.DB_PATH):
        os.remove(server.DB_PATH)
    server.init_db()
    _httpd = server.ThreadingHTTPServer(("127.0.0.1", PORT), server.Handler)
    threading.Thread(target=_httpd.serve_forever, daemon=True).start()
    for _ in range(100):                       # wait until reachable
        try:
            urllib.request.urlopen(ORIGIN + "/api/health", timeout=1)
            return
        except Exception:
            time.sleep(0.05)
    raise RuntimeError("test server did not start")


def tearDownModule():
    if _httpd:
        _httpd.shutdown()
    try:
        os.remove(server.DB_PATH)
    except OSError:
        pass


def call(method, path, body=None, token=None):
    """Returns (status, parsed_json_or_text)."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(ORIGIN + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read().decode("utf-8")
            ctype = r.headers.get("Content-Type", "")
            return r.status, (json.loads(raw) if raw and "json" in ctype else raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


_counter = [0]


def register(password="pass1234"):
    """Register a fresh unique user; returns (username, token)."""
    _counter[0] += 1
    name = "u%d_%d" % (os.getpid(), _counter[0])
    s, d = call("POST", "/api/auth/register", {"username": name, "password": password})
    assert s == 201, (s, d)
    return name, d["token"]


def make_items(n, prefix="w"):
    return [{"en": "%s%d" % (prefix, i), "zh": "中%d" % i} for i in range(n)]


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
class AuthTests(unittest.TestCase):
    def test_health(self):
        s, d = call("GET", "/api/health")
        self.assertEqual(s, 200)
        self.assertTrue(d["ok"])

    def test_register_and_me(self):
        name, token = register()
        s, d = call("GET", "/api/auth/me", token=token)
        self.assertEqual(s, 200)
        self.assertEqual(d["user"]["username"], name)

    def test_register_duplicate_is_409(self):
        name, _ = register()
        s, d = call("POST", "/api/auth/register", {"username": name, "password": "pass1234"})
        self.assertEqual(s, 409)
        s, d = call("POST", "/api/auth/register", {"username": name.upper(), "password": "pass1234"})
        self.assertEqual(s, 409)  # case-insensitive uniqueness

    def test_register_validation(self):
        s, _ = call("POST", "/api/auth/register", {"username": "", "password": "pass1234"})
        self.assertEqual(s, 400)
        s, _ = call("POST", "/api/auth/register", {"username": "shorty", "password": "123"})
        self.assertEqual(s, 400)

    def test_login_ok_and_wrong(self):
        name, _ = register(password="secret9")
        s, d = call("POST", "/api/auth/login", {"username": name, "password": "secret9"})
        self.assertEqual(s, 200)
        self.assertIn("token", d)
        s, _ = call("POST", "/api/auth/login", {"username": name, "password": "WRONG"})
        self.assertEqual(s, 401)
        s, _ = call("POST", "/api/auth/login", {"username": "nobody_xyz", "password": "secret9"})
        self.assertEqual(s, 401)

    def test_login_is_case_insensitive_username(self):
        name, _ = register(password="secret9")
        s, d = call("POST", "/api/auth/login", {"username": name.upper(), "password": "secret9"})
        self.assertEqual(s, 200)

    def test_logout_invalidates_token(self):
        _, token = register()
        s, _ = call("GET", "/api/auth/me", token=token)
        self.assertEqual(s, 200)
        s, d = call("POST", "/api/auth/logout", token=token)
        self.assertEqual(s, 200)
        s, _ = call("GET", "/api/auth/me", token=token)
        self.assertEqual(s, 401)

    def test_expired_session_is_rejected(self):
        _, token = register()
        conn = server.connect()
        conn.execute("UPDATE sessions SET expires_at=? WHERE token=?", (server.now_ms() - 1000, token))
        conn.commit()
        conn.close()
        s, _ = call("GET", "/api/auth/me", token=token)
        self.assertEqual(s, 401)
        # expired token row should be cleaned up
        conn = server.connect()
        gone = conn.execute("SELECT 1 FROM sessions WHERE token=?", (token,)).fetchone()
        conn.close()
        self.assertIsNone(gone)

    def test_bad_token_is_rejected(self):
        s, _ = call("GET", "/api/auth/me", token="not-a-real-token")
        self.assertEqual(s, 401)


# ---------------------------------------------------------------------------
# Protected data endpoints
# ---------------------------------------------------------------------------
class DataTests(unittest.TestCase):
    def test_endpoints_require_auth(self):
        for method, path, body in [
            ("GET", "/api/state", None),
            ("POST", "/api/sheets", {"items": make_items(1)}),
            ("POST", "/api/reviews", {"total": 1, "correct": 1, "items": []}),
            ("POST", "/api/import", {"format": "csv", "data": "a,b\n"}),
            ("GET", "/api/export?format=csv", None),
        ]:
            s, _ = call(method, path, body)
            self.assertEqual(s, 401, "%s %s should require auth" % (method, path))

    def test_create_and_state(self):
        _, token = register()
        s, d = call("POST", "/api/sheets", {"items": make_items(3)}, token=token)
        self.assertEqual(s, 201)
        self.assertEqual(d["wordCount"], 3)
        self.assertEqual(len(d["sheet"]["items"]), 3)
        s, d = call("GET", "/api/state", token=token)
        self.assertEqual(s, 200)
        self.assertEqual(d["wordCount"], 3)
        self.assertEqual(len(d["sheets"]), 1)
        self.assertEqual(d["limit"], server.WORD_LIMIT)

    def test_blank_items_rejected(self):
        _, token = register()
        s, _ = call("POST", "/api/sheets", {"items": [{"en": "", "zh": ""}]}, token=token)
        self.assertEqual(s, 400)

    def test_isolation_between_accounts(self):
        _, tokenA = register()
        call("POST", "/api/sheets", {"items": make_items(4)}, token=tokenA)
        _, tokenB = register()
        s, d = call("GET", "/api/state", token=tokenB)
        self.assertEqual(s, 200)
        self.assertEqual(d["wordCount"], 0)
        self.assertEqual(len(d["sheets"]), 0)

    def test_update_and_ownership(self):
        _, tokenA = register()
        s, d = call("POST", "/api/sheets", {"items": make_items(2)}, token=tokenA)
        sid = d["sheet"]["id"]
        # owner can update
        s, d = call("PUT", "/api/sheets/" + sid, {"items": make_items(3)}, token=tokenA)
        self.assertEqual(s, 200)
        self.assertEqual(len(d["sheet"]["items"]), 3)
        # another account cannot touch it
        _, tokenB = register()
        s, _ = call("PUT", "/api/sheets/" + sid, {"items": make_items(1)}, token=tokenB)
        self.assertEqual(s, 404)

    def test_delete_and_ownership(self):
        _, tokenA = register()
        s, d = call("POST", "/api/sheets", {"items": make_items(2)}, token=tokenA)
        sid = d["sheet"]["id"]
        _, tokenB = register()
        s, _ = call("DELETE", "/api/sheets/" + sid, token=tokenB)
        self.assertEqual(s, 404)
        s, d = call("DELETE", "/api/sheets/" + sid, token=tokenA)
        self.assertEqual(s, 200)
        self.assertEqual(d["wordCount"], 0)

    def test_review_create_and_persist(self):
        _, token = register()
        payload = {"total": 2, "correct": 1, "accuracy": 50,
                   "items": [{"zh": "中0", "en": "w0", "answer": "w0", "correct": True},
                             {"zh": "中1", "en": "w1", "answer": "x", "correct": False}]}
        s, d = call("POST", "/api/reviews", payload, token=token)
        self.assertEqual(s, 201)
        self.assertEqual(d["review"]["accuracy"], 50)
        s, d = call("GET", "/api/state", token=token)
        self.assertEqual(len(d["reviews"]), 1)
        self.assertEqual(d["reviews"][0]["correct"], 1)
        self.assertEqual(len(d["reviews"][0]["items"]), 2)

    def test_review_accuracy_autocomputed(self):
        _, token = register()
        s, d = call("POST", "/api/reviews",
                    {"total": 4, "correct": 3, "items": []}, token=token)
        self.assertEqual(s, 201)
        self.assertEqual(d["review"]["accuracy"], 75)

    def test_export_csv_and_json(self):
        _, token = register()
        call("POST", "/api/sheets", {"items": [{"en": "serendipity", "zh": "意外之喜"}]}, token=token)
        s, text = call("GET", "/api/export?format=csv", token=token)
        self.assertEqual(s, 200)
        self.assertIn("English,Chinese,Date", text)
        self.assertIn("serendipity", text)
        s, data = call("GET", "/api/export?format=json", token=token)
        self.assertEqual(s, 200)
        self.assertIn("sheets", data)
        self.assertEqual(data["limit"], server.WORD_LIMIT)

    def test_import_csv_merge_and_replace(self):
        _, token = register()
        s, d = call("POST", "/api/import",
                    {"format": "csv", "data": "English,Chinese\nalpha,甲\nbeta,乙\n", "mode": "merge"},
                    token=token)
        self.assertEqual(s, 200)
        self.assertEqual(d["imported"], 2)
        self.assertEqual(d["wordCount"], 2)
        # replace wipes then imports
        s, d = call("POST", "/api/import",
                    {"format": "csv", "data": "en,zh\ngamma,丙\n", "mode": "replace"},
                    token=token)
        self.assertEqual(s, 200)
        self.assertEqual(d["imported"], 1)
        self.assertEqual(d["wordCount"], 1)

    def test_import_json_backup_roundtrip(self):
        _, token = register()
        backup = {"sheets": [{"date": 1718668800000, "items": [{"en": "round", "zh": "圆"}]}],
                  "reviews": [{"date": 1718668800000, "total": 1, "correct": 1, "accuracy": 100,
                               "items": [{"zh": "圆", "en": "round", "answer": "round", "correct": True}]}]}
        s, d = call("POST", "/api/import",
                    {"format": "json", "data": json.dumps(backup), "mode": "replace"}, token=token)
        self.assertEqual(s, 200)
        self.assertEqual(d["imported"], 1)
        s, d = call("GET", "/api/state", token=token)
        self.assertEqual(d["wordCount"], 1)
        self.assertEqual(len(d["reviews"]), 1)

    def test_word_limit_enforced_per_account(self):
        _, token = register()
        original = server.WORD_LIMIT
        server.WORD_LIMIT = 3
        try:
            s, d = call("POST", "/api/sheets", {"items": make_items(2)}, token=token)
            self.assertEqual(s, 201)
            self.assertEqual(d["wordCount"], 2)
            # 2 + 2 > 3  -> rejected
            s, d = call("POST", "/api/sheets", {"items": make_items(2)}, token=token)
            self.assertEqual(s, 409)
            self.assertEqual(d["remaining"], 1)
            # exactly fits
            s, d = call("POST", "/api/sheets", {"items": make_items(1)}, token=token)
            self.assertEqual(s, 201)
            self.assertEqual(d["wordCount"], 3)
            # import respects remaining capacity (0 left -> all skipped)
            s, d = call("POST", "/api/import",
                        {"format": "csv", "data": "en,zh\np,P\nq,Q\n", "mode": "merge"}, token=token)
            self.assertEqual(s, 200)
            self.assertEqual(d["imported"], 0)
            self.assertEqual(d["skipped"], 2)
        finally:
            server.WORD_LIMIT = original

    def test_limit_does_not_leak_across_accounts(self):
        # Account A near a low cap must not affect account B's capacity.
        _, tokenA = register()
        _, tokenB = register()
        original = server.WORD_LIMIT
        server.WORD_LIMIT = 2
        try:
            call("POST", "/api/sheets", {"items": make_items(2)}, token=tokenA)  # A full
            s, d = call("POST", "/api/sheets", {"items": make_items(2)}, token=tokenB)  # B still empty
            self.assertEqual(s, 201)
            self.assertEqual(d["wordCount"], 2)
        finally:
            server.WORD_LIMIT = original


# ---------------------------------------------------------------------------
# Two-way sync (offline-first)
# ---------------------------------------------------------------------------
class SyncTests(unittest.TestCase):
    def test_push_then_pull(self):
        _, token = register()
        s, d = call("POST", "/api/sync", {"sheets": [{"id": "s1", "date": 1718668800000,
                    "updatedAt": 1718668800000, "items": [{"en": "alpha", "zh": "甲"}]}],
                    "reviews": [], "deletedSheetIds": []}, token=token)
        self.assertEqual(s, 200)
        self.assertEqual(d["wordCount"], 1)
        self.assertEqual(d["sheets"][0]["id"], "s1")
        self.assertIn("updatedAt", d["sheets"][0])
        # a "second device" with an empty local store pulls s1
        s, d = call("POST", "/api/sync", {"sheets": [], "reviews": []}, token=token)
        self.assertEqual(len(d["sheets"]), 1)

    def test_union_merge_two_devices(self):
        _, token = register()
        call("POST", "/api/sync", {"sheets": [{"id": "a", "date": 100, "updatedAt": 100,
             "items": [{"en": "a", "zh": "甲"}]}], "reviews": []}, token=token)
        s, d = call("POST", "/api/sync", {"sheets": [{"id": "b", "date": 200, "updatedAt": 200,
             "items": [{"en": "b", "zh": "乙"}]}], "reviews": []}, token=token)
        self.assertEqual(sorted(x["id"] for x in d["sheets"]), ["a", "b"])
        self.assertEqual(d["wordCount"], 2)

    def test_last_write_wins(self):
        _, token = register()
        call("POST", "/api/sync", {"sheets": [{"id": "x", "date": 100, "updatedAt": 100,
             "items": [{"en": "old", "zh": "旧"}]}], "reviews": []}, token=token)
        s, d = call("POST", "/api/sync", {"sheets": [{"id": "x", "date": 100, "updatedAt": 200,
             "items": [{"en": "new", "zh": "新"}, {"en": "extra", "zh": "额"}]}], "reviews": []}, token=token)
        sheet = [s for s in d["sheets"] if s["id"] == "x"][0]
        self.assertEqual([it["en"] for it in sheet["items"]], ["new", "extra"])
        # an older update is ignored
        s, d = call("POST", "/api/sync", {"sheets": [{"id": "x", "date": 100, "updatedAt": 50,
             "items": [{"en": "stale", "zh": "陈"}]}], "reviews": []}, token=token)
        sheet = [s for s in d["sheets"] if s["id"] == "x"][0]
        self.assertEqual(sheet["items"][0]["en"], "new")

    def test_delete_propagates(self):
        _, token = register()
        call("POST", "/api/sync", {"sheets": [{"id": "d1", "date": 1, "updatedAt": 1,
             "items": [{"en": "k", "zh": "可"}]}], "reviews": []}, token=token)
        s, d = call("POST", "/api/sync", {"sheets": [], "reviews": [], "deletedSheetIds": ["d1"]}, token=token)
        self.assertEqual(d["wordCount"], 0)
        self.assertEqual(len(d["sheets"]), 0)

    def test_reviews_union_no_dupes(self):
        _, token = register()
        rev = {"id": "r1", "date": 1, "total": 2, "correct": 1, "accuracy": 50,
               "items": [{"zh": "甲", "en": "a", "answer": "a", "correct": True}]}
        s, d = call("POST", "/api/sync", {"sheets": [], "reviews": [rev]}, token=token)
        self.assertEqual(len(d["reviews"]), 1)
        s, d = call("POST", "/api/sync", {"sheets": [], "reviews": [rev]}, token=token)
        self.assertEqual(len(d["reviews"]), 1)

    def test_sync_requires_auth(self):
        s, _ = call("POST", "/api/sync", {"sheets": [], "reviews": []})
        self.assertEqual(s, 401)

    def test_sync_isolation(self):
        _, tokenA = register()
        call("POST", "/api/sync", {"sheets": [{"id": "ax", "date": 1, "updatedAt": 1,
             "items": [{"en": "a", "zh": "甲"}]}], "reviews": []}, token=tokenA)
        _, tokenB = register()
        s, d = call("POST", "/api/sync", {"sheets": [], "reviews": []}, token=tokenB)
        self.assertEqual(d["wordCount"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

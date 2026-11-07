"""Verify cloud.py never leaks credentials into error messages or logs.

Run:  python -I tests/test_cloud_logging.py
Drives sign_in / _get_json with a fake aiohttp-style session whose request
raises an exception whose text embeds fake secrets, and asserts those secrets
appear in neither the raised QrioCloudError nor what config_flow would log.
(No real aiohttp needed — cloud.py only imports it for type-checking.)
"""
from __future__ import annotations

import asyncio
import importlib.util
import io
import logging
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT / "custom_components" / "qrio_sl2"

# A marker that must never survive into a message or a log line.
SECRET = "LEAKMARKER_pw=hunter2_token=eyJLEAK"


def _load_cloud():
    pkg = types.ModuleType("qrio_sl2")
    pkg.__path__ = [str(PKG)]
    sys.modules["qrio_sl2"] = pkg
    for name in ("const", "cloud"):
        spec = importlib.util.spec_from_file_location(f"qrio_sl2.{name}", PKG / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[f"qrio_sl2.{name}"] = mod
        spec.loader.exec_module(mod)
    return sys.modules["qrio_sl2.cloud"]


class _FakeResp:
    def __init__(self, status=200, json_data=None, raise_exc=None):
        self._status, self._json, self._raise = status, json_data or {}, raise_exc

    async def __aenter__(self):
        if self._raise is not None:
            raise self._raise
        return self

    async def __aexit__(self, *a):
        return False

    @property
    def status(self):
        return self._status

    async def json(self):
        return self._json


class _FakeSession:
    def __init__(self, resp):
        self._resp = resp

    def post(self, *a, **k):
        return self._resp

    def get(self, *a, **k):
        return self._resp


def test_sign_in_exception_is_sanitized():
    cloud = _load_cloud()
    sess = _FakeSession(_FakeResp(raise_exc=ConnectionError(f"boom {SECRET}")))
    try:
        asyncio.run(cloud.sign_in(sess, "me@example.com", "hunter2"))
        assert False, "expected QrioCloudError"
    except cloud.QrioCloudError as err:
        assert SECRET not in str(err), str(err)
        assert "ConnectionError" in str(err) and "sign-in" in str(err), str(err)
        # the raw cause is preserved for deep debugging, just not in the message
        assert isinstance(err.__cause__, ConnectionError)


def test_get_json_exception_is_sanitized():
    cloud = _load_cloud()
    sess = _FakeSession(_FakeResp(raise_exc=RuntimeError(f"header Bearer {SECRET}")))
    try:
        asyncio.run(cloud._get_json(sess, "/v1/u/all", "tok", {"ed_pk": "ab"}))
        assert False, "expected QrioCloudError"
    except cloud.QrioCloudError as err:
        assert SECRET not in str(err), str(err)
        assert "/v1/u/all" in str(err) and "RuntimeError" in str(err), str(err)


def test_http_status_messages_are_codes_only():
    cloud = _load_cloud()
    # 5xx -> cloud error with just the code
    try:
        asyncio.run(cloud.sign_in(_FakeSession(_FakeResp(status=503)), "e", "p"))
        assert False
    except cloud.QrioCloudError as err:
        assert "503" in str(err) and SECRET not in str(err)
    # 401 -> auth error, code only
    try:
        asyncio.run(cloud.sign_in(_FakeSession(_FakeResp(status=401)), "e", "p"))
        assert False
    except cloud.QrioAuthError as err:
        assert "401" in str(err)


def test_error_does_not_reach_logs():
    """Reproduce config_flow's logging and confirm the secret isn't emitted."""
    cloud = _load_cloud()
    sess = _FakeSession(_FakeResp(raise_exc=ConnectionError(f"leak {SECRET}")))
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    root = logging.getLogger()
    root.addHandler(handler)
    old_level = root.level
    root.setLevel(logging.DEBUG)
    try:
        try:
            asyncio.run(cloud.sign_in(sess, "me@example.com", "hunter2"))
        except cloud.QrioCloudError as err:
            # exactly what config_flow._fetch does on QrioCloudError
            logging.getLogger("custom_components.qrio_sl2.config_flow").warning(
                "Qrio cloud error: %s", err)
        handler.flush()
        out = buf.getvalue()
        assert "Qrio cloud error" in out, "expected the warning to be logged"
        assert SECRET not in out, f"secret leaked into logs: {out!r}"
        assert "hunter2" not in out
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS {t.__name__}")
    print(f"\nAll {len(tests)} tests passed.")

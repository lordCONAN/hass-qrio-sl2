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
    def __init__(self, status=200, json_data=None, raise_exc=None, delay=0.0):
        self._status, self._json, self._raise = status, json_data or {}, raise_exc
        self._delay = delay

    async def __aenter__(self):
        if self._delay:
            await asyncio.sleep(self._delay)
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


def _full_tb(err: BaseException) -> str:
    import traceback
    return "".join(traceback.format_exception(type(err), err, err.__traceback__))


def test_sign_in_exception_is_sanitized():
    cloud = _load_cloud()
    sess = _FakeSession(_FakeResp(raise_exc=ConnectionError(f"boom {SECRET}")))
    try:
        asyncio.run(cloud.sign_in(sess, "me@example.com", "hunter2"))
        assert False, "expected QrioCloudError"
    except cloud.QrioCloudError as err:
        assert SECRET not in str(err), str(err)
        assert "ConnectionError" in str(err) and "sign-in" in str(err), str(err)
        # cause suppressed (from None) so the secret can't surface in a traceback
        assert err.__cause__ is None and err.__suppress_context__ is True
        assert SECRET not in _full_tb(err), "secret leaked via full traceback"


def test_get_json_exception_is_sanitized():
    cloud = _load_cloud()
    sess = _FakeSession(_FakeResp(raise_exc=RuntimeError(f"header Bearer {SECRET}")))
    try:
        asyncio.run(cloud._get_json(sess, "/v1/u/all", "tok", {"ed_pk": "ab"}))
        assert False, "expected QrioCloudError"
    except cloud.QrioCloudError as err:
        assert SECRET not in str(err), str(err)
        assert "/v1/u/all" in str(err) and "RuntimeError" in str(err), str(err)
        assert err.__cause__ is None and err.__suppress_context__ is True
        assert SECRET not in _full_tb(err), "secret leaked via full traceback"


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
    # _get_json maps 401/403 to QrioAuthError (so cloud auth can trigger reauth)
    try:
        asyncio.run(cloud._get_json(_FakeSession(_FakeResp(status=403)), "/x", "tok", {}))
        assert False
    except cloud.QrioAuthError as err:
        assert "403" in str(err)


def test_safe_code_rejects_junk():
    cloud = _load_cloud()
    assert cloud._safe_code("V2-WF-28") == "V2-WF-28"
    # a long/space/quote-laden "code" (e.g. an injected credential) is scrubbed
    assert cloud._safe_code("x" * 100) == "unknown"
    assert cloud._safe_code("has space") == "unknown"
    assert cloud._safe_code(f"secret {SECRET}") == "unknown"
    assert cloud._safe_code(None) == "unknown"
    assert cloud._safe_code(12345) == "unknown"


def test_cloud_status_unknown_is_none():
    cloud = _load_cloud()
    for main, expect in [(2, True), (1, False), (0, None), (99, None)]:
        sess = _ScriptedSession(get=[_FakeResp(json_data={"main_lock": main})])
        st = asyncio.run(cloud.cloud_status(sess, "tok", "lock-1"))
        assert st["locked"] is expect, (main, st)
    # missing main_lock entirely
    sess = _ScriptedSession(get=[_FakeResp(json_data={})])
    assert asyncio.run(cloud.cloud_status(sess, "tok", "lock-1"))["locked"] is None


def test_cloud_operate_job_failure_code_is_validated():
    cloud = _load_cloud()
    sess = _ScriptedSession(
        post=[_FakeResp(json_data={"data": {"job_id": "J", "polling_interval": 20}})],
        get=[_FakeResp(json_data={"data": {"job_status": "failed",
                                           "status_code": f"junk {SECRET}"}})],
    )
    try:
        asyncio.run(cloud.cloud_operate(sess, "tok", "lock-1", opening=True, poll_timeout=10))
        assert False
    except cloud.QrioCloudError as err:
        assert SECRET not in str(err) and "unknown" in str(err), str(err)


def test_cloud_operate_timeout_is_uncertain():
    cloud = _load_cloud()
    # job never reaches a terminal state -> poll_timeout -> QrioUncertainError
    sess = _ScriptedSession(
        post=[_FakeResp(json_data={"data": {"job_id": "J", "polling_interval": 50}})],
        get=[_FakeResp(json_data={"data": {"job_status": "in_progress"}}) for _ in range(50)],
    )
    try:
        asyncio.run(cloud.cloud_operate(sess, "tok", "lock-1", opening=True, poll_timeout=0.4))
        assert False, "expected QrioUncertainError"
    except cloud.QrioUncertainError:
        pass


def _expect_uncertain(coro_factory):
    cloud = _load_cloud()
    try:
        asyncio.run(coro_factory(cloud))
        assert False, "expected QrioUncertainError"
    except cloud.QrioUncertainError:
        pass


def test_post_timeout_is_uncertain():
    # POST request times out AFTER it may have been sent -> uncertain, not safe.
    _expect_uncertain(lambda c: c.cloud_operate(
        _ScriptedSession(post=[_FakeResp(delay=0.5, json_data={"data": {"job_id": "J"}})]),
        "tok", "lock-1", opening=True, poll_timeout=5, http_timeout=0.15))


def test_post_connection_loss_is_uncertain():
    # A non-connect transport error during submit -> response may be lost -> uncertain.
    _expect_uncertain(lambda c: c.cloud_operate(
        _ScriptedSession(post=[_FakeResp(raise_exc=OSError("reset"))]),
        "tok", "lock-1", opening=True, poll_timeout=5))


def test_post_5xx_is_uncertain():
    _expect_uncertain(lambda c: c.cloud_operate(
        _ScriptedSession(post=[_FakeResp(status=502)]),
        "tok", "lock-1", opening=True, poll_timeout=5))


def test_post_accepted_without_job_id_is_uncertain():
    _expect_uncertain(lambda c: c.cloud_operate(
        _ScriptedSession(post=[_FakeResp(json_data={"data": {}})]),
        "tok", "lock-1", opening=True, poll_timeout=5))


def test_job_failed_is_uncertain_not_safe():
    # A hub-reported 'failed' is NOT proof the bolt stayed put -> uncertain.
    cloud = _load_cloud()
    sess = _ScriptedSession(
        post=[_FakeResp(json_data={"data": {"job_id": "J", "polling_interval": 20}})],
        get=[_FakeResp(json_data={"data": {"job_status": "failed", "status_code": "V2-X"}})],
    )
    try:
        asyncio.run(cloud.cloud_operate(sess, "tok", "lock-1", opening=False, poll_timeout=5))
        assert False
    except cloud.QrioUncertainError:
        pass


def test_post_4xx_is_safe_not_uncertain():
    # A received client error (e.g. 400) reliably means the command did NOT run.
    cloud = _load_cloud()
    sess = _ScriptedSession(post=[_FakeResp(status=400, json_data={"errors": [{"code": "V2-KC84"}]})])
    try:
        asyncio.run(cloud.cloud_operate(sess, "tok", "lock-1", opening=True, poll_timeout=5))
        assert False
    except cloud.QrioUncertainError:
        assert False, "4xx must be a safe QrioCloudError, not uncertain"
    except cloud.QrioCloudError as err:
        assert "400" in str(err)


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


class _ScriptedSession:
    """Fake aiohttp session: post()/get() pop canned responses in order."""

    def __init__(self, post=None, get=None):
        self._post = list(post or [])
        self._get = list(get or [])

    def post(self, *a, **k):
        return self._post.pop(0)

    def get(self, *a, **k):
        return self._get.pop(0)


def test_cloud_status_maps_state():
    cloud = _load_cloud()
    sess = _ScriptedSession(get=[_FakeResp(json_data={"main_lock": 2})])
    st = asyncio.run(cloud.cloud_status(sess, "tok", "lock-1"))
    assert st == {"locked": True, "thumb_turn": "locked"}, st
    sess = _ScriptedSession(get=[_FakeResp(json_data={"main_lock": 1})])
    st = asyncio.run(cloud.cloud_status(sess, "tok", "lock-1"))
    assert st == {"locked": False, "thumb_turn": "unlocked"}, st


def test_cloud_operate_polls_to_success():
    cloud = _load_cloud()
    sess = _ScriptedSession(
        post=[_FakeResp(json_data={"data": {"job_id": "J1", "polling_interval": 20}})],
        get=[
            _FakeResp(json_data={"data": {"job_status": "in_progress"}}),
            _FakeResp(json_data={"data": {"job_status": "succeeded", "status_code": "V2-WF-28",
                                          "attribute_data": {"thumbturn_state": "open"}}}),
        ],
    )
    res = asyncio.run(cloud.cloud_operate(sess, "tok", "lock-1", opening=True, poll_timeout=10))
    assert res["ok"] and res["thumbturn_state"] == "open" and res["status_code"] == "V2-WF-28", res


def test_cloud_operate_raises_on_job_failure():
    cloud = _load_cloud()
    sess = _ScriptedSession(
        post=[_FakeResp(json_data={"data": {"job_id": "J2", "polling_interval": 20}})],
        get=[_FakeResp(json_data={"data": {"job_status": "failed", "status_code": "V2-XX"}})],
    )
    try:
        asyncio.run(cloud.cloud_operate(sess, "tok", "lock-1", opening=False, poll_timeout=10))
        assert False, "expected QrioCloudError"
    except cloud.QrioCloudError:
        pass


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS {t.__name__}")
    print(f"\nAll {len(tests)} tests passed.")

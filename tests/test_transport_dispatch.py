"""Fail-safe operate-dispatch tests (pure transport.run_operate, no HA).

These verify the invariant that matters for a physical lock: a second command is
issued on another transport ONLY when the first positively did not submit. Each
test asserts whether the *secondary* transport was actually invoked.

Run:  python -I tests/test_transport_dispatch.py
"""
from __future__ import annotations

import asyncio
import importlib.util
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT / "custom_components" / "qrio_sl2"


_CACHE = {}


def _load():
    # Load once and reuse, so exception classes keep a single identity across the
    # whole test run (isinstance checks inside run_operate rely on that).
    if not _CACHE:
        pkg = types.ModuleType("qrio_sl2")
        pkg.__path__ = [str(PKG)]
        sys.modules["qrio_sl2"] = pkg
        for name in ("cloud", "transport"):
            spec = importlib.util.spec_from_file_location(f"qrio_sl2.{name}", PKG / f"{name}.py")
            m = importlib.util.module_from_spec(spec)
            sys.modules[f"qrio_sl2.{name}"] = m
            spec.loader.exec_module(m)
            _CACHE[name] = m
    return _CACHE["cloud"], _CACHE["transport"]


class _FakeAuth(Exception):
    """Stands in for ConfigEntryAuthFailed (HA) without importing HA."""


def _run(order_specs, *, auth=()):
    """order_specs: [(name, raises_exc_or_None)]. Returns (result, ran, resolved)."""
    cloud, transport = _load()
    ran: list[str] = []
    resolved: list[str] = []

    def make(name, exc):
        async def fn():
            ran.append(name)
            if exc is not None:
                raise exc
        return (name, fn)

    async def resolve(name, exc):
        resolved.append(name)

    order = [make(n, e) for n, e in order_specs]

    async def go():
        return await transport.run_operate(order, resolve_uncertain=resolve, auth_exc_types=auth)

    try:
        result = asyncio.run(go())
    except Exception as exc:  # noqa: BLE001
        result = ("raised", type(exc).__name__)
    return result, ran, resolved, (cloud, transport)


def test_success_primary_no_secondary():
    res, ran, resolved, _ = _run([("local", None), ("cloud", None)])
    assert res == "local" and ran == ["local"] and resolved == []


def test_not_submitted_falls_back():
    cloud, transport = _load()
    for exc in (transport.BleNotSubmitted("x"), cloud.QrioNotSubmitted("x"),
                cloud.QrioAuthError("x")):
        res, ran, resolved, _ = _run([("local", exc), ("cloud", None)])
        assert res == "cloud", (exc, res)
        assert ran == ["local", "cloud"], (exc, ran)   # SECONDARY was invoked
        assert resolved == []


def test_uncertain_does_not_fall_back():
    cloud, transport = _load()
    for exc in (transport.BleUncertain("x"), cloud.QrioUncertainError("x")):
        res, ran, resolved, _ = _run([("local", exc), ("cloud", None)])
        assert res == "local", (exc, res)
        assert ran == ["local"], (exc, ran)            # SECONDARY NOT invoked
        assert resolved == ["local"]                   # verified instead


def test_unexpected_exception_does_not_fall_back():
    # The crux: an unknown exception type must NOT permit a second command.
    res, ran, resolved, _ = _run([("local", ValueError("boom")), ("cloud", None)])
    assert res == "local" and ran == ["local"] and resolved == ["local"]


def test_single_transport_not_submitted_raises_operatefailed():
    cloud, transport = _load()
    res, ran, resolved, _ = _run([("cloud", cloud.QrioNotSubmitted("x"))])
    assert res == ("raised", "OperateFailed") and ran == ["cloud"] and resolved == []


def test_cloud_only_auth_is_reraised():
    # cloud-only + auth failure -> surfaced (so the caller starts re-auth), not verified
    res, ran, resolved, _ = _run([("cloud", _FakeAuth("dead"))], auth=(_FakeAuth,))
    assert res == ("raised", "_FakeAuth") and ran == ["cloud"] and resolved == []


def test_auth_in_fallback_mode_falls_back():
    # cloud primary auth failure, local backup -> fall back to local (don't disable it)
    res, ran, resolved, _ = _run([("cloud", _FakeAuth("dead")), ("local", None)],
                                 auth=(_FakeAuth,))
    assert res == "local" and ran == ["cloud", "local"] and resolved == []


def test_resolve_uncertain_may_raise_without_fallback():
    cloud, transport = _load()

    async def go():
        async def primary():
            raise cloud.QrioUncertainError("lost")

        async def secondary():
            raise AssertionError("secondary must NOT run after uncertain")

        async def resolve(name, exc):
            raise RuntimeError("could not verify")

        await transport.run_operate(
            [("cloud", primary), ("local", secondary)], resolve_uncertain=resolve)

    try:
        asyncio.run(go())
        assert False, "expected the resolve error to propagate"
    except RuntimeError:
        pass


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS {t.__name__}")
    print(f"\nAll {len(tests)} tests passed.")

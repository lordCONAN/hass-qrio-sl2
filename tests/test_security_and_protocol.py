"""Standalone tests (no Home Assistant import needed).

Run:  python -I tests/test_security_and_protocol.py
Covers the pure protocol helpers and static credential-handling guarantees:
the config entry must not persist the password or refresh token, and no logging
call may include a secret value.
"""
from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT / "custom_components" / "qrio_sl2"


def _load_protocol():
    spec = importlib.util.spec_from_file_location("qrio_protocol", PKG / "qrio_protocol.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["qrio_protocol"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_parse_advert():
    proto = _load_protocol()
    # 16 manufacturer bytes observed for a real lock in scan.pcapng
    md = bytes.fromhex("97dfd8bb167a34000f3310002d400100")
    info = proto.parse_advert(md)
    assert info["serial"] == 1061647, info
    assert info["lastlog"] == 81965, info
    assert info["enc_status"] == bytes.fromhex("97dfd8bb167a3400")
    assert proto.parse_advert(None) is None
    assert proto.parse_advert(b"\x00" * 8) is None   # too short
    assert proto.MANUFACTURER_ID == 565


def test_battery_levels():
    proto = _load_protocol()
    assert proto.battery_slot_level("ok_6v") == "good"
    assert proto.battery_slot_level("warn") == "low"
    assert proto.battery_slot_level("empty") == "empty"
    assert proto.battery_slot_level("ng_7v") == "unknown"
    assert proto.battery_overall("ok_6v", "ok_6v") == "good"
    assert proto.battery_overall("ok_6v", "warn") == "low"
    assert proto.battery_overall("ok_6v", "empty") == "replace"
    assert proto.battery_overall("empty", "empty") == "empty"


def test_entry_data_has_no_password_or_refresh():
    """The stored config entry must never include the password or refresh token."""
    src = (PKG / "config_flow.py").read_text(encoding="utf-8")
    # Grab every data={...} dict literal passed when creating/updating an entry.
    for block in re.findall(r"data=\{(.*?)\}", src, re.DOTALL):
        assert "PASSWORD" not in block, "password must not be stored in the entry"
        assert "refresh" not in block.lower(), "refresh token must not be stored"


def test_no_secret_is_logged():
    """No _LOGGER.* call may interpolate a secret-bearing variable."""
    secret_tokens = ("password", "client_seed", "seed_hex", "_signing_key",
                     "_ekey", "id_token", "refresh_token")
    for py in PKG.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for m in re.finditer(r"_LOGGER\.\w+\((.*?)\)", text, re.DOTALL):
            call = m.group(1).lower()
            for tok in secret_tokens:
                assert tok not in call, f"{py.name}: logging call may expose '{tok}': {m.group(1)[:80]}"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS {t.__name__}")
    print(f"\nAll {len(tests)} tests passed.")

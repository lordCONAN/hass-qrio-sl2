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
    import struct
    proto = _load_protocol()
    # Synthetic manufacturer payload: [8B enc][u32 LE serial][u32 LE lastLog].
    enc = bytes(range(8))
    md = enc + struct.pack("<I", 7654321) + struct.pack("<I", 4242)
    info = proto.parse_advert(md)
    assert info["serial"] == 7654321, info
    assert info["lastlog"] == 4242, info
    assert info["enc_status"] == enc
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


def test_entry_data_at_setup_has_no_secrets():
    """At setup the entry stores neither the password nor any cloud token —
    cloud tokens are only added later, when cloud is explicitly enabled."""
    src = (PKG / "config_flow.py").read_text(encoding="utf-8")
    m = re.search(r"def _build_entry_data.*?(?=\n\ndef |\n\nclass )", src, re.DOTALL)
    assert m, "could not find _build_entry_data"
    body = m.group(0)
    for forbidden in ("PASSWORD", "password", "CONF_REFRESH", "CONF_IDTOKEN",
                      "refresh_token", "id_token"):
        assert forbidden not in body, f"{forbidden} must not be stored at setup"


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

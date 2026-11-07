"""Pure Qrio SL-2 BLE protocol: framing, signing, response decode.

Transport-agnostic (no bleak / no Home Assistant imports) so it can be unit-tested
and reused. All layouts are byte/sig-confirmed against real HCI captures
(status/unlock/lock *.pklg); every command signature verifies over
frame[2 : 162+len(command)] with the pubkey embedded at ekey[58:90], and every
lock response signature verifies with the lock's ed_pk.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from nacl import signing

OP_UNLOCK = 0x01
OP_LOCK = 0x02
OP_STATUS = 0x07
DEVICE_TYPE_CU = 0x01
FRAME_LEN = 247
VERB = {OP_UNLOCK: "unlock", OP_LOCK: "lock", OP_STATUS: "status"}


# ---------- challenge (read of char 12EC = [4B LE epoch][16B nonce]) ----------
@dataclass
class Challenge:
    lock_time: bytes      # raw[0:4], 4-byte LE currentTime
    verifier_nonce: bytes # raw[4:20], the 16-byte verifierNonce (ru)
    raw: bytes

    @classmethod
    def parse(cls, b: bytes) -> "Challenge":
        if len(b) < 20:
            raise ValueError(f"challenge too short ({len(b)}B)")
        return cls(lock_time=bytes(b[0:4]), verifier_nonce=bytes(b[4:20]), raw=bytes(b))


# ---------- chunk framing (0x80|count / idx / 0x40|idx, <=19 data bytes) ----------
def chunk(payload: bytes, mtu_data: int = 19) -> list[bytes]:
    parts = [payload[i:i + mtu_data] for i in range(0, len(payload), mtu_data)]
    n = len(parts)
    out = []
    for i, p in enumerate(parts):
        prefix = (0x80 | n) if i == 0 else (0x40 | i) if i == n - 1 else i
        out.append(bytes([prefix]) + p)
    return out


# ---------- command field (ul/f.java a(): [opcode][len:4 LE][body]) ----------
def build_command_field(opcode: int, time_bytes: bytes) -> bytes:
    if opcode == OP_STATUS:
        return bytes.fromhex("070100000000")                      # ReadStatus(Weak)
    if opcode == OP_UNLOCK:
        return b"\x01" + struct.pack("<I", 6) + b"\x00\xff" + time_bytes  # Open(bAlert=0,toutFF)
    if opcode == OP_LOCK:
        return b"\x02" + struct.pack("<I", 4) + time_bytes                # Close(time)
    raise ValueError(f"unknown opcode {opcode:#04x}")


def build_signed_body(ekey: bytes, time_bytes: bytes, verifier_nonce: bytes,
                      prover_nonce: bytes, command_field: bytes) -> bytes:
    """jl/b.java body = 0x01 || deviceType(CU) || ekey || time || ru || cu || command.
    Equals the on-wire frame[2 : 162+len(command)]."""
    return (b"\x01" + bytes([DEVICE_TYPE_CU]) + ekey + time_bytes
            + verifier_nonce + prover_nonce + command_field)


def build_frame(ekey: bytes, signing_key: signing.SigningKey, opcode: int,
                chal: Challenge, prover_nonce: bytes, time_bytes: bytes | None = None) -> bytes:
    """Build the 247-B padded command frame. time_bytes defaults to the lock's
    just-read currentTime (tracks the lock's clock, which it validates)."""
    if len(ekey) != 122:
        raise ValueError(f"ekey is {len(ekey)}B, expected 122")
    if len(prover_nonce) != 16:
        raise ValueError("prover_nonce must be 16 B")
    if time_bytes is None:
        time_bytes = chal.lock_time
    command_field = build_command_field(opcode, time_bytes)
    body = build_signed_body(ekey, time_bytes, chal.verifier_nonce, prover_nonce, command_field)
    sig = signing_key.sign(body).signature                        # 64 B
    a11 = body + sig
    if 2 + len(a11) > FRAME_LEN:
        raise ValueError(f"a11 {len(a11)}B overflows frame")
    f = bytearray(FRAME_LEN)
    f[0:2] = struct.pack("<H", len(a11))                          # u16 LE payload length
    f[2:2 + len(a11)] = a11                                       # remainder stays zero-pad
    return bytes(f)


# ---------- STATUS response (unsigned; [u16 len][content]) ----------
_N = {255: "no_change", 1: "on", 0: "off"}
_THUMB = {0: "unknown", 1: "unlocked", 2: "locked"}            # ul/l.java OPENED/CLOSED
_BATT = {255: "unknown", 0: "ok_6v", 1: "ok_thumbturn", 2: "warn", 3: "empty_pending",
         4: "ep_reset", 5: "empty", 6: "ng_7v"}                # cl/b.java
_ACTIVE = {0: "A", 1: "B"}
_TXP = {255: "no_change", 0: "-40", 1: "-20", 2: "-16", 3: "-12", 4: "-8", 5: "-4",
        6: "0", 7: "+3", 8: "+4"}
_DEVSTATUS = {0: "ok", 0x71: "notify_enabled", 0x81: "operation_failed",
              0x82: "invalid_parameters", 0x83: "invalid_signature",
              0x84: "invalid_auth_time", 0xff: "failed"}
_BATT_ALERT = {255: "unknown", 0: "none", 1: "no_battery"}     # ul/e.java
_DRIVE = {255: "unknown", 0: "drove", 1: "not_driven"}         # ul/g.java (0=OK drove)
# battery enums that indicate a problem worth surfacing
BATTERY_PROBLEM = {"warn", "empty_pending", "ep_reset", "empty", "ng_7v", "no_battery"}

# Friendly battery levels, matching the Qrio app (li/g.java).
# Per slot (h()/i()): the raw cl/b state collapses to good / low / empty / unknown.
_SLOT_LEVEL = {
    "ok_6v": "good", "ok_thumbturn": "good",
    "warn": "low",
    "empty_pending": "empty", "ep_reset": "empty", "empty": "empty",
    "unknown": "unknown", "ng_7v": "unknown",
}


def battery_slot_level(raw: str | None) -> str:
    """One slot's friendly level (good/low/empty/unknown)."""
    return _SLOT_LEVEL.get(raw or "", "unknown")


def battery_overall(a_raw: str | None, b_raw: str | None) -> str:
    """The headline battery status the app shows (li/g.j).

    The lock runs on one of two cells and you hot-swap, so one empty slot is
    "replace" (still working), both empty is "empty".
    """
    levels = [battery_slot_level(a_raw), battery_slot_level(b_raw)]
    empties = levels.count("empty")
    if empties == 2:
        return "empty"
    if empties == 1:
        return "replace"
    if "low" in levels:
        return "low"
    if "good" in levels:
        return "good"
    return "unknown"


def decode_status(resp: bytes) -> dict | None:
    """Parse a ReadStatus(Weak) response into a flat dict, or None if not one."""
    if len(resp) < 15 or resp[0:2] != b"\x61\x00":
        return None
    c = resp[2:]
    if len(c) < 13:
        return None
    s8 = c[12] - 256 if c[12] >= 128 else c[12]
    return {
        "device_status": _DEVSTATUS.get(c[0], f"0x{c[0]:02x}"),
        "locked": c[8] == 2,
        "thumb_turn": _THUMB.get(c[8], f"0x{c[8]:02x}"),
        "battery_a": _BATT.get(c[5], f"0x{c[5]:02x}"),
        "battery_b": _BATT.get(c[6], f"0x{c[6]:02x}"),
        "active_battery": _ACTIVE.get(c[7], f"0x{c[7]:02x}"),
        "buzzer": _N.get(c[1], c[1]),
        "autolock_dooropen_timeout_s": c[4],
        "autolock_failsafe_timeout_s": c[3],
        "ibeacon_interval_ms": c[9] * 10,
        "ibeacon_tx_power_db": _TXP.get(c[10], f"0x{c[10]:02x}"),
        "ibeacon_signal_power_dbm": s8,
    }


# ---------- Open/Close response (SIGNED by the lock; ul/i.java j()) ----------
def decode_op_result(resp: bytes, lock_ed_pk: bytes) -> dict | None:
    """Parse + verify an Open/Close response. Returns dict (incl sig_ok/ok), or None."""
    if len(resp) < 2:
        return None
    ln = int.from_bytes(resp[0:2], "little")
    if ln < 64 or 2 + ln > len(resp):
        return None
    b_arr = resp[2:2 + ln]
    sig, signed = b_arr[-64:], b_arr[:-64]
    try:
        signing.VerifyKey(lock_ed_pk).verify(bytes(signed), bytes(sig))
        sig_ok = True
    except Exception:  # noqa: BLE001 - any verify failure means not authentic
        sig_ok = False
    clen = (ln - 68) - 16          # content; i10=16 cu_command_nonce present (CU path)
    if clen < 6:
        return None
    c = b_arr[:clen]
    return {
        "sig_ok": sig_ok,
        "ok": c[0] == 0,
        "device_status": _DEVSTATUS.get(c[0], f"0x{c[0]:02x}"),
        "battery_alert": _BATT_ALERT.get(c[1], f"0x{c[1]:02x}"),
        "drive_result": _DRIVE.get(c[2], f"0x{c[2]:02x}"),
        "battery_a": _BATT.get(c[3], f"0x{c[3]:02x}"),
        "battery_b": _BATT.get(c[4], f"0x{c[4]:02x}"),
        "active_battery": _ACTIVE.get(c[5], f"0x{c[5]:02x}"),
        "seq": int.from_bytes(c[6:10], "little") if clen >= 10 else None,
    }

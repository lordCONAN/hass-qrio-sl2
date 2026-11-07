"""Qrio King cloud client (async). Used ONLY at setup/reauth to mint an ekey.

Mints an ekey for a freshly generated local Ed25519 keypair:
  POST /v2/cu/users/sign_in   {email,password}  -> id_token (+ refresh_token)
  GET  /v1/u/all?ed_pk=<hex>  Bearer            -> per-lock master_key.ekey + lock{...}
  GET  /v1/u/ed_pk?lock_id=   Bearer            -> the lock's ed_pk (to verify responses)
The returned ekeys embed OUR ed_pk, so the lock verifies OUR BLE signatures.
Runtime lock/unlock/status never touch the cloud.
"""
from __future__ import annotations

import base64
import re

from aiohttp import ClientSession
from nacl import signing

from .const import API_BASE, BASE_HEADERS


class QrioAuthError(Exception):
    """Invalid credentials."""


class QrioCloudError(Exception):
    """Transport / unexpected-response error."""


def _auth_headers(token: str) -> dict[str, str]:
    return {**BASE_HEADERS, "Authorization": f"Bearer {token}"}


def decode_ekey(s: str | None) -> bytes | None:
    """ekey arrives as hex or base64url; return raw bytes (~122) or None."""
    if not s:
        return None
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        return bytes.fromhex(s)
    try:
        t = s.replace("-", "+").replace("_", "/")
        t += "=" * (-len(t) % 4)
        return base64.b64decode(t)
    except Exception:  # noqa: BLE001
        return None


async def sign_in(session: ClientSession, email: str, password: str) -> tuple[str, str | None]:
    try:
        async with session.post(f"{API_BASE}/v2/cu/users/sign_in", headers=BASE_HEADERS,
                                data={"email": email, "password": password}) as r:
            if r.status in (400, 401, 403):
                raise QrioAuthError(f"sign_in rejected ({r.status})")
            if r.status >= 400:
                raise QrioCloudError(f"sign_in HTTP {r.status}")
            j = await r.json()
    except (QrioAuthError, QrioCloudError):
        raise
    except Exception as exc:  # noqa: BLE001
        raise QrioCloudError(f"sign_in failed: {exc}") from exc
    token = j.get("id_token")
    if not token:
        raise QrioCloudError("sign_in: no id_token in response")
    return token, j.get("refresh_token")


async def _get_json(session: ClientSession, path: str, token: str, params: dict) -> dict:
    try:
        async with session.get(f"{API_BASE}{path}", headers=_auth_headers(token),
                               params=params) as r:
            if r.status >= 400:
                raise QrioCloudError(f"{path} HTTP {r.status}")
            return await r.json()
    except QrioCloudError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise QrioCloudError(f"{path} failed: {exc}") from exc


async def fetch_locks(session: ClientSession, email: str, password: str,
                      seed_hex: str | None = None) -> dict:
    """Sign in and list every lock on the account (with a minted ekey each).

    Reuses seed_hex when given (same account / reauth), else generates a fresh
    keypair. Does NOT fetch per-lock public keys — that happens once a lock is
    chosen (see fetch_lock_ed_pk). Returns:
      {email, client_seed_hex, refresh_token, token, locks: [ {lock_id,
       lock_name, bd_address, serial_no, fw_version, ekey_hex}, ... ]}
    The token is kept so the caller can fetch the chosen lock's ed_pk next.
    """
    sk = signing.SigningKey(bytes.fromhex(seed_hex)) if seed_hex else signing.SigningKey.generate()
    seed_hex = bytes(sk).hex()
    ed_pk_hex = bytes(sk.verify_key).hex()

    token, refresh = await sign_in(session, email, password)
    allj = await _get_json(session, "/v1/u/all", token, {"ed_pk": ed_pk_hex})
    data = allj.get("data") or []
    if not data:
        raise QrioCloudError("no locks returned for this account")

    locks = []
    for d in data:
        lock = d.get("lock") or {}
        ekraw = decode_ekey((d.get("master_key") or {}).get("ekey"))
        if not ekraw or len(ekraw) != 122:
            raise QrioCloudError(
                f"ekey for lock {lock.get('id')} decoded to "
                f"{len(ekraw) if ekraw else 0}B (expected 122)")
        if bytes.fromhex(ed_pk_hex) not in ekraw:
            raise QrioCloudError("minted ekey does not embed our key — account/key mismatch")
        locks.append({
            "lock_id": lock.get("id"),
            "lock_name": (lock.get("lock_setting") or {}).get("lock_name") or f"Qrio {lock.get('id')}",
            "bd_address": lock.get("bd_address"),
            "serial_no": lock.get("serial_no"),
            "fw_version": lock.get("fw_version"),
            "ekey_hex": ekraw.hex(),
        })
    return {"email": email, "client_seed_hex": seed_hex, "refresh_token": refresh,
            "token": token, "locks": locks}


async def fetch_lock_ed_pk(session: ClientSession, token: str, lock_id) -> str:
    """Fetch one lock's public key (to verify its signed BLE responses)."""
    pk = (await _get_json(session, "/v1/u/ed_pk", token, {"lock_id": lock_id})).get("ed_pk")
    if not pk:
        raise QrioCloudError(f"no lock ed_pk for lock {lock_id}")
    return pk

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
import logging
import re

from aiohttp import ClientSession
from nacl import signing

from .const import API_BASE, BASE_HEADERS

_LOGGER = logging.getLogger(__name__)


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
      {email, client_seed_hex, token, locks: [ {lock_id,
       lock_name, bd_address, serial_no, fw_version, ekey_hex}, ... ]}
    The token is kept only in memory so the caller can fetch the chosen lock's
    ed_pk next; it is never persisted.
    """
    sk = signing.SigningKey(bytes.fromhex(seed_hex)) if seed_hex else signing.SigningKey.generate()
    seed_hex = bytes(sk).hex()
    ed_pk_hex = bytes(sk.verify_key).hex()

    # The refresh token is intentionally discarded — runtime is pure local BLE
    # and never calls the cloud again; re-auth re-mints from the password.
    token, _refresh = await sign_in(session, email, password)
    allj = await _get_json(session, "/v1/u/all", token, {"ed_pk": ed_pk_hex})
    data = allj.get("data") or []
    if not data:
        raise QrioCloudError("no locks returned for this account")

    locks = []
    skipped = []
    for d in data:
        lock = d.get("lock") or {}
        lid = lock.get("id")
        name = (lock.get("lock_setting") or {}).get("lock_name") or f"Qrio {lid}"
        ekraw = decode_ekey((d.get("master_key") or {}).get("ekey"))
        # A lock with no master-key ekey (e.g. a shared/guest lock, or one you
        # don't hold a key for) can't be driven locally — skip it instead of
        # failing the whole mint, so the account's usable locks still show up.
        if not ekraw or len(ekraw) != 122:
            skipped.append(f"{name} (ekey {len(ekraw) if ekraw else 0}B)")
            continue
        if bytes.fromhex(ed_pk_hex) not in ekraw:
            skipped.append(f"{name} (key not embedded)")
            continue
        locks.append({
            "lock_id": lid,
            "lock_name": name,
            "bd_address": lock.get("bd_address"),
            "serial_no": lock.get("serial_no"),
            "fw_version": lock.get("fw_version"),
            "ekey_hex": ekraw.hex(),
        })
    if skipped:
        _LOGGER.info("Qrio: skipped locks without a usable local key: %s", skipped)
    if not locks:
        raise QrioCloudError(
            f"no lock on this account returned a usable local key "
            f"(checked {len(data)}; skipped: {skipped or 'none'})")
    return {"email": email, "client_seed_hex": seed_hex,
            "token": token, "locks": locks}


async def fetch_lock_ed_pk(session: ClientSession, token: str, lock_id) -> str:
    """Fetch one lock's public key (to verify its signed BLE responses)."""
    pk = (await _get_json(session, "/v1/u/ed_pk", token, {"lock_id": lock_id})).get("ed_pk")
    if not pk:
        raise QrioCloudError(f"no lock ed_pk for lock {lock_id}")
    return pk

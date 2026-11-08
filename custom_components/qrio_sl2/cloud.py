"""Qrio King cloud client (async).

Always used at setup/reauth to mint a local ekey:
  POST /v2/cu/users/sign_in   {email,password}  -> id_token (+ refresh_token)
  GET  /v1/u/all?ed_pk=<hex>  Bearer            -> per-lock master_key.ekey + lock{...}
  GET  /v1/u/ed_pk?lock_id=   Bearer            -> the lock's ed_pk (to verify responses)
The returned ekeys embed OUR ed_pk, so the lock verifies OUR BLE signatures.

Also used at RUNTIME only when the user opts into cloud control for a hub-equipped
lock (see cloud_status / cloud_operate / refresh_session): Qrio cloud -> hub -> lock,
with no per-command signing. Local-only setups never call the cloud at runtime.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import re
import time
from typing import TYPE_CHECKING

from nacl import signing

from .const import API_BASE, BASE_HEADERS

if TYPE_CHECKING:
    from aiohttp import ClientSession

_LOGGER = logging.getLogger(__name__)

# A failed TCP connect means the request was never sent (safe to fall back). Any
# other transport failure after that is ambiguous. aiohttp is always present at
# HA runtime; absent under standalone tests, where _CONNECT_FAILED stays empty.
try:  # pragma: no cover - import shape depends on environment
    from aiohttp import ClientConnectorError as _ClientConnectorError
    _CONNECT_FAILED: tuple = (_ClientConnectorError,)
except Exception:  # noqa: BLE001
    _CONNECT_FAILED = ()


class QrioAuthError(Exception):
    """Invalid/expired credentials (401/403) — needs re-authentication."""


class QrioCloudError(Exception):
    """Transport / unexpected-response error (ambiguous by default)."""


class QrioUncertainError(QrioCloudError):
    """A command may have been submitted; its outcome is unknown (do NOT resend)."""


class QrioNotSubmitted(QrioCloudError):
    """Positively established: the command was NOT submitted (safe to fall back)."""


def _auth_headers(token: str) -> dict[str, str]:
    return {**BASE_HEADERS, "Authorization": f"Bearer {token}"}


_CODE_RE = re.compile(r"[A-Za-z0-9._-]{1,40}")


def _safe_code(code) -> str:
    """Only surface a short, well-formed Qrio code; else a generic placeholder."""
    if isinstance(code, str) and _CODE_RE.fullmatch(code):
        return code
    return "unknown"


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
        # Never let the raw exception reach a message OR a chained traceback: its
        # text could echo the POSTed credentials/headers. Keep only the failure
        # type, and suppress the cause (`from None`) so tracebacks stay clean.
        raise QrioCloudError(
            f"sign-in request failed ({type(exc).__name__})") from None
    token = j.get("id_token")
    if not token:
        raise QrioCloudError("sign_in: no id_token in response")
    return token, j.get("refresh_token")


async def _get_json(session: ClientSession, path: str, token: str, params: dict) -> dict:
    try:
        async with session.get(f"{API_BASE}{path}", headers=_auth_headers(token),
                               params=params) as r:
            if r.status in (401, 403):
                raise QrioAuthError(f"{path} auth ({r.status})")
            if r.status >= 400:
                raise QrioCloudError(f"{path} HTTP {r.status}")
            return await r.json()
    except (QrioAuthError, QrioCloudError):
        raise
    except Exception as exc:  # noqa: BLE001
        # The Authorization: Bearer <token> header could appear in a raw aiohttp
        # error, so surface only the path + failure type (and no chained cause).
        raise QrioCloudError(
            f"{path} request failed ({type(exc).__name__})") from None


async def fetch_locks(session: ClientSession, email: str, password: str,
                      seed_hex: str | None = None) -> dict:
    """Sign in and list every lock on the account (with a minted ekey each).

    Reuses seed_hex when given (same account / reauth), else generates a fresh
    keypair. Does NOT fetch per-lock public keys — that happens once a lock is
    chosen (see fetch_lock_ed_pk). Returns:
      {email, client_seed_hex, token, refresh_token, locks: [ {lock_id,
       lock_name, bd_address, serial_no, fw_version, ekey_hex, has_hub,
       hub_id}, ... ]}
    token/refresh_token are kept so the caller can fetch the chosen lock's ed_pk
    and, for a hub-equipped lock, enable cloud control; refresh_token is stored
    only for cloud-capable locks (see config_flow).
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
    skipped = []
    for d in data:
        lock = d.get("lock") or {}
        lid = lock.get("id")
        setting = lock.get("lock_setting") or {}
        name = setting.get("lock_name") or f"Qrio {lid}"
        hub = setting.get("hub") or {}
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
            "has_hub": bool(hub.get("id")),
            "hub_id": hub.get("id"),
        })
    if skipped:
        _LOGGER.info("Qrio: skipped locks without a usable local key: %s", skipped)
    if not locks:
        raise QrioCloudError(
            f"no lock on this account returned a usable local key "
            f"(checked {len(data)}; skipped: {skipped or 'none'})")
    return {"email": email, "client_seed_hex": seed_hex,
            "token": token, "refresh_token": refresh, "locks": locks}


# ---------- Cloud remote control (hub-equipped locks) ----------
# Operate/status via the Qrio cloud -> the account's Hub -> lock. No per-command
# signing (the hub does the lock crypto); just an authenticated REST call + poll.

async def refresh_session(session: ClientSession, id_token: str,
                          refresh_token: str) -> tuple[str, str]:
    """Exchange (id_token, refresh_token) for a fresh id_token (+ refresh token).

    Qrio's refresh needs a real id_token alongside the refresh token (an empty
    one yields HTTP 500), so pass the last one we held.
    """
    try:
        async with session.post(f"{API_BASE}/v2/cu/users/refresh", headers=BASE_HEADERS,
                                data={"id_token": id_token or "",
                                      "refresh_token": refresh_token}) as r:
            if r.status in (400, 401, 403):
                raise QrioAuthError(f"refresh rejected ({r.status})")
            if r.status >= 400:
                raise QrioCloudError(f"refresh HTTP {r.status}")
            j = await r.json()
    except (QrioAuthError, QrioCloudError):
        raise
    except Exception as exc:  # noqa: BLE001
        raise QrioCloudError(
            f"refresh request failed ({type(exc).__name__})") from None
    data = j if "id_token" in j else (j.get("data") or {})
    new_id = data.get("id_token")
    if not new_id:
        raise QrioCloudError("refresh: no id_token in response")
    return new_id, data.get("refresh_token") or refresh_token


# main_lock int from thumbturn_state: same enum as BLE thumbturn (ul/l.java).
# 2=locked, 1=unlocked; anything else is genuinely unknown (NOT "unlocked").
_THUMB_CLOUD = {0: "unknown", 1: "unlocked", 2: "locked"}


def _as_int(v):
    """Coerce an int-or-numeric-string to int; anything else -> None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return int(v)
    return None


def _main_lock_from(j: dict):
    """Pull main_lock from the response, tolerating a `data` wrapper."""
    if not isinstance(j, dict):
        return None
    if "main_lock" in j:
        return _as_int(j.get("main_lock"))
    inner = j.get("data")
    if isinstance(inner, dict) and "main_lock" in inner:
        return _as_int(inner.get("main_lock"))
    return None


def _locked_from_main(main) -> bool | None:
    return True if main == 2 else (False if main == 1 else None)


async def cloud_status(session: ClientSession, token: str, lock_id: str) -> dict:
    """GET the lock's thumb-turn state via cloud -> {locked, thumb_turn}."""
    j = await _get_json(session, f"/v1/u/locks/{lock_id}/thumbturn_state", token, {})
    main = _main_lock_from(j)
    if main not in (1, 2) and _LOGGER.isEnabledFor(logging.DEBUG):
        # No secrets here — just the shape/keys and the resolved value — so we can
        # see why a 200 didn't yield a locked/unlocked state.
        keys = sorted(j.keys()) if isinstance(j, dict) else type(j).__name__
        _LOGGER.debug("cloud_status: main_lock=%r keys=%s", main, keys)
    return {"locked": _locked_from_main(main),
            "thumb_turn": _THUMB_CLOUD.get(main, "unknown")}


async def cloud_operate(session: ClientSession, token: str, lock_id: str, opening: bool,
                        poll_timeout: float = 60.0, http_timeout: float = 20.0) -> dict:
    """POST unlock/lock via cloud, poll the job to completion.

    Returns {ok, thumbturn_state, status_code}. The path param is NAMED key_id
    but takes the lock_id (the app passes a LockId there). The whole operation —
    the POST, polling delays and polling requests — is bounded by poll_timeout
    (monotonic). A timeout AFTER the POST is reported as QrioUncertainError (the
    command may have executed), so the caller never blindly resends.
    """
    verb = "unlock" if opening else "lock"
    deadline = time.monotonic() + poll_timeout

    def _remaining() -> float:
        return deadline - time.monotonic()

    # ---- submit ----
    # Reliably-not-submitted (safe to fall back): auth rejection, a received TCP
    # connect failure, and the specific 4xx the API returns BEFORE actuation
    # (400 bad request/validation incl. V2-KC84 "lock not found", 404, 422).
    # Everything else — lost response, 5xx, 409/429, odd 4xx, malformed body,
    # missing job_id — is AMBIGUOUS: the server may have run the command.
    async def _post():
        async with session.post(f"{API_BASE}/v2/cu/locks/{lock_id}/{verb}",
                                headers=_auth_headers(token)) as r:
            st = r.status
            if st in (401, 403):
                raise QrioAuthError(f"{verb} auth ({st})")
            if st in (400, 404, 422):
                raise QrioNotSubmitted(f"{verb} rejected ({st}{await _safe_error(r)})")
            if st >= 400:
                raise QrioUncertainError(f"{verb} HTTP {st} — outcome unknown")
            return await r.json()

    try:
        j = await asyncio.wait_for(_post(), timeout=max(min(http_timeout, _remaining()), 0.1))
    except (QrioAuthError, QrioNotSubmitted, QrioUncertainError):
        raise                                            # already classified
    except asyncio.CancelledError:
        raise
    except asyncio.TimeoutError:
        raise QrioUncertainError(f"{verb} submit timed out — may have executed") from None
    except _CONNECT_FAILED as exc:                       # TCP connect failed = not sent
        raise QrioNotSubmitted(f"{verb} connect failed ({type(exc).__name__})") from None
    except Exception as exc:  # noqa: BLE001 — response lost; may have executed
        raise QrioUncertainError(
            f"{verb} submit failed ({type(exc).__name__}) — may have executed") from None

    # Validate the (post-submission) response shape; anything odd is uncertain.
    if not isinstance(j, dict):
        raise QrioUncertainError(f"{verb}: malformed response — outcome unknown")
    data = j.get("data")
    if not isinstance(data, dict):
        raise QrioUncertainError(f"{verb}: malformed data — outcome unknown")
    job = data.get("job_id") or data.get("id")
    if not isinstance(job, str) or not job:
        raise QrioUncertainError(f"{verb}: no usable job_id — outcome unknown")
    pi = data.get("polling_interval")
    interval = max(pi / 1000.0, 0.25) if isinstance(pi, (int, float)) and pi > 0 else 0.3

    # ---- poll (command IS submitted; anything but a clean success is UNCERTAIN) ----
    while True:
        if _remaining() <= 0:
            raise QrioUncertainError(f"{verb} not confirmed within {poll_timeout:.0f}s")
        await asyncio.sleep(min(interval, max(_remaining(), 0.0)))
        if _remaining() <= 0:
            raise QrioUncertainError(f"{verb} not confirmed within {poll_timeout:.0f}s")
        try:
            jj = await asyncio.wait_for(
                _get_json(session, f"/v2/cu/lock_jobs/{job}/{verb}", token, {}),
                timeout=max(min(http_timeout, _remaining()), 0.1))
        except QrioAuthError as exc:
            # Already submitted; we just can't read the result. Never re-POST.
            raise QrioUncertainError(f"{verb} submitted; auth lost during polling") from exc
        except asyncio.CancelledError:
            raise
        except (QrioCloudError, asyncio.TimeoutError):
            continue   # transient poll hiccup — keep trying until the deadline
        if not isinstance(jj, dict):
            continue
        d = jj.get("data")
        if not isinstance(d, dict):
            continue
        status = d.get("job_status") or d.get("status")
        if not isinstance(status, str):
            continue   # malformed/typed status -> keep polling until the deadline
        status = status.lower()
        if status in ("succeeded", "success", "done", "completed"):
            return {"ok": True, "status_code": _safe_code(d.get("status_code")),
                    "thumbturn_state": (d.get("attribute_data") or {}).get("thumbturn_state")}
        if status and status not in ("in_progress", "processing", "running",
                                     "queued", "pending", "waiting"):
            # Any terminal non-success (failed/error/timeout/unknown). We have NOT
            # verified that the bolt stayed put, so treat it as uncertain, not as a
            # safe "didn't move" that would allow cross-transport fallback.
            raise QrioUncertainError(
                f"{verb} job did not succeed ({_safe_code(d.get('status_code'))})")
        # otherwise still in progress — keep polling


async def _safe_error(resp) -> str:
    """A validated Qrio error code from a 4xx body, or '' — never raw content."""
    try:
        j = await resp.json()
        errs = j.get("errors") or []
        if errs and isinstance(errs, list):
            code = (errs[0] or {}).get("code")
            if code:
                return f" ({_safe_code(code)})"
    except Exception:  # noqa: BLE001
        pass
    return ""


async def fetch_lock_ed_pk(session: ClientSession, token: str, lock_id) -> str:
    """Fetch one lock's public key (to verify its signed BLE responses)."""
    pk = (await _get_json(session, "/v1/u/ed_pk", token, {"lock_id": lock_id})).get("ed_pk")
    if not pk:
        raise QrioCloudError(f"no lock ed_pk for lock {lock_id}")
    return pk

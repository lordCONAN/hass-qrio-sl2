"""Transport-dispatch safety logic (pure — no Home Assistant imports).

Kept free of HA so the fail-safe operate dispatcher can be unit-tested directly.
The one rule that matters for a physical lock:

    Fall back to another transport ONLY when the primary raised an exception that
    POSITIVELY establishes the command was never submitted. Every other failure —
    uncertain, malformed, or simply unexpected — is treated as "may have executed":
    verify the lock state, never issue a second command.
"""
from __future__ import annotations

import asyncio

from . import cloud as cloud_api


class BleNotSubmitted(Exception):
    """A local BLE command was not (even partially) transmitted — safe to retry/fall back."""


class BleUncertain(Exception):
    """A local BLE command may have been transmitted — do NOT resend."""


class OperateFailed(Exception):
    """All transports failed without the command being submitted."""


# The allowlist: exceptions that GUARANTEE the command was not submitted.
_NOT_SUBMITTED = (BleNotSubmitted, cloud_api.QrioNotSubmitted, cloud_api.QrioAuthError)


def is_not_submitted(exc: BaseException) -> bool:
    """True only for the explicit not-submitted allowlist (never for uncertain)."""
    if isinstance(exc, cloud_api.QrioUncertainError):
        return False
    return isinstance(exc, _NOT_SUBMITTED)


async def run_operate(order, *, resolve_uncertain, auth_exc_types=()):  # noqa: ANN001
    """Run operate across `order` = [(name, async_fn), ...] with fail-safe fallback.

    - not-submitted failure  -> try the next transport (fall back)
    - uncertain / unexpected -> await resolve_uncertain(name, exc); return name (NO resend)
    - cloud-only auth failure -> re-raised for the caller to start re-auth
    Returns the transport name that ran; raises OperateFailed if all transports
    were confirmed not-submitted, or re-raises an auth exception for cloud-only.
    """
    last: BaseException | None = None
    for i, (name, fn) in enumerate(order):
        is_last = i == len(order) - 1
        try:
            await fn()
            return name
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            if auth_exc_types and isinstance(exc, auth_exc_types):
                # Auth failure = we never got far enough to submit (safe).
                if name == "cloud" and len(order) == 1:
                    raise                     # cloud-only -> surface for re-auth
                last = exc
                if is_last:
                    raise OperateFailed(type(exc).__name__) from exc
                continue
            if is_not_submitted(exc):
                last = exc
                if is_last:
                    raise OperateFailed(type(exc).__name__) from exc
                continue                      # confirmed not submitted -> fall back
            # Uncertain OR any unexpected exception -> verify state, never resend.
            await resolve_uncertain(name, exc)
            return name
    raise OperateFailed(type(last).__name__ if last else "no_transport")

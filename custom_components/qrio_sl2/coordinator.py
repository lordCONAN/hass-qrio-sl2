"""Coordinator for one Qrio SL-2 lock: local BLE and/or cloud (hub) transport."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time

from nacl import signing

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from bleak.exc import BleakError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from . import cloud as cloud_api
from . import qrio_protocol as proto
from . import transport
from .transport import BleNotSubmitted, BleUncertain
from .const import (
    ACK_TIMEOUT,
    BLE_COMMAND_TIMEOUT,
    BLE_CONNECT_TIMEOUT,
    CH_CHAL,
    CH_CMD,
    CH_NOTIFY,
    CLOUD_HTTP_TIMEOUT,
    CLOUD_JOB_TIMEOUT,
    CONF_IDTOKEN,
    CONF_LOCK,
    CONF_OPERATE_TRANSPORT,
    CONF_REFRESH,
    CONF_SEED,
    CONF_STATUS_TRANSPORT,
    DEFAULT_OPERATE_TRANSPORT,
    DEFAULT_STATUS_TRANSPORT,
    DOMAIN,
    KEEPALIVE_IDLE,
    OP_LOCK,
    OP_STATUS,
    OP_UNLOCK,
    STATUS_INTERVAL,
    T_CLOUD,
    T_CLOUD_LOCAL,
    T_LOCAL,
    T_LOCAL_CLOUD,
)

_LOGGER = logging.getLogger(__name__)

# BLE outcome markers live in the pure transport module (so the fallback allowlist
# is testable without Home Assistant). Aliased here for readability.
_NotSubmitted = BleNotSubmitted
_Uncertain = BleUncertain


def _jwt_expiring(token: str | None, skew: float = 60.0) -> bool:
    """True if the JWT is missing, undecodable, or within `skew` s of expiry."""
    if not token:
        return True
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0)
        return (exp - time.time()) < skew
    except Exception:  # noqa: BLE001
        return True


class QrioLockCoordinator(DataUpdateCoordinator[dict]):
    """Owns the BLE link + crypto for a single lock; polls STATUS, runs lock/unlock.

    The BLE connection (and its notify subscription) is kept open and reused
    across commands/polls, then dropped after KEEPALIVE_IDLE of inactivity, so
    lock/unlock don't pay the connect+discovery cost every time.
    """

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self._entry = entry
        lock = entry.data[CONF_LOCK]
        self.lock_id = lock["lock_id"]
        self.lock_name = lock["lock_name"]
        self.address = (lock["bd_address"] or "").upper()
        self.serial_no = lock.get("serial_no")
        self.fw_version = lock.get("fw_version")
        self.has_hub = bool(lock.get("has_hub"))
        self._ekey = bytes.fromhex(lock["ekey_hex"])
        self._lock_ed_pk = bytes.fromhex(lock["lock_ed_pk_hex"])
        self._signing_key = signing.SigningKey(bytes.fromhex(entry.data[CONF_SEED]))
        self._ble_lock = asyncio.Lock()
        self.last_result: dict | None = None
        # cloud transport state (hub-equipped locks only)
        self._id_token = entry.data.get(CONF_IDTOKEN)
        self._refresh_token = entry.data.get(CONF_REFRESH)
        self._token_lock = asyncio.Lock()
        self.status_transport = entry.options.get(
            CONF_STATUS_TRANSPORT, DEFAULT_STATUS_TRANSPORT)
        self.operate_transport = entry.options.get(
            CONF_OPERATE_TRANSPORT, DEFAULT_OPERATE_TRANSPORT)
        # persistent connection + notify reassembly state
        self._client: BleakClientWithServiceCache | None = None
        self._notify_started = False
        self._parts: dict[int, bytes] = {}
        self._count: int | None = None
        self._response_fut: asyncio.Future[bytes] | None = None
        self._alive_evt: asyncio.Event | None = None
        self._idle_handle = None
        self._closing = False
        # passive advert tracking: trigger a refresh only when the lock's
        # "lastLog" event counter changes (i.e. it was actually operated)
        self._unsub_advert = None
        self._last_lastlog: int | None = None
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} {self.lock_name}",
            update_interval=STATUS_INTERVAL,
        )

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self.lock_id}"

    @callback
    def start_advert_tracking(self) -> None:
        """Passively watch the lock's adverts so we refresh only on real events."""
        self._unsub_advert = bluetooth.async_register_callback(
            self.hass,
            self._advert_seen,
            {"address": self.address, "connectable": False},
            bluetooth.BluetoothScanningMode.PASSIVE,
        )

    @callback
    def _advert_seen(self, service_info, change) -> None:
        info = proto.parse_advert(service_info.manufacturer_data.get(proto.MANUFACTURER_ID))
        if info is None:
            return
        if self.serial_no is not None and str(info["serial"]) != str(self.serial_no):
            return  # not our lock (shouldn't happen: matched by address)
        lastlog = info["lastlog"]
        if lastlog == self._last_lastlog:
            return
        first = self._last_lastlog is None
        self._last_lastlog = lastlog
        if not first:
            # The lock was operated (manual/keypad/app) — read exact state now.
            _LOGGER.debug("%s: lastLog -> %s; refreshing", self.lock_name, lastlog)
            self.hass.async_create_task(self.async_request_refresh())

    # ---- STATUS (read-only; fallback/retry across transports is safe) ----
    async def _local_status(self) -> dict:
        resp = await self._exchange(OP_STATUS, keep_open=False)
        st = proto.decode_status(resp)
        if not st:
            raise UpdateFailed(f"unexpected STATUS response: {resp.hex()}")
        st["status_source"] = "local"           # a full, fresh BLE reading
        st["ble_measured_at"] = dt_util.utcnow().isoformat()
        return st

    async def _cloud_status(self) -> dict:
        st = await self._cloud_call(
            lambda tok: cloud_api.cloud_status(self._session(), tok, self.lock_id))
        # Cloud status carries thumb-turn only. Merge over the last reading so we
        # don't ERASE previously known BLE diagnostics (battery/signal); they ride
        # along as last-known (tagged source=cloud and keeping the original
        # ble_measured_at), never presented as a fresh cloud measurement.
        merged = {**(self.data or {}), **st, "status_source": "cloud"}
        return merged

    async def _async_update_data(self) -> dict:
        mode = self.status_transport if self.has_hub else T_LOCAL

        async def local() -> dict:
            try:
                return await self._local_status()
            except (_NotSubmitted, _Uncertain, BleakError) as exc:
                raise UpdateFailed(f"status (local): {type(exc).__name__}") from exc

        if mode == T_LOCAL:
            return await local()
        if mode == T_CLOUD:
            try:
                return await self._cloud_status()   # ConfigEntryAuthFailed -> reauth
            except cloud_api.QrioCloudError as exc:
                raise UpdateFailed(f"status (cloud): {exc}") from exc
        primary, secondary = ((local, self._cloud_status) if mode == T_LOCAL_CLOUD
                              else (self._cloud_status, local))
        try:
            return await primary()
        except Exception as exc:  # noqa: BLE001 — read-only, so fall back on anything
            _LOGGER.debug("%s: status primary failed (%s); trying other transport",
                          self.lock_name, type(exc).__name__)
            try:
                return await secondary()
            except Exception as exc2:  # noqa: BLE001
                raise UpdateFailed(
                    f"status failed on both transports ({type(exc2).__name__})") from exc2

    # ---- OPERATE (physical; never blindly resend after an uncertain outcome) ----
    async def async_set_locked(self, want_locked: bool) -> None:
        opcode = OP_LOCK if want_locked else OP_UNLOCK
        opening = not want_locked
        verb = proto.VERB[opcode]

        async def local() -> None:
            resp = await self._exchange(opcode, keep_open=True)   # typed errors
            res = proto.decode_op_result(resp, self._lock_ed_pk)
            if not res or not res["sig_ok"]:
                # A response we can't verify -> the bolt may have moved: uncertain.
                raise _Uncertain(f"{verb}: unverified lock response")
            if not res["ok"]:
                # The lock explicitly refused -> it did NOT drive: safe failure.
                raise _NotSubmitted(f"{verb} rejected ({res['device_status']})")
            self.last_result = res

        async def cloud() -> None:
            await self._cloud_call(
                lambda tok: cloud_api.cloud_operate(
                    self._session(), tok, self.lock_id, opening,
                    CLOUD_JOB_TIMEOUT, CLOUD_HTTP_TIMEOUT))

        executed = await self._dispatch_operate(local, cloud, want_locked, verb)
        # Optimistic state, then confirm via the SAME transport that executed, so a
        # (e.g. down BLE proxy) local status failure can't hide a successful cloud op.
        data = dict(self.data or {})
        data["locked"] = want_locked
        self.async_set_updated_data(data)
        await self._confirm_after_operate(executed)

    async def _dispatch_operate(self, local, cloud, want_locked: bool, verb: str) -> str:
        """Run operate per mode via the fail-safe runner (fall back ONLY on an
        explicitly not-submitted failure; otherwise verify, never resend)."""
        mode = self.operate_transport if self.has_hub else T_LOCAL
        order = {
            T_LOCAL: [("local", local)],
            T_CLOUD: [("cloud", cloud)],
            T_LOCAL_CLOUD: [("local", local), ("cloud", cloud)],
            T_CLOUD_LOCAL: [("cloud", cloud), ("local", local)],
        }[mode]

        async def resolve(name: str, exc: BaseException) -> None:
            await self._resolve_uncertain(want_locked, verb, type(exc).__name__)

        try:
            return await transport.run_operate(
                order, resolve_uncertain=resolve, auth_exc_types=(ConfigEntryAuthFailed,))
        except ConfigEntryAuthFailed:
            raise                                 # cloud-only: surface for re-auth
        except transport.OperateFailed as exc:
            raise HomeAssistantError(f"Qrio {verb} failed: {exc}") from exc

    async def _resolve_uncertain(self, want_locked: bool, verb: str, detail: str) -> None:
        """An operation's outcome is unknown: verify state, NEVER resend."""
        _LOGGER.warning("%s: %s outcome uncertain (%s) — verifying, not resending",
                        self.lock_name, verb, detail)
        confirmed = await self._confirm_state(want_locked)
        if confirmed is True:
            return                                # the lock is in the desired state
        if confirmed is False:
            raise HomeAssistantError(
                f"Qrio {verb} did not take effect (lock is in the opposite state); "
                f"not resending.")
        raise HomeAssistantError(
            f"Qrio {verb} outcome is uncertain — not resending; check the lock.")

    async def _confirm_state(self, want_locked: bool) -> bool | None:
        """Read status across available transports -> tri-state:

        True  = at least one transport confirms the DESIRED state,
        False = every definite reading is the OPPOSITE state,
        None  = no definite reading (unknown). Never issues an operation.
        """
        saw_opposite = False
        for reader in self._status_readers():
            try:
                st = await reader()
            except Exception:  # noqa: BLE001
                continue
            locked = st.get("locked")
            if locked is None:
                continue
            if locked == want_locked:
                return True                       # confirmed; stop (success)
            saw_opposite = True                   # keep checking the other transport
        return False if saw_opposite else None

    def _status_readers(self):
        readers = []
        if self.has_hub and self._refresh_token:
            readers.append(self._cloud_status)
        readers.append(self._local_status)
        return readers

    async def _confirm_after_operate(self, executed: str) -> None:
        reader = (self._cloud_status if executed == "cloud"
                  and self.has_hub and self._refresh_token else self._local_status)
        try:
            st = await reader()
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("%s: post-%s confirm failed (%s); keeping optimistic state",
                          self.lock_name, executed, type(exc).__name__)
            return
        self.async_set_updated_data(st)

    # ---- cloud auth ----
    @callback
    def start_reauth(self) -> None:
        """Kick off HA's re-authentication flow for this entry (cloud creds dead)."""
        self._entry.async_start_reauth(self.hass)

    def _session(self):
        return async_get_clientsession(self.hass)

    async def _cloud_call(self, make_coro):
        """Run a cloud call; on an auth error, refresh the token once and retry.

        Safe for status and for the operate SUBMIT (a 401 there means the command
        was not accepted). cloud_operate reports a post-submission auth loss as
        QrioUncertainError, which is NOT retried here.
        """
        token = await self._cloud_token()
        try:
            return await make_coro(token)
        except cloud_api.QrioAuthError:
            # Refresh only if nobody else already rotated past `token`.
            token = await self._cloud_token(rejected=token)
            try:
                return await make_coro(token)
            except cloud_api.QrioAuthError as exc:
                raise ConfigEntryAuthFailed("Qrio cloud session rejected") from exc

    async def _cloud_token(self, rejected: str | None = None) -> str:
        """A valid id_token, refreshing (and persisting) it as needed.

        Requires a stored id_token AND refresh_token — Qrio's refresh needs a real
        id_token, so a missing one means re-authentication, not an empty refresh.
        `rejected` is the token a caller just got a 401 on: if another coroutine has
        since refreshed (current token differs), reuse that instead of refreshing.
        """
        async with self._token_lock:
            if not self._refresh_token or not self._id_token:
                raise ConfigEntryAuthFailed("Qrio cloud not set up — re-authenticate")
            if rejected is not None:
                if self._id_token != rejected:
                    return self._id_token       # someone already refreshed — reuse it
            elif not _jwt_expiring(self._id_token):
                return self._id_token           # re-checked inside the lock (no race)
            try:
                new_id, new_refresh = await cloud_api.refresh_session(
                    self._session(), self._id_token, self._refresh_token)
            except cloud_api.QrioAuthError as exc:
                raise ConfigEntryAuthFailed("Qrio cloud session expired") from exc
            self._id_token, self._refresh_token = new_id, new_refresh
            self.hass.config_entries.async_update_entry(
                self._entry, data={**self._entry.data,
                                   CONF_IDTOKEN: new_id, CONF_REFRESH: new_refresh})
            return new_id

    async def async_shutdown(self) -> None:
        """Stop advert tracking and drop the kept-open BLE link on unload/reload."""
        self._closing = True
        if self._unsub_advert is not None:
            self._unsub_advert()
            self._unsub_advert = None
        self._cancel_idle_timer()
        async with self._ble_lock:
            await self._teardown()
        await super().async_shutdown()

    # ---- BLE plumbing ----
    def _ble_device(self):
        dev = bluetooth.async_ble_device_from_address(self.hass, self.address, connectable=True)
        if dev is None:
            raise UpdateFailed(
                f"{self.lock_name} ({self.address}) not reachable via any adapter/proxy")
        return dev

    def _on_notify(self, _char, data: bytearray) -> None:
        data = bytes(data)
        if not data:
            return
        if self._alive_evt is not None and not self._alive_evt.is_set():
            self._alive_evt.set()         # any notify proves the link is alive
        pfx, body = data[0], data[1:]
        if pfx & 0x80:                       # first chunk: low 6 bits = total count
            self._parts = {0: body}
            self._count = pfx & 0x3F
        else:                                # middle (idx) or last (0x40|idx)
            self._parts[pfx & 0x3F] = body
        n = self._count
        if n is not None and len(self._parts) == n and all(i in self._parts for i in range(n)):
            msg = b"".join(self._parts[i] for i in range(n))
            self._parts = {}
            self._count = None
            fut = self._response_fut
            # the ack is short (<64 B, status 113); keep the real signed response
            if fut is not None and not fut.done() and (len(msg) >= 64 or msg[:1] == b"\x61"):
                fut.set_result(msg)

    def _on_disconnect(self, _client) -> None:
        """Lock/proxy dropped the link — forget the client so we reconnect next time."""
        self._client = None
        self._notify_started = False
        fut = self._response_fut
        if fut is not None and not fut.done():
            fut.set_exception(BleakError("disconnected mid-exchange"))

    async def _ensure_connected(self) -> BleakClientWithServiceCache:
        if self._client is not None and self._client.is_connected:
            return self._client
        self._client = None
        self._notify_started = False
        device = self._ble_device()
        client: BleakClientWithServiceCache = await establish_connection(
            BleakClientWithServiceCache, device, self.lock_name,
            disconnected_callback=self._on_disconnect,
            max_attempts=3, timeout=BLE_CONNECT_TIMEOUT)
        await client.start_notify(CH_NOTIFY, self._on_notify)
        self._client = client
        self._notify_started = True
        return client

    async def _teardown(self) -> None:
        # Must NEVER raise: a cleanup error after a command was sent could otherwise
        # mask an uncertain outcome or be mistaken for a not-submitted failure and
        # trigger an unsafe fallback. Swallow everything (except cancellation).
        client, self._client = self._client, None
        was_notifying, self._notify_started = self._notify_started, False
        if client is None:
            return
        try:
            if was_notifying and client.is_connected:
                await client.stop_notify(CH_NOTIFY)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            pass
        try:
            await client.disconnect()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            pass

    def _cancel_idle_timer(self) -> None:
        if self._idle_handle is not None:
            self._idle_handle.cancel()
            self._idle_handle = None

    def _schedule_idle_disconnect(self) -> None:
        self._cancel_idle_timer()
        if self._closing:
            return
        self._idle_handle = self.hass.loop.call_later(
            KEEPALIVE_IDLE,
            lambda: self.hass.async_create_task(self._idle_disconnect()),
        )

    async def _idle_disconnect(self) -> None:
        async with self._ble_lock:
            self._idle_handle = None
            await self._teardown()

    async def _exchange(self, opcode: int, keep_open: bool = False) -> bytes:
        """Challenge→command→response. Serialized per lock.

        The lock allows only one connection, so we release it right after unless
        keep_open is set (a lock/unlock, whose paired status refresh then reuses
        and releases the link). A reused connection can be stale (the lock dropped
        us without our callback firing); if it fails, tear it down and reconnect
        once — only a failure on a freshly established link is reported.
        """
        async with self._ble_lock:
            self._cancel_idle_timer()
            reused = self._client is not None and self._client.is_connected
            try:
                result = await self._run_once(opcode)
            except _Uncertain:
                # Command was sent and acked; its result is unknown. NEVER re-run
                # (that could drive the bolt a second time) — surface uncertainty.
                await self._teardown()
                raise
            except Exception as first_exc:  # noqa: BLE001 — not submitted: safe to retry
                await self._teardown()
                if not reused:
                    raise
                _LOGGER.debug("%s: reused BLE link failed (%s); reconnecting",
                              self.lock_name, type(first_exc).__name__)
                try:
                    result = await self._run_once(opcode)
                except Exception:
                    await self._teardown()
                    raise
            if keep_open:
                self._schedule_idle_disconnect()
            else:
                await self._teardown()
            return result

    async def _run_once(self, opcode: int) -> bytes:
        verb = proto.VERB[opcode]
        # `wrote` flips true the instant we may have put command bytes on air. After
        # that, ANY failure is uncertain (the lock may have received+acted); before
        # it (connect / challenge read), a failure is reliably "not submitted".
        wrote = False
        self._parts = {}
        self._count = None
        fut: asyncio.Future[bytes] = self.hass.loop.create_future()
        alive = asyncio.Event()
        self._response_fut = fut
        self._alive_evt = alive
        try:
            client = await self._ensure_connected()
            chal = proto.Challenge.parse(await client.read_gatt_char(CH_CHAL))
            prover = os.urandom(16)
            frame = proto.build_frame(self._ekey, self._signing_key, opcode, chal, prover)
            for c in proto.chunk(frame):
                wrote = True                      # a write is about to / may hit the air
                await client.write_gatt_char(CH_CMD, c, response=False)
            # Phase 1: the quick ack is the lock's proof of RECEIPT. No ack means we
            # can't confirm receipt — and bytes were already sent — so: UNCERTAIN.
            try:
                await asyncio.wait_for(alive.wait(), timeout=ACK_TIMEOUT)
            except asyncio.TimeoutError as exc:
                raise _Uncertain(f"no ack to {verb} after sending") from exc
            # Phase 2: acked and acting; a lost signed response => bolt may have moved.
            try:
                return await asyncio.wait_for(fut, timeout=BLE_COMMAND_TIMEOUT)
            except asyncio.TimeoutError as exc:
                raise _Uncertain(f"no response to {verb} after ack") from exc
        except (_NotSubmitted, _Uncertain):
            raise
        except Exception as exc:  # noqa: BLE001 — connect/read/write BleakError, etc.
            if wrote:
                raise _Uncertain(f"{verb} BLE failure after send ({type(exc).__name__})") from exc
            raise _NotSubmitted(f"{verb} BLE failure before send ({type(exc).__name__})") from exc
        finally:
            self._response_fut = None
            self._alive_evt = None

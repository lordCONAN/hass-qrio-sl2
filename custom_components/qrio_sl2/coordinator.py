"""BLE coordinator for one Qrio SL-2 lock (via HA Bluetooth + ESPHome proxy)."""
from __future__ import annotations

import asyncio
import logging
import os

from nacl import signing

from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from bleak.exc import BleakError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from .const import (
    ACK_TIMEOUT,
    BLE_COMMAND_TIMEOUT,
    BLE_CONNECT_TIMEOUT,
    CH_CHAL,
    CH_CMD,
    CH_NOTIFY,
    DOMAIN,
    KEEPALIVE_IDLE,
    OP_LOCK,
    OP_STATUS,
    OP_UNLOCK,
    STATUS_INTERVAL,
)
from . import qrio_protocol as proto

_LOGGER = logging.getLogger(__name__)


class QrioLockCoordinator(DataUpdateCoordinator[dict]):
    """Owns the BLE link + crypto for a single lock; polls STATUS, runs lock/unlock.

    The BLE connection (and its notify subscription) is kept open and reused
    across commands/polls, then dropped after KEEPALIVE_IDLE of inactivity, so
    lock/unlock don't pay the connect+discovery cost every time.
    """

    def __init__(self, hass: HomeAssistant, entry_id: str, lock: dict, seed_hex: str) -> None:
        self.lock_id = lock["lock_id"]
        self.lock_name = lock["lock_name"]
        self.address = (lock["bd_address"] or "").upper()
        self.serial_no = lock.get("serial_no")
        self.fw_version = lock.get("fw_version")
        self._ekey = bytes.fromhex(lock["ekey_hex"])
        self._lock_ed_pk = bytes.fromhex(lock["lock_ed_pk_hex"])
        self._signing_key = signing.SigningKey(bytes.fromhex(seed_hex))
        self._ble_lock = asyncio.Lock()
        self.last_result: dict | None = None
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

    async def _async_update_data(self) -> dict:
        # Release the link right after a poll so the phone app isn't locked out.
        resp = await self._exchange(OP_STATUS, keep_open=False)
        st = proto.decode_status(resp)
        if not st:
            raise UpdateFailed(f"unexpected STATUS response: {resp.hex()}")
        return st

    async def async_set_locked(self, want_locked: bool) -> None:
        """Send LOCK or UNLOCK, verify the signed result, then refresh state."""
        opcode = OP_LOCK if want_locked else OP_UNLOCK
        # Hold the link briefly so the status refresh below can reuse it; that
        # refresh (keep_open=False) then releases it for the app.
        resp = await self._exchange(opcode, keep_open=True)
        res = proto.decode_op_result(resp, self._lock_ed_pk)
        if not res or not res["sig_ok"]:
            raise UpdateFailed(f"{proto.VERB[opcode]}: unverified lock response")
        if not res["ok"]:
            raise UpdateFailed(f"{proto.VERB[opcode]} rejected: {res['device_status']}")
        self.last_result = res
        # optimistic state for a snappy UI, then confirm with a STATUS read
        data = dict(self.data or {})
        data["locked"] = want_locked
        self.async_set_updated_data(data)
        await self.async_request_refresh()

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
        client, self._client = self._client, None
        was_notifying, self._notify_started = self._notify_started, False
        if client is None:
            return
        try:
            if was_notifying and client.is_connected:
                await client.stop_notify(CH_NOTIFY)
        except BleakError:
            pass
        try:
            await client.disconnect()
        except BleakError:
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
            except Exception as first_exc:  # noqa: BLE001
                await self._teardown()
                if not reused:
                    raise
                _LOGGER.debug("%s: reused BLE link failed (%s); reconnecting",
                              self.lock_name, first_exc)
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
        client = await self._ensure_connected()
        self._parts = {}
        self._count = None
        fut: asyncio.Future[bytes] = self.hass.loop.create_future()
        alive = asyncio.Event()
        self._response_fut = fut
        self._alive_evt = alive
        try:
            chal = proto.Challenge.parse(await client.read_gatt_char(CH_CHAL))
            prover = os.urandom(16)
            frame = proto.build_frame(self._ekey, self._signing_key, opcode, chal, prover)
            for c in proto.chunk(frame):
                await client.write_gatt_char(CH_CMD, c, response=False)
            # Phase 1: any notify (the quick ack) proves the link is alive. None
            # within ACK_TIMEOUT means the link is dead -> let the caller retry.
            try:
                await asyncio.wait_for(alive.wait(), timeout=ACK_TIMEOUT)
            except asyncio.TimeoutError as exc:
                raise UpdateFailed(f"no ack to {proto.VERB[opcode]} (stale link?)") from exc
            # Phase 2: wait for the real signed response (after the bolt drives).
            try:
                return await asyncio.wait_for(fut, timeout=BLE_COMMAND_TIMEOUT)
            except asyncio.TimeoutError as exc:
                raise UpdateFailed(f"no response to {proto.VERB[opcode]}") from exc
        finally:
            self._response_fut = None
            self._alive_evt = None

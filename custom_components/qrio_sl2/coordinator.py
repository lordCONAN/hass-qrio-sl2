"""BLE coordinator for one Qrio SL-2 lock (via HA Bluetooth + ESPHome proxy)."""
from __future__ import annotations

import asyncio
import logging
import os

from nacl import signing

from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from bleak.exc import BleakError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from .const import (
    BLE_CONNECT_TIMEOUT,
    CH_CHAL,
    CH_CMD,
    CH_NOTIFY,
    DOMAIN,
    OP_LOCK,
    OP_STATUS,
    OP_UNLOCK,
    STATUS_INTERVAL,
)
from . import qrio_protocol as proto

_LOGGER = logging.getLogger(__name__)


class QrioLockCoordinator(DataUpdateCoordinator[dict]):
    """Owns the BLE link + crypto for a single lock; polls STATUS, runs lock/unlock."""

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
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} {self.lock_name}",
            update_interval=STATUS_INTERVAL,
        )

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self.lock_id}"

    async def _async_update_data(self) -> dict:
        resp = await self._exchange(OP_STATUS)
        st = proto.decode_status(resp)
        if not st:
            raise UpdateFailed(f"unexpected STATUS response: {resp.hex()}")
        return st

    async def async_set_locked(self, want_locked: bool) -> None:
        """Send LOCK or UNLOCK, verify the signed result, then refresh state."""
        opcode = OP_LOCK if want_locked else OP_UNLOCK
        resp = await self._exchange(opcode)
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

    # ---- BLE plumbing ----
    def _ble_device(self):
        dev = bluetooth.async_ble_device_from_address(self.hass, self.address, connectable=True)
        if dev is None:
            raise UpdateFailed(
                f"{self.lock_name} ({self.address}) not reachable via any adapter/proxy")
        return dev

    async def _exchange(self, opcode: int) -> bytes:
        """One full connect→challenge→command→response round-trip. Serialized per lock."""
        async with self._ble_lock:
            device = self._ble_device()
            client: BleakClientWithServiceCache = await establish_connection(
                BleakClientWithServiceCache, device, self.lock_name,
                max_attempts=3, timeout=BLE_CONNECT_TIMEOUT)
            try:
                return await self._do_exchange(client, opcode)
            finally:
                try:
                    await client.disconnect()
                except BleakError:
                    pass

    async def _do_exchange(self, client: BleakClientWithServiceCache, opcode: int) -> bytes:
        parts: dict[int, bytes] = {}
        state = {"count": None}
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[bytes] = loop.create_future()

        def on_notify(_char, data: bytearray) -> None:
            data = bytes(data)
            if not data:
                return
            pfx, body = data[0], data[1:]
            if pfx & 0x80:                       # first chunk: low 6 bits = total count
                parts.clear()
                state["count"] = pfx & 0x3F
                parts[0] = body
            else:                                # middle (idx) or last (0x40|idx)
                parts[pfx & 0x3F] = body
            n = state["count"]
            if n is not None and len(parts) == n and all(i in parts for i in range(n)):
                msg = b"".join(parts[i] for i in range(n))
                parts.clear()
                state["count"] = None
                # the ack is short (<64 B, status 113); keep the real signed response
                if (len(msg) >= 64 or msg[:1] == b"\x61") and not fut.done():
                    fut.set_result(msg)

        await client.start_notify(CH_NOTIFY, on_notify)
        try:
            chal = proto.Challenge.parse(await client.read_gatt_char(CH_CHAL))
            prover = os.urandom(16)
            frame = proto.build_frame(self._ekey, self._signing_key, opcode, chal, prover)
            for c in proto.chunk(frame):
                await client.write_gatt_char(CH_CMD, c, response=False)
            try:
                return await asyncio.wait_for(fut, timeout=BLE_CONNECT_TIMEOUT)
            except asyncio.TimeoutError as exc:
                raise UpdateFailed(f"no response to {proto.VERB[opcode]}") from exc
        finally:
            try:
                await client.stop_notify(CH_NOTIFY)
            except BleakError:
                pass

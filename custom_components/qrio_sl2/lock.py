"""Lock entity for the Qrio SL-2."""
from __future__ import annotations

from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import UpdateFailed

from .const import DOMAIN
from .coordinator import QrioLockCoordinator
from .entity import QrioEntity


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinators: list[QrioLockCoordinator] = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(QrioLock(c) for c in coordinators)


class QrioLock(QrioEntity, LockEntity):
    """A Qrio deadbolt. Locking/unlocking happens over local BLE only."""

    _attr_name = None  # the device name is the lock name

    def __init__(self, coordinator: QrioLockCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.unique_id}_lock"

    @property
    def is_locked(self) -> bool | None:
        data = self.coordinator.data
        return data.get("locked") if data else None

    async def async_lock(self, **kwargs) -> None:
        await self._operate(True)

    async def async_unlock(self, **kwargs) -> None:
        await self._operate(False)

    async def _operate(self, want_locked: bool) -> None:
        verb = "lock" if want_locked else "unlock"
        self._attr_is_locking = want_locked
        self._attr_is_unlocking = not want_locked
        self.async_write_ha_state()
        try:
            await self.coordinator.async_set_locked(want_locked)
        except UpdateFailed as exc:
            raise HomeAssistantError(f"Qrio {verb} failed: {exc}") from exc
        finally:
            self._attr_is_locking = False
            self._attr_is_unlocking = False
            self.async_write_ha_state()

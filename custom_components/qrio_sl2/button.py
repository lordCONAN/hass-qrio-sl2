"""Button to refresh the Qrio SL-2's battery on demand (one local BLE read)."""
from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import QrioLockCoordinator
from .entity import QrioEntity


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinators: list[QrioLockCoordinator] = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(QrioRefreshBatteryButton(c) for c in coordinators)


class QrioRefreshBatteryButton(QrioEntity, ButtonEntity):
    """Press to read battery/signal once over local BLE (cached until next press)."""

    _attr_translation_key = "refresh_battery"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:battery-sync"

    def __init__(self, coordinator: QrioLockCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.unique_id}_refresh_battery"

    @property
    def available(self) -> bool:
        # The button is usable even before the first successful read.
        return True

    async def async_press(self) -> None:
        await self.coordinator.async_read_battery_now(raise_on_error=True)

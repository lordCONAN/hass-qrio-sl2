"""Diagnostic sensors for the Qrio SL-2 (battery state, thumb-turn, signal)."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import SIGNAL_STRENGTH_DECIBELS_MILLIWATT, EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import QrioLockCoordinator
from .entity import QrioEntity


@dataclass(frozen=True, kw_only=True)
class QrioSensorDescription(SensorEntityDescription):
    value: Callable[[dict], object]


SENSORS: tuple[QrioSensorDescription, ...] = (
    QrioSensorDescription(
        key="thumb_turn",
        translation_key="thumb_turn",
        icon="mdi:rotate-right",
        device_class=SensorDeviceClass.ENUM,
        options=["locked", "unlocked", "unknown"],
        value=lambda d: d.get("thumb_turn"),
    ),
    QrioSensorDescription(
        key="battery_a",
        translation_key="battery_a",
        entity_category=EntityCategory.DIAGNOSTIC,
        icon="mdi:battery",
        value=lambda d: d.get("battery_a"),
    ),
    QrioSensorDescription(
        key="battery_b",
        translation_key="battery_b",
        entity_category=EntityCategory.DIAGNOSTIC,
        icon="mdi:battery",
        value=lambda d: d.get("battery_b"),
    ),
    QrioSensorDescription(
        key="active_battery",
        translation_key="active_battery",
        entity_category=EntityCategory.DIAGNOSTIC,
        icon="mdi:battery-sync",
        value=lambda d: d.get("active_battery"),
    ),
    QrioSensorDescription(
        key="signal_power",
        translation_key="signal_power",
        entity_category=EntityCategory.DIAGNOSTIC,
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        entity_registry_enabled_default=False,
        value=lambda d: d.get("ibeacon_signal_power_dbm"),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinators: list[QrioLockCoordinator] = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        QrioSensor(c, desc) for c in coordinators for desc in SENSORS
    )


class QrioSensor(QrioEntity, SensorEntity):
    entity_description: QrioSensorDescription

    def __init__(self, coordinator: QrioLockCoordinator, desc: QrioSensorDescription) -> None:
        super().__init__(coordinator)
        self.entity_description = desc
        self._attr_unique_id = f"{coordinator.unique_id}_{desc.key}"

    @property
    def native_value(self):
        data = self.coordinator.data
        return self.entity_description.value(data) if data else None

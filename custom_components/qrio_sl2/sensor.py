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

from . import qrio_protocol as proto
from .const import DOMAIN
from .coordinator import QrioLockCoordinator
from .entity import QrioEntity


@dataclass(frozen=True, kw_only=True)
class QrioSensorDescription(SensorEntityDescription):
    value: Callable[[dict], object]
    ble_only: bool = False   # value comes only from a fresh BLE read (cloud can't refresh it)


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
        key="battery",
        translation_key="battery",
        icon="mdi:battery",
        device_class=SensorDeviceClass.ENUM,
        options=["good", "low", "replace", "empty", "unknown"],
        ble_only=True,
        value=lambda d: proto.battery_overall(d.get("battery_a"), d.get("battery_b")),
    ),
    QrioSensorDescription(
        key="battery_a",
        translation_key="battery_a",
        entity_category=EntityCategory.DIAGNOSTIC,
        icon="mdi:battery",
        device_class=SensorDeviceClass.ENUM,
        options=["good", "low", "empty", "unknown"],
        ble_only=True,
        value=lambda d: proto.battery_slot_level(d.get("battery_a")),
    ),
    QrioSensorDescription(
        key="battery_b",
        translation_key="battery_b",
        entity_category=EntityCategory.DIAGNOSTIC,
        icon="mdi:battery",
        device_class=SensorDeviceClass.ENUM,
        options=["good", "low", "empty", "unknown"],
        ble_only=True,
        value=lambda d: proto.battery_slot_level(d.get("battery_b")),
    ),
    QrioSensorDescription(
        key="active_battery",
        translation_key="active_battery",
        entity_category=EntityCategory.DIAGNOSTIC,
        icon="mdi:battery-sync",
        ble_only=True,
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
        ble_only=True,
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

    @property
    def extra_state_attributes(self):
        # For BLE-only diagnostics, make it explicit when the shown value is a
        # cached last-known reading (status came via cloud, which can't refresh it).
        data = self.coordinator.data
        if not data or not self.entity_description.ble_only:
            return None
        source = data.get("status_source")
        measured = data.get("ble_measured_at")
        attrs = {"last_measured": measured}
        if source == "cloud":
            attrs["reading"] = "cached"          # value is last-known BLE, not fresh
        elif source == "local":
            attrs["reading"] = "fresh"
        return attrs

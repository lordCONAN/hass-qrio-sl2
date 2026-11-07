"""Shared entity base: device registry + availability for a Qrio lock."""
from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import QrioLockCoordinator


class QrioEntity(CoordinatorEntity[QrioLockCoordinator]):
    """Base entity bound to one lock's coordinator."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: QrioLockCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, str(coordinator.lock_id))},
            name=coordinator.lock_name,
            manufacturer="Qrio",
            model="Smart Lock SL-2 (Q-SL2)",
            sw_version=coordinator.fw_version,
            connections={("bluetooth", coordinator.address)} if coordinator.address else set(),
        )

    @property
    def available(self) -> bool:
        return self.coordinator.last_update_success

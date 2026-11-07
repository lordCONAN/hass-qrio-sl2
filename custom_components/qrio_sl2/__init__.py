"""Qrio Smart Lock SL-2 (local BLE) integration."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_LOCK, CONF_SEED, DOMAIN, PLATFORMS
from .coordinator import QrioLockCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up the one lock this entry represents."""
    coordinator = QrioLockCoordinator(
        hass, entry.entry_id, entry.data[CONF_LOCK], entry.data[CONF_SEED]
    )
    # Prime it; async_refresh never raises, so a lock that is temporarily out of
    # range just stays unavailable until its first successful poll.
    await coordinator.async_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = [coordinator]
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        for coordinator in hass.data[DOMAIN].pop(entry.entry_id, []):
            await coordinator.async_shutdown()
    return unloaded

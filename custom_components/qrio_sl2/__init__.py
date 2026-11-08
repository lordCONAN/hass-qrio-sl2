"""Qrio Smart Lock SL-2 integration (local BLE, with optional cloud via a hub)."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    CONF_OPERATE_TRANSPORT,
    CONF_STATUS_TRANSPORT,
    DEFAULT_OPERATE_TRANSPORT,
    DEFAULT_STATUS_TRANSPORT,
    DOMAIN,
    PLATFORMS,
)
from .coordinator import QrioLockCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up the one lock this entry represents."""
    coordinator = QrioLockCoordinator(hass, entry)
    # Start passive advert tracking before priming, so an event-counter change
    # triggers a refresh even while we're between (now-infrequent) polls.
    coordinator.start_advert_tracking()
    # Prime it; async_refresh never raises, so a lock that is temporarily out of
    # range just stays unavailable until its first successful poll.
    await coordinator.async_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = [coordinator]
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    # Reload when the transport options change so the new modes take effect.
    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))
    return True


async def _async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload only when the transport OPTIONS changed.

    Token persistence updates entry.data (not options) and would otherwise reload
    the integration mid-operation — skip those.
    """
    coordinators = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if coordinators:
        c = coordinators[0]
        same = (
            entry.options.get(CONF_STATUS_TRANSPORT, DEFAULT_STATUS_TRANSPORT)
            == c.status_transport
            and entry.options.get(CONF_OPERATE_TRANSPORT, DEFAULT_OPERATE_TRANSPORT)
            == c.operate_transport
        )
        if same:
            return
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        for coordinator in hass.data[DOMAIN].pop(entry.entry_id, []):
            await coordinator.async_shutdown()
    return unloaded

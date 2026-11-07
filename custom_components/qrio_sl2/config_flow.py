"""Config flow: sign in to Qrio, then choose ONE lock to add (one entry per lock)."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .cloud import QrioAuthError, QrioCloudError, fetch_lock_ed_pk, fetch_locks
from .const import (
    CONF_EMAIL,
    CONF_LOCK,
    CONF_REFRESH,
    CONF_SEED,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

USER_SCHEMA = vol.Schema({vol.Required(CONF_EMAIL): str, vol.Required(CONF_PASSWORD): str})


class QrioConfigFlow(ConfigFlow, domain=DOMAIN):
    """Each run adds exactly one lock, chosen from the account's locks."""

    VERSION = 1

    def __init__(self) -> None:
        self._enr: dict | None = None
        self._reauth_entry: ConfigEntry | None = None

    async def async_step_bluetooth(self, discovery_info) -> ConfigFlowResult:
        """A Qrio lock advertised nearby — still need account credentials to add it."""
        return await self.async_step_user()

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            email = user_input[CONF_EMAIL].strip()
            # Reuse an already-configured account's key so we don't mint a new one
            # per lock (the ekey set already covers every lock on the account).
            seed = next((e.data.get(CONF_SEED) for e in self._async_current_entries()
                         if e.data.get(CONF_EMAIL) == email), None)
            enr, err = await self._fetch(email, user_input[CONF_PASSWORD], seed)
            if err:
                errors["base"] = err
            else:
                self._enr = enr
                return await self.async_step_select_lock()
        return self.async_show_form(step_id="user", data_schema=USER_SCHEMA, errors=errors)

    async def async_step_select_lock(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pick one lock. Locks already set up are filtered out."""
        assert self._enr is not None
        configured = {e.unique_id for e in self._async_current_entries()}
        choices = {
            str(l["lock_id"]): l["lock_name"]
            for l in self._enr["locks"]
            if str(l["lock_id"]) not in configured
        }
        if not choices:
            return self.async_abort(reason="all_configured")

        errors: dict[str, str] = {}
        if user_input is not None:
            chosen = user_input[CONF_LOCK]
            lock = next(l for l in self._enr["locks"] if str(l["lock_id"]) == chosen)
            session = async_get_clientsession(self.hass)
            try:
                lock = {**lock,
                        "lock_ed_pk_hex": await fetch_lock_ed_pk(
                            session, self._enr["token"], lock["lock_id"])}
            except QrioCloudError:
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(str(lock["lock_id"]))
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=lock["lock_name"],
                    data={
                        CONF_EMAIL: self._enr["email"],
                        CONF_SEED: self._enr["client_seed_hex"],
                        CONF_REFRESH: self._enr["refresh_token"],
                        CONF_LOCK: lock,
                    },
                )
        return self.async_show_form(
            step_id="select_lock",
            data_schema=vol.Schema({vol.Required(CONF_LOCK): vol.In(choices)}),
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        self._reauth_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        entry = self._reauth_entry
        assert entry is not None
        email = entry.data[CONF_EMAIL]
        lock_id = str(entry.data[CONF_LOCK]["lock_id"])
        if user_input is not None:
            enr, err = await self._fetch(email, user_input[CONF_PASSWORD],
                                         seed=entry.data[CONF_SEED])
            if err:
                errors["base"] = err
            else:
                fresh = next((l for l in enr["locks"] if str(l["lock_id"]) == lock_id), None)
                if fresh is None:
                    errors["base"] = "lock_gone"
                else:
                    session = async_get_clientsession(self.hass)
                    try:
                        fresh = {**fresh, "lock_ed_pk_hex":
                                 await fetch_lock_ed_pk(session, enr["token"], fresh["lock_id"])}
                    except QrioCloudError:
                        errors["base"] = "cannot_connect"
                    else:
                        self.hass.config_entries.async_update_entry(
                            entry,
                            data={**entry.data, CONF_SEED: enr["client_seed_hex"],
                                  CONF_REFRESH: enr["refresh_token"], CONF_LOCK: fresh},
                        )
                        await self.hass.config_entries.async_reload(entry.entry_id)
                        return self.async_abort(reason="reauth_successful")
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
            description_placeholders={"email": email},
            errors=errors,
        )

    async def _fetch(self, email: str, password: str, seed: str | None = None):
        session = async_get_clientsession(self.hass)
        try:
            return await fetch_locks(session, email, password, seed_hex=seed), None
        except QrioAuthError:
            return None, "invalid_auth"
        except QrioCloudError as exc:
            _LOGGER.warning("Qrio cloud error: %s", exc)
            return None, "cannot_connect"
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Unexpected error contacting Qrio")
            return None, "unknown"

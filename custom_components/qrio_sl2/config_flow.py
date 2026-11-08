"""Config flow: sign in to Qrio, then choose ONE lock to add (one entry per lock)."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .cloud import QrioAuthError, QrioCloudError, fetch_lock_ed_pk, fetch_locks
from .const import (
    CONF_EMAIL,
    CONF_IDTOKEN,
    CONF_LOCK,
    CONF_OPERATE_TRANSPORT,
    CONF_REFRESH,
    CONF_SEED,
    CONF_STATUS_TRANSPORT,
    DEFAULT_OPERATE_TRANSPORT,
    DEFAULT_STATUS_TRANSPORT,
    DOMAIN,
    T_CLOUD,
    T_CLOUD_LOCAL,
    T_LOCAL,
    T_LOCAL_CLOUD,
)

_LOGGER = logging.getLogger(__name__)

USER_SCHEMA = vol.Schema({vol.Required(CONF_EMAIL): str, vol.Required(CONF_PASSWORD): str})

# Human-readable labels for the transport dropdowns (vol.In stores the keys).
TRANSPORT_LABELS = {
    T_LOCAL: "Local (Bluetooth) only",
    T_CLOUD: "Cloud (hub) only",
    T_LOCAL_CLOUD: "Local first, cloud fallback",
    T_CLOUD_LOCAL: "Cloud first, local fallback",
}


def _build_entry_data(enr: dict, lock: dict) -> dict:
    """Entry data for a newly added lock.

    Cloud tokens are NOT stored at setup — the integration defaults to local-only,
    so no cloud session token is retained until the user explicitly enables a cloud
    transport (which re-authenticates via the options flow). `has_hub` is kept so
    the options flow knows cloud is available; it is not a secret.
    """
    return {
        CONF_EMAIL: enr["email"],
        CONF_SEED: enr["client_seed_hex"],
        CONF_LOCK: lock,
    }


def _cloud_enabled(options) -> bool:
    """True if either transport option is set to a cloud mode."""
    return (options.get(CONF_STATUS_TRANSPORT, DEFAULT_STATUS_TRANSPORT) != T_LOCAL
            or options.get(CONF_OPERATE_TRANSPORT, DEFAULT_OPERATE_TRANSPORT) != T_LOCAL)


class QrioConfigFlow(ConfigFlow, domain=DOMAIN):
    """Each run adds exactly one lock, chosen from the account's locks."""

    VERSION = 1

    def __init__(self) -> None:
        self._enr: dict | None = None
        self._reauth_entry: ConfigEntry | None = None

    async def async_step_bluetooth(self, discovery_info) -> ConfigFlowResult:
        """A Qrio lock advertised nearby — still need account credentials to add it."""
        address = discovery_info.address
        # Entries key on the cloud lock_id, but discovery keys on the BLE MAC, so
        # HA can't dedupe them itself. Match the advertised address against each
        # entry's stored bd_address and abort, else the "Discovered" card nags
        # forever for a lock that's already set up.
        for entry in self._async_current_entries():
            bd = (entry.data.get(CONF_LOCK) or {}).get("bd_address")
            if bd and bd.upper() == address.upper():
                return self.async_abort(reason="already_configured")
        # Dedupe repeated adverts of the same not-yet-added lock into one flow.
        await self.async_set_unique_id(address, raise_on_progress=False)
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
                    data=_build_entry_data(self._enr, lock),
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
                        new_data = {**entry.data, **_build_entry_data(enr, fresh)}
                        # Keep cloud tokens only if cloud is actually enabled AND the
                        # lock still has a hub; otherwise ensure none are retained.
                        if _cloud_enabled(entry.options) and fresh.get("has_hub"):
                            new_data[CONF_REFRESH] = enr["refresh_token"]
                            new_data[CONF_IDTOKEN] = enr["token"]
                        else:
                            new_data.pop(CONF_REFRESH, None)
                            new_data.pop(CONF_IDTOKEN, None)
                        self.hass.config_entries.async_update_entry(entry, data=new_data)
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

    @staticmethod
    @callback
    def async_get_options_flow(entry: ConfigEntry) -> OptionsFlow:
        return QrioOptionsFlow(entry)


class QrioOptionsFlow(OptionsFlow):
    """Choose local/cloud transport — only offered for a hub-equipped lock."""

    def __init__(self, entry: ConfigEntry) -> None:
        self._entry = entry
        self._pending: dict[str, Any] | None = None

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        # The form is always available (local-only is valid for any lock). Choosing
        # a cloud mode routes through async_step_cloud_auth, which authenticates,
        # confirms a hub exists (incl. for entries created before cloud support),
        # and stores the session token.
        if user_input is not None:
            both_local = (user_input[CONF_STATUS_TRANSPORT] == T_LOCAL
                          and user_input[CONF_OPERATE_TRANSPORT] == T_LOCAL)
            have_tokens = (bool(self._entry.data.get(CONF_REFRESH))
                           and bool(self._entry.data.get(CONF_IDTOKEN)))
            if both_local:
                # Cloud fully off -> purge any stored cloud tokens.
                if have_tokens:
                    self.hass.config_entries.async_update_entry(
                        self._entry,
                        data={k: v for k, v in self._entry.data.items()
                              if k not in (CONF_REFRESH, CONF_IDTOKEN)},
                    )
                return self.async_create_entry(title="", data=user_input)
            # A cloud mode is selected. If the tokens were purged earlier, collect
            # the password and re-mint them before saving (so cloud actually works
            # instead of silently falling back).
            if not have_tokens:
                self._pending = user_input
                return await self.async_step_cloud_auth()
            return self.async_create_entry(title="", data=user_input)
        opts = self._entry.options
        schema = vol.Schema({
            vol.Required(
                CONF_STATUS_TRANSPORT,
                default=opts.get(CONF_STATUS_TRANSPORT, DEFAULT_STATUS_TRANSPORT),
            ): vol.In(TRANSPORT_LABELS),
            vol.Required(
                CONF_OPERATE_TRANSPORT,
                default=opts.get(CONF_OPERATE_TRANSPORT, DEFAULT_OPERATE_TRANSPORT),
            ): vol.In(TRANSPORT_LABELS),
        })
        return self.async_show_form(step_id="init", data_schema=schema)

    async def async_step_cloud_auth(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Re-mint cloud tokens (reusing the existing local key) to enable cloud."""
        errors: dict[str, str] = {}
        email = self._entry.data.get(CONF_EMAIL, "")
        lock_id = str((self._entry.data.get(CONF_LOCK) or {}).get("lock_id"))
        if user_input is not None:
            session = async_get_clientsession(self.hass)
            try:
                enr = await fetch_locks(session, email, user_input[CONF_PASSWORD],
                                        seed_hex=self._entry.data.get(CONF_SEED))
            except QrioAuthError:
                errors["base"] = "invalid_auth"
            except QrioCloudError:
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Qrio options: cloud re-auth failed")
                errors["base"] = "unknown"
            else:
                fresh = next((l for l in enr["locks"]
                              if str(l["lock_id"]) == lock_id), None)
                if not fresh or not fresh.get("has_hub"):
                    errors["base"] = "no_hub"
                elif not enr.get("refresh_token") or not enr.get("token"):
                    # Shouldn't happen, but never enable cloud with empty tokens.
                    errors["base"] = "cannot_connect"
                else:
                    # Keep the existing local key material; just (re)store tokens.
                    new_lock = {**(self._entry.data.get(CONF_LOCK) or {}),
                                "has_hub": True, "hub_id": fresh.get("hub_id")}
                    self.hass.config_entries.async_update_entry(
                        self._entry,
                        data={**self._entry.data,
                              CONF_REFRESH: enr["refresh_token"],
                              CONF_IDTOKEN: enr["token"],
                              CONF_LOCK: new_lock},
                    )
                    return self.async_create_entry(title="", data=self._pending)
        return self.async_show_form(
            step_id="cloud_auth",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
            description_placeholders={"email": email},
            errors=errors,
        )

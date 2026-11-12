"""Constants for the Qrio Smart Lock SL-2 (local BLE) integration."""
from __future__ import annotations

from datetime import timedelta

DOMAIN = "qrio_sl2"
PLATFORMS = ["lock", "sensor"]

# ----- Qrio King cloud API (used ONLY at setup/reauth to mint an ekey) -----
API_BASE = "https://sl2-api.qrioinc.com"
BASE_HEADERS = {
    "X-App-Version": "3.5.4",
    "X-Platform": "Android",
    "X-App-Name": "me.qrio.smartlock2",
    "User-Agent": "okhttp/4.12.0",
}

# ----- BLE GATT (operational service b88612e9) -----
SVC_UUID = "b88612e9-b3c1-45ee-aaf5-5e145e2d9831"
CH_CMD = "b88612ea-b3c1-45ee-aaf5-5e145e2d9831"      # write-without-response (command)
CH_NOTIFY = "b88612eb-b3c1-45ee-aaf5-5e145e2d9831"   # notify (responses)
CH_CHAL = "b88612ec-b3c1-45ee-aaf5-5e145e2d9831"     # read (challenge / currentTime+nonce)

# ----- Protocol opcodes (ul/f.java: Open=1, Close=2, ReadStatus=7) -----
OP_UNLOCK = 0x01
OP_LOCK = 0x02
OP_STATUS = 0x07
DEVICE_TYPE_CU = 0x01                                # jl/a.java CU (phone) = 1
FRAME_LEN = 247                                      # fixed, zero-padded

# ----- Config entry keys (one config entry == one lock) -----
CONF_EMAIL = "email"
CONF_SEED = "client_seed_hex"
CONF_LOCK = "lock"            # the single selected lock's dict
# Cloud auth tokens — stored ONLY for hub-equipped (cloud-capable) locks, so
# cloud operate/status can refresh the session unattended. Local-only locks
# store neither (keeps the 0.2.1 hardening). A warning is shown in options.
CONF_REFRESH = "refresh_token"
CONF_IDTOKEN = "id_token"
# Last-known BLE-only diagnostics (battery slots + active battery + timestamp),
# persisted so they survive a reload/restart and still show (as cached) when
# status runs over cloud, which can't read them. Slow-changing, so writes are
# rare; signal power is intentionally NOT persisted (fast-changing, optional).
CONF_BLE_SNAPSHOT = "ble_snapshot"
BLE_DIAG_KEYS = ("battery_a", "battery_b", "active_battery")
# per-lock dict keys
LK_ID = "lock_id"
LK_NAME = "lock_name"
LK_ADDR = "bd_address"
LK_EKEY = "ekey_hex"          # normalized to hex, 122 B
LK_EDPK = "lock_ed_pk_hex"
LK_SERIAL = "serial_no"
LK_FW = "fw_version"
LK_HAS_HUB = "has_hub"        # lock.lock_setting.hub present in /v1/u/all
LK_HUB_ID = "hub_id"

# ----- Transport options (per-entry, set in the options flow) -----
CONF_STATUS_TRANSPORT = "status_transport"
CONF_OPERATE_TRANSPORT = "operate_transport"
T_LOCAL = "local"             # local BLE only
T_CLOUD = "cloud"             # cloud (hub) only
T_LOCAL_CLOUD = "local_cloud"  # local first, cloud fallback
T_CLOUD_LOCAL = "cloud_local"  # cloud first, local fallback
TRANSPORTS = [T_LOCAL, T_CLOUD, T_LOCAL_CLOUD, T_CLOUD_LOCAL]
# Local-only by default: cloud is opt-in (consent) and avoids any cloud traffic
# / stored-token use until the user explicitly enables it in the options flow.
DEFAULT_STATUS_TRANSPORT = T_LOCAL
DEFAULT_OPERATE_TRANSPORT = T_LOCAL

# ----- Behaviour -----
# External lock events are now caught in near-real-time from BLE adverts (the
# "lastLog" counter), each triggering an on-demand STATUS read — no connection
# in between. This periodic poll is just a safety net (battery, missed adverts),
# so it can be infrequent, keeping the lock's single BLE slot free for the phone.
STATUS_INTERVAL = timedelta(minutes=30)
BLE_CONNECT_TIMEOUT = 30.0
# After writing a command, the lock first sends a quick notify ack, then the
# real response once it has (for lock/unlock) driven the bolt. No notify at all
# within ACK_TIMEOUT means the (possibly reused) link is dead -> reconnect once.
ACK_TIMEOUT = 5.0
BLE_COMMAND_TIMEOUT = 20.0                 # full wait for the real response
# Cloud operate: POST returns a job; poll it every polling_interval (ms) until
# job_status is terminal, capped at CLOUD_JOB_TIMEOUT (the app uses 60s).
CLOUD_JOB_TIMEOUT = 60.0
CLOUD_HTTP_TIMEOUT = 20.0
# The lock accepts only ONE BLE connection at a time, so holding it open blocks
# the Qrio phone app ("Connected to another device", error 114). We therefore
# release it as soon as we're done: status polls disconnect immediately, and a
# lock/unlock holds it only briefly (so the paired status refresh can reuse the
# link) before releasing. This is just a fallback idle timeout for that window.
KEEPALIVE_IDLE = 8.0
# When the lock advertises that it was just operated (lastLog changed), we no
# longer connect immediately to read status: connecting during the lock's post-
# unlock grace appears to collapse the ~4-min hands-free auto-lock window down to
# the short regular one. Instead we wait out the grace, then do one debounced
# read. 300s is safely past the ~255s (0xFF) failsafe window.
ADVERT_REFRESH_DELAY = 300.0

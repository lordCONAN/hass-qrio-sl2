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
CONF_REFRESH = "refresh_token"
CONF_LOCK = "lock"            # the single selected lock's dict
# per-lock dict keys
LK_ID = "lock_id"
LK_NAME = "lock_name"
LK_ADDR = "bd_address"
LK_EKEY = "ekey_hex"          # normalized to hex, 122 B
LK_EDPK = "lock_ed_pk_hex"
LK_SERIAL = "serial_no"
LK_FW = "fw_version"

# ----- Behaviour -----
STATUS_INTERVAL = timedelta(seconds=60)   # STATUS is read-only; safe to poll
BLE_CONNECT_TIMEOUT = 30.0

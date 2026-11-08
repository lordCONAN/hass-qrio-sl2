# Qrio Smart Lock SL-2 — Home Assistant integration

Control a **Qrio Smart Lock SL-2 (Q-SL2)** from Home Assistant. By default it runs
**local Bluetooth only** — lock, unlock and read status with **no Qrio cloud at
runtime** — through an **ESPHome Bluetooth proxy**, so the lock doesn't need to be
near your HA host. If you have a **Qrio Hub**, you can optionally enable **cloud
control** (Qrio cloud → your hub → lock) per-entry, and use it as a fallback.

Your Qrio password is used **once, at setup**, to mint a local Ed25519 key for your
account (the lock verifies *your* key over BLE); after that local lock/unlock/status
is a direct, signed BLE exchange and the password is never stored.

## Features

- `lock` entity per lock (one entry per lock) — lock / unlock
- Status: thumb-turn (locked / unlocked / **unknown**), battery A/B + overall level,
  active battery, advertised signal power. Near-real-time updates from BLE adverts.
- Local lock responses are **signature-verified** against the lock's own key
  (authentic, not spoofable)
- Account-level config flow (email + password) → mints a key for the chosen lock
- **Optional cloud control (Qrio Hub required)**: independently configurable
  transport for **status** and for **lock/unlock** — Local only / Cloud only /
  Local→Cloud fallback / Cloud→Local fallback. Opt-in (defaults to local only).
  Fallback never blindly resends after an uncertain outcome — it verifies state or
  reports the operation as uncertain.

## Requirements

- Home Assistant 2024.8+ with the **Bluetooth** integration, reachable to the lock
  via a built-in adapter or an **ESPHome BT proxy** near the door
- A Qrio account that already has the lock(s) registered

## Install (HACS / Marketplace custom repository)

1. In HACS (or the built-in **Marketplace**) → **⋮ → Custom repositories**, add this
   repository's URL with category **Integration**.
2. Install **“Qrio Smart Lock SL-2”**, then restart Home Assistant.
3. **Settings → Devices & services → + Add integration → Qrio**, enter your Qrio
   email and password, then pick the lock to add (one config entry per lock, with a
   lock entity + sensors). Runs local-only by default.
4. *(Optional, hub required)* Open the integration's **Configure** to enable cloud
   control for status and/or lock/unlock.

(For a quick test without HACS, copy `custom_components/qrio_sl2/` into your HA
`config/custom_components/` directory and restart.)

## How it works

| Phase | Network | What happens |
|------|---------|--------------|
| Setup / reauth | Qrio cloud (once) | `sign_in` → `/v1/u/all?ed_pk=…` mints a 122-byte ekey that embeds a freshly generated local key; `/v1/u/ed_pk` fetches the lock's public key; `lock_setting.hub` tells us if a hub is paired. |
| Runtime (local) | **Local BLE** | Read challenge (`12EC`) → build a 247-byte frame signed with the local key (`jl.b` body) → write chunked to `12EA` → verify/decode the notify on `12EB`. |
| Runtime (cloud, optional) | **Qrio cloud → hub → lock** | `POST /v2/cu/locks/{lock_id}/unlock\|lock` → poll `GET /v2/cu/lock_jobs/{job}/…`; status via `GET /v1/u/locks/{lock_id}/thumbturn_state`. No per-command signing (the hub does it). |

The password is **never stored** — only derived key material (seed + per-lock ekey
+ lock public key) is kept in the config entry. If an ekey is ever rejected, use
**Re-authenticate** to re-mint.

### Cloud control and token storage

Cloud control is **off by default** and only available for a lock that has a paired
**Qrio Hub**. Enable it per-lock in the integration's **Configure** (options) dialog,
choosing the transport for status and for lock/unlock independently.

When any cloud transport is enabled, a Qrio **refresh token** (and the current id
token) is stored in the Home Assistant config entry so the cloud session can be
kept alive without re-entering your password. **Security trade-off:** that token can
operate your lock via Qrio's cloud and lives in HA's `.storage` (protected by host
file permissions; HA has no per-integration encrypted secret store). It is stored
only for hub-equipped locks, and is **purged** if you set both transports back to
**Local only**. Local-only setups store no cloud token.

Cloud also tends to be faster than a cold BLE connect and keeps working if the BLE
proxy is down — but it depends on Qrio's servers and your hub, and uses an
unofficial API with your own credentials.

## Protocol notes

The signed command body is
`0x01 ‖ deviceType(CU) ‖ ekey(122) ‖ time(4 LE) ‖ verifierNonce(16) ‖ proverNonce(16) ‖ command`,
placed at `frame[2:…]` with a `u16‑LE` length prefix and zero-padded to 247 bytes;
the Ed25519 signature covers that body and is verified by the lock against the key
embedded at `ekey[58:90]`. Commands: `ReadStatus=07 01000000 00`,
`Open(unlock)=01 06000000 00 ff <time>`, `Close(lock)=02 04000000 <time>`. All of
this is byte/signature-confirmed against real HCI captures.

## Safety

Status reads never move the bolt. Lock/unlock are only triggered by HA `lock.lock`
/ `lock.unlock` calls. The integration reports the lock's own signed result,
including “already in position”, so entity state stays honest. An unknown thumb-turn
reading is reported as **unknown**, never silently as unlocked. When a lock/unlock
outcome is uncertain (e.g. an acknowledgement was lost), the integration **does not
resend** through another transport — it verifies the lock's state, and if it can't
confirm, reports the operation as uncertain rather than guessing.

## Credits

The Qrio SL-2 BLE protocol was reverse-engineered, and this integration written,
with **[Claude Code](https://claude.com/claude-code)** (Anthropic) — from decoding
the command framing and Ed25519 signing to the Home Assistant integration itself.

## Disclaimer

Unofficial, not affiliated with Qrio. Use at your own risk.

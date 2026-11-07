# Qrio Smart Lock SL-2 — local Home Assistant integration

Control a **Qrio Smart Lock SL-2 (Q-SL2)** from Home Assistant over **Bluetooth
only** — lock, unlock and read status with **no Qrio cloud or hub at runtime**.

Your Qrio password is used **once, at setup**, to mint a local Ed25519 key for your
account (the lock verifies *your* key over BLE); after that every lock/unlock/status
is a direct, signed BLE exchange. Works through an **ESPHome Bluetooth proxy**, so
the lock does not need to be near your HA host.

## Features

- `lock` entity per lock on your account (auto-discovered) — lock / unlock
- Status polling (read-only, every 60 s): thumb-turn (locked/unlocked), battery A/B,
  active battery, advertised signal power
- Lock responses are **signature-verified** against the lock's own key (authentic,
  not spoofable)
- Account-level config flow (email + password) → mints keys for **all** your locks

## Requirements

- Home Assistant 2024.8+ with the **Bluetooth** integration, reachable to the lock
  via a built-in adapter or an **ESPHome BT proxy** near the door
- A Qrio account that already has the lock(s) registered

## Install (HACS custom repository)

1. Push this repo to GitHub, then edit `custom_components/qrio_sl2/manifest.json`
   and replace the three `REPLACE_ME` placeholders (`documentation`,
   `issue_tracker`, `codeowners`) with your GitHub repo/handle.
2. In HACS → **⋮ → Custom repositories**, add the repo URL, category **Integration**.
3. Install **“Qrio Smart Lock SL-2 (local)”**, then restart Home Assistant.
4. **Settings → Devices & services → Add integration → Qrio**, enter your Qrio
   email and password. One device per lock appears with a lock entity + sensors.

(For a quick test without HACS, copy `custom_components/qrio_sl2/` into your HA
`config/custom_components/` directory and restart.)

## How it works

| Phase | Network | What happens |
|------|---------|--------------|
| Setup / reauth | Qrio cloud (once) | `sign_in` → `/v1/u/all?ed_pk=…` mints a 122-byte ekey that embeds a freshly generated local key; `/v1/u/ed_pk` fetches each lock's public key. |
| Runtime | **Local BLE only** | Read challenge (`12EC`) → build a 247-byte frame signed with the local key (`jl.b` body) → write chunked to `12EA` → verify/decode the notify on `12EB`. |

The password is not stored; only the derived key material (seed + per-lock ekey +
lock public key) is kept in the config entry. If an ekey is ever rejected, use
**Reconfigure / Re-authenticate** to re-mint.

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
including “already in position”, so entity state stays honest.

## Credits

The Qrio SL-2 BLE protocol was reverse-engineered, and this integration written,
with **[Claude Code](https://claude.com/claude-code)** (Anthropic) — from decoding
the command framing and Ed25519 signing to the Home Assistant integration itself.

## Disclaimer

Unofficial, not affiliated with Qrio. Use at your own risk.

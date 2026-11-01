# kestrel_5700_connect_library

A documented Bluetooth Low Energy interface for the **Kestrel 5700 Elite Ballistic**,
and a Python client that reads gun profiles, environment and the live firing
solution directly from the device.

## Status
- A PC (Windows, bleak) connects directly, with no pairing, mutually authenticates,
  and runs the encrypted command channel.
- Reads working: device identity, privacy status, settings, all gun profiles
  (decoded parameters, drag model, twist, record checksum), the environment
  record, the live solution for the gun selected on the device, and the Target
  Card of the sector selected on the device (10 targets).
- Not available over BLE as far as known: selecting a Target Card sector or
  reading sector names. Open items are listed in `docs/ICD.md` §11.

## Layout
- `docs/ICD.md` — the BLE Interface Control Document: GATT, framing, packets,
  encryption/auth, command catalogue with send policy, message layouts, NACK
  codes, behaviours. Written for humans and AI agents.
- `AGENTS.md` — rules for AI agents working in this repo.
- `tools/kestrel_proto.py` — framing, CRC, packets, AES-128 crypto.
- `tools/kestrel_client.py` — BLE client: connect → auth → verified reads.

## Setup
`python -m venv venv` then `venv/Scripts/python -m pip install -r requirements.txt`
(latest stable Python).

## Run
From `tools/`: `../venv/Scripts/python kestrel_client.py` prints the device
identity, every gun profile, the environment record, the live solution and the
Target Card of the sector selected on the device (switch sectors on the device), and
writes a full frame log under `private/captures/`. If the scan finds nothing
right after a previous run, run it again (ICD L1-6).

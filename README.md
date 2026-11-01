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
- Device mode (the Kestrel as central to a LiNK rangefinder) is documented in
  `docs/ICD.md` §13, including an implementer's guide (§13.5) for building a
  device that sends range, direction of fire and inclination and receives the
  Kestrel's solution.
- Not available over BLE as far as known: selecting a Target Card sector or
  reading sector names. Open items are listed in `docs/ICD.md` §11.

## Layout
- `docs/ICD.md` — the BLE Interface Control Document: GATT, framing, packets,
  encryption/auth, command catalogue with send policy, message layouts, NACK
  codes, behaviours. Written for humans and AI agents.
- `AGENTS.md` — rules for AI agents working in this repo.
- `tools/kestrel_proto.py` — framing, CRC, packets, AES-128 crypto.
- `tools/kestrel_client.py` — BLE client: connect → auth → verified reads.
- `tools/decode_full_solution.py` — offline decoder for `0x008a` full-solution
  records (ICD §7.9), e.g. from a Target Card read.

## Setup
`python -m venv venv` then `venv/Scripts/python -m pip install -r requirements.txt`
(latest stable Python).

## Run
From `tools/`: `../venv/Scripts/python kestrel_client.py` prints the device
identity, every gun profile, the environment record, the live solution and the
Target Card of the sector selected on the device (switch sectors on the device), and
writes a full frame log under `private/captures/`. If the scan finds nothing
right after a previous run, run it again (ICD L1-6).

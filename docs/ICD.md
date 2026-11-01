# Kestrel 5700 Elite — BLE Interface Control Document (ICD)

| Item | Value |
|---|---|
| Document | KESTREL-BLE-ICD |
| Revision | 1.5 (2026-11-01, NZDT) |
| Interface | Bluetooth Low Energy, Kestrel (peripheral) ↔ HOST (central) |
| Applies to | Model `5700AL`, firmware `1.57`, hardware `Rev 14` (one unit) |
| Reference implementation | `tools/kestrel_proto.py` (layers 1–3), `tools/kestrel_client.py` (layer 4) |

---

## 0. Reading guide (for humans and AI agents)

**Status tags.** Every fact carries one tag. Rely on VERIFIED; treat the rest as hypotheses.

| Tag | Meaning |
|---|---|
| `VERIFIED` | Observed live on the wire against the unit with the reference client. |
| `INFERRED` | Consistent with the command naming or with observed patterns, but not directly confirmed on the wire. |
| `USER` | Reported by the device owner from the device screen or use. |
| `UNKNOWN` | Seen on the wire, meaning not established. |

**Command policy.** Every opcode in §6 has a policy. Agents must follow it.

| Policy | Rule |
|---|---|
| `SAFE` | Read-only, verified live. May be sent freely. |
| `UNTESTED` | Looks read-only but has never been sent. Ask the owner before the first send. |
| `RESTRICTED` | Changes device state, or has unknown side effects. Send only with the owner's explicit approval for that action. |
| `FORBIDDEN` | Destructive, or firmware/bootloader. Never send. |

**Privacy rule.** Never write the unit's serial number, BLE address or privacy PIN into docs, code or commits. Use the placeholders `<SERIAL>`, `<BLE_ADDR>` and `<PIN>`. Real values stay in the owner's private notes. Don't record the owner's gun profiles either (names, bullets, parameter values); describe fields by layout only.

**Conventions.**
- All multi-byte integers are little-endian.
- `u8`/`u16`/`u32` are unsigned; `f32` is IEEE-754 binary32 LE.
- Offsets are 0-based and relative to the structure named in the table heading. `[a:b]` is the half-open byte range.
- Hex is lowercase. Opcodes are written as `0x00NN` (u16).

---

## 1. System overview

```
HOST (PC / phone)                             KESTREL 5700 Elite
 BLE central  ── GATT write 85920200 ──▶  LiNK command service (encrypted after auth)
              ◀── indicate 85920100 ───
              ◀── notify 0329xxxx ─────  live sensor stream (cleartext, no auth)
```

Layers on the LiNK channel, bottom up:
1. GATT (§2)
2. HDLC framing (§3)
3. Packets (§4)
4. Encryption and auth (§5)
5. Commands (§6, §7)

---

## 2. Layer 1 — BLE / GATT

| ID | Fact | Status |
|---|---|---|
| L1-1 | Advertised name `ELITE - <SERIAL>`. The advertisement carries service `03290000-…` and manufacturer data, company ID `0x00ea`, value `0a00ffff`. | VERIFIED |
| L1-2 | No pairing or bonding needed. A plain connection from Windows (bleak/WinRT) works. | VERIFIED |
| L1-3 | ATT MTU is 23. The host writes in ≤20-byte chunks with write-with-response. | VERIFIED |
| L1-4 | Kestrel→host data arrives as indications of exactly 20 bytes. Bytes after a frame's closing flag are `00` padding and must be ignored. | VERIFIED |
| L1-5 | Only one central at a time. While connected, the Kestrel stops advertising. | VERIFIED |
| L1-6 | Right after a disconnect, the next scan sometimes doesn't find the device (3 of 16 runs). An immediate retry works. Cause unknown. | VERIFIED (cause UNKNOWN) |

### 2.1 GATT table

| Service | Characteristic | Handle | Properties | Purpose | Status |
|---|---|---|---|---|---|
| `85920000-0338-4b83-ae4a-ac1d217adb03` LiNK | `8592ffff-…` | 2 | read | 204 B table of u16 values (`0500 0800 0b00 … 4b00`, then `ff` fill). Meaning UNKNOWN. | VERIFIED read |
| | `85920100-…` | 4 | read, indicate | **Kestrel→host** frames (CCCD handle 6) | VERIFIED |
| | `85920200-…` | 7 | write | **host→Kestrel** frames | VERIFIED |
| `1800` GAP | `2a00` device name | 10 | read | `ELITE - <SERIAL>` (NUL padded, 34 B) | VERIFIED |
| `180f` Battery | `2a19` | 15 | read | u8 percent | VERIFIED |
| `180a` Device info | `2a29` manufacturer | 18 | read | `Kestrel by NK` | VERIFIED |
| | `2a24` model | 20 | read, **write** | `5700AL`. Do not write. | VERIFIED |
| | `2a25` serial | 22 | read | `<SERIAL>` | VERIFIED |
| | `2a27` hardware rev | 24 | read | `Rev 14` | VERIFIED |
| | `2a26` firmware rev | 26 | read | `1.57` | VERIFIED |
| `03290000-eab4-dea1-b24e-44ec023874db` live stream | `03290200` | 31 | read | `0.09` (stream version?) | VERIFIED read |
| | `03290101`, `0105` | 33, 57 | read, write, notify | Control/config; write semantics UNKNOWN. Do not write. | VERIFIED read |
| | `03290102`, `0103`, `0106` | 36, 38, 69 | read, write | UNKNOWN. Do not write. | VERIFIED read |
| | `03290104` | 40 | read, write | 7 B, e.g. `0f1f0c0b06ea07`; looks like a clock (`…ea07` = 2026). Do not write. | INFERRED |
| | `03290107` | 71 | notify | UNKNOWN | VERIFIED |
| | `03290300`, `0310`, `0320`, `0330`, `0340`, `0350`, `0360`, `0370`, `0380` | 42–76 | read, notify | Sensor/solution stream; see §9 | see §9 |

---

## 3. Layer 2 — HDLC framing (LiNK channel)

| ID | Fact | Status |
|---|---|---|
| L2-1 | A frame is `7e` ‖ escaped(body ‖ crc16) ‖ `7e`. | VERIFIED |
| L2-2 | Escaping: any `7e` or `7d` inside is sent as `7d` followed by (byte XOR `0x20`). | VERIFIED |
| L2-3 | CRC-16/X.25: poly `0x1021` reflected (`0x8408`), init `0xffff`, xorout `0xffff`. Computed over the unescaped body and appended LE. | VERIFIED |
| L2-4 | A frame may span several indications. Parse as a byte stream: a `7e` opens a frame when outside one, closes it when inside one. Ignore `00` bytes outside a frame (L1-4). | VERIFIED |
| L2-5 | The body is either a cleartext packet (§4) or, after auth, `N×16` bytes of ciphertext (§5). Tell them apart by checking whether `u16 @2 == len(body) − 4`. | VERIFIED |

---

## 4. Layer 3 — Packets

Packet = `[u16 type][u16 len][payload: len bytes]`. Same format in both directions, and the same inside encryption.

| type | Name | Payload | Status |
|---|---|---|---|
| `0` | COMMAND | `[u16 opcode][args…]` | VERIFIED |
| `1`, `2` | (list form) | `len = 6 × n` entries. Defined, but never seen on the wire. | INFERRED |
| `3` | RESPONSE | Response data only; **no opcode** | VERIFIED |
| `4` | ACK | `[u16 opcode]` | VERIFIED |
| `5` | NACK | `[u16 opcode][u16 reason]` (§8) | VERIFIED |

Note: reading the header as `[u8 type][u8 flag][u16 len]` is wrong. The apparent "flag" is the high byte of the u16 type and is always `00`.

### 4.1 Exchange rules (stop-and-wait)

| ID | Rule | Status |
|---|---|---|
| X-1 | Either side can send a COMMAND. The receiver ACKs it (`type 4`, the same opcode) or NACKs it (`type 5`). | VERIFIED |
| X-2 | Data comes back as one or more RESPONSE packets. The host ACKs each RESPONSE with the **opcode of the command it answers** (the RESPONSE itself carries none). | VERIFIED |
| X-3 | Some replies arrive as a Kestrel-initiated COMMAND instead (e.g. `0x0091`, `0x00a1`). The host ACKs it with *that* COMMAND's opcode. | VERIFIED |
| X-4 | Multi-packet transfers end with the Kestrel sending COMMAND `0x0012` EOD (no args). The host ACKs it. | VERIFIED |
| X-5 | A NACK ends the transaction; no ACK of the NACK is sent. | VERIFIED |
| X-6 | The Kestrel can push unsolicited COMMANDs (e.g. `0x00a7`). The host should ACK them. A NACK with reason 3 for `0x00a7` is also accepted. | VERIFIED |
| X-7 | One transaction at a time. Wait for completion (§6 "Completes on") before sending the next command. | VERIFIED |

---

## 5. Layer 4 — Encryption and authentication

### 5.1 Constants

| Name | Value | Status |
|---|---|---|
| `KEY` (AES-128 link key) | `98e439ab2d999f58c1c58a7e66c7905d` | VERIFIED |
| `C0` (conventional first auth block) | `a7f1d92a82c8d8fe434d98558ce2b347` | VERIFIED |
| `P0 = AES-ECB-decrypt(KEY, C0)` | `ab61e698ab5ade1507dc351b5a8979a5` | VERIFIED |

### 5.2 Data-frame encryption (both directions, after auth)

| ID | Fact | Status |
|---|---|---|
| E-1 | body = AES-128-CBC(KEY, IV = 16×`00`, plaintext = `R16 ‖ packet ‖ 00-pad to a multiple of 16`), where `R16` is 16 random bytes. | VERIFIED |
| E-2 | Receiver: decrypt with IV = 0, drop the first 16 bytes, parse the packet, and ignore padding after `4 + len`. | VERIFIED |
| E-3 | ACKs and NACKs are encrypted as well. | VERIFIED |
| E-4 | No session key and no counter: every frame of every session uses the static `KEY`. | VERIFIED |

### 5.3 Authentication sequence (cleartext packets)

| Step | Dir | type | Payload | Notes |
|---|---|---|---|---|
| 1 | H→K | 0 | `8100` | GetPrivacyStatus (§7.3) |
| 2 | K→H | 4 | `8100` | |
| 3 | K→H | 3 | `[u8 privacy_status]` | `00` observed |
| 4 | H→K | 4 | `8100` | |
| 5 | H→K | 0 | `7e00 00` | RequestAuth, args `[00]` |
| 6 | K→H | 4 | `7e00` | |
| 7 | K→H | 0 | `7f00 ‖ nonceK[16]` | Kestrel challenge |
| 8 | H→K | 4 | `7f00` | |
| 9 | H→K | 3 | `AES-CBC(KEY, IV0, P0 ‖ nonceK) ‖ 00000000` (36 B) | Host proof. Its first ciphertext block equals `C0`. |
| 10 | K→H | 4 | `7f00` | Host accepted |
| 11 | K→H | 0 | `7e00 00` | Kestrel asks the host to challenge it |
| 12 | H→K | 4 | `7e00` | |
| 13 | H→K | 0 | `7f00 ‖ nonceH[16]` | Host challenge (random) |
| 14 | K→H | 4 | `7f00` | |
| 15 | K→H | 3 | `AES-CBC(KEY, IV0, Rk ‖ nonceH) ‖ 00000000` (36 B) | `Rk` is random. **Verify:** CBC-decrypt the first 32 B; bytes `[16:32]` must equal `nonceH`. |
| 16 | H→K | 4 | `7f00` | From here on, every frame in both directions is encrypted (§5.2) |

All steps VERIFIED (13 sessions; step 15 checked every time). Behaviour when auth fails: UNKNOWN.

### 5.4 Privacy PIN

`0x0082` PrivAuthenticate carries the unit PIN (`<PIN>`). With privacy status `00` it isn't needed: every SAFE read in §6 works without it. VERIFIED that it's not needed; the command itself is UNTESTED.

---

## 6. Layer 5 — Command catalogue

Command names follow the vendor's naming (INFERRED for commands not exercised). "Args" means the bytes after the u16 opcode.

### 6.1 SAFE (verified reads)

| Opcode | Name | Args | Reply | Completes on | Status |
|---|---|---|---|---|---|
| `0x0006` | GetExtDevSN | none | RESPONSE §7.1 | first RESPONSE | VERIFIED |
| `0x000a` | GetExtDevName | none | RESPONSE §7.2 | first RESPONSE | VERIFIED |
| `0x0081` | GetPrivacyStatus | none | RESPONSE §7.3 | first RESPONSE | VERIFIED (cleartext and encrypted) |
| `0x0084` | GetSettings | `[u8 kind]` | RESPONSE §7.4, then EOD | EOD | VERIFIED. `kind` 0/2/3 valid; 1/4/5 → NACK `0x0a`. |
| `0x0087` | GetGun | `[u16 slot]` | 3 × RESPONSE §7.5, then EOD | EOD | VERIFIED. Slots 0–10 on this unit; 11+ → NACK `0x0b`. **Side effect: selects the gun on the device** (B-1). Restore the original selection afterwards. |
| `0x0090` | GetEnvironment | none | COMMAND `0x0091` §7.6 | that COMMAND | VERIFIED |
| `0x0094` | GetActiveGunIndex | `[00][u16 0]` | RESPONSE §7.7 | first RESPONSE | VERIFIED. The slot selected on the device (B-2). |
| `0x00a0` | GetRemoteSoln | `[u8 type=0][u8 counter]` | COMMAND `0x00a1` §7.8, or NACK `0x0c` | that COMMAND | VERIFIED. `counter` is a free-running byte, echoed back. |
| `0x0093` | CalcFullSolution (Target Card pull) | exactly `[t][t][ff][00]`, t = 0…9 | COMMAND `0x008a` §7.9 | that COMMAND | VERIFIED: the vendor app's arguments; selected gun and a valid live solution unchanged across a full pull; records reproducible between pulls (§7.10). Any other arguments stay RESTRICTED (§6.4). |

### 6.2 Verified unsupported or unavailable on this unit (sending is harmless)

| Opcode | Name | Args sent | Result | Status |
|---|---|---|---|---|
| `0x0077` | GetSupUnits | none | NACK `0x03` | VERIFIED |
| `0x00a2` | GetCurScreen | none / `[00]` | NACK `0x03` | VERIFIED |
| `0x00ac` | GetSupportedUnits | none | NACK `0x03` | VERIFIED |
| `0x00ad` | GetUnits | none | NACK `0x03` | VERIFIED |
| `0x00cf` | GetWez | `[ff ff]` | NACK `0x0a` | VERIFIED |

### 6.3 Kestrel-initiated COMMANDs seen on the wire

| Opcode | Name | When | Host action | Status |
|---|---|---|---|---|
| `0x0012` | EOD | end of multi-packet replies | ACK | VERIFIED |
| `0x0091` | SetEnvironment | reply to `0x0090` | ACK | VERIFIED |
| `0x00a1` | SetRemoteSoln | reply to `0x00a0` | ACK | VERIFIED |
| `0x00a7` | SetTgtStatus | unsolicited | ACK (NACK reason 3 is also accepted) | VERIFIED |
| `0x008a` | SetFullSoln | reply to `0x0093`, and pushed after a host `0x0089` | ACK | VERIFIED |
| `0x007c`, `0x00a6` SetFullUnits, `0x0089` SetFullInputs, `0x0088` SetGun (+ RESPONSE parts, EOD) | — | burst after a non-zero `0x0092` (see §6.5) | ACK | VERIFIED once; payloads UNKNOWN |

### 6.4 UNTESTED / RESTRICTED / FORBIDDEN (not exercised, INFERRED)

"Args len" is the expected argument byte count.

| Opcode | Name | Args len | Policy | Why |
|---|---|---|---|---|
| `0x0093` | CalcFullSolution | 4: `[u8 targetNumber (0xff = current)][u8 solutionId][u8 doExtraCalcs 0–2][u8 setAsActiveTgt]` | RESTRICTED | Triggers device computation. Exercised once with owner approval, args `ff 00 00 00`: the Kestrel ACKed and pushed COMMAND `0x008a` (§7.9); the selected gun and the live solution were unchanged (VERIFIED). Other argument values UNTESTED. The vendor app's "Pull Targets from Kestrel" sends `[t][t][ff][00]` for t = 0…9 and gets one `0x008a` per target (VERIFIED, observed). |
| `0x0092` | StartStopStreaming | 9: `[u8 subsystem][u16 p][6 × u8]` | RESTRICTED | See §6.5 |
| `0x00a9` | KeepAlive | 0 | UNTESTED | |
| `0x00a8` | FreeToCommunicate | 2 | UNTESTED | |
| `0x0082` | PrivAuthenticate | 8 | UNTESTED | Needs `<PIN>`; not needed today |
| `0x0083` | StopEncrypting | — | RESTRICTED | Changes link security |
| `0x009d` | EnableNkPEX | 1 | RESTRICTED | |
| `0x005e` | AB (Applied Ballistics) family: Ack/Nack/Heartbeat/StartGunDump | sub-command | RESTRICTED | |
| `0x00a4` | SystemEvent | 2 | RESTRICTED | |
| `0x0095` | SetActiveGunIndex | 5 | RESTRICTED | Writes state |
| `0x0091` / `0x00a1` / `0x00a7` (host→K) | SetEnvironment / SetRemoteSoln / SetTgtStatus | var | RESTRICTED | Writes state |
| `0x0078`, `0x0079`, `0x007a`, `0x00a3`, `0x00a5`, `0x00a6`, `0x00ae`, `0x00d0` | SetUnits, SetSupTargets, SetBalInput, SetCurScreen, Set2700Wind, SetFullUnits, SetUnits(sys), SetWez | var | RESTRICTED | Writes state |
| `0x0088` (host→K) | SetGun | var | RESTRICTED | Overwrites profiles |
| `0x0089` (host→K) | SetFullInputs | 28 (§7.11) | RESTRICTED | Writes the current target's inputs (range, inclination, DoF); the device recalculates and pushes `0x008a`. Used by the vendor app's range/DoF controls (VERIFIED, observed). Not sent by this client. |
| `0x008a` (K→host) | SetFullSoln | 90 | — | Full solution record, reply to `0x0093` (§7.9) |
| `0x007a` | SetBalInput: range, DoF, inclination, latitude, WD, WS1, WS2, target speed/direction, do-extra-calcs | 17 | RESTRICTED | Writes the target inputs |
| `0x0086` | EraseGuns | 2 | **FORBIDDEN** | Deletes gun profiles |
| `0x00b5` | Reboot | 1 | **FORBIDDEN** | |
| `0x0035` / `0x0036` / `0x0037` | BG11x WriteFlash / ApplyUpdate / Erase | var | **FORBIDDEN** | Radio firmware flashing |
| bootloader / firmware-update commands (enter/query/exit bootloader, erase/apply flash) | — | — | **FORBIDDEN** | Main firmware flashing |

### 6.5 Note on `0x0092` StartStopStreaming

- `arg[0]` selects a subsystem (valid 0, 3, 4, 5); the meaning of the remaining bytes is UNKNOWN. INFERRED.
- All-zero args (`9200` + 9 × `00`) are the normal value, presumably "stop". INFERRED.
- One send with non-zero args (`00 e803 010101010101`) was ACKed. The Kestrel then pushed the §6.3 burst (units, target status, inputs, a full gun record) and a `0x0091`. VERIFIED once. No stop was sent afterwards; the link was simply closed.
- After this, the owner reported that the device did not recalculate a ballistic solution until the gun profile was changed on the device (USER). The cause is not established.
- **Do not send non-zero `0x0092` args until their semantics are established.**

---

## 7. Message definitions

### 7.1 MSG-0006-R — device serial (RESPONSE)
| Offset | Size | Type | Field | Status |
|---|---|---|---|---|
| 0 | len | ASCII, no terminator | serial `<SERIAL>` (7 digits observed) | VERIFIED |

### 7.2 MSG-000A-R — device name (RESPONSE)
| Offset | Size | Type | Field | Status |
|---|---|---|---|---|
| 0 | len | ASCII, no terminator | `ELITE - <SERIAL>` | VERIFIED |

### 7.3 MSG-0081-R — privacy status (RESPONSE)
| Offset | Size | Type | Field | Status |
|---|---|---|---|---|
| 0 | 1 | u8 | privacy status. `00` observed; reads work without a PIN. | VERIFIED value; meaning INFERRED |

### 7.4 MSG-0084-R — settings (RESPONSE, then EOD)
| kind | Name | Length | Example | Status |
|---|---|---|---|---|
| 0 | GunTransferSettings | 7 | `000000001e1300` | VERIFIED raw; fields UNKNOWN |
| 2 | TgtInfoSettings | 8 | `000000000a000100` | VERIFIED raw; fields UNKNOWN |
| 3 | BalInfoSettings | 152 | starts `000000000000964300a08c45…`; f32 LE values, a run of `ff` near the end | VERIFIED raw; fields UNKNOWN |

The kind names are INFERRED. All three records were byte-identical before and after a target-range change and several gun selections (VERIFIED), so they hold static configuration, not live target values. Kind 3 is mostly f32 pairs that look like input limits (e.g. `-90`/`90`); kind 2 `+4 = 0x0a` may be the number of targets (A–J) (INFERRED). Kind 2 `+6` (u16) is the current sector's **target designator: `0` = ABC, `1` = 123** (VERIFIED across three sectors: it was the only byte in all three records to change when the sector was switched on the device).

### 7.5 MSG-0087-R — gun record (3 × RESPONSE, then EOD)

**Part 0** (219 B)
| Offset | Size | Type | Field | Status |
|---|---|---|---|---|
| 0 | 1 | u8 | part number = `0` | VERIFIED |
| 1 | 1 | u8 | `00` | VERIFIED |
| 2 | 2 | u16 | slot index (echo of request) | VERIFIED |
| 4 | 4 | — | `00000000` | VERIFIED (11/11) |
| 8 | 4 | f32 | **MV, muzzle velocity**, ft/s (the one value not stored metric) | VERIFIED (display fps; m/s display UNTESTED) |
| 12 | 4 | f32 | **BC** for G1/G7. With an AB custom model (DM `0x0a`) the device displays BC as 1, but this field can still hold the earlier G1/G7 value; four such profiles hold `1.0`. BC cannot be edited on the device while DM is AB (USER) | VERIFIED (G1 profile; one AB profile shown as 1 with a different stored value, USER) |
| 16 | 4 | f32 | **BW, bullet weight**, g (display gr) | VERIFIED |
| 20 | 4 | f32 | **BD, bullet diameter**, mm (display in) | VERIFIED |
| 24 | 4 | f32 | BL, bullet length, mm | INFERRED (value matches a plausible length; not read on screen) |
| 28 | 4 | f32 | **ZR, zero range**, m | VERIFIED |
| 32 | 4 | f32 | **BH, bore (scope) height**, cm (display in) | VERIFIED |
| 36 | 4 | f32 | **ZH, zero height**, cm; signed | VERIFIED |
| 40 | 4 | f32 | ZO, zero offset, cm; signed | INFERRED (only `0` seen on screen) |
| 44 | 4 | f32 | **RT, rifle twist** (distance per turn), cm (display in). **Sign = RTd**: positive = right-hand, negative = left-hand | VERIFIED (R → L flipped only the sign bit) |
| 48 | 24 | — | zero in all 11 profiles | UNKNOWN |
| 72 | 24 | 6 × f32 | `1.0` in all 11 profiles; DSF values candidate (the device holds up to 6) | INFERRED |
| 96 | 123 | f32 pairs | (value, Mach) table, Mach 0.5 → 1.5 here, continuing into part 1 up to Mach 3.0: the **AB custom drag curve**. Present in all 10 profiles with DM `0x0a`; all zero in the G1 profile. | INFERRED (10/10 vs 0/1) |

**Byte stream.** Parts 0, 1 and 2 are one contiguous record split across packets: drop each part's 2-byte header and join them. Fields are packed and can straddle a part boundary; part-0 bytes 216–218 plus part-1 byte 2 decode as Mach 1.6 in the table above (VERIFIED, 10/11 profiles). Offsets in this section stay per part.

**Device-side conversion:** changing DM G1 → G7 on the device also rewrote BC (converted to a G7 value). Changing it back restored the original BC exactly, and the record was byte-identical to the original (VERIFIED). Re-reading an unchanged gun returns an identical record (VERIFIED).

**Not yet located:** Eunit/Wunit (likely global settings rather than per gun).

**Not in the gun record:** the Manage Guns On/Off state. No byte or bit separates the enabled profiles from the disabled ones across 11 records (VERIFIED, enabled set per USER). It is not in the §7.4 settings records either (no matching bitmap). Where it is exposed, if at all, is UNKNOWN.

**Part 1** (219 B)
| Offset | Size | Type | Field | Status |
|---|---|---|---|---|
| 0 | 1 | u8 | part number = `1` | VERIFIED |
| 1 | 1 | u8 | `00` | VERIFIED |
| 2 | 165 | mixed | Continues the part-0 (value, Mach) table up to Mach 3.0, then further fields. In a profile without the table, the non-zero bytes are two f32 `1.0` at 135 and 139, then u16 values at 143. One of these u16 equals MV in ft/s. | INFERRED |
| 167 | 12 | ASCII | **profile name**, NUL padded; no terminator when all 12 bytes are used | VERIFIED (11/11) |
| 179 | 2 | bytes | `0a0a` in all 11 profiles | UNKNOWN |
| 181 | 1 | u8 | **Eunit, elevation unit**: `1` = mil, `2` = TMOA (other values UNTESTED) | VERIFIED (mil ↔ TMOA on the device) |
| 182 | 1 | u8 | **Wunit, windage unit**: same coding as Eunit | VERIFIED |
| 183 | 2 | bytes | `0101` in all 11 profiles | UNKNOWN |
| 185 | 1 | u8 | **DM, drag model**: `0x00` = G1, `0x01` = G7, `0x0a` = Applied Ballistics custom drag model (shown on the device by bullet maker, e.g. "Hornady") | VERIFIED (G1 ↔ G7 by toggle; `0x0a` USER, one profile) |
| 186 | 17 | ASCII | **bullet manufacturer**, NUL padded, may be empty | VERIFIED (11/11) |
| 203 | 16 | ASCII | **bullet model**, NUL padded, may be empty | VERIFIED (11/11) |

**Part 2** (6 B)
| Offset | Size | Type | Field | Status |
|---|---|---|---|---|
| 0 | 1 | u8 | part number = `2` | VERIFIED |
| 1 | 3 | — | `000000` | VERIFIED |
| 4 | 2 | u16 LE | **record checksum**: CRC-16/MCRF4XX (poly `0x1021` reflected, init `0xFFFF`, no final XOR; = X.25 without its final XOR). Covers the byte stream from part-0 offset 8 through part-2 offset 3. `kestrel_proto.gun_record_crc` | VERIFIED (15/15 records: 11 profiles + 4 edited states) |

### 7.6 MSG-0091-C — environment (Kestrel COMMAND; offsets after the opcode)
34 bytes. Values are little-endian scaled integers; each is preceded by a u16 that was constant across reads (possibly a field tag). Checked against the device's Environment menu with Update = Lock; the display rounds.

| Offset | Size | Type | Field | Status |
|---|---|---|---|---|
| 0 | 3 | — | `000000` observed | UNKNOWN |
| 3 | 3 | 3 × u8 | `01 01 01` observed; enable-flag candidates (spin drift and aero jump were On) | INFERRED |
| 6 | 1 | — | `00` observed | UNKNOWN |
| 7 | 2 | u16 | `0x0044` observed | UNKNOWN |
| 9 | 3 | i24 | **latitude**, × 0.001 deg (negative = south) | VERIFIED |
| 12 | 2 | u16 | `0x001c` observed | UNKNOWN |
| 14 | 2 | i16 | **temperature**, × 0.01 °C | VERIFIED |
| 16 | 2 | u16 | `0x0053` observed | UNKNOWN |
| 18 | 3 | i24 | **station pressure**, × 0.01 hPa | VERIFIED |
| 21 | 2 | u16 | `0x001b` observed | UNKNOWN |
| 23 | 2 | u16 | **relative humidity**, × 0.01 % | VERIFIED |
| 25 | 2 | u16 | `0x003c` observed | UNKNOWN |
| 27 | 3 | i24 | **density altitude**, × 0.1 m | VERIFIED (one sample) |
| 30 | 2 | u16 | `0x0002` observed | UNKNOWN |
| 32 | 2 | — | varies by unit; meaning UNKNOWN | UNKNOWN |

Not in this record: wind speeds, wind direction and DoF (they are target values; see §7.8).

### 7.7 MSG-0094-R — "active gun index" (RESPONSE)
| Offset | Size | Type | Field | Status |
|---|---|---|---|---|
| 0 | 2 | u16 | `0` observed | UNKNOWN |
| 2 | 2 | u16 | **slot of the gun selected on the device** (B-2) | VERIFIED |

### 7.8 MSG-00A1-C — remote (live) solution (Kestrel COMMAND; offsets after the opcode)
| Offset | Size | Type | Field | Status |
|---|---|---|---|---|
| 0 | 1 | u8 | type (echo of request `arg[0]`) | VERIFIED |
| 1 | 1 | u8 | counter (echo of request `arg[1]`) | VERIFIED |
| 2 | 1 | u8 | `00` | VERIFIED |
| 3 | 12 | ASCII | **selected gun's profile name**, NUL padded | VERIFIED (matches the profile on screen, USER) |
| 15 | 1 | u8 | **Eunit** of the selected gun (§7.5 part 1 +181): `1` = mil, `2` = TMOA | VERIFIED |
| 16 | 1 | — | `00` | UNKNOWN |
| 17 | 1 | u8 | **Wunit** of the selected gun (§7.5 part 1 +182) | VERIFIED |
| 18 | 5 | bytes | `0001010a0a` observed | UNKNOWN |
| 23 | 4 | f32 | **TR, target range**, in m (display set to m) | VERIFIED (300 → 400 on screen) |
| 27 | 4 | f32 | **DoF, direction of fire**, degrees | VERIFIED (203.0 ↔ "203 deg") |
| 31 | 4 | f32 | **Elv, elevation hold**, in mil (Eunit mil); negative = Up | VERIFIED (−25.2544 ↔ "25.25U mil") |
| 35 | 4 | f32 | **Wnd1, windage hold at WS1**, in mil; negative = Right | VERIFIED (−0.4347 ↔ "0.43R mil") |
| 39 | 4 | f32 | **Wnd2, windage hold at WS2**, in mil; negative = Right | VERIFIED (−2.2675 ↔ "2.27R mil") |
| 43 | 4 | f32 | **WS1, wind speed 1 (average)**, in m/s regardless of display unit | VERIFIED (1.788 ↔ "4 mph") |
| 47 | 4 | f32 | **WS2, wind speed 2 (maximum)**, in m/s | VERIFIED (6.3 ↔ "14 mph"; the display rounds 14.09) |
| 51 | 4 | f32 | **WD, wind direction**, degrees relative to DoF (the device shows it as a clock or as degrees) | VERIFIED (24.0 ↔ "24 deg") |
| 55 | 4 | f32 | **latitude**, degrees (same value as §7.6 +9) | VERIFIED |
| 59 | 4 | f32 | **temperature**, °C (same value as §7.6 +14) | VERIFIED |
| 63 | 4 | f32 | **station pressure**, hPa (same value as §7.6 +18) | VERIFIED |
| 67 | 4 | f32 | **relative humidity**, % (same value as §7.6 +23) | VERIFIED |
| 71 | 32 | 8 × f32 | byte-identical copy of the selected gun's MV, ZR, BH, RT, BD, BC, BW, BL, in that order, same units as §7.5 part 0 (offsets 8, 28, 32, 44, 20, 12, 16, 24) | VERIFIED copy |
| 103 | 4 | f32 | **Ideg, inclination**, degrees | VERIFIED (0 → 0.0, 1° → 1.0, 5° → 5.0) |

The record carries the holds and most solver inputs. Target speed is not in it: TS = 0.9 m/s on screen, and no field holds that value (VERIFIED, one record). The derived outputs shown in the device's Ballistics menu (RTrns, RSubs, MaxO, AerJ, vCor, hCor, SpnD, Trce, Drop, Lead, ToF, RemV, RemE) do not appear in it as f32 in any of the screen's units (VERIFIED, one 400 m record). **Units are fixed, whatever the display shows:** holds are always mil and range always metres. Switching Eunit/Wunit to TMOA left the hold values byte-identical (only +15/+17 changed), and switching the device's range unit to yards left the whole record and the gun record unchanged (VERIFIED). Other Eunit values (SMOA, inches, cm, clicks) are UNTESTED.

### 7.9 MSG-008A-C — full solution (Kestrel COMMAND, reply to `0x0093`)
90 bytes, **packed (not 4-byte aligned)**. Offsets are relative to the record (after the opcode).

| Offset | Size | Type | Field | Status |
|---|---|---|---|---|
| 0 | 2 | — | `0000` | UNKNOWN |
| 2 | 2 | u16 | **range**, cm (= §7.8 TR × 100) | INFERRED (= §7.8 value, one record) |
| 4 | 4 | — | `00000000` | UNKNOWN |
| 8 | 3 | i24 | **DoF, direction of fire**, × 0.001° (= §7.8 DoF) | INFERRED (= §7.8 value, one record) |
| 11 | 4 | f32 | **Elv, elevation hold**, mil; negative = Up | VERIFIED copy (byte-identical to §7.8 +31) |
| 15 | 4 | f32 | **Wnd1, windage hold at WS1**, mil; negative = Right | VERIFIED copy (= §7.8 +35) |
| 19 | 4 | f32 | **Wnd2, windage hold at WS2**, mil; negative = Right | VERIFIED copy (= §7.8 +39) |
| 23 | 2 | — | `0000` | UNKNOWN |
| 25 | 2 | u16 | **WS1, wind speed 1 (average)**, mm/s (= §7.8 WS1 × 1000) | INFERRED (= §7.8 value, one record) |
| 27 | 2 | u16 | **WS2, wind speed 2 (maximum)**, mm/s | INFERRED (= §7.8 value, one record) |
| 29 | 2 | u16 | **WD, wind direction**, × 0.001° | INFERRED (= §7.8 value, one record) |
| 31 | 1 | — | `00` | UNKNOWN |
| 32 | 3 | bytes | same 3-byte encoding as the §7.6 latitude field (i24 × 0.001°) | INFERRED |
| 35 | 4 | — | `00000000` | UNKNOWN |
| 39 | 4 | f32 | **RemV, remaining velocity**, m/s | INFERRED (physics, see note) |
| 43 | 4 | f32 | **RemE, remaining energy**, J | INFERRED (= ½·BW·RemV², see note) |
| 47 | 4 | f32 | **ToF, time of flight**, s | INFERRED (physics, see note) |
| 51 | 4 | f32 | `0x4f800000` (= 2³²): "not computed" sentinel | INFERRED |
| 55 | 4 | f32 | output; unidentified | UNKNOWN |
| 59 | 16 | 4 × f32 | small values; spin-drift / coriolis / aero-jump candidates (mil) | UNKNOWN |
| 75 | 4 | f32 | sentinel (as +51) | INFERRED |
| 79 | 4 | f32 | output; unidentified | UNKNOWN |
| 83 | 4 | f32 | output; unidentified | UNKNOWN |
| 87 | 3 | — | `010000` trailing | UNKNOWN |

Pushed after the host's `0x0093` is ACKed; ACK it with its own opcode, like the other Kestrel COMMANDs (§4.1).

Mapped from one record (`0x0093` args `ff 00 00 00`, i.e. doExtraCalcs = 0). The front half (range through WD) was cross-checked field for field against the §7.8 `0x00a1` record from the *same* transaction; the three holds are a byte-identical copy of it. **RemV/RemE/ToF are self-consistent:** RemE computed as ½·BW·RemV² (BW from §7.5 +16) matches the stored RemE to 0.04 %, confirming both together, and ToF fits the mean velocity over the range. This record is therefore the carrier for the remaining-velocity/energy/ToF outputs §7.8 lacks.

Two back-half f32 slots hold `0x4f800000` (exactly 2³²), read as a "not computed" sentinel — consistent with doExtraCalcs = 0 having been requested. Still open: the unidentified back-half f32 (the derived outputs §7.8 lists — spin drift, aero jump, coriolis, drop — are candidates), the 3 bytes at +32 bytes at +32, and whether doExtraCalcs = 1/2 fills the sentinel slots.

### 7.10 Target Card
The Target Card is stored **on the device** (Elite only). It holds 10 targets (designated A–J or 1–10), each with its own range, DoF, inclination, target speed and wind (WD, WS1, WS2). The device computes a solution for each, and a LiNK rangefinder can range into the highlighted target (manual). §7.4 kind 2 `+4 = 0x0a` matches the 10-target count (INFERRED).

The targets are further grouped into named **sectors**, each holding 10 targets. The sector name is shown on the device's Target Card sub-menu (`Sctr…`), and the vendor app can "Pull Targets from Kestrel" (USER, vendor documentation). So sectors and their targets are readable over BLE. TgtInfo (§7.4 kind 2) follows the current sector's designator but carries no sector number or name (VERIFIED, three sectors). No known command addresses sectors or sector names.

**Reading the Target Card.** The vendor app's "Pull Targets from Kestrel" is `0x0084` kind 2, then 10 × `0x0093 [t][t][ff][00]` for t = 0…9 (target t, solutionId t, doExtraCalcs `0xff`, not set active), each answered by one `0x008a` (§7.9) (VERIFIED, observed). Target numbers 0–9 index the 10 targets of the **current sector**: pulls in two sectors returned entirely different target ranges, matching each sector (VERIFIED). The pull changed neither the selected gun nor the live solution (VERIFIED with a valid solution before and after; earlier pulls ran while the device was in a menu, B-6). Repeated pulls return byte-identical records. To read every sector, switch the sector on the device and pull again; label the targets with the designator from §7.4 kind 2 `+6`. No sector name crossed the link during the pull.


### 7.11 MSG-0089-C — SetFullInputs (host COMMAND; offsets after the opcode)
Observed from the vendor app when the user changes range or DoF; the device's current target took the new values (USER) and the device pushed `0x008a`.

| Offset | Size | Type | Field | Status |
|---|---|---|---|---|
| 0 | 2 | — | `0000` observed | UNKNOWN |
| 2 | 3 | i24 | **range**, × 0.01 m | VERIFIED (500 m) |
| 5 | 3 | i24 | **Ideg, inclination**, × 0.001° | INFERRED (matched the current 1°) |
| 8 | 3 | i24 | **DoF**, × 0.001° | VERIFIED (44° → 90° changed only this field) |
| 11 | 6 | 2 × i24 | `ffffff` each; "not set" candidates | UNKNOWN |
| 17 | 6 | 2 × i24 | `010080` each (`0x800001`); "not set" candidates | UNKNOWN |
| 23 | 1 | u8 | `0x81` observed | UNKNOWN |
| 24 | 4 | bytes | `ff00ff00` observed | UNKNOWN |

Wind values were set on the device but not carried here, so the unset fields are likely the wind and target-speed inputs the app does not control (INFERRED).

---

## 8. NACK reason codes

| Reason | Meaning | Status |
|---|---|---|
| `0x03` | Command not supported (probably also used for "args too short") | VERIFIED (unsupported); INFERRED (short args) |
| `0x0a` | Invalid argument / item not available | VERIFIED |
| `0x0b` | Index out of range (GetGun past the last slot) | VERIFIED |
| `0x0c` | No solution available: the device has not computed one, e.g. because the selected gun is disabled in Manage Guns (B-1) | VERIFIED |
| `0x0000` with opcode `0xffff` | Kestrel could not decode the frame (e.g. cleartext sent into an encrypted session, or a malformed frame) | INFERRED |

---

## 9. Live sensor stream (`0329` service, cleartext, no auth)

**Not verified in this revision.** Treat as INFERRED.
- After the CCCD is enabled, notifications arrive roughly every 5 s.
- `03290310`: `[u16 wind ×0.01][i16 temp ×0.01 °C][8001 sentinel][u16 RH ×0.01 %][u16 pressure ×0.1 hPa]…`
- `03290320`/`0330`: further environment values. `0340`/`0350` are solution-shaped but stay at `8001` ("unavailable"); the live solution is carried by §7.8.

---

## 10. Behaviours

| ID | Behaviour | Status |
|---|---|---|
| B-1 | **GetGun selects.** `0x0087` returns the record *and* makes that slot the gun selected on the device, the same as choosing it on screen. This also works for a gun that is disabled in Manage Guns, and the device then shows no ballistic results. The selection persists across disconnects. Seen: slot 0 → 1 (screen followed, solution for slot 1), slot 1 → 5 (disabled; screen followed, no results). A full gun-list read therefore leaves the device on the last slot read; read the originally selected slot again at the end (`Kestrel.get_guns`). | VERIFIED (USER confirmed the screen) |
| B-2 | **`0x0094` is the selected slot.** It changed 0 → 1 → 5 as GetGun selected those slots, and it reported slot 0 while slot 0 was selected on screen. It needs no GetGun, so it is the way to find the selected gun without disturbing it. Earlier readings of it as "the last-read slot" were this same behaviour, since every read changed the selection. | VERIFIED |
| B-3 | Auth state is per connection; every new connection must re-authenticate (§5.3). | VERIFIED |
| B-4 | Typical latency: ~0.2 s to ACK, about 1 s per 219 B RESPONSE part. A full GetGun takes about 3 s. | VERIFIED |
| B-5 | **Solution unavailable after remote operations.** GetRemoteSoln NACKs `0x0c`, and the device shows no ballistic results, while the selected gun is disabled in Manage Guns. GetGun can select such a gun (B-1), and a full list read can leave the device on one. Selecting an enabled gun clears it. This is the "nudge" the device seemed to need. | VERIFIED (USER: slot 5 is disabled) |
| B-6 | **While a target value is being edited on the device**, `0xa1` still answers, but every f32 from +23 on reads NaN. Valid values return once the edit is done (two 2 s polls during a range edit). | VERIFIED |
| B-7 | **Slot order changes.** Editing a gun on the device moves it to slot 0, pushing the others down; untouched guns keep their order. Seen: after editing the slot-1 gun it became slot 0 and the former slot 0 became slot 1. Slot numbers are positions, not stable IDs; identify guns by name. `0x0094` follows the move. | VERIFIED (one edit) |

---

## 11. Open items (in priority order)

1. §7.9 partly mapped: range, DoF, the three holds and the three wind values (front half, cross-checked against §7.8), plus RemV/RemE/ToF. Still open — the unidentified back-half f32 (spin drift / coriolis / aero jump / drop and the other §7.8-absent outputs are candidates) and the 3 bytes at +32; read `0x0093` with doExtraCalcs = 1/2 (RESTRICTED) to fill and label the `2³²` sentinel slots. Test target numbers 0–9 against the Target Card (§7.10). Confirm §7.8 +103 as Ideg. Check hold and range units under other unit settings.
2. §7.5: decode the AB drag-curve table (pairing/format of the values); the rest of part 1.
3. §7.6: meaning of the u16 values between fields, the `01 01 01` flags and the last two bytes.
4. `0x0092` arg semantics (§6.5). Low priority: the vendor app's live solution screen does not use it; it polls `0x00a0` about once a second (VERIFIED, 70 polls in one session).
5. Meaning of `8592ffff` and the §7.4 settings fields.
6. Sectors (§7.10): no known command selects a sector or reads its name.

## 12. Revision history

| Rev | Date | Change |
|---|---|---|
| 1.0 | 2026-11-01 | First release. |
| 1.1 | 2026-11-01 | §7.8 laid out field by field: range, elevation and both windage holds VERIFIED against the screen; gun-copy order VERIFIED; derived outputs shown absent. Added B-6. WS1, WS2 (m/s), WD and DoF (deg), latitude, temperature, pressure, RH VERIFIED; TS shown absent. §7.6 laid out field by field (scaled integers) and the raw example removed. §7.5 part 0 mapped (MV ft/s; others metric); the three parts shown to form one byte stream. |
| 1.2 | 2026-11-01 | B-1, B-2 and B-5 rewritten: GetGun selects the gun on the device, `0x0094` is the selected slot, and NACK `0x0c` means no solution (selected gun disabled). These supersede the 1.0 "last-read slot" interpretation. |
| 1.3 | 2026-11-01 | §7.5: DM byte (part 1 +185), twist direction (sign of RT) and the record checksum (CRC-16/MCRF4XX) VERIFIED by on-device toggles. §7.4: settings shown static. Gun On/Off state shown absent from the gun record. DM `0x0a` = AB custom drag model; BC field semantics under AB corrected. |
| 1.4 | 2026-11-01 | `0x0093` CalcFullSolution exercised once (owner-approved): reply `0x008a` SetFullSoln, 90 B, no state change (§6.4, §6.3, §7.9). Added §7.10 Target Card (sectors). New SetBalInput row. BC not editable under AB (USER). |
| 1.5 | 2026-11-01 | §7.9 `0x008a` full-solution record mapped from a second CalcFullSolution record (doExtraCalcs = 0): front half (range, DoF, holds, winds) cross-checked against the §7.8 record from the same transaction; RemV/RemE/ToF identified and internally confirmed (RemE = ½·BW·RemV²). `2³²` back-half slots read as "not computed" sentinels. §11-1 revised. |
| 1.6 | 2026-11-01 | Target Card read path observed from the vendor app: `0x0084` kind 2, then 10 × `0x0093 [t][t][ff][00]` → `0x008a` (§6.4, §7.10). §7.9 +32: literal value replaced by its encoding (privacy). |
| 1.7 | 2026-11-01 | §7.4 kind 2 `+6` = target designator (0 = ABC, 1 = 123), VERIFIED by switching sectors; TgtInfo carries no sector number or name (§7.10). |
| 1.8 | 2026-11-01 | §7.10: a Target Card pull returns the current sector's 10 targets (VERIFIED in two sectors); pulls leave the device state unchanged. |
| 1.9 | 2026-11-01 | §6.1: `0x0093` with exactly the Target Card arguments `[t][t][ff][00]` moved to SAFE; other arguments stay RESTRICTED. |
| 1.10 | 2026-11-01 | Units: holds always mil and range always metres regardless of display (VERIFIED); Eunit/Wunit located (§7.5 part 1 +181/+182, copied to §7.8 +15/+17); §7.8 +103 = Ideg (VERIFIED). Added B-7 (editing a gun moves it to slot 0). |
| 1.11 | 2026-11-01 | Added §7.11 `0x0089` SetFullInputs (range, Ideg, DoF), observed from the vendor app; `0x008a` is also pushed after it. The vendor app's live screen polls `0x00a0` and does not use `0x0092`. |
| 1.12 | 2026-11-01 | Added §13 Device mode: the Kestrel as central to a LiNK rangefinder; peer advertisement and GATT; cleartext HDLC with ASCII `0x005e` sentences (ST, AI, A+, A3, AB). |
| 1.13 | 2026-11-01 | §13.5: acting as the rangefinder verified (range, bearing and inclination drive the Kestrel's solution; no ACKs needed from the device). |
| 1.14 | 2026-11-01 | §13: name not used for discovery (USER); added §13.5 implementer's guide with test vectors; dropout handling. |


## 13. Device mode: LiNK rangefinder link

With **Bluetooth › Conct = Device**, the Kestrel is the BLE **central** and connects to a LiNK rangefinder (the **peripheral**). Reference peer: Vortex Fury HD 5000 AB in BAL mode.

### 13.1 Link layer
| Item | Value | Status |
|---|---|---|
| Kestrel advertising in Device mode | none: the Kestrel stops advertising, so PC/mobile connections (§1–§12) are unavailable until Conct is changed back | VERIFIED |
| Peer advertisement | flags `05`; manufacturer data company `0x049b` = `0200ffffffff`; complete name `<MODEL>-<SERIAL>`; scan response: 128-bit service `49535343-fe7d-4ae5-8fa9-9fafd205e455` and the manufacturer data again | VERIFIED (one peer) |
| Which of these the Kestrel filters on | not the name: a device advertising an unrelated name is listed under Name › New and accepted. Service UUID vs manufacturer data: UNKNOWN, so advertise both | name VERIFIED (USER); rest UNKNOWN |
| Peer GATT | service `49535343-fe7d-4ae5-8fa9-9fafd205e455`: char `0000fff1-…` write / write-without-response (Kestrel → peer); char `0000fff2-…` notify (peer → Kestrel), CCCD enabled by the Kestrel with `0100` | VERIFIED |
| MTU | 23 | VERIFIED |
| BLE pairing / bonding | none observed | VERIFIED |
| Pairing on the Kestrel | Name › New lists the peer; the Kestrel then reconnects to that peer's address automatically | VERIFIED |

### 13.2 Framing
§3 HDLC and §4 packets, **in cleartext**: no §5 authentication and no encryption on this link (VERIFIED). Every sentence is a COMMAND with opcode `0x005e` whose argument bytes are ASCII: `:` + a two-letter ID + comma-separated fields + `\r` (`\r\n` seen on A3). The Kestrel ACKs each peer COMMAND (type 4, op `0x005e`); the peer does not ACK the Kestrel's (VERIFIED, ~100 frames).

### 13.3 Sentences
| ID | Direction | Format | Fields | Status |
|---|---|---|---|---|
| `A+` | peer → Kestrel | `:A+` | none; sent at session start and occasionally | VERIFIED presence; meaning (hello / keep-alive) INFERRED |
| `ST` | peer → Kestrel | `:ST,RRRR,±BBB.B` | **range** in whole **yards**, 4 digits; **bearing** (direction of fire), degrees | range VERIFIED (≈32 m → `0034`/`0035`, ≈23 m → `0025`); bearing INFERRED |
| `AI` | peer → Kestrel | `:AI,±II.I` | **inclination**, degrees; sent continuously | VERIFIED (+4° and −3° targets) |
| `A3` | Kestrel → peer | `:A3,TT.TT,PP.PP,HH.HH,±LL.LL,<name>` | **temperature °F**, **station pressure inHg**, **RH %**, **latitude °**, **selected gun's profile name** | VERIFIED (same values as §7.6 in °F/inHg); units fixed regardless of display INFERRED |
| `AB` | Kestrel → peer | `:AB,1,f2,…,f13` (13 fields) | f1 `1`; f5 **range, yards** (echo of the last `ST`); f6 **WS1 mph**; f7 **WS2 mph**; f8 **WD °**; f13 **MV ft/s** of the selected gun; f2–f4 and f9–f12 are solution outputs (not mapped) | f5 VERIFIED (echoed 31/34/36); f6–f8 VERIFIED (= §7.8 WS1/WS2/WD); f13 VERIFIED; others UNKNOWN |
| — | Kestrel → peer | COMMAND `0x000b` SetExtDevName, ASCII name | the name the user gave this device in the Kestrel's device list, sent once per session | VERIFIED (USER) |

The Kestrel resends `A3` every few seconds and `AB` several times a second. The Kestrel's minimum range is 25 yd ("Unusable target data received" below it, per the peer's manual); 25 yd ranges were accepted.

### 13.4 Acting as the rangefinder
A device that advertises as in §13.1 and serves `fff1`/`fff2` is accepted by the Kestrel as a rangefinder (VERIFIED with an independent implementation):
- After the Kestrel enables `fff2` notifications, the device sends `:A+`; the Kestrel then streams `A3` and `AB`. Sending `:AI` every 2 s is enough, and the device need not ACK the Kestrel's sentences (VERIFIED).
- Each `:ST` (range 109–1094 yd; bearing `+000.0`…`+270.0`, zero-padded to three integer digits) together with the current `:AI` produced an `AB` echoing the new range within about 1 s, and every change of range, bearing or inclination changed the solution (VERIFIED, 14 combinations). The range from `ST` becomes the Kestrel's target range (USER).
- A different advertised name is listed under Name › New and accepted (VERIFIED, USER).
- Links dropped with supervision timeouts (`0x08`) after 2–70 s at the bench and the Kestrel reconnected within about 1.5 s; the same happened with the reference peer. Cause UNKNOWN. Dropouts between Kestrels and rangefinders are a widely reported field problem, so treat them as normal (§13.5 step 6).

### 13.5 Implementer's guide: building a rangefinder for Device mode

Everything a device needs to send range, direction of fire and inclination to a Kestrel and receive the solution. All of it is cleartext; no keys, PIN or bonding are involved.

**1. Advertise** (connectable, legacy advertising, public address). Advertising data:

```
02 01 05                                  flags
09 ff 9b 04 02 00 ff ff ff ff             manufacturer data, company 0x049b
NN 09 <name>                              complete local name (any name)
```
Scan response:
```
11 07 55 e4 05 d2 af 9f a9 8f e5 4a 7d fe 43 53 53 49     128-bit service 49535343-fe7d-4ae5-8fa9-9fafd205e455
09 ff 9b 04 02 00 ff ff ff ff                             manufacturer data again
```

**2. Serve one GATT service** `49535343-fe7d-4ae5-8fa9-9fafd205e455`:

| Characteristic | Properties | Use |
|---|---|---|
| `0000fff1-0000-1000-8000-00805f9b34fb` | write, write without response | Kestrel → device bytes |
| `0000fff2-0000-1000-8000-00805f9b34fb` | notify, with a CCCD | device → Kestrel bytes |

Keep the ATT MTU at 23: send at most 20 bytes per notification and split longer frames across notifications. Accept frames that span several writes on `fff1`.

**3. Pair on the Kestrel** (user action): Bluetooth › Conct = Device › Name › New, pick the device. The Kestrel connects, enables `fff2` notifications (CCCD `0100`), and from then on reconnects to that device's address by itself.

**4. Frame everything** as §3/§4 LiNK frames, without encryption: `7e` + escaped(`[u16 type][u16 len][payload]` + CRC-16/X.25 little-endian) + `7e`, where `7e`/`7d` inside a frame become `7d 5e`/`7d 5d`. Each sentence is a COMMAND (type 0) whose payload is `5e 00` followed by the ASCII sentence and `\r`. Test vectors:

| Content | Frame bytes |
|---|---|
| `:A+\r` | `7e 00 00 06 00 5e 00 3a 41 2b 0d 82 d7 7e` |
| `:ST,0035,+044.0\r` | `7e 00 00 12 00 5e 00 3a 53 54 2c 30 30 33 35 2c 2b 30 34 34 2e 30 0d f7 ac 7e` |
| `:AI,+01.0\r` | `7e 00 00 0c 00 5e 00 3a 41 49 2c 2b 30 31 2e 30 0d a5 51 7e` |
| ACK from the Kestrel (type 4, op `0x005e`) | `7e 04 00 02 00 5e 00 b2 97 7e` |

**5. Talk.**
1. When notifications are enabled, send `:A+`.
2. Send `:AI,±II.I` (inclination in degrees, two integer digits) every 1–2 s.
3. On each measurement, send `:ST,RRRR,±BBB.B`: range in whole **yards** (4 digits; convert metres with ÷ 0.9144 and round), bearing in degrees with three integer digits (`+044.0`). Below 25 yd the Kestrel rejects the range.
4. Read the Kestrel's sentences from `fff1`: `A3` every few seconds, `AB` about once a second (§13.3). The solution for your range is the first `AB` whose field 5 equals the yards you sent and that arrives after the send; allow about 2.5 s for direction and inclination changes to be applied.
5. Do not ACK the Kestrel's sentences; it ACKs yours. `0x000b` carries the name the user gave your device on the Kestrel.

**6. Be robust.** The link can drop at any time (`0x08`, see §13.4); keep advertising after a disconnect and the Kestrel reconnects within seconds. A measurement sent just before a drop is lost: if no `AB` echoes your range within about 3 s, send `:ST` again.

### 13.6 Open
- `AB` solution fields; whether the Kestrel filters on the service UUID or the manufacturer data; whether the Kestrel's sentences change when the peer's "Kestrel Solution in FURY" setting is off.

# Notes for AI agents

- **Start with `docs/ICD.md`.** It is the single source of truth for the Kestrel BLE
  interface. Every fact carries a status tag (VERIFIED / INFERRED / USER / UNKNOWN);
  build only on VERIFIED, and treat the rest as hypotheses to test.
- **Command policy (ICD §0, §6).** Send `SAFE` commands freely. Ask the owner
  before the first send of an `UNTESTED` one. `RESTRICTED` needs the owner's
  explicit approval for that action. Never send `FORBIDDEN` (erase, reboot,
  firmware/bootloader). Don't send commands with guessed arguments.
- **Public vs private.** This repo publishes protocol knowledge and the client
  only. The git-ignored `private/` folder (if present) holds the owner's working
  material; read `private/NOTES.md` first. Never copy anything from `private/`
  into tracked files, and never describe in tracked files how the knowledge was
  obtained.
- **Privacy.** Never write the unit's serial number, BLE address or PIN into
  tracked files, commits or examples; use `<SERIAL>`, `<BLE_ADDR>`, `<PIN>`. Don't
  record the owner's gun profiles (names, bullets, parameter values) either;
  describe fields by layout only.
- **Real device first.** The Kestrel is the source of truth. Check new decoding
  against live reads with `tools/kestrel_client.py`.
- **Keep the ICD current.** When a fact changes status, update its row and add a
  line to the revision history (§12). Keep the format: stable IDs, field tables
  with offset/size/type/status.
- `0x0093` CalcFullSolution is SAFE only with the Target Card arguments
  `[t][t][ff][00]` (ICD §6.1, §7.10); any other arguments are RESTRICTED.
- Side effect to know about: GetGun (`0x0087`) also selects that gun on the
  device, even a disabled one (ICD B-1). Find the selected gun with `0x0094`, and
  restore it after reading other slots.

"""Direct BLE client for the Kestrel 5700 Elite: connect, mutual-auth, then issue
encrypted read commands and decode the replies. Implements docs/ICD.md.

Only commands verified live against the device are exposed here. All are reads,
but GetGun also selects the gun it reads on the device (ICD B-1); get_guns()
restores the selection. CalcFullSolution is used only with the vendor app's
Target Card arguments, which leave the device unchanged (ICD §7.10).
Set/Erase/Reboot/firmware opcodes are not wrapped.

Usage: kestrel_client.py                 # identity, guns, environment, solution, target card
       kestrel_client.py --name ELITE --log my_session.log

Requires the project venv (bleak, pycryptodome) and kestrel_proto.py beside it.
"""
import argparse
import asyncio
import datetime
import os
import struct
import sys
import time

from bleak import BleakClient, BleakScanner

import kestrel_proto as kp

WRITE_UUID = "85920200-0338-4b83-ae4a-ac1d217adb03"
NOTIFY_UUID = "85920100-0338-4b83-ae4a-ac1d217adb03"
CHUNK = 20  # ATT MTU is 23 on this device

# Opcodes (u16) used by this client. See docs/ICD.md for the full map.
OP_GET_SERIAL = 0x0006
OP_GET_NAME = 0x000A
OP_EOD = 0x0012
OP_REQUEST_AUTH = 0x007E
OP_AUTH_DATA = 0x007F
OP_GET_PRIVACY_STATUS = 0x0081
OP_GET_SETTINGS = 0x0084
OP_GET_GUN = 0x0087
OP_GET_ENVIRONMENT = 0x0090
OP_SET_ENVIRONMENT = 0x0091  # pushed by the Kestrel in reply to GET_ENVIRONMENT
OP_GET_ACTIVE_GUN = 0x0094
OP_GET_REMOTE_SOLN = 0x00A0
OP_SET_REMOTE_SOLN = 0x00A1  # pushed by the Kestrel in reply to GET_REMOTE_SOLN
OP_CALC_FULL_SOLN = 0x0093
OP_SET_FULL_SOLN = 0x008A    # pushed by the Kestrel in reply to CALC_FULL_SOLN
OP_FREE_TO_COMMUNICATE = 0x00A8  # the Kestrel's opening frame on a HUD link

TARGET_COUNT = 10            # targets per Target Card sector

SETTINGS_GUN_TRANSFER = 0
SETTINGS_TGT_INFO = 2
SETTINGS_BAL_INFO = 3


class Nack(Exception):
    def __init__(self, op, reason):
        self.op, self.reason = op, reason
        super().__init__(f"NACK op={op:#06x} reason={reason:#04x} "
                         f"({kp.NACK_REASONS.get(reason, 'unknown')})")


def _op(payload: bytes) -> int:
    return payload[0] | payload[1] << 8 if len(payload) >= 2 else -1


def _cstr(b: bytes) -> str:
    return b.split(b"\x00")[0].decode("latin1")


class BleTransport:
    """The Kestrel's own LiNK service over a direct BLE connection (PC/mobile mode)."""

    def __init__(self, client: BleakClient):
        self.client = client

    async def start(self, on_bytes):
        await self.client.start_notify(NOTIFY_UUID, lambda _char, data: on_bytes(data))

    async def write(self, frame: bytes):
        for off in range(0, len(frame), CHUNK):
            await self.client.write_gatt_char(WRITE_UUID, frame[off:off + CHUNK], response=True)


class Kestrel:
    """One LiNK session. `transport` moves raw frame bytes: start(on_bytes) delivers
    what the Kestrel sends, write(frame) sends a whole HDLC frame. BleTransport is
    the direct PC/mobile link; a HUD link (ICD §14) carries the same session."""

    def __init__(self, transport, log_path=None):
        self.transport = transport
        self.encrypted = False
        self._q: asyncio.Queue = asyncio.Queue()
        self._buf = bytearray()
        self._in_frame = False
        self._esc = False
        self._soln_counter = 0
        self._t0 = time.monotonic()
        self._log = open(log_path, "w") if log_path else None

    def log(self, s):
        line = f"{time.monotonic() - self._t0:8.3f} {s}"
        print(line)
        if self._log:
            self._log.write(line + "\n")
            self._log.flush()

    # ---- transport ----
    def _on_bytes(self, data: bytes):
        # Over BLE, indications arrive as fixed 20-byte chunks; bytes after a
        # closing flag are zero padding and are skipped while outside a frame.
        for b in data:
            if b == kp.FLAG:
                if self._in_frame and self._buf:
                    raw = bytes(self._buf)
                    if len(raw) >= 2 and kp.crc_x25(raw[:-2]) == (raw[-2] | raw[-1] << 8):
                        self._q.put_nowait(raw[:-2])
                    else:
                        self.log(f"   bad CRC, dropped {raw.hex()}")
                    self._in_frame = False
                else:
                    self._in_frame = True
                self._buf.clear()
                self._esc = False
            elif not self._in_frame:
                continue
            elif b == kp.ESC:
                self._esc = True
            else:
                self._buf.append(b ^ 0x20 if self._esc else b)
                self._esc = False

    async def start(self):
        await self.transport.start(self._on_bytes)

    async def _send(self, ptype: int, payload: bytes):
        packet = kp.encode_packet(ptype, payload)
        body = kp.encrypt_packet(packet) if self.encrypted else packet
        self.log(f"=> {'ENC' if self.encrypted else 'CLR'} type={ptype} {payload.hex()}")
        await self.transport.write(kp.hdlc_wrap(body))

    async def _recv(self, timeout):
        while True:
            body = await asyncio.wait_for(self._q.get(), timeout)
            p = None
            if self.encrypted and len(body) % 16 == 0 and len(body) >= 32:
                p = kp.parse_packet(kp.decrypt_frame_body(body))
            if p is None and kp.is_cleartext(body):
                p = kp.parse_packet(body)
            if p is None:
                self.log(f"<= undecodable frame {body.hex()}")
                continue
            ptype, payload = p
            self.log(f"<= type={ptype} len={len(payload)} {payload.hex()}")
            return ptype, payload

    async def _ack(self, op: int):
        await self._send(kp.T_ACK, struct.pack("<H", op))

    async def request(self, op: int, args: bytes = b"", done=None, timeout=8.0):
        """Send a command and run the stop-and-wait exchange until `done(type,
        payload)` is true (default: the first RESPONSE). Returns every RESPONSE
        and Kestrel COMMAND (push) received, as (type, payload) pairs.

        ACK rules: a RESPONSE is ACKed with the request's opcode; a Kestrel
        COMMAND is ACKed with its own opcode."""
        done = done or (lambda t, p: t == kp.T_RESPONSE)
        await self._send(kp.T_COMMAND, struct.pack("<H", op) + args)
        out = []
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"op {op:#06x}: no completion within {timeout}s")
            ptype, payload = await self._recv(left)
            if ptype == kp.T_NACK and _op(payload) == op:
                raise Nack(op, payload[2] | payload[3] << 8 if len(payload) >= 4 else -1)
            if ptype == kp.T_RESPONSE:
                await self._ack(op)
            elif ptype == kp.T_COMMAND:
                await self._ack(_op(payload))
            else:
                continue  # ACKs of our own command
            out.append((ptype, payload))
            if done(ptype, payload):
                return out

    async def _expect(self, pred, timeout=5.0):
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                raise TimeoutError("auth: expected packet not seen")
            ptype, payload = await self._recv(left)
            if pred(ptype, payload):
                return payload

    # ---- auth ----
    async def hud_open(self, timeout=10.0):
        """HUD link (ICD §14.2): the Kestrel opens every connection with
        FreeToCommunicate; ACK it, then authenticate(privacy_status=False)."""
        await self._expect(lambda t, p: t == kp.T_COMMAND and _op(p) == OP_FREE_TO_COMMUNICATE, timeout)
        await self._ack(OP_FREE_TO_COMMUNICATE)

    async def authenticate(self, privacy_status=True):
        """Cleartext handshake: GetPrivacyStatus (not supported on a HUD link), then
        the host proves the key on the Kestrel's nonce, then the Kestrel proves it
        on ours."""
        if privacy_status:
            await self._send(kp.T_COMMAND, struct.pack("<H", OP_GET_PRIVACY_STATUS))
            status = await self._expect(lambda t, p: t == kp.T_RESPONSE)
            await self._ack(OP_GET_PRIVACY_STATUS)
            self.log(f"[auth] privacy status {status.hex()}")

        await self._send(kp.T_COMMAND, struct.pack("<HB", OP_REQUEST_AUTH, 0))
        p = await self._expect(lambda t, p: t == kp.T_COMMAND and _op(p) == OP_AUTH_DATA)
        nonce = p[2:18]
        await self._ack(OP_AUTH_DATA)
        await self._send(kp.T_RESPONSE, kp.auth_response(nonce))
        await self._expect(lambda t, p: t == kp.T_ACK and _op(p) == OP_AUTH_DATA)

        await self._expect(lambda t, p: t == kp.T_COMMAND and _op(p) == OP_REQUEST_AUTH)
        await self._ack(OP_REQUEST_AUTH)
        host_nonce = os.urandom(16)
        await self._send(kp.T_COMMAND, struct.pack("<H", OP_AUTH_DATA) + host_nonce)
        reply = await self._expect(lambda t, p: t == kp.T_RESPONSE and len(p) >= 32)
        await self._ack(OP_AUTH_DATA)
        if not kp.verify_auth_reply(reply, host_nonce):
            raise RuntimeError("Kestrel failed mutual authentication")
        self.encrypted = True
        self.log("[auth] complete; Kestrel verified; link encrypted")

    # ---- read commands (all verified live) ----
    async def get_serial(self) -> str:
        return _cstr((await self.request(OP_GET_SERIAL))[0][1])

    async def get_device_name(self) -> str:
        return _cstr((await self.request(OP_GET_NAME))[0][1])

    async def get_active_gun_index(self) -> int:
        """GetActiveGunIndex: the slot of the gun selected on the device."""
        data = (await self.request(OP_GET_ACTIVE_GUN, b"\x00\x00\x00"))[0][1]
        return struct.unpack_from("<H", data, 2)[0]

    async def get_settings(self, kind: int) -> bytes:
        """kind: SETTINGS_GUN_TRANSFER (0), SETTINGS_TGT_INFO (2), SETTINGS_BAL_INFO (3)."""
        msgs = await self.request(OP_GET_SETTINGS, bytes([kind]),
                                  done=lambda t, p: t == kp.T_COMMAND and _op(p) == OP_EOD)
        return b"".join(p for t, p in msgs if t == kp.T_RESPONSE)

    async def get_gun(self, index: int) -> dict:
        """Full gun record: three RESPONSE parts, then EOD. Raises Nack(0x0b)
        past the last slot. Side effect: the device selects this gun, even one
        that is disabled in Manage Guns (ICD B-1). Slot numbers are positions in
        a most-recently-edited-first list (ICD B-7); identify guns by name."""
        msgs = await self.request(OP_GET_GUN, struct.pack("<H", index),
                                  done=lambda t, p: t == kp.T_COMMAND and _op(p) == OP_EOD)
        parts = [p for t, p in msgs if t == kp.T_RESPONSE]
        p0 = parts[0] if parts else b""
        p1 = parts[1] if len(parts) > 1 else b""
        gun = {
            "index": index,
            "name": _cstr(p1[167:179]),
            "bullet_maker": _cstr(p1[186:203]),
            "bullet_model": _cstr(p1[203:219]),
            "parts": parts,
        }
        if len(p0) >= 48:  # part 0 f32 fields, ICD §7.5
            for key, off in (("mv_fps", 8), ("bc", 12), ("bw_g", 16), ("bd_mm", 20),
                             ("bl_mm", 24), ("zr_m", 28), ("bh_cm", 32), ("zh_cm", 36),
                             ("zo_cm", 40), ("rt_cm", 44)):
                gun[key] = struct.unpack_from("<f", p0, off)[0]
            gun["twist"] = "L" if gun["rt_cm"] < 0 else "R"  # sign of RT
        if len(p1) > 185:
            gun["dm"] = {0: "G1", 1: "G7", 0x0A: "AB"}.get(p1[185], f"{p1[185]:#04x}")
            units = {1: "mil", 2: "TMOA"}  # display units only; holds are always sent in mil
            gun["eunit"] = units.get(p1[181], f"{p1[181]:#04x}")
            gun["wunit"] = units.get(p1[182], f"{p1[182]:#04x}")
        stream = b"".join(p[2:] for p in parts)
        if len(stream) == 438:
            gun["crc_ok"] = kp.gun_record_crc(stream) == int.from_bytes(stream[436:438], "little")
        return gun

    async def get_guns(self, max_slots=32):
        """Read every slot, then re-read the originally selected one so the
        device ends up on the gun it started with."""
        selected = await self.get_active_gun_index()
        guns = []
        try:
            for i in range(max_slots):
                try:
                    guns.append(await self.get_gun(i))
                except Nack as e:
                    if e.reason == 0x0B:
                        break
                    raise
        finally:
            if not guns or guns[-1]["index"] != selected:
                await self.get_gun(selected)
        return guns

    async def get_environment(self) -> dict:
        """Environment record (pushed as 0x91), scaled integers per ICD §7.6."""
        msgs = await self.request(OP_GET_ENVIRONMENT,
                                  done=lambda t, p: t == kp.T_COMMAND and _op(p) == OP_SET_ENVIRONMENT)
        e = msgs[-1][1][2:]
        i24 = lambda o: int.from_bytes(e[o:o + 3], "little", signed=True)
        return {"lat_deg": i24(9) / 1000, "temp_c": struct.unpack_from("<h", e, 14)[0] / 100,
                "pressure_hpa": i24(18) / 100, "rh_pct": struct.unpack_from("<H", e, 23)[0] / 100,
                "density_alt_m": i24(27) / 10, "raw": e}

    async def get_remote_solution(self) -> dict:
        """Live solution record (pushed as 0xa1). args = [type 0][rolling counter].
        Raises Nack(0x0c) when the device has no solution, e.g. while the
        selected gun is disabled in Manage Guns. Fields: ICD §7.8."""
        counter = self._soln_counter & 0xFF
        self._soln_counter += 1
        msgs = await self.request(OP_GET_REMOTE_SOLN, bytes([0, counter]),
                                  done=lambda t, p: t == kp.T_COMMAND and _op(p) == OP_SET_REMOTE_SOLN)
        rec = msgs[-1][1][2:]  # [type][counter echo][00][gun name, 12 B]...
        f = lambda o: struct.unpack_from("<f", rec, o)[0]
        return {"counter": rec[1], "gun_name": _cstr(rec[3:15]), "range_m": f(23),
                "dof_deg": f(27), "elev_mil": f(31), "wnd1_mil": f(35), "wnd2_mil": f(39),
                "ws1_ms": f(43), "ws2_ms": f(47), "wd_deg": f(51), "raw": rec}

    async def get_target_card(self) -> dict:
        """Target Card of the sector currently selected on the device, read the way
        the vendor app's "Pull Targets" does: TgtInfo, then CalcFullSolution
        [t][t][ff][00] for t = 0..9, each answered by one 0x8a record (ICD §7.10).
        These exact args leave the device state unchanged. Sectors cannot be selected
        or named over BLE; switch the sector on the device and call this again.
        The 0x8a record already carries the computed solution, so each target
        reports its range, the elevation/windage holds and remaining
        velocity/energy/time of flight (ICD §7.9) alongside the raw record."""
        info = await self.get_settings(SETTINGS_TGT_INFO)
        numeric = len(info) > 6 and info[6] == 1  # designator: 0 = ABC, 1 = 123
        targets = []
        for t in range(TARGET_COUNT):
            msgs = await self.request(OP_CALC_FULL_SOLN, bytes([t, t, 0xFF, 0x00]), timeout=10.0,
                                      done=lambda ty, p: ty == kp.T_COMMAND and _op(p) == OP_SET_FULL_SOLN)
            rec = msgs[-1][1][2:]
            f = lambda o: struct.unpack_from("<f", rec, o)[0]
            targets.append({
                "index": t, "label": str(t + 1) if numeric else chr(ord("A") + t),
                "range_m": struct.unpack_from("<H", rec, 2)[0] / 100,
                "elev_mil": f(11), "wnd1_mil": f(15), "wnd2_mil": f(19),
                "remv_ms": f(39), "reme_j": f(43), "tof_s": f(47), "raw": rec})
        return {"designator": "123" if numeric else "ABC", "targets": targets}


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="ELITE")
    ap.add_argument("--log", default=None,
                    help="write the full frame log here (default: private/captures/pc_client_<time>.log)")
    args = ap.parse_args()
    if args.log:
        log_path = args.log
    else:
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "private", "captures")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, f"pc_client_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")

    print(f"scanning for {args.name}…")
    dev = await BleakScanner.find_device_by_filter(
        lambda d, a: (a.local_name or d.name or "").startswith(args.name), timeout=30.0)
    if not dev:
        print("not found (another central connected? device asleep?)")
        sys.exit(1)
    async with BleakClient(dev, timeout=30.0) as client:
        k = Kestrel(BleTransport(client), log_path)
        await k.start()
        await k.authenticate()
        report = await read_all(k)
    print_summary(report, log_path)


async def read_all(k: Kestrel) -> dict:
    """Every verified read on an authenticated session (direct or HUD link)."""
    r = {"serial": await k.get_serial(), "name": await k.get_device_name(),
         "active": await k.get_active_gun_index()}
    r["guns"] = await k.get_guns()
    r["env"] = await k.get_environment()
    try:
        r["soln"] = await k.get_remote_solution()
    except Nack as e:
        r["soln"] = {"error": str(e)}
    r["card"] = await k.get_target_card()
    return r


def print_summary(r: dict, log_path: str):
    name, serial, active, guns, env, soln, card = (
        r["name"], r["serial"], r["active"], r["guns"], r["env"], r["soln"], r["card"])
    print("\n==== summary ====")
    print(f"device       {name}  serial {serial}")
    print(f"selected     slot {active}")
    for g in guns:
        print(f"gun[{g['index']:2d}]{'*' if g['index'] == active else ' '}    {g['name']:<12} "
              f"MV {g['mv_fps']:.0f} fps  BC {g['bc']:.3f}  BW {g['bw_g']:.3f} g  "
              f"BD {g['bd_mm']:.2f} mm  ZR {g['zr_m']:.0f} m  DM {g['dm']}  twist {g['twist']}  "
              f"crc {'ok' if g['crc_ok'] else 'BAD'}  {g['bullet_maker']} {g['bullet_model']}")
    print(f"environment  lat {env['lat_deg']:.3f}  {env['temp_c']:.2f} C  {env['pressure_hpa']:.2f} hPa  "
          f"RH {env['rh_pct']:.2f} %  DA {env['density_alt_m']:.1f} m")
    if "error" in soln:
        print(f"solution     unavailable: {soln['error']}")
    else:
        print(f"solution     {soln['gun_name']!r}: range {soln['range_m']:.0f} m  "
              f"elev {soln['elev_mil']:+.2f} mil (neg = up)  wnd1 {soln['wnd1_mil']:+.2f}  "
              f"wnd2 {soln['wnd2_mil']:+.2f} mil (neg = right)")
    print(f"target card  current sector, designator {card['designator']}  "
          f"(elev/wnd: neg = up/right, mil):")
    for t in card["targets"]:
        print(f"  {t['label']:<2} {t['range_m']:7.1f} m  elev {t['elev_mil']:+6.2f}  "
              f"wnd {t['wnd1_mil']:+5.2f}/{t['wnd2_mil']:+5.2f}  "
              f"RemV {t['remv_ms']:4.0f} m/s  RemE {t['reme_j']:5.0f} J  ToF {t['tof_s']:.3f} s")
    print(f"log          {os.path.normpath(log_path)}")


if __name__ == "__main__":
    asyncio.run(main())

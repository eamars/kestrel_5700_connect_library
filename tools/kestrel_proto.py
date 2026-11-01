"""Kestrel 5700 LiNK BLE protocol: framing, CRC, packets, and AES-128 crypto.

Model (verified live from a PC, see docs/ICD.md):
- Transport: HDLC 0x7e framing, 0x7d escape (byte ^ 0x20), trailing
  CRC-16/X.25 stored little-endian.
- Packet: [u16 LE type][u16 LE len][payload(len)].
    type 0 COMMAND  payload = [u16 LE opcode][args]
    type 3 RESPONSE payload = response data (no opcode)
    type 4 ACK      payload = [u16 LE opcode]
    type 5 NACK     payload = [u16 LE opcode][u16 LE reason]
- Encryption after auth: per-frame AES-128-CBC, IV=0, over
  [16 random bytes][packet][zero pad to 16]. The first block is a throwaway
  (it randomizes the ciphertext); the receiver discards it.
- Auth: Kestrel sends a 16-byte nonce; host replies with the 36-byte payload
  CBC(IV=0, [P0, nonce]) + 00000000, where P0 = ECB_dec(key, FIXED). The
  Kestrel's own reply uses a random first block, so any first block works.
"""
import os
import struct

from Crypto.Cipher import AES

KEY = bytes.fromhex("98e439ab2d999f58c1c58a7e66c7905d")
FIXED = bytes.fromhex("a7f1d92a82c8d8fe434d98558ce2b347")
P0 = AES.new(KEY, AES.MODE_ECB).decrypt(FIXED)  # ab61e698...

FLAG = 0x7E
ESC = 0x7D

T_COMMAND = 0
T_RESPONSE = 3
T_ACK = 4
T_NACK = 5

NACK_REASONS = {
    0x03: "command not supported",
    0x0A: "invalid argument / not available",
    0x0B: "index out of range",
    0x0C: "no solution available (e.g. the selected gun is disabled in Manage Guns)",
}


def crc_x25(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (crc & 1) else (crc >> 1)
    return crc ^ 0xFFFF


def gun_record_crc(stream: bytes) -> int:
    """Checksum of a gun record (ICD §7.5): CRC-16/MCRF4XX (X.25 without the final
    XOR) over stream[6:436], i.e. part-0 offset 8 through part-2 offset 3. `stream`
    is the three parts joined without their 2-byte headers; the result is stored
    little-endian at stream[436:438] (part-2 offset 4)."""
    return crc_x25(stream[6:436]) ^ 0xFFFF


def hdlc_wrap(body: bytes) -> bytes:
    crc = crc_x25(body)
    raw = body + bytes([crc & 0xFF, crc >> 8])
    out = bytearray([FLAG])
    for b in raw:
        if b in (FLAG, ESC):
            out += bytes([ESC, b ^ 0x20])
        else:
            out.append(b)
    out.append(FLAG)
    return bytes(out)


def hdlc_unwrap_all(stream: bytes):
    """Return frame bodies (CRC checked and stripped) from a raw 7e byte stream."""
    frames = []
    cur = bytearray()
    in_frame = False
    esc = False
    for b in stream:
        if b == FLAG:
            if in_frame and cur:
                raw = bytes(cur)
                if len(raw) >= 2 and crc_x25(raw[:-2]) == (raw[-2] | raw[-1] << 8):
                    frames.append(raw[:-2])
            cur = bytearray()
            in_frame = True
            esc = False
        elif not in_frame:
            continue
        elif b == ESC:
            esc = True
        else:
            cur.append(b ^ 0x20 if esc else b)
            esc = False
    return frames


def encode_packet(ptype: int, payload: bytes) -> bytes:
    return struct.pack("<HH", ptype, len(payload)) + payload


def parse_packet(msg: bytes):
    """Return (type, payload), or None if msg is too short for its length field."""
    if len(msg) < 4:
        return None
    ptype, ln = struct.unpack_from("<HH", msg)
    if 4 + ln > len(msg):
        return None
    return ptype, msg[4:4 + ln]


def is_cleartext(body: bytes) -> bool:
    return len(body) >= 4 and (body[2] | body[3] << 8) == len(body) - 4


def encrypt_packet(packet: bytes, prefix: bytes = None) -> bytes:
    """Encrypt one packet into a frame body (not yet HDLC-wrapped)."""
    buf = (prefix or os.urandom(16)) + packet
    if len(buf) % 16:
        buf += b"\x00" * (16 - len(buf) % 16)
    return AES.new(KEY, AES.MODE_CBC, b"\x00" * 16).encrypt(buf)


def decrypt_frame_body(body: bytes):
    """Decrypt one HDLC frame body (CRC already stripped). Returns the packet
    bytes (prefix removed, may carry zero padding) or None if it is not N*16."""
    if len(body) < 32 or len(body) % 16:
        return None
    pt = AES.new(KEY, AES.MODE_CBC, b"\x00" * 16).decrypt(body)
    return pt[16:]  # drop throwaway prefix block


def auth_response(nonce: bytes) -> bytes:
    """36-byte auth payload = CBC(IV=0, [P0, nonce]) + 00000000."""
    ct = AES.new(KEY, AES.MODE_CBC, b"\x00" * 16).encrypt(P0 + nonce)
    return ct + b"\x00\x00\x00\x00"


def verify_auth_reply(reply: bytes, nonce: bytes) -> bool:
    """True if the Kestrel's 36-byte reply proves it holds the key for `nonce`."""
    pt = AES.new(KEY, AES.MODE_CBC, b"\x00" * 16).decrypt(reply[:32])
    return pt[16:] == nonce

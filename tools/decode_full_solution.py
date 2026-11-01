#!/usr/bin/env python3
"""Decode Kestrel ``0x008a`` SetFullSoln records (ICD docs/ICD.md §7.9).

A ``0x008a`` record is the 90-byte ballistic solution the Kestrel pushes in
reply to ``0x0093`` CalcFullSolution. A "Pull Targets from Kestrel" (§7.10)
yields ten of them, one per Target-Card slot.

Usage::

    python tools/decode_full_solution.py CAPTURE
    python tools/decode_full_solution.py CAPTURE --raw     # full f32 dump too
    python tools/decode_full_solution.py <180-hex-chars>   # a single record

``CAPTURE`` may be:
  * a pull-targets JSON  ``{"records": {"0": "<hex>", ...}}`` (hex = the 90-byte
    payload after the ``8a00`` opcode), or
  * a ``.log``/``.txt`` transcript with lines containing ``8a00<hex>`` (the
    bytes after ``len=NN``), or
  * one or more raw 180-char hex strings on the command line.

The record layout is only partly mapped (§7.9). This tool prints the fields
that are identified, flags the ``2**32`` "unavailable" sentinel, dumps the
still-UNKNOWN f32 slots verbatim, and -- for multi-record captures -- shows
which byte ranges are constant across records vs vary per record. That
constant/varying split is the main handle on the unmapped fields: a value that
tracks range is a per-shot output, one that does not is a gun/environment
constant.
"""
import json
import re
import struct
import sys

# f32 whose value is exactly 2**32; the Kestrel uses it as "no value here".
SENTINEL = 0x4F800000

REC_LEN = 90


def f32(b, o):
    return struct.unpack_from("<f", b, o)[0]


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def i24(b, o):
    """Signed little-endian 24-bit integer at offset o (as in §7.6 latitude)."""
    v = b[o] | (b[o + 1] << 8) | (b[o + 2] << 16)
    return v - (1 << 24) if v & 0x800000 else v


def is_sentinel(b, o):
    return struct.unpack_from("<I", b, o)[0] == SENTINEL


def hold(mil, up_down=False):
    """Format a hold like the device: magnitude + direction. §7.8 sign rules:
    elevation negative = Up; windage negative = Right."""
    if mil != mil:  # NaN (value being edited on device, B-6)
        return "NaN"
    d = ("U" if mil < 0 else "D") if up_down else ("R" if mil < 0 else "L")
    return f"{abs(mil):.2f}{d}"


def decode(payload):
    """Decode one 90-byte 0x008a payload into a dict. Keys ending in '?' are
    unconfirmed; '_raw' keys are UNKNOWN slots dumped verbatim."""
    if len(payload) != REC_LEN:
        raise ValueError(f"expected {REC_LEN} bytes, got {len(payload)}")
    d = {
        # --- identified (ICD §7.9) ---------------------------------------
        "range_m": u16(payload, 2) / 100.0,              # +2  u16, cm
        "dof_deg": i24(payload, 8) / 1000.0,             # +8  i24, x0.001 deg
        "elev_mil": f32(payload, 11),                    # +11 f32 (copy §7.8)
        "wnd1_mil": f32(payload, 15),                    # +15 f32
        "wnd2_mil": f32(payload, 19),                    # +19 f32
        "ws1_ms": u16(payload, 25) / 1000.0,             # +25 u16, mm/s
        "ws2_ms": u16(payload, 27) / 1000.0,             # +27 u16, mm/s
        "wd_deg": u16(payload, 29) / 1000.0,             # +29 u16, x0.001 deg
        "lat_deg": i24(payload, 32) / 1000.0,            # +32 i24, x0.001 deg
        "remV_ms": f32(payload, 39),                     # +39 f32 m/s
        "remE_J": f32(payload, 43),                      # +43 f32 J
        "tof_s": f32(payload, 47),                       # +47 f32 s
        "target_id": payload[88],                        # +88 echo of request t
        # --- unconfirmed / unknown ---------------------------------------
        "u23_raw": u16(payload, 23),      # 0 in some records, nonzero in others
        "u31_raw": payload[31],           # 0 or 0x05 seen; meaning open
        "f35?": f32(payload, 35),         # per-target output, meaning open
        "f55?": f32(payload, 55),         # per-target output (drop candidate)
        "corr_mil?": [f32(payload, o) for o in (59, 63, 67, 71)],  # spin/coriolis/aerojump?
        "const79?": f32(payload, 79),     # constant across targets (gun/env)
        "const83?": f32(payload, 83),     # constant across targets (gun/env)
        "sentinel_51": is_sentinel(payload, 51),
        "sentinel_75": is_sentinel(payload, 75),
    }
    # Internal cross-check: RemE should equal 1/2 * m * RemV**2, so the record
    # implies a bullet mass. If it lands near a real bullet weight, RemV/RemE
    # are mutually confirmed (ICD §7.9 note).
    if d["remV_ms"]:
        m_kg = 2 * d["remE_J"] / (d["remV_ms"] ** 2)
        d["implied_bw_g"] = m_kg * 1000.0
        d["implied_bw_gr"] = m_kg * 1000.0 / 0.06479891
    return d


def print_record(key, payload, raw=False):
    d = decode(payload)
    print(f"\n--- record {key}  (target {d['target_id']}) ---")
    print(f"  range        {d['range_m']:8.1f} m")
    print(f"  DoF          {d['dof_deg']:8.1f} deg")
    print(f"  elevation    {hold(d['elev_mil'], up_down=True):>8s}  mil")
    print(f"  windage W1   {hold(d['wnd1_mil']):>8s}  mil")
    print(f"  windage W2   {hold(d['wnd2_mil']):>8s}  mil")
    print(f"  wind         WS1 {d['ws1_ms']:.1f}  WS2 {d['ws2_ms']:.1f} m/s   "
          f"dir {d['wd_deg']:.1f} deg")
    print(f"  latitude     {d['lat_deg']:8.3f} deg")
    print(f"  rem. vel     {d['remV_ms']:8.1f} m/s")
    print(f"  rem. energy  {d['remE_J']:8.1f} J     "
          f"(implies BW {d.get('implied_bw_g', 0):.2f} g / "
          f"{d.get('implied_bw_gr', 0):.0f} gr)")
    print(f"  time of flt  {d['tof_s']:8.4f} s")
    print(f"  unmapped: f35={d['f35?']:.4f}  f55={d['f55?']:.3f}  "
          f"corr(mil?)={['%.4f' % c for c in d['corr_mil?']]}")
    print(f"            const79={d['const79?']:.2f}  const83={d['const83?']:.2f}  "
          f"sentinels@51/75={d['sentinel_51']}/{d['sentinel_75']}  "
          f"u23={d['u23_raw']} u31={d['u31_raw']}")
    if raw:
        print("  raw f32 by offset:")
        for o in range(0, REC_LEN - 3):
            v = f32(payload, o)
            if struct.unpack_from("<I", payload, o)[0] == SENTINEL:
                print(f"    +{o:2d}  <sentinel 2**32>")
            elif v == v and 1e-3 < abs(v) < 1e6:
                print(f"    +{o:2d}  {v:14.5f}")


def cross_target_map(records):
    """Show which byte offsets are constant across all records vs vary.
    Constant bytes are shared inputs (wind, location, gun); varying bytes are
    per-target (range, holds, outputs)."""
    payloads = list(records.values())
    if len(payloads) < 2:
        return
    const = [all(p[i] == payloads[0][i] for p in payloads) for i in range(REC_LEN)]
    print("\n=== constant (.) vs varying (X) byte map across records ===")
    for base in range(0, REC_LEN, 30):
        row = "".join("." if const[i] else "X" for i in range(base, min(base + 30, REC_LEN)))
        print(f"  +{base:2d}: {row}")
    # Collapse into ranges for readability.
    print("  varying byte ranges:", _ranges([i for i in range(REC_LEN) if not const[i]]))


def _ranges(idxs):
    out, start = [], None
    for i in idxs + [None]:
        if start is None:
            start = prev = i
        elif i is not None and i == prev + 1:
            prev = i
        else:
            out.append(f"{start}" if start == prev else f"{start}-{prev}")
            start = prev = i
    return ", ".join(out)


def _records_from_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    recs = data.get("records", data)
    return {k: bytes.fromhex(v) for k, v in sorted(recs.items(), key=lambda kv: int(kv[0]))}


def _records_from_log(path):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    out, n = {}, 0
    for m in re.finditer(r"8a00([0-9a-fA-F]{180})", text):
        out[str(n)] = bytes.fromhex(m.group(1))
        n += 1
    return out


def load(arg):
    if re.fullmatch(r"[0-9a-fA-F]{180}", arg):
        return {"0": bytes.fromhex(arg)}
    if arg.lower().endswith(".json"):
        return _records_from_json(arg)
    return _records_from_log(arg)


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    raw = "--raw" in argv
    args = [a for a in argv if a != "--raw"]
    records = {}
    for a in args:
        records.update(load(a))
    if not records:
        print("no 0x008a records found")
        return 1
    for key, payload in records.items():
        print_record(key, payload, raw=raw)
    cross_target_map(records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

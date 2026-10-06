#!/usr/bin/env python3
"""Independent decoder for the SOA wire fixture in compression_test.go.

The five 32-bit integers in an SOA record are the ones a hand-transcribed test
gets wrong: they are pure digits with no visual anchor, so "1209600" and
"12096000" look the same in a diff and nobody notices. This script reads them
out of the fixture itself using nothing but the wire format, so the expected
value in the Go test is derived rather than typed.

RFC 1035 3.3.13:
    SOA RDATA = MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM
with the last five as 32-bit unsigned integers, in that order.

Usage:
    python3 scripts/soa-oracle.py            # print the expected value
    python3 scripts/soa-oracle.py --check    # verify the Go test agrees

Shares no code with internal/dns. That is the point: it is a second reading of
the same bytes, not the same reading twice.
"""

from __future__ import annotations

import binascii
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "internal" / "dns" / "compression_test.go"
GO_TEST = ROOT / "internal" / "dns" / "compression_test.go"

#: The five field names, in wire order, for the report.
FIELDS = ("SERIAL", "REFRESH", "RETRY", "EXPIRE", "MINIMUM")


def fixture_hex() -> str:
    """Extract the fixtureSOA hex literal from the Go source."""
    source = FIXTURE.read_text()
    match = re.search(r'fixtureSOA\s*=\s*((?:"[0-9a-fA-F]+"\s*\+?\s*)+)', source)
    if not match:
        raise SystemExit(f"fixtureSOA not found in {FIXTURE}")
    return "".join(re.findall(r'"([0-9a-fA-F]+)"', match.group(1)))


def read_name(msg: bytes, off: int) -> tuple[str, int]:
    """Decode a possibly-compressed name.

    Returns the name and the offset just past it IN THE ORIGINAL STREAM, which
    is what lets a caller keep walking the bytes that follow a compressed name.
    Compression pointers are followed with a jump limit so a crafted packet
    cannot loop forever.
    """
    labels: list[str] = []
    after = -1
    jumps = 0
    while True:
        if off >= len(msg):
            raise ValueError("name runs past the end of the message")
        length = msg[off]
        if length == 0:
            if after == -1:
                after = off + 1
            return ".".join(labels), after
        if length & 0xC0 == 0xC0:
            if after == -1:
                after = off + 2
            pointer = struct.unpack("!H", msg[off:off + 2])[0] & 0x3FFF
            jumps += 1
            if jumps > 32:
                raise ValueError("compression pointer loop")
            off = pointer
            continue
        labels.append(msg[off + 1:off + 1 + length].decode("ascii", "replace"))
        off += 1 + length


def decode_soa(hex_msg: str) -> dict:
    """Decode one SOA record out of a complete DNS response message."""
    msg = binascii.unhexlify(hex_msg)
    qdcount = struct.unpack("!H", msg[4:6])[0]

    off = 12
    for _ in range(qdcount):
        _, off = read_name(msg, off)
        off += 4  # QTYPE + QCLASS

    _, off = read_name(msg, off)  # the record's own name
    rrtype, rrclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
    off += 10
    if rrtype != 6:
        raise SystemExit(f"fixture record is type {rrtype}, not SOA (6)")

    rd_start = off
    mname, nxt = read_name(msg, rd_start)
    rname, nxt = read_name(msg, nxt)

    numeric = msg[nxt:nxt + 20]
    if len(numeric) < 20:
        raise SystemExit(f"SOA rdata holds only {len(numeric)} of the 20 numeric bytes")
    values = struct.unpack("!IIIII", numeric)

    return {
        "mname": mname,
        "rname": rname,
        "ttl": ttl,
        "rdlen": rdlen,
        "numeric_hex": numeric.hex(),
        "fields": dict(zip(FIELDS, values)),
        "value": f"{mname} {rname} " + " ".join(str(v) for v in values),
        "consumed": (nxt + 20) - rd_start,
    }


def main() -> int:
    result = decode_soa(fixture_hex())

    print(f"  MNAME = {result['mname']}")
    print(f"  RNAME = {result['rname']}")
    print(f"  {len(result['numeric_hex']) // 2} numeric bytes: {result['numeric_hex']}")
    for name, value in result["fields"].items():
        print(f"  {name:<8} = {value}")
    print(f"  consumed {result['consumed']} of {result['rdlen']} rdata bytes")
    print()
    print("full SOA value (what dig prints, and what netgraph should print):")
    print(f"  {result['value']}")

    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        source = GO_TEST.read_text()
        if result["value"] in source:
            print()
            print("OK: the Go test asserts this exact value.")
            return 0
        print()
        print(f"MISMATCH: {GO_TEST} does not assert this value.")
        print(f"  expected substring: {result['value']}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

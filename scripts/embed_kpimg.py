#!/usr/bin/env python3
"""Append the kpimg blob to a freshly linked xtc-patch binary.

Layout (read back by src/xtc-patch.c, EMB_MAGIC/EMB_TRAILER):
    <blob bytes> "XTCPKP01" <u32 blob size> <u32 pad 0>

The blob must be the device-verified build: the md5 is pinned here so a debug
or diagnostic variant (spin-entry, nomap, nosetup, ...) can never be shipped by
accident.
"""
import hashlib
import struct
import sys

CANONICAL_MD5 = "8ca5dcbbbeadb649115bbf792caf258c"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: embed_kpimg.py <binary> <kpimg blob>", file=sys.stderr)
        return 2
    exe, blob = sys.argv[1], sys.argv[2]
    data = open(blob, "rb").read()
    digest = hashlib.md5(data).hexdigest()
    if digest != CANONICAL_MD5:
        print(f"refusing to embed {blob}: md5 {digest} != {CANONICAL_MD5}", file=sys.stderr)
        return 1
    with open(exe, "ab") as f:
        f.write(data)
        f.write(b"XTCPKP01" + struct.pack("<II", len(data), 0))
    print(f"embedded {len(data)} bytes (md5 {digest})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

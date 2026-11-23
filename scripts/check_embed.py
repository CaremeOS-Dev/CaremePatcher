#!/usr/bin/env python3
"""Verify that a built binary carries the device-verified kpimg blob.

Reads the 16-byte trailer the tool itself parses (src/xtc-patch.c):
    <blob> "XTCPKP01" <u32 size> <u32 pad>
and checks the blob's size and md5 against the pinned canonical build.
"""
import hashlib
import struct
import sys

CANONICAL_MD5 = "8ca5dcbbbeadb649115bbf792caf258c"
CANONICAL_SIZE = 276252


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: check_embed.py <binary> [...]", file=sys.stderr)
        return 2
    rc = 0
    for path in sys.argv[1:]:
        data = open(path, "rb").read()
        if len(data) < 16 or data[-16:-8] != b"XTCPKP01":
            print(f"{path}: no kpimg trailer (built with NO_EMBED?)")
            rc = 1
            continue
        size = struct.unpack("<I", data[-8:-4])[0]
        blob = data[-16 - size:-16]
        digest = hashlib.md5(blob).hexdigest()
        ok = size == CANONICAL_SIZE and digest == CANONICAL_MD5
        print(f"{path}: embedded {size} bytes md5 {digest} -> {'OK' if ok else 'MISMATCH'}")
        if not ok:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())

# CaremePatcher

Standalone boot-image patcher for BBK/XTC (CaremeOS) watches — **XTCL Z9 / Z8A /
Z6DFB / Z7** and other `msm8937_32go` devices that are 32-bit only.

It takes a stock `boot.img` from one of these watches and produces a patched
image whose kernel carries the KernelPatch (AArch32 port) payload, without
touching the vendor's layout:

```
bvfix  →  kptools -p  →  AArch32 entry fix  →  zopfli  →  in-place repack
       →  decoded-size field discovery  →  14 checks  →  VERDICT: IMAGE_OK
```

## Why a separate tool

`magiskboot` repacks only header + kernel + ramdisk, so it drops what these
images actually need:

* the **kernel-slot layout** — zImage stub (21,568 B), a gzip payload slot and a
  QCDT table that follow it, all at fixed absolute offsets;
* the **vendor payload-slot tail** — the stub keeps a jump table at the very end
  of the slot (`008d9230 008d91f5 008d9248 00005440 …`); zero-filling the gap
  behind a shorter gzip stream makes the stub jump to a bogus address (measured:
  `Data Abort @ DFAR=0xFFFFC000`, then ~467 k prefetch aborts);
* the **decoded-size field** — a dword in a small metadata struct just before
  QCDT that the zImage prelude uses to relocate memory. Its offset is *not*
  fixed: Z9 4.1.0 → `0x901021`, Z9 4.1.5 → `0x90101d`, Z8A → `0x9061df`,
  Z6DFB → `0x8d99f1`, Z7 → `0x8f24a0`. Writing the wrong one leaves the prelude
  on the stock size while the image grew by the blob → hang or a ~1 s reset
  loop.

Nothing here is hardcoded to one device: page size, kernel size, the payload
slot, the size field, the `boot_vfail` branch and the entry instruction are all
derived from the image being patched (`--field`/`--no-bvfix`/`--inert` exist for
diagnosis).

## Build

The tool links KernelPatch's `kptools` in-process (`-Dmain=kptools_main`), so a
KernelPatch checkout is required — set `XTC_KP_DIR`, or keep it at
`../KernelPatch` / `third_party/KernelPatch`.

```bash
# Linux / macOS (needs zlib)
./scripts/build.sh linux                     # -> out/xtc-patch

# Windows, cross from Linux (or on a Windows box with mingw + zlib)
./scripts/build.sh windows                   # -> out/xtc-patch.exe

# Windows, native PowerShell + MinGW
powershell -File scripts\build.ps1           # -> out\xtc-patch.exe

# Android (NDK r27b), the library `boot_patch.sh` calls
./scripts/build.sh android-armv7 --ndk <ndk>  # -> out/armeabi-v7a/libxtcpatch.so
./scripts/build.sh android-arm64 --ndk <ndk>  # -> out/arm64-v8a/libxtcpatch.so
```

Every binary gets `kpimg/kpimg-canonical.bin` appended with a 16-byte trailer
(`XTCPKP01` + size), which is why `-k` is optional. `scripts/embed_kpimg.py`
refuses to embed anything whose md5 is not
`8ca5dcbbeadb649115bbf792caf258c` — the build that was verified on hardware.
`scripts/check_embed.py` re-checks the same thing on a finished binary.

## Usage

```
xtc-patch.exe <boot.img> [-o out.img] [-k kpimg] [-s superkey]
             [--packaging <img>] [--cmdline-from <img>]
             [-i <zopfli iterations>] [-t <threads>] [--field <off>]
             [--no-bvfix] [--no-kp] [--inert] [--skip-rc] [--force] [-v]
```

Patch `boot.img` from the *same* firmware build as the watch, then
`fastboot boot out.img`. Patching an image from a different firmware build is
allowed but is the usual cause of a bootloop.

The run ends with a 14-point verification and refuses to write the output unless
every check passes (`VERDICT: IMAGE_OK`).

## Verification status

* `xtc-patch.exe` built by this repo's Windows job (mingw, static) reproduces
  the host tool: patching a Z9 4.1.0 `boot.img` ends in `VERDICT: IMAGE_OK`,
  and the Android build of the same sources produced byte-identical output to
  the host tool on the device-verified image.
* The blob it embeds is the same one the manager ships
  (`8ca5dcbbeadb649115bbf792caf258c`), and KernelPatch CI pins that build by its
  `compile_time`-masked md5.

## License

GPL-2.0 — see `LICENSE`. It links KernelPatch (`kptools`, GPL-2.0) and bundles
[zopfli](https://github.com/google/zopfli) (Apache-2.0) under `third_party/`.

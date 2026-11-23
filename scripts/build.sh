#!/usr/bin/env bash
# build.sh -- build xtc-patch for linux / windows (mingw) / android one at a time.
#
#   ./scripts/build.sh linux
#   ./scripts/build.sh windows  -o out/xtc-patch.exe
#   ./scripts/build.sh android-armv7 --ndk /path/to/ndk          (libxtcpatch.so)
#
# Environment:
#   XTC_KP_DIR   KernelPatch checkout (default: ../KernelPatch, then third_party/KernelPatch)
#   CC           override the compiler
#   NO_EMBED=1   do not append the kpimg blob (diagnostics only)
#
# The KernelPatch sources are linked in-process: kptools.c is compiled with
# -Dmain=kptools_main so the tool drives it directly instead of spawning a
# child process.  zopfli is vendored under third_party/.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target=${1:-linux}
shift || true

out=""
ndk="${NDK:-}"
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out=$2; shift 2 ;;
        --ndk) ndk=$2; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# --- locate the KernelPatch checkout ------------------------------------
kp="${XTC_KP_DIR:-}"
if [ -z "$kp" ]; then
    for cand in "$root/../KernelPatch" "$root/third_party/KernelPatch"; do
        [ -d "$cand/tools" ] && { kp=$(cd "$cand" && pwd); break; }
    done
fi
[ -n "$kp" ] && [ -d "$kp/tools" ] || {
    echo "KernelPatch checkout not found; set XTC_KP_DIR" >&2; exit 1; }
zop="$root/third_party/zopfli"
blob="$root/kpimg/kpimg-canonical.bin"
[ -f "$zop/zopfli.h" ] || { echo "third_party/zopfli missing" >&2; exit 1; }

inc=(-I"$root/src" -I"$kp/tools" -I"$zop" -I"$kp/tools/lib/sha"
     -I"$kp/tools/lib/bz2" -I"$kp/tools/lib/lz4" -I"$kp/tools/lib/xz")

sources=()
while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    sources+=("$kp/tools/$line")
done < "$root/scripts/kptools_sources.txt"

for f in "$zop"/*.c; do
    [ "$(basename "$f")" = "zgzip.c" ] && continue
    sources+=("$f")
done

mkdir -p "$root/out"

case "$target" in
linux)
    cc=${CC:-cc}
    : "${out:=$root/out/xtc-patch}"
    extra=(-O2 -w)
    libs=(-lz -lm -pthread)
    defs=()
    ;;
windows)
    cc=${CC:-x86_64-w64-mingw32-gcc}
    : "${out:=$root/out/xtc-patch.exe}"
    extra=(-O2 -w)
    libs=(-lz -lm -static)
    defs=()
    ;;
android-armv7|android-arm64)
    [ -n "$ndk" ] || { echo "pass --ndk <path>" >&2; exit 2; }
    tc="$ndk/toolchains/llvm/prebuilt/linux-x86_64"
    [ -d "$tc" ] || tc="$ndk/toolchains/llvm/prebuilt/windows-x86_64"
    cc="${CC:-$tc/bin/clang}"
    abi=armeabi-v7a; tgt=armv7a-linux-androideabi27
    [ "$target" = "android-arm64" ] && { abi=arm64-v8a; tgt=aarch64-linux-android27; }
    : "${out:=$root/out/$abi/libxtcpatch.so}"
    extra=(-O2 -w --target="$tgt" --sysroot="$tc/sysroot" -fPIE -pie)
    libs=(-lm -pthread)
    defs=(-DXTC_NO_ZLIB)
    sources+=("$root/src/zlib_stub.c")
    ;;
*)
    echo "unknown target: $target" >&2; exit 2 ;;
esac

objdir=$(mktemp -d)
trap 'rm -rf "$objdir"' EXIT

echo "[1/3] kptools.c (main -> kptools_main)"
"$cc" "${extra[@]}" "${defs[@]}" "${inc[@]}" -Dmain=kptools_main \
      -c "$kp/tools/kptools.c" -o "$objdir/kptools_main.o"

echo "[2/3] linking $target -> $out"
mkdir -p "$(dirname "$out")"
"$cc" "${extra[@]}" "${defs[@]}" "${inc[@]}" \
      -o "$out" "$root/src/xtc-patch.c" "$root/src/xtc_zopfli_parallel.c" \
      "${sources[@]}" "$objdir/kptools_main.o" "${libs[@]}"

if [ "${NO_EMBED:-0}" != "1" ]; then
    echo "[3/3] appending kpimg blob"
    python3 "$root/scripts/embed_kpimg.py" "$out" "$blob"
else
    echo "[3/3] skipped (NO_EMBED=1)"
fi

ls -l "$out"
md5sum "$out" 2>/dev/null || md5 "$out"

/*
 * xtc-patch -- portable Windows patcher for XTC Z-series ARM32 boot images.
 *
 * Self-contained single EXE (MinGW, statically linked): no Python, no WSL and
 * no external tools.  Reproduces the verified b6_build_v5.py +
 * finalize_0139_image.py pipeline byte-for-byte:
 *
 *   1. probe the base boot image     (ANDROID! v0, page 2048, zImage + gzip)
 *   2. decode the kernel Image       (gzip -> raw Image)
 *   3. bvfix                         (defeat the BBK "boot_vfail" reboot check)
 *   4. KernelPatch                   (in-process kptools -p: superkey + kpimg)
 *   5. AArch32 entry fix             (word0 = EB04352E, word1 -> blob entry)
 *   6. recompress with zopfli        (same encoder/options as repack_boot_img2.py)
 *   7. in-place repack               (payload must fit the stock slot, so the
 *                                     kernel slot, ramdisk offset and vendor
 *                                     vbmeta block keep their absolute offsets)
 *   8. trailer restore + decoded-size field
 *   9. 12-point verification         (VERDICT: IMAGE_OK)
 *
 * The kpimg blob is appended to the EXE at build time (16-byte trailer magic
 * "XTCPKP01" + size), so -k is optional.  -b/-o/-s are all overridable.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#ifndef XTC_NO_ZLIB
#include "zlib.h"                                   /* inflate the stock payload */
#endif
#include "zopfli.h"                                 /* byte-exact gzip encoder   */
#include "sha1.h"

int kptools_main(int argc, char **argv);            /* tools/kptools.c, renamed  */

#define PAGE          2048u
#define MAGIC_ZIMAGE  0x016F2818u
#define EMB_MAGIC     "XTCPKP01"
#define EMB_TRAILER   16
#define DEFAULT_SUPERKEY "3yFqpYXCTcxoHE3"
/* md5 of the boot image the XTC Z9 ARM32 port was verified against
 * (kernel banner "Linux version 4.9.193-perf ... Fri Apr 3 20:52:23").  Patching
 * a DIFFERENT build is allowed but is the usual cause of a bootloop, because the
 * kernel then does not match the rest of the firmware on the device. */

static int g_verbose;
static int g_iters = 0;          /* zopfli iterations, 0 = build default */
static int g_threads = 0;        /* 0 = auto (chunked encoder only) */
static size_t g_img_size = 0;     /* output image size, taken from the base file */
static size_t g_field_off = 0;   /* --field: force the decoded-size field offset */
static int g_no_bvfix = 0;       /* --no-bvfix: diagnose, skip the boot_vfail patch */
static int g_no_kp = 0;           /* --no-kp: diagnose, only bvfix + repack */
static int g_skip_rc = 0;         /* --skip-rc: old blobs have no rc template */
static int g_inert = 0;           /* --inert: append the blob but never execute it */

/* ------------------------------------------------------------------ utils -- */
static unsigned char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *b;
    long n;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    b = (unsigned char *)malloc(n ? (size_t)n : 1);
    if (!b) { fclose(f); return NULL; }
    if (n && fread(b, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(b); return NULL; }
    fclose(f);
    *out_len = (size_t)n;
    return b;
}

static int write_file(const char *path, const void *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (len && fwrite(buf, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

static uint32_t rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32(unsigned char *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static const char *base_name(const char *p)
{
    const char *s, *r = p;
    for (s = p; *s; s++) if (*s == '\\' || *s == '/') r = s + 1;
    return r;
}

/* -------------------------------------------------------------------- md5 -- */
typedef struct { uint32_t h[4]; uint64_t n; unsigned char buf[64]; size_t bl; } md5_ctx;
#define ROL(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
static void md5_init(md5_ctx *c)
{
    c->h[0] = 0x67452301u; c->h[1] = 0xefcdab89u;
    c->h[2] = 0x98badcfeu; c->h[3] = 0x10325476u;
    c->n = 0; c->bl = 0;
}
static void md5_block(md5_ctx *c, const unsigned char *p)
{
    static const uint32_t K[64] = {
        0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
        0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
        0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
        0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
        0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
        0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
        0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
        0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u };
    static const unsigned char S[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
    uint32_t m[16], a, b, cc, d, f, t;
    int i, g;
    for (i = 0; i < 16; i++) m[i] = rd32(p + i * 4);
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    for (i = 0; i < 64; i++) {
        if (i < 16)      { f = (b & cc) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & cc); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ cc ^ d;          g = (3 * i + 5) & 15; }
        else             { f = cc ^ (b | ~d);       g = (7 * i) & 15; }
        t = d; d = cc; cc = b;
        b = b + ROL(a + f + K[i] + m[g], S[i]);
        a = t;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
}
static void md5_update(md5_ctx *c, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    c->n += len;
    if (c->bl) {
        size_t k = 64 - c->bl;
        if (k > len) k = len;
        memcpy(c->buf + c->bl, p, k);
        c->bl += k; p += k; len -= k;
        if (c->bl == 64) { md5_block(c, c->buf); c->bl = 0; }
    }
    while (len >= 64) { md5_block(c, p); p += 64; len -= 64; }
    if (len) { memcpy(c->buf, p, len); c->bl = len; }
}
static void md5_final(md5_ctx *c, unsigned char out[16])
{
    unsigned char pad[72];
    uint64_t bits = c->n * 8;
    size_t padlen = (c->bl < 56) ? (56 - c->bl) : (120 - c->bl);
    int i;
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    md5_update(c, pad, padlen);
    for (i = 0; i < 8; i++) pad[i] = (unsigned char)(bits >> (8 * i));
    md5_update(c, pad, 8);
    for (i = 0; i < 4; i++) {
        out[i * 4 + 0] = (unsigned char)(c->h[i]);
        out[i * 4 + 1] = (unsigned char)(c->h[i] >> 8);
        out[i * 4 + 2] = (unsigned char)(c->h[i] >> 16);
        out[i * 4 + 3] = (unsigned char)(c->h[i] >> 24);
    }
}
static void md5_hex(const void *data, size_t len, char out[33])
{
    md5_ctx c; unsigned char d[16]; int i;
    md5_init(&c);
    md5_update(&c, data, len);
    md5_final(&c, d);
    for (i = 0; i < 16; i++) sprintf(out + i * 2, "%02x", d[i]);
    out[32] = 0;
}

/* ------------------------------------------------------------------ bvfix -- */
#define VA_BASE 0xC0008000UL
static const char *BV_STRINGS[3] = { "boot_vfail", "verify success", "qpnp_pon" };
static size_t g_bvfix_site = 0;      /* offset bvfix actually patched */
static uint32_t g_bvfix_old = 0, g_bvfix_new = 0;  /* recorded words for verification */

static int bvfix_apply(unsigned char *b, size_t n)
{
    size_t minp = (size_t)-1, maxp = 0, lo, hi, wn, w, best = 0, second = 0;
    int i, best_sc = -1, second_sc = -1, ncand = 0;

    for (i = 0; i < 3; i++) {
        size_t nl = strlen(BV_STRINGS[i]), p;
        for (p = 0; p + nl <= n; p++)
            if (memcmp(b + p, BV_STRINGS[i], nl) == 0) {
                if (p < minp) minp = p;
                if (p > maxp) maxp = p;
            }
    }
    if (minp == (size_t)-1) { printf("  bvfix: anchors not found (not an XTC/BBK kernel)\n"); return -1; }
    lo = minp > 0x800 ? minp - 0x800 : 0;
    hi = maxp + 0x800;
    wn = n / 4;

    for (w = 0; w + 2 <= wn; w++) {
        uint32_t cw = rd32(b + w * 4), nw;
        int sc, bl = 0, nstr = 0;
        size_t j, start;
        if ((cw & 0xFFF0FFFFu) != 0xE350003Au) continue;              /* cmp rN,#0x3a */
        nw = rd32(b + (w + 1) * 4);
        if ((nw & 0x0F000000u) != 0x0A000000u) continue;              /* cond. branch */
        ncand++;
        start = w > 16 ? w - 16 : 0;
        for (j = start; j < w + 8 && j < wn; j++) {
            uint32_t x = rd32(b + j * 4), rd, lo16, k;
            if ((x & 0xFFF00000u) != 0xE3000000u) continue;
            rd = (x >> 12) & 0xF;
            lo16 = (((x >> 16) & 0xF) << 12) | (x & 0xFFF);
            for (k = j + 1; k < j + 5 && k < wn; k++) {
                uint32_t x2 = rd32(b + k * 4);
                if ((x2 & 0xFFF00000u) == 0xE3400000u && ((x2 >> 12) & 0xF) == rd) {
                    unsigned long addr = ((unsigned long)((((x2 >> 16) & 0xF) << 12) | (x2 & 0xFFF)) << 16) | lo16;
                    if (addr >= VA_BASE) {
                        unsigned long off = addr - VA_BASE;
                        if (off >= lo && off <= hi) nstr++;
                    }
                    break;
                }
            }
        }
        for (j = w + 2; j < w + 8 && j < wn; j++)
            if ((rd32(b + j * 4) & 0x0F000000u) == 0x0B000000u) { bl = 1; break; }
        sc = nstr * 3 + (bl ? 3 : 0);
        if (g_verbose)
            printf("  bvfix: cmp@0x%lx branch@0x%lx score=%d bl=%d str=%d\n",
                   (unsigned long)(w * 4), (unsigned long)(w * 4 + 4), sc, bl, nstr);
        if (sc > best_sc) { second_sc = best_sc; second = best; best_sc = sc; best = w * 4; }
        else if (sc > second_sc) { second_sc = sc; second = w * 4; }
    }
    if (!ncand) { printf("  bvfix: no cmp#0x3a + conditional-branch site\n"); return -1; }
    if (ncand > 1 && best_sc - second_sc < 3) {
        printf("  bvfix: ambiguous site (margin %d < 3)\n", best_sc - second_sc);
        return -1;
    }
    {
        uint32_t oldw = rd32(b + best + 4);
        uint32_t neww = (oldw & 0x0FFFFFFFu) | 0xE0000000u;
        wr32(b + best + 4, neww);
        g_bvfix_site = best + 4;              /* verify these exact words later */
        g_bvfix_old = oldw;
        g_bvfix_new = neww;
        printf("  bvfix: cmp@0x%lx branch@0x%lx  0x%08x -> 0x%08x  (%d candidate(s))\n",
               (unsigned long)best, (unsigned long)(best + 4),
               (unsigned)oldw, (unsigned)neww, ncand);
    }
    return (int)best;
}

/* Print the build stamp carried by the boot image's kernel cmdline, e.g.
 *   appjenkins=1361 modemjenkins = 128
 * A base whose stamp differs from the device's own firmware is the classic
 * cause of a bootloop: the kernel is from another CI build. */
static void print_build_stamp(const unsigned char *b, size_t len)
{
    char cmd[513];
    const char *aj, *mj;
    if (len < 0x240) return;
    memcpy(cmd, b + 0x40, 512);
    cmd[512] = 0;
    aj = strstr(cmd, "appjenkins=");
    mj = strstr(cmd, "modemjenkins");
    printf("  build: ");
    if (aj) {
        int n = 0;
        const char *p = aj + 11;
        printf("appjenkins=");
        while (p[n] && p[n] != ' ' && n < 12) { putchar(p[n]); n++; }
    } else {
        printf("appjenkins=<none>");
    }
    if (mj) {
        int n = 0;
        const char *p = strchr(mj, '=');
        if (p) {
            p++;
            while (*p == ' ') p++;
            printf("  modemjenkins=");
            while (p[n] && p[n] != ' ' && n < 12) { putchar(p[n]); n++; }
        }
    }
    printf("   (reference image: appjenkins=1361 modemjenkins=128)\n");
}

/* ------------------------------------------------------------ boot probing -- */
typedef struct {
    size_t size;
    uint32_t page, ks, rs, ss, ka, ra, tags;
    size_t region_off, gz_off, zend, slot, qcdt_len;
    size_t field_off;            /* discovered decoded-size field, 0 if unknown */
} boot_info;

static int boot_probe(const unsigned char *b, size_t n, boot_info *o)
{
    size_t i;
    memset(o, 0, sizeof(*o));
    o->size = n;
    if (n < 4096) {
        printf("ERROR: image is only %zu bytes\n", n);
        return -1;
    }
    if (memcmp(b, "ANDROID!", 8) != 0) {
        printf("ERROR: not an Android boot image (missing ANDROID! header)\n");
        return -1;
    }
    o->page = rd32(b + 36);
    o->ks   = rd32(b + 8);
    o->rs   = rd32(b + 16);
    o->ss   = rd32(b + 24);
    o->ka   = rd32(b + 12);
    o->ra   = rd32(b + 20);
    o->tags = rd32(b + 32);
    /* every layout parameter comes from the image itself: page size must be a
     * power of two, the file must be a whole number of pages, and the declared
     * regions must fit.  No assumption about 2048 or 32 MiB. */
    if (o->page < 512 || (o->page & (o->page - 1)) != 0) {
        printf("ERROR: implausible page size %u\n", o->page);
        return -1;
    }
    if (n % o->page != 0) {
        printf("ERROR: image size %zu is not a multiple of the page size %u\n", n, o->page);
        return -1;
    }
    if (o->ss != 0) { printf("ERROR: second stage present (unsupported layout)\n"); return -1; }
    o->region_off = o->page;
    if (o->region_off + o->ks > n) { printf("ERROR: kernel_size out of range\n"); return -1; }
    if (rd32(b + o->region_off + 0x24) != MAGIC_ZIMAGE) {
        printf("ERROR: kernel region is not an ARM zImage (magic @0x24 mismatch)\n");
        return -1;
    }
    for (i = 0; i + 3 < o->ks; i++) {
        const unsigned char *p = b + o->region_off + i;
        if (p[0] == 0x1F && p[1] == 0x8B && p[2] == 0x08) { o->gz_off = i; break; }
    }
    if (!o->gz_off) { printf("ERROR: no gzip kernel payload found\n"); return -1; }
    o->zend = rd32(b + o->region_off + 0x2C);
    if (o->zend <= o->gz_off || o->zend > o->ks) { printf("ERROR: zImage 'end' field out of range\n"); return -1; }
    o->slot = o->zend - o->gz_off;
    o->qcdt_len = o->ks - o->zend;
    printf("  header : page=%u kernel_size=0x%x ramdisk_size=0x%x kernel_addr=0x%x ramdisk_addr=0x%x tags=0x%x\n",
           o->page, o->ks, o->rs, o->ka, o->ra, o->tags);
    printf("  kernel : stub 0x%zx | payload slot 0x%zx | qcdt 0x%zx (zImage end 0x%zx)\n",
           o->gz_off, o->slot, o->qcdt_len, o->zend);
    return 0;
}

static unsigned char *gunzip_all(const unsigned char *src, size_t slen, size_t *out_len)
{
#ifndef XTC_NO_ZLIB
    z_stream zs;
    size_t cap = 32u << 20, have = 0;
    unsigned char *out = (unsigned char *)malloc(cap);
    int rc;
    if (!out) return NULL;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) { free(out); return NULL; }
    zs.next_in = (Bytef *)src;
    zs.avail_in = (uInt)slen;
    for (;;) {
        if (have == cap) {
            unsigned char *n2;
            cap *= 2;
            n2 = (unsigned char *)realloc(out, cap);
            if (!n2) { inflateEnd(&zs); free(out); return NULL; }
            out = n2;
        }
        zs.next_out = out + have;
        zs.avail_out = (uInt)(cap - have);
        rc = inflate(&zs, Z_NO_FLUSH);
        have = cap - zs.avail_out;
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK) { inflateEnd(&zs); free(out); return NULL; }
    }
    inflateEnd(&zs);
    *out_len = have;
    return out;
#else
    (void)src; (void)slen; (void)out_len;
    return NULL;
#endif
}

/* --------------------------------------------------------------- embedded --- */
static unsigned char *load_embedded_kpimg(const char *exe, size_t *len)
{
    size_t n = 0;
    unsigned char *me = read_file(exe, &n);
    unsigned char *kp = NULL;
    uint32_t sz;
    if (!me) return NULL;
    if (n > EMB_TRAILER + 4 && memcmp(me + n - EMB_TRAILER, EMB_MAGIC, 8) == 0) {
        sz = rd32(me + n - EMB_TRAILER + 8);
        if (sz && n >= (size_t)EMB_TRAILER + sz) {
            kp = (unsigned char *)malloc(sz);
            if (kp) {
                memcpy(kp, me + n - EMB_TRAILER - sz, sz);
                *len = sz;
            }
        }
    }
    free(me);
    return kp;
}

/* ------------------------------------------------------------------ verify -- */
/* The vendor appends a small metadata struct right after the compressed kernel
 * stream (just before QCDT).  Its FIRST dword is the decompressed kernel size,
 * and the zImage prelude references it by absolute offset.  That offset is NOT
 * fixed across firmware builds:
 *     4.1.0 -> 0x901021        4.1.5 -> 0x90101d   (4 bytes earlier)
 * Writing the wrong one leaves the real field stale while the decompressed
 * image is bigger, and the prelude then relocates memory with the old size:
 * a small delta hangs, a large delta resets the board.  So discover the field
 * instead of hardcoding it: scan back from the QCDT start for a dword equal to
 * the base's own decoded length. */
static size_t find_size_field(const unsigned char *img, const boot_info *bi, size_t dec_len)
{
    size_t qcdt = bi->region_off + bi->zend;
    size_t lo = qcdt > 0x400 ? qcdt - 0x400 : 0;
    size_t i, hit = 0;
    for (i = lo; i + 4 <= qcdt; i++)
        if (rd32(img + i) == (uint32_t)dec_len) hit = i;   /* keep the last one */
    return hit;
}

static int verify_image(const unsigned char *img, const boot_info *bi,
                        const unsigned char *base, const unsigned char *kp, size_t kp_len,
                        const unsigned char *patched, size_t plen,
                        const char *superkey)
{
    int ok = 1;
    unsigned char *dec = NULL;
    size_t dec_len = 0;

#define CHK(name, cond, extra) do { \
        if (!(cond)) ok = 0; \
        printf("  [%s] %-34s %s\n", (cond) ? "OK" : "XX", name, extra); \
    } while (0)

    CHK("total size == base size", bi->size == g_img_size, "");
    CHK("header ANDROID!", !memcmp(img, "ANDROID!", 8), "");
    CHK("page_size == base page", rd32(img + 36) == bi->page, "");
    CHK("kernel_size unchanged", rd32(img + 8) == bi->ks, "");
    dec = gunzip_all(img + bi->region_off + bi->gz_off, rd32(img + bi->region_off + 0x2C) - bi->gz_off, &dec_len);
#ifdef XTC_NO_ZLIB
    /* built without zlib (Android): magiskboot already hands us the raw Image, so the
     * compressed payload cannot be re-inflated here.  The structural checks below
     * still run; the round-trip check is skipped with an explicit note. */
    printf("  [--] payload round-trip check        skipped (built without zlib)\n");
#else
    {
        char buf[96];
        snprintf(buf, sizeof(buf), "%zu bytes", dec_len);
        CHK("payload gunzips", dec != NULL, buf);
    }
#endif
    {
        /* The checks below inspect the decoded kernel.  Android builds have no zlib,
         * so the payload cannot be re-inflated there -- but the raw Image kptools
         * produced IS that kernel, so verify it instead of skipping every check
         * (with -O2 the old `if (dec)` guard made clang delete the whole block). */
        const unsigned char *decoded = dec ? dec : patched;
        size_t decoded_len = dec ? dec_len : plen;
        char buf[96];
        if (dec) {
            snprintf(buf, sizeof(buf), "%zu vs %zu", dec_len, plen);
            CHK("decoded == patched Image", dec_len == plen && !memcmp(dec, patched, plen), buf);
        }
        snprintf(buf, sizeof(buf), "0x%08x -> 0x%08x @0x%zx", g_bvfix_old, g_bvfix_new, g_bvfix_site);
        if (g_no_bvfix) {
            CHK("bvfix skipped (--no-bvfix)", 1, buf);
        } else {
                        CHK("bvfix: unconditional B to the same target",
                g_bvfix_site && rd32(decoded + g_bvfix_site) == g_bvfix_new &&
                (g_bvfix_new >> 24) == 0xEA &&
                ((g_bvfix_new ^ g_bvfix_old) & 0x00FFFFFFu) == 0, buf);
        }
        snprintf(buf, sizeof(buf), "%02x%02x%02x%02x", decoded[0], decoded[1], decoded[2], decoded[3]);
        if (g_no_kp) {
            CHK("entry untouched (--no-kp)", 1, buf);
        } else {
            if (g_inert) CHK("entry untouched (--inert)", 1, buf);
        else CHK("entry word1 is an A32 B", ((rd32(decoded + 4) >> 24) & 0x0F) == 0xA, buf);
        }
        {
            size_t i, cnt = 0;
            for (i = 0; i + 6 <= decoded_len; i++) if (!memcmp(decoded + i, "KP1158", 6)) cnt++;
            snprintf(buf, sizeof(buf), "count=%zu", cnt);
            CHK(g_no_kp ? "NO KP blob (--no-kp)" : "exactly ONE KP1158",
                g_no_kp ? (cnt == 0) : (cnt == 1), buf);
        }
        if (!g_no_kp) {
            /* The blob carries the rc template with a literal "%s"; the superkey
             * hash (not the plain key) is what kptools bakes into the preset page.
             * This mirrors b6_build_v5.py's check exactly. */
            static const char *tmpl = "/system/bin/truncate %s -Z";
            size_t need = strlen(tmpl), i2;
            int found = 0;
            for (i2 = 0; i2 + need <= decoded_len; i2++)
                if (!memcmp(decoded + i2, tmpl, need)) { found = 1; break; }
            if (g_skip_rc) CHK("rc template present (skipped --skip-rc)", 1, tmpl);
            else CHK("rc template present", found, tmpl);
            found = 0;
            for (i2 = 0; i2 + 12 <= decoded_len; i2++)
                if (!memcmp(decoded + i2, "truncate su ", 12)) { found = 1; break; }
            CHK("no 'truncate su ' left", !found, "");
        }
        if (!g_no_kp) {
            size_t blob = 0, i2;
            for (i2 = 0; i2 + 4 <= decoded_len; i2++) if (!memcmp(decoded + i2, "KP11", 4)) { blob = i2; break; }
            if (!blob) CHK("blob present", 0, "not found");
            else {
                char buf[96];
                size_t diffs = 0, first = 0, last = 0;
                for (i2 = 0; i2 < kp_len && blob + i2 < decoded_len; i2++) {
                    if (decoded[blob + i2] != kp[i2]) {
                        if (!diffs) first = i2;
                        last = i2;
                        diffs++;
                    }
                }
                snprintf(buf, sizeof(buf), "%zu diffs within 0x%zx..0x%zx", diffs, first, last);
                CHK("blob == source (preset page only)", diffs == 0 || last < bi->page, buf);
            }
        }
        snprintf(buf, sizeof(buf), "%zu bytes @0x%zx", bi->rs,
                 ((bi->page + bi->ks + bi->page - 1) / bi->page) * bi->page);
        CHK("ramdisk identical to base",
            !memcmp(img + ((bi->page + bi->ks + bi->page - 1) / bi->page) * bi->page,
                    base + ((bi->page + bi->ks + bi->page - 1) / bi->page) * bi->page, bi->rs), buf);
        {
            char buf2[96];
            size_t fo = bi->field_off;
            snprintf(buf2, sizeof(buf2), "%zu vs %zu (field@0x%zx)", (size_t)rd32(img + fo), decoded_len, fo);
            CHK("decoded-size field", rd32(img + fo) == (uint32_t)decoded_len, buf2);
        }
        free(dec);
    }
    return ok;
#undef CHK
}

/* -------------------------------------------------------------------- main -- */
static void usage(void)
{
    printf(
        "xtc-patch -- XTC Z-series ARM32 boot image patcher (KernelPatch 0.13.9)\n"
        "\n"
        "usage: xtc-patch.exe [boot.img] [-o out.img] [-k kpimg] [-s superkey]\n"
        "                     [--packaging <img>] [--cmdline-from <img>]\n"
        "                     [--force] [-v] [-h]\n"
        "\n"
        "  -b, --boot <img>     boot image to patch (or pass it directly; default\n"
        "                       new-boot.img next to this exe)\n"
        "  -o, --out  <img>     output image (default <boot>-kp-<stamp>.img)\n"
        "  -k, --kpimg <blob>   ARM32 kpimg blob (default: embedded in this exe)\n"
        "  -s, --superkey <key> root superkey (default %s)\n"
        "      --packaging <img>  take the boot container (header / zImage stub /\n"
        "                       QCDT / ramdisk / vendor tail) from this image\n"
        "                       instead of the target.  Needed when a newer\n"
        "                       firmware's container refuses a patched kernel.\n"
        "      --cmdline-from <img> take the kernel cmdline from this image\n"
        "                       (default: the target, so the build stamps match\n"
        "                       the firmware being targeted)\n"
        "      --image <raw>    patch this already-decompressed kernel Image and use\n"
        "                       -b/--boot only for the container layout (used on\n"
        "                       Android, where magiskboot does the decompression)\n"
        "      --force          patch even if the target already carries a KP blob\n"
        "  -v, --verbose        show bvfix candidates and per-check detail\n"
        "  -h, --help           this text\n"
        "\n"
        "The output keeps the stock layout (kernel slot, ramdisk offset and the\n"
        "vendor vbmeta block stay at their absolute offsets), so it boots exactly\n"
        "like the stock image.  Nothing is flashed.\n", DEFAULT_SUPERKEY);
}

int main(int argc, char **argv)
{
    const char *boot = NULL, *out = NULL, *kpimg = NULL, *superkey = DEFAULT_SUPERKEY;
    const char *packaging = NULL, *cmdline_from = NULL, *raw_image = NULL;
    int force = 0, i, rc = 1;
    unsigned char *base = NULL, *pkg = NULL, *cmd = NULL;
    unsigned char *dec = NULL, *kp = NULL, *img = NULL, *patched = NULL;
    size_t base_len = 0, pkg_len = 0, cmd_len = 0, dec_len = 0, kp_len = 0, plen = 0;
    boot_info bi, ti;
    unsigned char *stub = NULL, *qcdt = NULL;
    char md5s[33], outbuf[1200];

    setvbuf(stdout, NULL, _IONBF, 0);
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(); return 0; }
        else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) g_verbose = 1;
        else if (!strcmp(a, "--force")) force = 1;
        else if ((!strcmp(a, "-b") || !strcmp(a, "--boot")) && i + 1 < argc) boot = argv[++i];
        else if ((!strcmp(a, "-o") || !strcmp(a, "--out")) && i + 1 < argc) out = argv[++i];
        else if ((!strcmp(a, "-k") || !strcmp(a, "--kpimg")) && i + 1 < argc) kpimg = argv[++i];
        else if ((!strcmp(a, "-s") || !strcmp(a, "--superkey")) && i + 1 < argc) superkey = argv[++i];
        else if (!strcmp(a, "--packaging") && i + 1 < argc) packaging = argv[++i];
        else if (!strcmp(a, "--cmdline-from") && i + 1 < argc) cmdline_from = argv[++i];
        else if (!strcmp(a, "--image") && i + 1 < argc) raw_image = argv[++i];
        else if ((!strcmp(a, "-i") || !strcmp(a, "--iters")) && i + 1 < argc) g_iters = atoi(argv[++i]);
        else if ((!strcmp(a, "-t") || !strcmp(a, "--threads")) && i + 1 < argc) g_threads = atoi(argv[++i]);
        else if (!strcmp(a, "--field") && i + 1 < argc) g_field_off = (size_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--no-bvfix")) g_no_bvfix = 1;
        else if (!strcmp(a, "--no-kp")) g_no_kp = 1;
        else if (!strcmp(a, "--skip-rc")) g_skip_rc = 1;
        else if (!strcmp(a, "--inert")) g_inert = 1;
        else if (a[0] != '-' && !boot) boot = a;
        else { printf("unknown option: %s\n\n", a); usage(); return 2; }
    }

    printf("xtc-patch  KernelPatch 0.13.9 / ARM32   (b6+finalize equivalent)\n");
    printf("----------------------------------------------------------------\n");

    if (!boot) boot = "new-boot.img";
    base = read_file(boot, &base_len);
    if (!base) { printf("ERROR: cannot open boot image: %s\n", boot); return 1; }
    g_img_size = base_len;    /* nothing below assumes a fixed 32 MiB */
    md5_hex(base, base_len, md5s);
    printf("  boot : %s\n  size : %zu bytes  md5 %s\n", boot, base_len, md5s);
    print_build_stamp(base, base_len);
    /* No reference-image table: every layout parameter is discovered from this
     * file.  What matters is that the base really comes from the device's own
     * firmware -- the build stamp above is the thing to compare. */
    printf("  base : layout will be probed from this image (no hardcoded offsets)\n");

    /* ---- optional cross-version packaging ---- */
    if (packaging) {
        pkg = read_file(packaging, &pkg_len);
        if (!pkg) { printf("ERROR: cannot open packaging image: %s\n", packaging); goto done; }
        md5_hex(pkg, pkg_len, md5s);
        printf("  pack : %s\n  size : %zu bytes  md5 %s\n", packaging, pkg_len, md5s);
        if (pkg_len != base_len) {
            printf("ERROR: packaging image is %zu bytes, target base is %zu bytes\n", pkg_len, base_len);
            goto done;
        }
    }
    if (cmdline_from) {
        cmd = read_file(cmdline_from, &cmd_len);
        if (!cmd || cmd_len < 0x240) {
            printf("ERROR: cannot use %s as cmdline source\n", cmdline_from);
            goto done;
        }
    }

    printf("\n[1] probing boot image\n");
    /* The layout (kernel slot, stub, QCDT, ramdisk, tail) comes from the
     * packaging image; the kernel payload and the cmdline come from the target
     * image.  Without --packaging both are the same file. */
    if (boot_probe(base, base_len, &ti) != 0) goto done;
    if (packaging && pkg) {
        if (boot_probe(pkg, pkg_len, &bi) != 0) goto done;
        printf("  packaging layout taken from: %s\n", packaging);
        printf("  kernel payload taken from  : %s\n", boot);
        if (ti.ks != bi.ks)
            printf("  note: kernel_size differs (target 0x%x / packaging 0x%x); "
                   "the packaging value wins\n", ti.ks, bi.ks);
    } else {
        bi = ti;
    }

    if (raw_image) {
        /* Android path: magiskboot already decompressed the kernel for us. */
        size_t rlen = 0;
        unsigned char *rbuf = read_file(raw_image, &rlen);
        if (!rbuf) { printf("ERROR: cannot read raw Image: %s\n", raw_image); goto done; }
        dec = rbuf;
        dec_len = rlen;
        printf("  raw Image  : %s (%zu bytes)\n", raw_image, dec_len);
    } else {
        dec = gunzip_all(base + ti.region_off + ti.gz_off, ti.zend - ti.gz_off, &dec_len);
        if (!dec) { printf("ERROR: kernel payload does not gunzip\n"); goto done; }
        printf("  decoded kernel Image: %zu bytes\n", dec_len);
    }

    /* resolve the decoded-size field for the image whose layout we will write */
    if (g_field_off) {
        bi.field_off = g_field_off;
        printf("  decoded-size field forced to 0x%zx (--field)\n", g_field_off);
    } else {
        size_t tfo = find_size_field(base, &ti, dec_len);
        if (packaging && pkg) {
            unsigned char *pdec = NULL; size_t pdec_len = 0;
            if (raw_image) {
                /* the packaging image is the layout source and is still compressed */
                pdec = gunzip_all(pkg + bi.region_off + bi.gz_off, bi.zend - bi.gz_off, &pdec_len);
            } else {
                pdec = gunzip_all(pkg + bi.region_off + bi.gz_off, bi.zend - bi.gz_off, &pdec_len);
            }
            if (!pdec) { printf("ERROR: packaging kernel payload does not gunzip\n"); goto done; }
            bi.field_off = find_size_field(pkg, &bi, pdec_len);
            free(pdec);
            printf("  packaging decoded size: %zu -> size field @0x%zx\n", pdec_len, bi.field_off);
        } else {
            bi.field_off = tfo;
        }
        if (!bi.field_off) {
            printf("ERROR: cannot locate the zImage decoded-size field in this build;\n");
            printf("       pass --field <hex offset> if you know it (search tip: it is a\n");
            printf("       little-endian u32 equal to the stock decoded kernel length in\n");
            printf("       the padding right before the QCDT block).\n");
            goto done;
        }
        printf("  size field located at 0x%zx (discovered, not hardcoded)\n", bi.field_off);
    }
    {
        /* The field is what the zImage prelude uses to relocate memory; it must
         * end up equal to the decompressed size we actually write.  A base that
         * ships it as 0 is still patchable -- we set it. */
        uint32_t field = bi.field_off ? rd32(base + bi.field_off) : 0;
        if (field == (uint32_t)dec_len) {
            printf("  size field @0x%zx: %u (matches decoded length)\n", bi.field_off, field);
        } else if (field == 0) {
            printf("  WARNING: size field @0x%zx is 0 in this base; it will be set to\n"
                   "           %zu in the output (same as the reference pipeline).\n",
                   bi.field_off, dec_len);
        } else {
            printf("ERROR: decoded-size field@0x%zx is %u but the payload decodes to %zu\n"
                   "       -> not an XTC stock boot image (field should match or be 0)\n",
                   bi.field_off, field, dec_len);
            goto done;
        }
    }
    {
        size_t k; int has = 0;
        for (k = 0; k + 6 <= dec_len; k++) if (!memcmp(dec + k, "KP1158", 6)) { has = 1; break; }
        if (has && !force) {
            printf("ERROR: target is ALREADY patched (KP blob in the decoded kernel).\n"
                   "       patch the pristine stock image instead (or --force).\n");
            goto done;
        }
        if (has) printf("  WARNING: already patched, --force given\n");
    }

    if (kpimg) {
        kp = read_file(kpimg, &kp_len);
        if (!kp) { printf("ERROR: cannot open kpimg: %s\n", kpimg); goto done; }
        printf("  kpimg: %s\n", kpimg);
    } else {
        kp = load_embedded_kpimg(argv[0], &kp_len);
        if (!kp) {
            printf("ERROR: no embedded kpimg and no -k given\n");
            goto done;
        }
        printf("  kpimg: embedded in %s\n", base_name(argv[0]));
    }
    md5_hex(kp, kp_len, md5s);
    printf("  kpimg: %zu bytes  md5 %s\n", kp_len, md5s);

    printf("\n[2] bvfix (vendor boot-verify guard)\n");
    if (g_no_bvfix) {
        printf("  skipped (--no-bvfix)\n");
    } else if (bvfix_apply(dec, dec_len) < 0) goto done;

    if (g_no_kp) {
        /* diagnostic build: bvfix + repack only, no KernelPatch blob/entry */
        patched = (unsigned char *)malloc(dec_len);
        if (!patched) { printf("ERROR: out of memory\n"); goto done; }
        memcpy(patched, dec, dec_len);
        plen = dec_len;
        printf("\n[3] KernelPatch skipped (--no-kp): plain Image, %zu bytes\n", plen);
    } else {
    printf("\n[3] KernelPatch (kptools -p, in-process)\n");
    {
        char in_tmp[1024], kp_tmp[1024], pat_tmp[1024];
        const char *tmp = getenv("TEMP");
        char *av[11];
        int ac = 0;
        if (!tmp) tmp = ".";
        snprintf(in_tmp,  sizeof(in_tmp),  "%s\\xtc-patch-base.bin", tmp);
        snprintf(kp_tmp,  sizeof(kp_tmp),  "%s\\xtc-patch-kpimg.bin", tmp);
        snprintf(pat_tmp, sizeof(pat_tmp), "%s\\xtc-patch-patched.bin", tmp);
        if (write_file(in_tmp, dec, dec_len) != 0 || write_file(kp_tmp, kp, kp_len) != 0) {
            printf("ERROR: cannot write temp files\n");
            goto done;
        }
        av[ac++] = "kptools";
        av[ac++] = "-p";
        av[ac++] = "-i"; av[ac++] = in_tmp;
        av[ac++] = "-S"; av[ac++] = (char *)superkey;
        av[ac++] = "-k"; av[ac++] = kp_tmp;
        av[ac++] = "-o"; av[ac++] = pat_tmp;
        if (kptools_main(ac, av) != 0) { printf("ERROR: kptools failed\n"); goto done; }
        patched = read_file(pat_tmp, &plen);
        remove(in_tmp); remove(kp_tmp); remove(pat_tmp);
        if (!patched) { printf("ERROR: cannot read patched Image\n"); goto done; }
        printf("  patched Image: %zu bytes\n", plen);
    }

    printf("\n[4] AArch32 entry fix\n");
    if (g_inert) {
        /* diagnostic: put the stock entry words back so the blob never runs */
        memcpy(patched, dec, 8);
        printf("  entry left at the stock words (--inert): %08x %08x\n",
               rd32(patched), rd32(patched + 4));
    } else {
        uint32_t w0 = rd32(patched), nb, imm;
        uint32_t w0_stock = rd32(dec);   /* keep this build's own entry word */
        size_t blob_page = ((dec_len + 4095) / 4096) * 4096;
        size_t want = blob_page + 4096;
        long tgt;
        if (memcmp(patched + blob_page, "KP11", 4) != 0) {
            printf("ERROR: no KP blob at 0x%zx\n", blob_page);
            goto done;
        }
        if (((w0 >> 24) & 0x0F) != 0xA) { printf("ERROR: kptools word0 is not an A32 B: %08x\n", w0); goto done; }
        nb = (w0 - 1) & 0xFFFFFFFFu;
        wr32(patched + 4, nb);
        wr32(patched, w0_stock);
        imm = nb & 0xFFFFFFu;
        if (imm >= 0x800000u) imm -= 0x1000000u;
        tgt = 4 + 8 + (long)imm * 4;
        printf("  w0/w1 -> %08x / %08x   B_target=0x%lx  want=0x%zx\n",
               w0_stock, nb, (unsigned long)tgt, want);
        if ((size_t)tgt != want) { printf("ERROR: entry self-check failed\n"); goto done; }
        printf("  entry self-check: OK\n");
    }

    } /* end of !g_no_kp */

    printf("\n[5] recompress (zopfli gzip)\n");
    {
        ZopfliOptions zo;
        unsigned char *gz = NULL;
        size_t gz_len = 0, pad;
        ZopfliInitOptions(&zo);
        {
            /* ARM builds are far slower: fewer iterations, the slot has ~2.4% slack. */
#ifdef XTC_NO_ZLIB
            int def_iters = 2;
#else
            int def_iters = 15;
#endif
            zo.numiterations = g_iters > 0 ? g_iters : def_iters;
            printf("  zopfli iterations: %d\n", zo.numiterations);
        }
#ifdef XTC_NO_ZLIB
        {
            /* ARM: chunked + threaded encoder (single deflate stream, output is
             * identical for any thread count) */
            extern int xtc_zopfli_gzip(const ZopfliOptions *, const unsigned char *,
                                       size_t, int, unsigned char **, size_t *);
            int th = g_threads;
            if (th <= 0) {
                long cpus = sysconf(_SC_NPROCESSORS_ONLN);
                th = cpus > 6 ? 6 : (int)cpus;
                if (th < 1) th = 1;
            }
            printf("  chunked zopfli, %d thread(s)\n", th);
            if (xtc_zopfli_gzip(&zo, patched, plen, th, &gz, &gz_len) != 0) {
                printf("ERROR: chunked zopfli failed\n");
                goto done;
            }
        }
#else
        ZopfliCompress(&zo, ZOPFLI_FORMAT_GZIP, patched, plen, &gz, &gz_len);
#endif
        if (!gz) { printf("ERROR: zopfli failed\n"); goto done; }
        printf("  compressed: %zu bytes   stock slot: %zu bytes\n", gz_len, bi.slot);
        if (gz_len > bi.slot) {
            printf("ERROR: payload exceeds the stock slot by %zu bytes; refusing to\n"
                   "       rebuild the layout (the ramdisk would move past the vendor\n"
                   "       vbmeta block).\n", gz_len - bi.slot);
            free(gz);
            goto done;
        }
        pad = bi.slot - gz_len;
        img = (unsigned char *)malloc(g_img_size);
        if (!img) { printf("ERROR: out of memory\n"); free(gz); goto done; }
        memcpy(img, pkg ? pkg : base, g_img_size);       /* header + ramdisk + tail */
        stub = (unsigned char *)malloc(bi.gz_off);
        qcdt = (unsigned char *)malloc(bi.qcdt_len ? bi.qcdt_len : 1);
        if (!stub || !qcdt) { printf("ERROR: out of memory\n"); free(gz); goto done; }
        memcpy(stub, (pkg ? pkg : base) + bi.region_off, bi.gz_off);
        if (bi.qcdt_len) memcpy(qcdt, (pkg ? pkg : base) + bi.region_off + bi.zend, bi.qcdt_len);
        memcpy(img + bi.region_off, stub, bi.gz_off);
        memcpy(img + bi.region_off + bi.gz_off, gz, gz_len);
        if (pad) {
            /* The vendor zImage stub keeps a table at the very end of the payload
             * slot (region offsets, entry hint, ...).  Zero-filling the gap after
             * our shorter stream used to wipe that table, and the stub then
             * jumped to a bogus address (seen as a data abort at 0xffffc000 and
             * endless prefetch aborts).  Keep the base bytes instead. */
            const unsigned char *srcimg = pkg ? pkg : base;
            memcpy(img + bi.region_off + bi.gz_off + gz_len,
                   srcimg + bi.region_off + bi.gz_off + gz_len, pad);
        }
        memcpy(img + bi.region_off + bi.zend, qcdt, bi.qcdt_len);
        printf("  layout: stub 0x%zx + payload 0x%zx + pad 0x%zx + qcdt 0x%zx (kernel_size unchanged)\n",
               bi.gz_off, gz_len, pad, bi.qcdt_len);
        free(gz);
    }

    printf("\n[6] repack (header id + trailer + size field)\n");
    {
        SHA1_CTX s;
        unsigned char dg[SHA1_DIGEST_SIZE];
        uint32_t v;
        sha1_init(&s);
        sha1_update(&s, img + bi.region_off, bi.ks);
        v = bi.ks;   sha1_update(&s, (const uint8_t *)&v, 4);
        sha1_update(&s, img + ((bi.page + bi.ks + bi.page - 1) / bi.page) * bi.page, bi.rs);
        v = bi.rs;   sha1_update(&s, (const uint8_t *)&v, 4);
        v = bi.ss;   sha1_update(&s, (const uint8_t *)&v, 4);
        v = bi.tags; sha1_update(&s, (const uint8_t *)&v, 4);
        v = bi.page; sha1_update(&s, (const uint8_t *)&v, 4);
        sha1_final(&s, dg);
        memset(img + 576, 0, 32);                 /* the id field is 32 bytes only */
        memcpy(img + 576, dg, SHA1_DIGEST_SIZE);
        wr32(img + bi.field_off, (uint32_t)plen);
        {
            /* kernel cmdline always describes the TARGET firmware, even when the
             * container came from another build (cross-version packaging). */
            const unsigned char *cs = cmd ? cmd : base;
            memcpy(img + 0x40, cs + 0x40, 0x200);
            printf("  cmdline taken from target/--cmdline-from\n");
        }
        printf("  header id (sha1) written; vendor payload-slot tail kept from %s\n", packaging ? "packaging image" : "base");
        printf("  decoded-size field@0x%zx = %zu\n", bi.field_off, plen);
    }

    printf("\n[7] verification\n");
    if (!verify_image(img, &bi, pkg ? pkg : base, kp, kp_len, patched, plen, superkey)) {
        printf("\nVERDICT: IMAGE_BAD\n");
        goto done;
    }
    printf("\nVERDICT: IMAGE_OK\n");

    if (!out) {
        const char *bn = base_name(boot);
        size_t dl = (size_t)(bn - boot);
        char stem[512];
        size_t l = strlen(bn);
        time_t t;
        struct tm *tmv;
        if (l > 4 && bn[l - 4] == '.') l -= 4;
        if (l >= sizeof(stem)) l = sizeof(stem) - 1;
        memcpy(stem, bn, l); stem[l] = 0;
        t = time(NULL);
        tmv = localtime(&t);
        snprintf(outbuf, sizeof(outbuf), "%.*s%s-kp-%04d%02d%02d-%02d%02d.img",
                 (int)dl, boot, stem,
                 tmv->tm_year + 1900, tmv->tm_mon + 1, tmv->tm_mday, tmv->tm_hour, tmv->tm_min);
        out = outbuf;
    }
    if (write_file(out, img, g_img_size) != 0) { printf("ERROR: cannot write %s\n", out); goto done; }
    md5_hex(img, g_img_size, md5s);
    printf("\n  written: %s\n  md5    : %s\n  size   : %zu bytes\n", out, md5s, g_img_size);
    printf("\n  boot it with:  fastboot boot \"%s\"\n", out);
    rc = 0;

done:
    free(base); free(dec); free(kp); free(img); free(patched); free(stub); free(qcdt);
    return rc;
}

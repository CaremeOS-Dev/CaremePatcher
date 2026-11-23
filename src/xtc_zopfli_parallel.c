/*
 * xtc_zopfli_parallel.c -- chunked (optionally threaded) zopfli gzip encoder.
 *
 * Why: the vendor's zImage prelude relocates memory using a decoded-size field,
 * so the recompressed kernel payload must fit the STOCK kernel slot.  zlib and
 * zlib-ng miss that slot by ~50 KB, so zopfli-class density is required -- but
 * plain zopfli is single-threaded and takes minutes on an ARM watch.
 *
 * This encoder keeps zopfli's own 1 MB master blocks but compresses them
 * independently (in parallel when asked) and stitches them into ONE deflate
 * stream by inserting an empty stored block between chunks.  A stored block
 * begins on a byte boundary, so every chunk after the first starts at bit 0 and
 * the concatenation is a valid single deflate stream.  Cost: ~5 bytes per chunk.
 *
 * Output bytes are IDENTICAL for any thread count (serial and parallel use the
 * same chunking and alignment), which keeps host and device outputs comparable.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zopfli.h"
#include "deflate.h"

#ifndef XTC_ZOPFLI_CHUNK
#define XTC_ZOPFLI_CHUNK 1000000u     /* matches ZOPFLI_MASTER_BLOCK_SIZE */
#endif

/* ---------------- crc32 (gzip trailer) ---------------- */
static unsigned long xtc_crc_table[256];
static int xtc_crc_ready;

static void xtc_crc_init(void)
{
    unsigned long c;
    int n, k;
    for (n = 0; n < 256; n++) {
        c = (unsigned long)n;
        for (k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320UL ^ (c >> 1) : (c >> 1);
        xtc_crc_table[n] = c;
    }
    xtc_crc_ready = 1;
}

static unsigned long xtc_crc32(const unsigned char *buf, size_t len)
{
    unsigned long c = 0xFFFFFFFFUL;
    size_t n;
    if (!xtc_crc_ready) xtc_crc_init();
    for (n = 0; n < len; n++) c = xtc_crc_table[(c ^ buf[n]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFUL;
}

/* ---------------- one chunk ---------------- */
typedef struct {
    const ZopfliOptions *opt;
    const unsigned char *in;
    size_t start, end;
    int final;
    unsigned char *out;
    size_t outlen;
    unsigned char bp;
} xtc_job;

static void xtc_run_job(xtc_job *j)
{
    j->bp = 0;
    j->out = NULL;
    j->outlen = 0;
    ZopfliDeflatePart(j->opt, 2 /* dynamic blocks */, j->final, j->in,
                      j->start, j->end, &j->bp, &j->out, &j->outlen);
}

#ifndef _WIN32
#include <pthread.h>

typedef struct {
    xtc_job *jobs;
    size_t nchunks;
    size_t next;
    pthread_mutex_t mu;
} xtc_pool;

static void *xtc_worker(void *arg)
{
    xtc_pool *p = (xtc_pool *)arg;
    for (;;) {
        size_t i;
        pthread_mutex_lock(&p->mu);
        i = p->next++;
        pthread_mutex_unlock(&p->mu);
        if (i >= p->nchunks) break;
        xtc_run_job(&p->jobs[i]);
    }
    return NULL;
}
#endif

/* Append an empty stored block (BFINAL=0, BTYPE=00, LEN=0, NLEN=0xFFFF).
 * The three header bits are all zero, so a partially filled byte keeps its zero
 * padding; a fresh zero byte is needed only when those bits do not fit in the
 * current byte (bp == 0, or bp >= 6 where they spill over). */
static void xtc_append_align(unsigned char **out, size_t *outsize, unsigned char bp)
{
    if (bp == 0 || bp >= 6) (*out)[(*outsize)++] = 0x00;
    (*out)[(*outsize)++] = 0x00;   /* LEN low   */
    (*out)[(*outsize)++] = 0x00;   /* LEN high  */
    (*out)[(*outsize)++] = 0xFF;   /* NLEN low  */
    (*out)[(*outsize)++] = 0xFF;   /* NLEN high */
}

/*
 * Chunked zopfli gzip.  threads <= 1 -> serial (same bytes as any other count).
 * Returns 0 on success; *out must be free()d by the caller.
 */
int xtc_zopfli_gzip(const ZopfliOptions *opt, const unsigned char *in, size_t n,
                    int threads, unsigned char **out, size_t *outlen)
{
    size_t nchunks, i;
    xtc_job *jobs;
    unsigned char *buf;
    size_t buflen, cap;

    if (!in || !n || !out || !outlen) return -1;
    nchunks = (n + XTC_ZOPFLI_CHUNK - 1) / XTC_ZOPFLI_CHUNK;
    jobs = (xtc_job *)calloc(nchunks, sizeof(xtc_job));
    if (!jobs) return -1;

    for (i = 0; i < nchunks; i++) {
        jobs[i].opt = opt;
        jobs[i].in = in;
        jobs[i].start = i * XTC_ZOPFLI_CHUNK;
        jobs[i].end = (jobs[i].start + XTC_ZOPFLI_CHUNK < n)
                          ? jobs[i].start + XTC_ZOPFLI_CHUNK : n;
        jobs[i].final = (i + 1 == nchunks) ? 1 : 0;
    }

#ifndef _WIN32
    if (threads > 1 && nchunks > 1) {
        xtc_pool pool;
        pthread_t *tid;
        int t, spawned = 0;
        if ((size_t)threads > nchunks) threads = (int)nchunks;
        tid = (pthread_t *)calloc((size_t)threads, sizeof(pthread_t));
        if (!tid) { threads = 1; goto serial; }
        pool.jobs = jobs;
        pool.nchunks = nchunks;
        pool.next = 0;
        pthread_mutex_init(&pool.mu, NULL);
        for (t = 0; t < threads; t++)
            if (pthread_create(&tid[t], NULL, xtc_worker, &pool) == 0) spawned++;
        if (spawned == 0) {
            pthread_mutex_destroy(&pool.mu);
            free(tid);
            goto serial;
        }
        for (t = 0; t < spawned; t++) pthread_join(tid[t], NULL);
        pthread_mutex_destroy(&pool.mu);
        free(tid);
        for (i = 0; i < nchunks; i++)
            if (!jobs[i].out && jobs[i].end > jobs[i].start) xtc_run_job(&jobs[i]);
        goto stitch;
    }
serial:
#endif
    for (i = 0; i < nchunks; i++) xtc_run_job(&jobs[i]);

#ifndef _WIN32
stitch:
#endif
    cap = 10 + n + (n >> 3) + 64;
    buf = (unsigned char *)malloc(cap);
    if (!buf) {
        for (i = 0; i < nchunks; i++) free(jobs[i].out);
        free(jobs);
        return -1;
    }
    buflen = 0;
    buf[buflen++] = 31;  buf[buflen++] = 139; buf[buflen++] = 8; buf[buflen++] = 0;
    buf[buflen++] = 0;   buf[buflen++] = 0;   buf[buflen++] = 0; buf[buflen++] = 0;
    buf[buflen++] = 2;   buf[buflen++] = 3;   /* XFL=best, OS=unix */

    for (i = 0; i < nchunks; i++) {
        size_t need = buflen + jobs[i].outlen + 8;
        if (need > cap) {
            unsigned char *nb;
            cap = need * 2;
            nb = (unsigned char *)realloc(buf, cap);
            if (!nb) {
                free(buf);
                for (; i < nchunks; i++) free(jobs[i].out);
                free(jobs);
                return -1;
            }
            buf = nb;
        }
        if (jobs[i].outlen) memcpy(buf + buflen, jobs[i].out, jobs[i].outlen);
        buflen += jobs[i].outlen;
        if (i + 1 < nchunks) xtc_append_align(&buf, &buflen, jobs[i].bp);
        free(jobs[i].out);
    }

    {
        unsigned long crc = xtc_crc32(in, n);
        buf[buflen++] = (unsigned char)(crc & 0xFF);
        buf[buflen++] = (unsigned char)((crc >> 8) & 0xFF);
        buf[buflen++] = (unsigned char)((crc >> 16) & 0xFF);
        buf[buflen++] = (unsigned char)((crc >> 24) & 0xFF);
        buf[buflen++] = (unsigned char)(n & 0xFF);
        buf[buflen++] = (unsigned char)((n >> 8) & 0xFF);
        buf[buflen++] = (unsigned char)((n >> 16) & 0xFF);
        buf[buflen++] = (unsigned char)((n >> 24) & 0xFF);
    }

    free(jobs);
    *out = buf;
    *outlen = buflen;
    return 0;
}

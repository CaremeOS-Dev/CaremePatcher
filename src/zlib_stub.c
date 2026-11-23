/* zlib_stub.c -- link-time stubs for the zlib entry points that kptools
 * references but the ARM32 boot-patch path never calls (ikconfig dump, bzImage
 * loader, boot-image compressor).  The Android build links without libz because
 * NDK r27 no longer ships the zlib import library, and we deliberately do not
 * need it: magiskboot hands us the decompressed kernel, and compression is done
 * by the vendored zopfli encoder.
 *
 * Every stub fails loudly at runtime (returns an error) instead of pretending to
 * work, so an unexpected call cannot silently corrupt anything.
 */
typedef unsigned long uLong;
typedef unsigned int uInt;
typedef unsigned char Bytef;
typedef void *voidp;
typedef struct gzFile_s *gzFile;

#ifndef NULL
#define NULL ((void *)0)
#endif

#define Z_ERRNO (-1)
#define Z_STREAM_ERROR (-2)
#define Z_DATA_ERROR (-3)

int inflateInit2_(void *strm, int windowBits, const char *version, int stream_size)
{
    (void)strm; (void)windowBits; (void)version; (void)stream_size;
    return Z_STREAM_ERROR;
}
int inflate(void *strm, int flush) { (void)strm; (void)flush; return Z_DATA_ERROR; }
int inflateEnd(void *strm) { (void)strm; return Z_STREAM_ERROR; }

int deflateInit2_(void *strm, int level, int method, int windowBits,
                  int memLevel, int strategy, const char *version, int stream_size)
{
    (void)strm; (void)level; (void)method; (void)windowBits; (void)memLevel;
    (void)strategy; (void)version; (void)stream_size;
    return Z_STREAM_ERROR;
}
int deflate(void *strm, int flush) { (void)strm; (void)flush; return Z_STREAM_ERROR; }
int deflateEnd(void *strm) { (void)strm; return Z_STREAM_ERROR; }
uLong deflateBound(void *strm, uLong sourceLen) { (void)strm; return sourceLen + 64; }

uLong crc32(uLong crc, const Bytef *buf, uInt len) { (void)crc; (void)buf; (void)len; return 0; }

gzFile gzopen(const char *path, const char *mode) { (void)path; (void)mode; return NULL; }
int gzread(gzFile file, voidp buf, unsigned len) { (void)file; (void)buf; (void)len; return -1; }
int gzclose(gzFile file) { (void)file; return Z_ERRNO; }

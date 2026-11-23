#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zopfli.h"

int xtc_zopfli_gzip(const ZopfliOptions *opt, const unsigned char *in, size_t n,
                    int threads, unsigned char **out, size_t *outlen);

int main(int argc, char **argv)
{
    FILE *f;
    long n;
    unsigned char *in, *out = NULL;
    size_t outlen = 0;
    ZopfliOptions opt;
    int threads = argc > 3 ? atoi(argv[3]) : 1;
    if (argc < 3) { fprintf(stderr, "usage: %s in out.gz [threads]\n", argv[0]); return 2; }
    f = fopen(argv[1], "rb");
    if (!f) { perror("in"); return 1; }
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    in = malloc(n);
    if (fread(in, 1, n, f) != (size_t)n) return 1;
    fclose(f);
    ZopfliInitOptions(&opt);
    opt.numiterations = argc > 4 ? atoi(argv[4]) : 2;
    if (xtc_zopfli_gzip(&opt, in, (size_t)n, threads, &out, &outlen) != 0) {
        fprintf(stderr, "encode failed\n"); return 1;
    }
    f = fopen(argv[2], "wb");
    fwrite(out, 1, outlen, f);
    fclose(f);
    printf("%s: %zu bytes (threads=%d iters=%d)\n", argv[2], outlen, threads, opt.numiterations);
    free(in); free(out);
    return 0;
}

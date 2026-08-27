// statblockprobe.c — warm-stat counterpart of xattr_ab/xblockprobe.c (bd-4iqg6).
// Repeated stat() of ONE warm file: no I/O, no directory work, so what it isolates is
// the per-request FUSE round trip and the path resolution, and essentially nothing else.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <errno.h>

static long nvcsw(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1;
    return ru.ru_nvcsw;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s DIR N\n", argv[0]); return 2; }
    char path[4096];
    snprintf(path, sizeof(path), "%s/payload.bin", argv[1]);
    int n = atoi(argv[2]);
    struct stat st;
    unsigned long long digest = 0x9E3779B97F4A7C15ull;

    if (stat(path, &st) != 0) { fprintf(stderr, "warm stat %s: %s\n", path, strerror(errno)); return 1; }

    long v0 = nvcsw();
    int done = 0;
    for (int i = 0; i < n; i++) {
        if (stat(path, &st) != 0) break;
        digest = digest * 1099511628211ull ^ (unsigned long long)st.st_size;
        done++;
    }
    long v1 = nvcsw();
    printf("stats=%d nvcsw=%ld nvcsw_per_stat=%.3f digest=%llu\n", done, v1 - v0,
           done ? (double)(v1 - v0) / done : 0.0, digest);
    return 0;
}

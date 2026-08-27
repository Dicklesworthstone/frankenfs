// blockprobe.c — which FUSE crossings actually BLOCK the client?
//
// The crossing ladder (bd-4iqg6) left a contradiction on the record: removing a
// getxattr crossing bought ~1.6x more wall time than removing an open/release one,
// while the daemon's own dispatch_ns ranked getxattr as the CHEAPER crossing. Either
// dispatch_ns misses where the cost lands, or crossings are not uniform-cost.
//
// The candidate resolution is that not every crossing is on the client's critical
// path: FUSE RELEASE is a background request the kernel does not wait for, so
// deleting 1280 release crossings removes daemon work while removing no client
// blocking at all. If that is right, zero-message open's 2558 removed crossings are
// only ~1278 blocking ones, and the per-blocking-crossing rates reconcile.
//
// This measures that directly, and with a COUNT rather than a stopwatch:
// `getrusage(RUSAGE_SELF).ru_nvcsw` counts VOLUNTARY context switches. A crossing the
// client must wait on costs one (the client sleeps until the daemon replies); a
// background crossing costs none. Single-threaded on purpose so the count is
// attributable and not smeared across a thread pool.
//
// usage: blockprobe DIR N
// prints: files=%d nvcsw=%ld nvcsw_per_file=%.3f nivcsw=%ld bytes=%zd

#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#define BUFSZ 65536

static long nvcsw(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1;
    return ru.ru_nvcsw;
}
static long nivcsw(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1;
    return ru.ru_nivcsw;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s DIR N\n", argv[0]);
        return 2;
    }
    const char *dir = argv[1];
    int n = atoi(argv[2]);
    char *buf = malloc(BUFSZ);
    if (!buf) return 1;
    char path[4096];

    // Warm the mount and the client's own allocations OUTSIDE the counted region,
    // so the delta is the per-file protocol cost and not first-touch noise.
    snprintf(path, sizeof(path), "%s/parallel-read/read-000000.bin", dir);
    int warm = open(path, O_RDONLY);
    if (warm >= 0) {
        while (read(warm, buf, BUFSZ) > 0) {}
        close(warm);
    }

    long v0 = nvcsw(), i0 = nivcsw();
    ssize_t total = 0;
    int done = 0;
    for (int i = 0; i < n; i++) {
        snprintf(path, sizeof(path), "%s/parallel-read/read-%06d.bin", dir, i % 256);
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "open %s: %s\n", path, strerror(errno));
            break;
        }
        ssize_t got;
        while ((got = read(fd, buf, BUFSZ)) > 0) total += got;
        close(fd);
        done++;
    }
    long v1 = nvcsw(), i1 = nivcsw();

    printf("files=%d nvcsw=%ld nvcsw_per_file=%.3f nivcsw=%ld bytes=%zd\n", done, v1 - v0,
           done ? (double)(v1 - v0) / done : 0.0, i1 - i0, total);
    free(buf);
    return 0;
}

// writeprobe.c — bulk durable write: fixed bytes, fixed block size, periodic fsync.
//
// Reports its own voluntary context switches so the write row can be placed on the
// same blocking-crossings scale as the read rows (bd-4iqg6), where warm stat measured
// 1.000 blocking crossings per op and the worst row 2.001.
//
// The write path is expected to behave differently from every read row decomposed so
// far: those were ~99% FUSE round trip with the daemon nearly idle, while bulk durable
// write is the one row where our own memcpy and allocator are a third of daemon CPU.
// If that holds, this probe should show FEW blocking crossings per write and the cost
// should instead appear in instructions retired.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <unistd.h>

static long nvcsw(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1;
    return ru.ru_nvcsw;
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s PATH MB BS SYNC_EVERY\n", argv[0]); return 2; }
    const char *path = argv[1];
    long mb = atol(argv[2]), bs = atol(argv[3]), se = atol(argv[4]);
    long total = mb * 1024 * 1024, nblocks = total / bs;

    char *buf = malloc(bs);
    if (!buf) return 1;
    // Non-constant bytes: a compressing or zero-eliding path must not get a free ride.
    for (long i = 0; i < bs; i++) buf[i] = (char)(i * 31 + 7);

    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return 1; }

    long v0 = nvcsw();
    long written = 0, syncs = 0, blocks = 0;
    for (long i = 0; i < nblocks; i++) {
        ssize_t w = write(fd, buf, bs);
        if (w != bs) { fprintf(stderr, "write %ld: %s\n", i, strerror(errno)); break; }
        written += w;
        blocks++;
        if (se > 0 && (i + 1) % se == 0) {
            if (fsync(fd) != 0) { fprintf(stderr, "fsync: %s\n", strerror(errno)); break; }
            syncs++;
        }
    }
    if (fsync(fd) == 0) syncs++;
    long v1 = nvcsw();

    printf("blocks=%ld bytes=%ld syncs=%ld nvcsw=%ld nvcsw_per_write=%.4f\n", blocks, written,
           syncs, v1 - v0, blocks ? (double)(v1 - v0) / blocks : 0.0);
    close(fd);
    free(buf);
    return 0;
}

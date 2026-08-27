// iovprobe.c — before anyone refactors two traits to replace a 64 MiB memcpy with a
// vectored write, find out what pwritev(2) will actually accept and what it costs.
//
// The flush coalesces up to 16,384 4 KiB blocks into ONE contiguous run. A vectored
// write of that run needs 16,384 iovecs, and IOV_MAX is typically 1024 — so the run
// would become 16 syscalls, not one. This measures the real limit and compares:
//   A: one pwrite of a pre-coalesced buffer      (today: 1 memcpy + 1 syscall)
//   B: pwritev over per-block pointers           (proposed: 0 memcpy + N syscalls)
// against the same O_DIRECT fd, alternating, so drift hits both.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define BLK 4096
static uint64_t now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
    return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec;}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s DEV BLOCKS ROUNDS\n", argv[0]); return 2; }
    const char *dev = argv[1];
    long blocks = atol(argv[2]), rounds = atol(argv[3]);
    printf("IOV_MAX=%ld  blocks=%ld (%.1f MiB)  iovecs needed=%ld\n",
           (long)IOV_MAX, blocks, blocks * (double)BLK / (1024*1024), blocks);

    // ⚠ THIS PROBE DESTROYS THE FIRST ~64 MiB PAST 1 MiB OF WHATEVER IT OPENS.
    // On 2026-08-27 it was pointed at a live ext4 fixture and corrupted it; the
    // next bulk run failed with EINVAL opening its own data file. Require an
    // explicit opt-in so a fixture path cannot be passed by reflex.
    if (getenv("IOVPROBE_I_WILL_DESTROY_THIS_DEVICE") == NULL) {
        fprintf(stderr,
                "refusing to write to %s: this probe overwrites %.1f MiB at offset 1 MiB.\n"
                "Point it at a scratch image you can lose, then set\n"
                "  IOVPROBE_I_WILL_DESTROY_THIS_DEVICE=1\n",
                dev, blocks * (double)BLK / (1024 * 1024));
        return 2;
    }

    int fd = open(dev, O_RDWR | O_DIRECT);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", dev, strerror(errno)); return 1; }

    // Per-block buffers, each 4 KiB-aligned, exactly as Arc<AlignedVec> would be.
    void **blk = malloc((size_t)blocks * sizeof(void *));
    for (long i = 0; i < blocks; i++) {
        if (posix_memalign(&blk[i], BLK, BLK) != 0) { perror("posix_memalign"); return 1; }
        memset(blk[i], 0xC7, BLK);
    }
    void *flat = NULL;
    if (posix_memalign(&flat, BLK, (size_t)blocks * BLK) != 0) { perror("posix_memalign"); return 1; }
    struct iovec *iov = malloc((size_t)blocks * sizeof(struct iovec));
    for (long i = 0; i < blocks; i++) { iov[i].iov_base = blk[i]; iov[i].iov_len = BLK; }

    uint64_t ta = 0, tb = 0;
    long calls_b = 0;
    off_t off = 1u << 20;
    for (long r = 0; r < rounds; r++) {
        // A: coalesce then one pwrite
        uint64_t t0 = now_ns();
        for (long i = 0; i < blocks; i++) memcpy((char *)flat + i * BLK, blk[i], BLK);
        if (pwrite(fd, flat, (size_t)blocks * BLK, off) < 0) { perror("pwrite"); return 1; }
        ta += now_ns() - t0;

        // B: pwritev in IOV_MAX-sized batches, no memcpy
        t0 = now_ns();
        long done = 0; long calls = 0;
        while (done < blocks) {
            long n = blocks - done; if (n > IOV_MAX) n = IOV_MAX;
            ssize_t w = pwritev(fd, iov + done, (int)n, off + done * BLK);
            if (w < 0) { fprintf(stderr, "pwritev(%ld iovecs): %s\n", n, strerror(errno)); return 1; }
            if (w != (ssize_t)n * BLK) { fprintf(stderr, "short pwritev: %zd of %ld\n", w, n * BLK); return 1; }
            done += n; calls++;
        }
        tb += now_ns() - t0;
        calls_b = calls;
    }
    printf("A coalesce+pwrite : %8.3f ms/round  (1 memcpy of %.1f MiB + 1 syscall)\n",
           ta / 1e6 / rounds, blocks * (double)BLK / (1024*1024));
    printf("B pwritev no-copy : %8.3f ms/round  (0 memcpy + %ld syscalls)\n",
           tb / 1e6 / rounds, calls_b);
    printf("B/A = %.4f  (<1 means the vectored path wins)\n", (double)tb / (double)ta);
    close(fd);
    return 0;
}

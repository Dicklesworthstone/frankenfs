// dioprobe.c — does an O_DIRECT open still bypass the page cache when the mount
// negotiated FUSE_NO_OPEN_SUPPORT (FFS_FUSE_ZERO_MESSAGE_OPEN)?
//
// bd-q0xnl left zero-message open measured at a balanced 1.160389x but DEFAULT OFF
// on a named, unmeasured correctness worry: `kernel_open_flags` withholds
// FOPEN_KEEP_CACHE precisely when the client passed O_DIRECT, and with zero-message
// open the daemon never sees the open at all, so an O_DIRECT open might silently
// get page-cached behaviour. That is a correctness question, not a timing one, so
// this is a COUNTED oracle rather than a benchmark.
//
// Method: read THE SAME aligned block N times from one open file and let the runner
// count how many of those reads actually reached the daemon (`op_counts read`).
//   - a true O_DIRECT open must send every read to the daemon  -> count ~= N
//   - a page-cached open serves repeats from the client cache  -> count ~= 1
//
// The runner gives each pass its OWN mount lifetime, because `op_counts` is only
// emitted at unmount and is cumulative — one pass per mount is what makes the
// number attributable.
//
// The BUFFERED pass is the negative control and is not optional: it is what proves
// the oracle can see caching at all on this stack. Without it, "N reads reached the
// daemon" is equally consistent with O_DIRECT working and with the count being
// broken. The control must show ~1; if it shows ~N, the oracle is void and the
// O_DIRECT arm says nothing.
//
// usage: dioprobe MODE PATH N        MODE = dio | buf
// prints: mode=%s reads=%d bytes=%zd digest=%llu

#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BLK 4096

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s dio|buf PATH N\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    const char *path = argv[2];
    int n = atoi(argv[3]);
    int direct = strcmp(mode, "dio") == 0;

    int flags = O_RDONLY;
    if (direct) flags |= O_DIRECT;
    int fd = open(path, flags);
    if (fd < 0) {
        // Report rather than abort: an EINVAL here is itself a finding (the mount
        // refused O_DIRECT), and the runner must be able to tell that apart from a
        // cache result.
        fprintf(stderr, "open(%s, %s) failed: %s\n", path, mode, strerror(errno));
        printf("mode=%s reads=-1 bytes=-1 digest=0 open_errno=%d\n", mode, errno);
        return 1;
    }

    void *buf = NULL;
    if (posix_memalign(&buf, BLK, BLK) != 0) {
        fprintf(stderr, "posix_memalign: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    uint64_t digest = 0x9E3779B97F4A7C15ull;
    ssize_t total = 0;
    int done = 0;
    for (int i = 0; i < n; i++) {
        // Same offset every time: repeats are what a page cache can absorb and a
        // direct-I/O open cannot.
        ssize_t got = pread(fd, buf, BLK, 0);
        if (got < 0) {
            fprintf(stderr, "pread #%d: %s\n", i, strerror(errno));
            break;
        }
        total += got;
        done++;
        const unsigned char *p = (const unsigned char *)buf;
        for (int j = 0; j < 64; j++) digest = digest * 1099511628211ull ^ p[j * 61];
    }

    printf("mode=%s reads=%d bytes=%zd digest=%llu open_errno=0\n", mode, done, total,
           (unsigned long long)digest);
    free(buf);
    close(fd);
    return 0;
}

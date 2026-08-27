// xblockprobe.c — the deterministic decomposition of the campaign's WORST row.
//
// `ext4 xattr-get-list-report` is the worst vs-incumbent ratio on the board and the
// one read row the capability-probe parity lever cannot rescue: FFS_FUSE_XATTR_NO_SUPPORT
// is REFUSED here because this image genuinely HAS xattrs, so answering ENOSYS would
// be a lie rather than a restriction.
//
// So decompose it with counts instead of a stopwatch, using the instrument validated
// on the parallel-read row (bd-4iqg6): `getrusage(RUSAGE_SELF).ru_nvcsw` counts the
// crossings the client actually WAITS on, and pairs with the daemon's own
// `crossings_*` / `op_counts` census.
//
// One report = the banked batch, five PATH-BASED syscalls:
//   getxattr(inline,   "user.inline")
//   getxattr(external, "user.external")
//   getxattr(inline,   "user.absent")   -> ENODATA expected
//   listxattr(inline)
//   listxattr(many)
//
// Every one of those resolves a path, and on this host a path resolution is what
// triggers the kernel's audit `security.capability` probe. The question this answers
// is therefore exact and countable: how many crossings does a 5-op report actually
// cost, how many of them block, and how many are the user's xattr work versus
// scaffolding the user never asked for?
//
// usage: xblockprobe DIR N
// prints: reports=%d nvcsw=%ld nvcsw_per_report=%.3f ops=%d bytes=%zd

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <unistd.h>

static long nvcsw(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1;
    return ru.ru_nvcsw;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s DIR N\n", argv[0]);
        return 2;
    }
    const char *dir = argv[1];
    int n = atoi(argv[2]);

    char inl[4096], ext[4096], many[4096];
    snprintf(inl, sizeof(inl), "%s/xattr-inline.bin", dir);
    snprintf(ext, sizeof(ext), "%s/xattr-external.bin", dir);
    snprintf(many, sizeof(many), "%s/xattr-many.bin", dir);

    char buf[65536];
    ssize_t total = 0;
    int ops = 0;

    // Warm outside the counted region so the delta is steady-state protocol cost.
    getxattr(inl, "user.inline", buf, sizeof(buf));
    listxattr(many, buf, sizeof(buf));

    long v0 = nvcsw();
    for (int i = 0; i < n; i++) {
        ssize_t r;
        r = getxattr(inl, "user.inline", buf, sizeof(buf));
        if (r > 0) { total += r; ops++; }
        r = getxattr(ext, "user.external", buf, sizeof(buf));
        if (r > 0) { total += r; ops++; }
        r = getxattr(inl, "user.absent", buf, sizeof(buf));
        // ENODATA is the expected answer and still costs a full round trip.
        if (r < 0 && errno == ENODATA) ops++;
        r = listxattr(inl, buf, sizeof(buf));
        if (r > 0) { total += r; ops++; }
        r = listxattr(many, buf, sizeof(buf));
        if (r > 0) { total += r; ops++; }
    }
    long v1 = nvcsw();

    printf("reports=%d nvcsw=%ld nvcsw_per_report=%.3f ops=%d bytes=%zd\n", n, v1 - v0,
           n ? (double)(v1 - v0) / n : 0.0, ops, total);
    return 0;
}

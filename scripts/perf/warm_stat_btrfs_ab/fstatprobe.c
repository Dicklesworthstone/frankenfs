// fstatprobe.c — the audit counterfactual that needs no change to host security config.
//
// bd-4iqg6 established the capability probe's caller is __audit_inode, reached from
// filename_lookup. That predicts something testable WITHOUT touching auditctl: a
// syscall that resolves no path cannot reach __audit_inode, so it must pay no
// capability probe at all.
//
// stat(path)  -> filename_lookup -> __audit_inode -> get_vfs_caps_from_disk
// fstat(fd)   -> no path resolution at all
//
// Same file, same mount, same process, back to back. If the probe is bound to path
// resolution the two modes differ by exactly the probe; if it is bound to the metadata
// operation itself they do not differ.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

static long nvcsw(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1;
    return ru.ru_nvcsw;
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s stat|fstat DIR N\n", argv[0]); return 2; }
    int use_f = strcmp(argv[1], "fstat") == 0;
    char path[4096];
    snprintf(path, sizeof(path), "%s/payload.bin", argv[2]);
    int n = atoi(argv[3]);
    struct stat st;
    unsigned long long digest = 0x9E3779B97F4A7C15ull;

    // The fd is opened OUTSIDE the counted region in both modes, so the open's own
    // path resolution (and its one probe) cannot be mistaken for per-op cost.
    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return 1; }
    if (stat(path, &st) != 0) { fprintf(stderr, "warm: %s\n", strerror(errno)); return 1; }

    long v0 = nvcsw();
    int done = 0;
    for (int i = 0; i < n; i++) {
        int rc = use_f ? fstat(fd, &st) : stat(path, &st);
        if (rc != 0) break;
        digest = digest * 1099511628211ull ^ (unsigned long long)st.st_size;
        done++;
    }
    long v1 = nvcsw();
    printf("mode=%s ops=%d nvcsw=%ld nvcsw_per_op=%.4f digest=%llu\n", argv[1], done, v1 - v0,
           done ? (double)(v1 - v0) / done : 0.0, digest);
    close(fd);
    return 0;
}

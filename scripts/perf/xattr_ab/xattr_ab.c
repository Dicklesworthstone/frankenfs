// xattr_ab.c — reproduce ffs-mounted-kernel-bench's `xattr-get-list-report` batch
// (crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs:3846) against N live
// mounts INTERLEAVED IN ONE INVOCATION, arm order rotated per round.
//
// batch = per report: getxattr(inline, user.inline), getxattr(external,
// user.external), getxattr(inline, user.absent) expecting ENODATA,
// listxattr(inline), listxattr(many). Single client thread, as the banked row.
//
// The digest folds VALUE BYTES and NAME BYTES only — never a path — so two arms
// on different mountpoints must agree, and the field is a real cross-arm parity
// oracle. A digest that cannot be equal across arms is not one (learned on the
// readdir+stat rig, whose digest hashed the absolute path).
//
// usage: xattr_ab ROUNDS OPS CPU FUSEPID label=dir [label=dir ...]
// prints CSV: round,pos,arm,total_ns,digest,daemon_ticks

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#define MAX_ARMS 8

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t fold(uint64_t d, const char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        d ^= (unsigned char)buf[i];
        d *= 0x00000100000001B3ull;
    }
    return d;
}

static int read_daemon_ticks(int pid, unsigned long long *out) {
    if (pid <= 0) { *out = 0; return 0; }
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) return -1;
    buf[n] = 0;
    char *close_paren = strrchr(buf, ')');
    if (!close_paren) return -1;
    unsigned long long utime = 0, stime = 0;
    int field = 3;
    for (char *tok = strtok(close_paren + 2, " "); tok; tok = strtok(NULL, " "), field++) {
        if (field == 14) utime = strtoull(tok, NULL, 10);
        if (field == 15) { stime = strtoull(tok, NULL, 10); break; }
    }
    *out = utime + stime;
    return 0;
}

static int run_batch(const char *root, int ops, uint64_t *total_ns, uint64_t *digest_out) {
    char inline_path[4096], external_path[4096], many_path[4096];
    snprintf(inline_path, sizeof(inline_path), "%s/xattr-inline.bin", root);
    snprintf(external_path, sizeof(external_path), "%s/xattr-external.bin", root);
    snprintf(many_path, sizeof(many_path), "%s/xattr-many.bin", root);

    char value[8192], names[16384];
    uint64_t digest = 0xCBF29CE484222325ull;
    uint64_t t0 = now_ns();
    for (int report = 0; report < ops; report++) {
        ssize_t n = getxattr(inline_path, "user.inline", value, sizeof(value));
        if (n < 0) { fprintf(stderr, "getxattr inline: %s\n", strerror(errno)); return -1; }
        digest = fold(digest, value, (size_t)n);

        n = getxattr(external_path, "user.external", value, sizeof(value));
        if (n < 0) { fprintf(stderr, "getxattr external: %s\n", strerror(errno)); return -1; }
        digest = fold(digest, value, (size_t)n);

        // The absent probe must MISS. A filesystem that answered it would be
        // faster and wrong, so the error code is folded in rather than ignored.
        n = getxattr(inline_path, "user.absent", value, sizeof(value));
        if (n >= 0) { fprintf(stderr, "absent xattr unexpectedly present\n"); return -1; }
        if (errno != ENODATA) { fprintf(stderr, "absent getxattr: %s\n", strerror(errno)); return -1; }
        digest ^= 0xA11CE00000000001ull;

        n = listxattr(inline_path, names, sizeof(names));
        if (n < 0) { fprintf(stderr, "listxattr inline: %s\n", strerror(errno)); return -1; }
        digest = fold(digest, names, (size_t)n);

        n = listxattr(many_path, names, sizeof(names));
        if (n < 0) { fprintf(stderr, "listxattr many: %s\n", strerror(errno)); return -1; }
        digest = fold(digest, names, (size_t)n);

        digest ^= ((uint64_t)report << 17) | ((uint64_t)report >> 47);
    }
    *total_ns = now_ns() - t0;
    *digest_out = digest;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s ROUNDS OPS CPU FUSEPID label=dir [label=dir ...]\n", argv[0]);
        return 2;
    }
    int rounds = atoi(argv[1]), ops = atoi(argv[2]), cpu = atoi(argv[3]);
    int fuse_pid = atoi(argv[4]);

    const char *labels[MAX_ARMS];
    const char *dirs[MAX_ARMS];
    int arms = 0;
    for (int i = 5; i < argc && arms < MAX_ARMS; i++) {
        char *eq = strchr(argv[i], '=');
        if (!eq) { fprintf(stderr, "bad arm spec %s\n", argv[i]); return 2; }
        *eq = 0;
        labels[arms] = argv[i];
        dirs[arms] = eq + 1;
        arms++;
    }

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        fprintf(stderr, "sched_setaffinity: %s\n", strerror(errno));
        return 1;
    }

    for (int a = 0; a < arms; a++) {
        uint64_t t = 0, d = 0;
        if (run_batch(dirs[a], ops < 20 ? ops : 20, &t, &d) != 0) return 1;
        fprintf(stderr, "warmup %s %.3fms digest=%llu\n", labels[a], (double)t / 1e6,
                (unsigned long long)d);
    }

    printf("round,pos,arm,total_ns,digest,daemon_ticks\n");
    for (int round = 0; round < rounds; round++) {
        for (int pos = 0; pos < arms; pos++) {
            int a = (pos + round) % arms;   // rotate arm order per round
            unsigned long long before = 0, after = 0;
            read_daemon_ticks(fuse_pid, &before);
            uint64_t t = 0, d = 0;
            if (run_batch(dirs[a], ops, &t, &d) != 0) return 1;
            read_daemon_ticks(fuse_pid, &after);
            printf("%d,%d,%s,%llu,%llu,%llu\n", round, pos, labels[a],
                   (unsigned long long)t, (unsigned long long)d, after - before);
        }
    }
    return 0;
}

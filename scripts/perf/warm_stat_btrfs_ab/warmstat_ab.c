// warmstat_ab.c — reproduce ffs-mounted-kernel-bench's `warm-stat` batch
// (crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs:3812 `stat_batch`) against
// N live mounts INTERLEAVED IN ONE INVOCATION, arm order rotated per round.
//
// batch = `operations` repeated stat()s of ONE warm file, single client thread,
// folding size/mode/nlink/index. No I/O, no allocation, no directory work — which
// is why bd-warm-stat-is-the-fuse-floor-4wxw9 calls it the cleanest instrument in
// either bank: what it isolates is the per-request FUSE round trip and the inode
// lookup, and essentially nothing else.
//
// The digest folds metadata and the loop index only — never a path — so two arms on
// different mountpoints must agree, and the field is a real cross-arm parity oracle.
//
// usage: warmstat_ab ROUNDS OPS CPU FUSEPID label=dir [label=dir ...]
// prints CSV: round,pos,arm,total_ns,digest,daemon_ticks

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_ARMS 8

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
static uint64_t rotl(uint64_t v, unsigned n) { return (v << n) | (v >> (64 - n)); }

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
    char *cp = strrchr(buf, ')');
    if (!cp) return -1;
    unsigned long long ut = 0, st = 0;
    int field = 3;
    for (char *tok = strtok(cp + 2, " "); tok; tok = strtok(NULL, " "), field++) {
        if (field == 14) ut = strtoull(tok, NULL, 10);
        if (field == 15) { st = strtoull(tok, NULL, 10); break; }
    }
    *out = ut + st;
    return 0;
}

static int run_batch(const char *root, long ops, uint64_t *total_ns, uint64_t *digest_out) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/payload.bin", root);
    uint64_t digest = 0x9E3779B97F4A7C15ull;
    struct stat st;
    uint64_t t0 = now_ns();
    for (long i = 0; i < ops; i++) {
        if (stat(path, &st) != 0) {
            fprintf(stderr, "timed stat %s: %s\n", path, strerror(errno));
            return -1;
        }
        uint64_t row = (uint64_t)st.st_size * 0xD6E8FEB86659FD93ull;
        row ^= rotl((uint64_t)st.st_mode, 17);
        row ^= rotl((uint64_t)st.st_nlink, 31);
        row ^= (uint64_t)i;
        digest = rotl(digest, 9) ^ row;
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
    int rounds = atoi(argv[1]);
    long ops = atol(argv[2]);
    int cpu = atoi(argv[3]), fuse_pid = atoi(argv[4]);

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
        if (run_batch(dirs[a], ops < 200 ? ops : 200, &t, &d) != 0) return 1;
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

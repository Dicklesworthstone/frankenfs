// fsync_ab.c — reproduce ffs-mounted-kernel-bench's `fsync-journal-commit` batch
// (crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs:4252 fsync_journal_batch)
// against N live mounts INTERLEAVED IN ONE INVOCATION, arm order rotated per round.
//
// batch = `ops` iterations of: pwrite 4096 bytes at offset 0 of <root>/fsync.bin,
// then fsync the file. Single thread, as the banked row (1 -> 1).
//
// Each arm may carry a /sys/block/<dev>/stat path so the SECTORS WRITTEN per batch
// are counted per arm — the durability-class check bd-4zjkz says this row needs.
//
// usage: fsync_ab ROUNDS OPS CPU FUSEPID label=dir[=statfile] ...
// prints CSV: round,pos,arm,total_ns,ns_per_op,sectors_written,digest,daemon_ticks

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_ARMS 8

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t rotl(uint64_t v, unsigned n) {
    n &= 63;
    return n == 0 ? v : (v << n) | (v >> (64 - n));
}

// /sys/block/<dev>/stat, 1-based: 5 = writes completed, 7 = sectors written,
// 16 = FLUSH requests completed (the cache barriers a durability boundary costs).
static void block_stat(const char *statfile, unsigned long long *ios,
                       unsigned long long *sectors, unsigned long long *flushes) {
    *ios = 0; *sectors = 0; *flushes = 0;
    if (!statfile || !*statfile) return;
    FILE *f = fopen(statfile, "r");
    if (!f) return;
    unsigned long long v[17] = {0};
    int n = 0;
    for (int i = 0; i < 17; i++) {
        if (fscanf(f, "%llu", &v[i]) != 1) break;
        n = i + 1;
    }
    fclose(f);
    if (n >= 7) { *ios = v[4]; *sectors = v[6]; }
    if (n >= 16) { *flushes = v[15]; }
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
    char *p = strrchr(buf, ')');
    if (!p) return -1;
    p += 2;
    unsigned long long utime = 0, stime = 0;
    int field = 3;
    char *tok = strtok(p, " ");
    while (tok) {
        if (field == 14) utime = strtoull(tok, NULL, 10);
        if (field == 15) { stime = strtoull(tok, NULL, 10); break; }
        field++;
        tok = strtok(NULL, " ");
    }
    *out = utime + stime;
    return 0;
}

static int run_batch(const char *root, unsigned long ops, unsigned long sequence,
                     uint64_t *total_ns, uint64_t *digest_out) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/fsync.bin", root);
    int fd = open(path, O_RDWR);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return -1; }
    static unsigned char payload[4096];
    uint64_t digest = 0;

    uint64_t t0 = now_ns();
    for (unsigned long i = 0; i < ops; i++) {
        unsigned char value = (unsigned char)((sequence * 37 + i * 17) % 251);
        memset(payload, value, sizeof(payload));
        size_t done = 0;
        while (done < sizeof(payload)) {
            ssize_t w = pwrite(fd, payload + done, sizeof(payload) - done, (off_t)done);
            if (w <= 0) { fprintf(stderr, "pwrite: %s\n", strerror(errno)); close(fd); return -1; }
            done += (size_t)w;
        }
        if (fsync(fd) != 0) { fprintf(stderr, "fsync: %s\n", strerror(errno)); close(fd); return -1; }
        digest ^= rotl((uint64_t)value, (unsigned)(i % 64));
    }
    uint64_t t1 = now_ns();
    close(fd);
    *total_ns = t1 - t0;
    *digest_out = digest;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s ROUNDS OPS CPU FUSEPID label=dir[=statfile] ...\n", argv[0]);
        return 2;
    }
    int rounds = atoi(argv[1]);
    unsigned long ops = strtoul(argv[2], NULL, 10);
    int cpu = atoi(argv[3]);
    int fusepid = atoi(argv[4]);
    int narms = argc - 5;
    if (narms > MAX_ARMS) { fprintf(stderr, "too many arms\n"); return 2; }
    char *labels[MAX_ARMS], *dirs[MAX_ARMS], *stats[MAX_ARMS];
    for (int i = 0; i < narms; i++) {
        char *s = argv[5 + i];
        char *eq = strchr(s, '=');
        if (!eq) { fprintf(stderr, "bad arm spec %s\n", s); return 2; }
        *eq = 0;
        labels[i] = s;
        dirs[i] = eq + 1;
        char *eq2 = strchr(dirs[i], '=');
        if (eq2) { *eq2 = 0; stats[i] = eq2 + 1; } else { stats[i] = NULL; }
    }

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        fprintf(stderr, "sched_setaffinity: %s\n", strerror(errno));
        return 1;
    }

    unsigned long sequence = 0;
    for (int i = 0; i < narms; i++) {
        uint64_t t, dg;
        if (run_batch(dirs[i], ops, sequence++, &t, &dg) != 0) return 1;
        fprintf(stderr, "warmup %s %.3fms (%.1f us/op)\n", labels[i], t / 1e6, t / 1e3 / (double)ops);
    }

    printf("round,pos,arm,total_ns,ns_per_op,sectors_written,write_ios,flush_ios,digest,daemon_ticks\n");
    for (int r = 0; r < rounds; r++) {
        for (int pos = 0; pos < narms; pos++) {
            int i = (pos + r) % narms;
            unsigned long long tb = 0, ta = 0;
            unsigned long long sb, ib, fb, sa, ia, fa;
            block_stat(stats[i], &ib, &sb, &fb);
            read_daemon_ticks(fusepid, &tb);
            uint64_t t, dg;
            if (run_batch(dirs[i], ops, sequence++, &t, &dg) != 0) return 1;
            read_daemon_ticks(fusepid, &ta);
            block_stat(stats[i], &ia, &sa, &fa);
            printf("%d,%d,%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n", r, pos, labels[i],
                   (unsigned long long)t, (unsigned long long)(t / ops),
                   sa - sb, ia - ib, fa - fb, (unsigned long long)dg, ta - tb);
            fflush(stdout);
        }
    }
    return 0;
}

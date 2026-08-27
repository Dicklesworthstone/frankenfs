// storm_ab.c — reproduce ffs-mounted-kernel-bench's `create-delete-storm` batch
// (crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs:4138
// create_delete_storm_batch) against N live mounts INTERLEAVED IN ONE INVOCATION,
// arm order rotated per round.
//
// batch = serially create `ops` empty files storm-%08d in create-delete-storm/,
// fsync the parent, remove all `ops`, fsync the parent again. Single thread, as
// the banked row (1 -> 1 threads).
//
// usage: storm_ab ROUNDS OPS CPU FUSEPID label=dir [label=dir ...]
// prints CSV: round,pos,arm,create_ns,fsync1_ns,delete_ns,fsync2_ns,total_ns,digest,daemon_ticks

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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

static uint64_t digest_path(const char *p) {
    uint64_t h = 1469598103934665603ull;
    for (const unsigned char *c = (const unsigned char *)p; *c; c++) {
        h ^= *c;
        h *= 1099511628211ull;
    }
    return h;
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

static int fsync_dir(const char *dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", dir, strerror(errno)); return -1; }
    if (fsync(fd) != 0) { fprintf(stderr, "fsync %s: %s\n", dir, strerror(errno)); close(fd); return -1; }
    close(fd);
    return 0;
}

static int run_batch(const char *root, unsigned long ops, uint64_t *create_ns,
                     uint64_t *fsync1_ns, uint64_t *delete_ns, uint64_t *fsync2_ns,
                     uint64_t *digest_out) {
    char parent[3584];
    snprintf(parent, sizeof(parent), "%s/create-delete-storm", root);
    char path[4096];
    uint64_t digest = 0;

    uint64_t t0 = now_ns();
    for (unsigned long i = 0; i < ops; i++) {
        snprintf(path, sizeof(path), "%s/storm-%08lu", parent, i);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) { fprintf(stderr, "create %s: %s\n", path, strerror(errno)); return -1; }
        close(fd);
        digest ^= digest_path(path);
    }
    uint64_t t1 = now_ns();
    if (fsync_dir(parent) != 0) return -1;
    uint64_t t2 = now_ns();
    for (unsigned long i = 0; i < ops; i++) {
        snprintf(path, sizeof(path), "%s/storm-%08lu", parent, i);
        if (remove(path) != 0) { fprintf(stderr, "remove %s: %s\n", path, strerror(errno)); return -1; }
    }
    uint64_t t3 = now_ns();
    if (fsync_dir(parent) != 0) return -1;
    uint64_t t4 = now_ns();

    *create_ns = t1 - t0;
    *fsync1_ns = t2 - t1;
    *delete_ns = t3 - t2;
    *fsync2_ns = t4 - t3;
    *digest_out = digest ^ ops;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s ROUNDS OPS CPU FUSEPID label=dir [...]\n", argv[0]);
        return 2;
    }
    int rounds = atoi(argv[1]);
    unsigned long ops = strtoul(argv[2], NULL, 10);
    int cpu = atoi(argv[3]);
    int fusepid = atoi(argv[4]);
    int narms = argc - 5;
    if (narms > MAX_ARMS) { fprintf(stderr, "too many arms\n"); return 2; }
    char *labels[MAX_ARMS];
    char *dirs[MAX_ARMS];
    for (int i = 0; i < narms; i++) {
        char *s = argv[5 + i];
        char *eq = strchr(s, '=');
        if (!eq) { fprintf(stderr, "bad arm spec %s\n", s); return 2; }
        *eq = 0;
        labels[i] = s;
        dirs[i] = eq + 1;
    }

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        fprintf(stderr, "sched_setaffinity: %s\n", strerror(errno));
        return 1;
    }

    for (int i = 0; i < narms; i++) {
        uint64_t c, f1, d, f2, dg;
        if (run_batch(dirs[i], ops, &c, &f1, &d, &f2, &dg) != 0) return 1;
        fprintf(stderr, "warmup %s create=%.3fms fsync1=%.3fms delete=%.3fms fsync2=%.3fms\n",
                labels[i], c / 1e6, f1 / 1e6, d / 1e6, f2 / 1e6);
    }

    printf("round,pos,arm,create_ns,fsync1_ns,delete_ns,fsync2_ns,total_ns,digest,daemon_ticks\n");
    for (int r = 0; r < rounds; r++) {
        for (int pos = 0; pos < narms; pos++) {
            int i = (pos + r) % narms;
            unsigned long long tb = 0, ta = 0;
            read_daemon_ticks(fusepid, &tb);
            uint64_t c, f1, d, f2, dg;
            if (run_batch(dirs[i], ops, &c, &f1, &d, &f2, &dg) != 0) return 1;
            read_daemon_ticks(fusepid, &ta);
            printf("%d,%d,%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n", r, pos, labels[i],
                   (unsigned long long)c, (unsigned long long)f1,
                   (unsigned long long)d, (unsigned long long)f2,
                   (unsigned long long)(c + f1 + d + f2),
                   (unsigned long long)dg, ta - tb);
            fflush(stdout);
        }
    }
    return 0;
}

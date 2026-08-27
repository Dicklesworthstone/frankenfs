// bulkwrite_ab.c — reproduce ffs-mounted-kernel-bench's `bulk-durable-write` batch shape
// (crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs:4279 bulk_durable_write_batch)
// against N live mounts INTERLEAVED IN ONE INVOCATION, arm order rotated per round.
//
// batch = open <root>/bulk-durable.bin O_RDWR, `chunks` sequential pwrite()s of
// 1 MiB each, then one fsync of the file. Single client thread, as the banked row.
//
// usage: bulkwrite_ab ROUNDS CHUNKS CPU label=dir=block-stat=FUSEPID [...]
// prints CSV: round,pos,arm,write_ns,fsync_ns,total_ns,bytes,daemon_ticks

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
#define CHUNK (1024UL * 1024UL)

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// /sys/block/<dev>/stat, 1-based: 5 = writes completed, 7 = sectors written,
// 16 = FLUSH requests completed. Split per PHASE so the 64 MiB of payload can be
// told apart from what the durability boundary costs.
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

struct phase_io { unsigned long long ios, sectors, flushes; };

static void io_delta(const char *sf, struct phase_io *before, struct phase_io *out) {
    struct phase_io now;
    block_stat(sf, &now.ios, &now.sectors, &now.flushes);
    out->ios = now.ios - before->ios;
    out->sectors = now.sectors - before->sectors;
    out->flushes = now.flushes - before->flushes;
    *before = now;
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

// bulk_durable_sequence_byte from the harness.
static unsigned char seq_byte(unsigned long sequence) {
    return (unsigned char)(((sequence % 251) * 37 + 113) % 251);
}

static unsigned char *payload;

struct arm {
    char *label;
    char *dir;
    char *statfile;
    int fusepid;
};

static int parse_arm(char *spec, struct arm *out) {
    char *eq = strchr(spec, '=');
    if (!eq) return -1;
    *eq = 0;
    out->label = spec;
    out->dir = eq + 1;

    eq = strchr(out->dir, '=');
    if (!eq) return -1;
    *eq = 0;
    out->statfile = eq + 1;

    eq = strchr(out->statfile, '=');
    if (!eq) return -1;
    *eq = 0;
    char *pid_text = eq + 1;
    char *end = NULL;
    long pid = strtol(pid_text, &end, 10);
    if (out->label[0] == 0 || out->dir[0] == 0 || out->statfile[0] == 0
        || *pid_text == 0 || *end != 0 || pid < 0 || pid > INT32_MAX) {
        return -1;
    }
    out->fusepid = (int)pid;
    return 0;
}

static int self_test(void) {
    char first[] = "baseA=/mnt/a=/sys/block/loop1/stat=101";
    char second[] = "baseB=/mnt/b=/sys/block/loop2/stat=202";
    char missing_pid[] = "baseA=/mnt/a=/sys/block/loop1/stat";
    char invalid_pid[] = "baseA=/mnt/a=/sys/block/loop1/stat=not-a-pid";
    struct arm a;
    struct arm b;
    struct arm ignored;

    if (parse_arm(first, &a) != 0 || parse_arm(second, &b) != 0
        || strcmp(a.label, "baseA") != 0 || strcmp(b.label, "baseB") != 0
        || a.fusepid != 101 || b.fusepid != 202 || a.fusepid == b.fusepid
        || parse_arm(missing_pid, &ignored) == 0 || parse_arm(invalid_pid, &ignored) == 0) {
        fprintf(stderr, "per-arm PID parser self-test failed\n");
        return 1;
    }
    puts("per-arm PID parser self-test passed");
    return 0;
}

static int run_batch(const char *root, unsigned long chunks, unsigned long sequence,
                     uint64_t *write_ns, uint64_t *fsync_ns,
                     const char *statfile, struct phase_io io[2],
                     int fusepid, unsigned long long dticks[2]) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/bulk-durable.bin", root);
    int fd = open(path, O_RDWR);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0) { fprintf(stderr, "fstat: %s\n", strerror(errno)); return -1; }
    if ((unsigned long)st.st_size != chunks * CHUNK) {
        fprintf(stderr, "%s is %llu bytes, expected %lu\n", path,
                (unsigned long long)st.st_size, chunks * CHUNK);
        return -1;
    }
    memset(payload, seq_byte(sequence), CHUNK);

    struct phase_io mark;
    block_stat(statfile, &mark.ios, &mark.sectors, &mark.flushes);
    unsigned long long dm = 0, dnow = 0;
    read_daemon_ticks(fusepid, &dm);

    uint64_t t0 = now_ns();
    for (unsigned long i = 0; i < chunks; i++) {
        off_t off = (off_t)(i * CHUNK);
        size_t done = 0;
        while (done < CHUNK) {
            ssize_t w = pwrite(fd, payload + done, CHUNK - done, off + (off_t)done);
            if (w <= 0) { fprintf(stderr, "pwrite: %s\n", strerror(errno)); return -1; }
            done += (size_t)w;
        }
    }
    uint64_t t1 = now_ns();
    io_delta(statfile, &mark, &io[0]);
    read_daemon_ticks(fusepid, &dnow); dticks[0] = dnow - dm; dm = dnow;
    if (fsync(fd) != 0) { fprintf(stderr, "fsync: %s\n", strerror(errno)); return -1; }
    uint64_t t2 = now_ns();
    io_delta(statfile, &mark, &io[1]);
    read_daemon_ticks(fusepid, &dnow); dticks[1] = dnow - dm;
    close(fd);
    *write_ns = t1 - t0;
    *fsync_ns = t2 - t1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) return self_test();
    if (argc < 5) {
        fprintf(stderr, "usage: %s ROUNDS CHUNKS CPU label=dir=block-stat=FUSEPID [...]\n", argv[0]);
        return 2;
    }
    int rounds = atoi(argv[1]);
    unsigned long chunks = strtoul(argv[2], NULL, 10);
    int cpu = atoi(argv[3]);
    int narms = argc - 4;
    if (narms > MAX_ARMS) { fprintf(stderr, "too many arms\n"); return 2; }
    struct arm arms[MAX_ARMS];
    for (int i = 0; i < narms; i++) {
        if (parse_arm(argv[4 + i], &arms[i]) != 0) {
            fprintf(stderr, "bad arm spec %s\n", argv[4 + i]);
            return 2;
        }
    }

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        fprintf(stderr, "sched_setaffinity: %s\n", strerror(errno));
        return 1;
    }
    if (posix_memalign((void **)&payload, 4096, CHUNK) != 0) return 1;

    unsigned long sequence = 0;
    struct phase_io io[2];
    unsigned long long dticks[2] = {0, 0};
    for (int i = 0; i < narms; i++) {
        uint64_t w, f;
        if (run_batch(arms[i].dir, chunks, sequence++, &w, &f, arms[i].statfile,
                      io, arms[i].fusepid, dticks) != 0) return 1;
        fprintf(stderr, "warmup %s write=%.3fms fsync=%.3fms\n", arms[i].label, w / 1e6, f / 1e6);
    }

    printf("round,pos,arm,write_ns,fsync_ns,total_ns,bytes,daemon_ticks,w_ios,w_sec,w_fl,f_ios,f_sec,f_fl,w_dticks,f_dticks\n");
    for (int r = 0; r < rounds; r++) {
        for (int pos = 0; pos < narms; pos++) {
            int i = (pos + r) % narms;
            unsigned long long tb = 0, ta = 0;
            read_daemon_ticks(arms[i].fusepid, &tb);
            uint64_t w, f;
            if (run_batch(arms[i].dir, chunks, sequence++, &w, &f, arms[i].statfile,
                          io, arms[i].fusepid, dticks) != 0) return 1;
            read_daemon_ticks(arms[i].fusepid, &ta);
            printf("%d,%d,%s,%llu,%llu,%llu,%lu,%llu", r, pos, arms[i].label,
                   (unsigned long long)w, (unsigned long long)f,
                   (unsigned long long)(w + f), chunks * CHUNK, ta - tb);
            for (int q = 0; q < 2; q++)
                printf(",%llu,%llu,%llu", io[q].ios, io[q].sectors, io[q].flushes);
            printf(",%llu,%llu\n", dticks[0], dticks[1]);
            fflush(stdout);
        }
    }
    return 0;
}

// pread_ab.c — reproduce ffs-mounted-kernel-bench's `parallel-read-8t` batch shape
// (crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs:4063 parallel_read_batch)
// against N live mounts INTERLEAVED IN ONE INVOCATION, arm order rotated per round.
//
// batch = readdir <root>/parallel-read, BYTE-SORT the paths, then THREADS workers
// each open + pread one whole 256 KiB file per stride step, folding a content digest.
//
// usage: pread_ab ROUNDS THREADS CPUBASE label=dir=FUSEPID [label=dir=FUSEPID ...]
// prints CSV: round,pos,arm,list_ns,read_ns,total_ns,digest,daemon_ticks

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_ARMS 8
#define FILE_BYTES (256 * 1024)

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t rotl(uint64_t v, unsigned n) {
    n &= 63;
    return n == 0 ? v : (v << n) | (v >> (64 - n));
}

static int cmp_bytes(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

struct worker {
    pthread_t tid;
    int worker;
    int threads;
    int cpu;
    char **paths;
    size_t count;
    unsigned char *buf;
    uint64_t digest;
    int err;
};

struct arm {
    char *label;
    char *dir;
    int fusepid;
};

static int parse_arm(char *spec, struct arm *arm) {
    char *label_end = strchr(spec, '=');
    if (!label_end || label_end == spec) {
        fprintf(stderr, "bad arm spec %s (expected label=dir=FUSEPID)\n", spec);
        return -1;
    }
    *label_end = 0;
    char *dir = label_end + 1;
    char *pid_start = strrchr(dir, '=');
    if (!pid_start || pid_start == dir || pid_start[1] == 0) {
        fprintf(stderr, "bad arm spec %s (expected label=dir=FUSEPID)\n", spec);
        return -1;
    }
    *pid_start = 0;
    errno = 0;
    char *end = NULL;
    long pid = strtol(pid_start + 1, &end, 10);
    if (errno != 0 || end == pid_start + 1 || *end != 0 || pid < 0 || pid > INT_MAX) {
        fprintf(stderr, "bad daemon pid in arm spec\n");
        return -1;
    }
    arm->label = spec;
    arm->dir = dir;
    arm->fusepid = (int)pid;
    return 0;
}

static int parser_self_test(void) {
    struct arm arm;
    char fuse[] = "ffsA=/mnt/a=101";
    char kernel[] = "k1=/mnt/k1=0";
    char missing_pid[] = "bad=/mnt";
    char nonnumeric_pid[] = "bad=/mnt=no";
    char negative_pid[] = "bad=/mnt=-1";
    if (parse_arm(fuse, &arm) != 0 || strcmp(arm.label, "ffsA") != 0
        || strcmp(arm.dir, "/mnt/a") != 0 || arm.fusepid != 101) return 1;
    if (parse_arm(kernel, &arm) != 0 || strcmp(arm.label, "k1") != 0
        || strcmp(arm.dir, "/mnt/k1") != 0 || arm.fusepid != 0) return 1;
    if (parse_arm(missing_pid, &arm) == 0) return 1;
    if (parse_arm(nonnumeric_pid, &arm) == 0) return 1;
    if (parse_arm(negative_pid, &arm) == 0) return 1;
    return 0;
}

static void *worker_main(void *arg) {
    struct worker *w = arg;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(w->cpu, &set);
    if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0) {
        w->err = errno;
        return NULL;
    }
    uint64_t digest = 0;
    for (size_t i = (size_t)w->worker; i < w->count; i += (size_t)w->threads) {
        int fd = open(w->paths[i], O_RDONLY);
        if (fd < 0) { w->err = errno; return NULL; }
        size_t done = 0;
        while (done < FILE_BYTES) {
            ssize_t r = pread(fd, w->buf + done, FILE_BYTES - done, (off_t)done);
            if (r <= 0) { w->err = errno ? errno : EIO; close(fd); return NULL; }
            done += (size_t)r;
        }
        close(fd);
        uint64_t row = (uint64_t)w->buf[0]
                     | ((uint64_t)w->buf[FILE_BYTES / 2] << 8)
                     | ((uint64_t)w->buf[FILE_BYTES - 1] << 16)
                     | rotl((uint64_t)FILE_BYTES, 29)
                     | rotl((uint64_t)i, 41);
        digest = rotl(digest, 11) ^ row;
    }
    w->digest = digest;
    return NULL;
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

static int run_batch(const char *root, int threads, int cpubase, uint64_t *list_ns,
                     uint64_t *read_ns, uint64_t *digest_out) {
    char parent[3584];
    snprintf(parent, sizeof(parent), "%s/parallel-read", root);

    uint64_t t0 = now_ns();
    DIR *d = opendir(parent);
    if (!d) { fprintf(stderr, "opendir %s: %s\n", parent, strerror(errno)); return -1; }
    size_t cap = 512, count = 0;
    char **paths = malloc(cap * sizeof(char *));
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (count == cap) { cap *= 2; paths = realloc(paths, cap * sizeof(char *)); }
        size_t len = strlen(parent) + 1 + strlen(e->d_name) + 1;
        char *p = malloc(len);
        snprintf(p, len, "%s/%s", parent, e->d_name);
        paths[count++] = p;
    }
    closedir(d);
    qsort(paths, count, sizeof(char *), cmp_bytes);
    uint64_t t1 = now_ns();

    struct worker *ws = calloc((size_t)threads, sizeof(struct worker));
    for (int i = 0; i < threads; i++) {
        ws[i].worker = i;
        ws[i].threads = threads;
        ws[i].cpu = cpubase + i;
        ws[i].paths = paths;
        ws[i].count = count;
        ws[i].buf = malloc(FILE_BYTES);
        if (pthread_create(&ws[i].tid, NULL, worker_main, &ws[i]) != 0) {
            fprintf(stderr, "pthread_create: %s\n", strerror(errno));
            return -1;
        }
    }
    uint64_t digest = 0;
    int err = 0;
    for (int i = 0; i < threads; i++) {
        pthread_join(ws[i].tid, NULL);
        digest ^= ws[i].digest;
        if (ws[i].err) err = ws[i].err;
        free(ws[i].buf);
    }
    uint64_t t2 = now_ns();
    if (err) { fprintf(stderr, "worker error: %s\n", strerror(err)); return -1; }

    for (size_t i = 0; i < count; i++) free(paths[i]);
    free(paths);
    free(ws);
    *list_ns = t1 - t0;
    *read_ns = t2 - t1;
    *digest_out = digest;
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) return parser_self_test();
    if (argc < 5) {
        fprintf(stderr, "usage: %s ROUNDS THREADS CPUBASE label=dir=FUSEPID [...]\n", argv[0]);
        return 2;
    }
    int rounds = atoi(argv[1]);
    int threads = atoi(argv[2]);
    int cpubase = atoi(argv[3]);
    int narms = argc - 4;
    if (narms > MAX_ARMS) { fprintf(stderr, "too many arms\n"); return 2; }
    struct arm arms[MAX_ARMS];
    for (int i = 0; i < narms; i++) {
        if (parse_arm(argv[4 + i], &arms[i]) != 0) return 2;
    }

    for (int i = 0; i < narms; i++) {
        uint64_t l, rd, dg;
        if (run_batch(arms[i].dir, threads, cpubase, &l, &rd, &dg) != 0) return 1;
        fprintf(stderr, "warmup %s list=%.3fms read=%.3fms digest=%llu\n",
                arms[i].label, l / 1e6, rd / 1e6, (unsigned long long)dg);
    }

    printf("round,pos,arm,list_ns,read_ns,total_ns,digest,daemon_ticks\n");
    for (int r = 0; r < rounds; r++) {
        for (int pos = 0; pos < narms; pos++) {
            int i = (pos + r) % narms;
            unsigned long long tb = 0, ta = 0;
            read_daemon_ticks(arms[i].fusepid, &tb);
            uint64_t l, rd, dg;
            if (run_batch(arms[i].dir, threads, cpubase, &l, &rd, &dg) != 0) return 1;
            read_daemon_ticks(arms[i].fusepid, &ta);
            printf("%d,%d,%s,%llu,%llu,%llu,%llu,%llu\n", r, pos, arms[i].label,
                   (unsigned long long)l, (unsigned long long)rd,
                   (unsigned long long)(l + rd), (unsigned long long)dg, ta - tb);
            fflush(stdout);
        }
    }
    return 0;
}

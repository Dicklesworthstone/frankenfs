// rdstat_ab.c — reproduce ffs-mounted-kernel-bench's `readdir-stat-8t` batch shape
// (crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs:4171 readdir_stat_batch)
// against N live mounts INTERLEAVED IN ONE INVOCATION, with arm order rotated per
// round so position cannot be priced as effect.
//
// batch = readdir <root>/large-directory collecting every path, then THREADS
// workers each lstat()ing its stride slice exactly once, folding a digest.
//
// usage: rdstat_ab ROUNDS THREADS CPUBASE FUSEPID label=dir [label=dir ...]
//   FUSEPID: pid whose /proc/<pid>/stat utime+stime delta is reported per round
//            (0 = skip)
// prints CSV: round,pos,arm,readdir_ns,stat_ns,total_ns,digest,daemon_ticks

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
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

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t digest_path(const char *p) {
    // FNV-1a over the path bytes; stands in for the harness's digest_path.
    uint64_t h = 1469598103934665603ull;
    for (const unsigned char *c = (const unsigned char *)p; *c; c++) {
        h ^= *c;
        h *= 1099511628211ull;
    }
    return h;
}

static uint64_t rotl(uint64_t v, unsigned n) { return (v << n) | (v >> (64 - n)); }

struct worker {
    pthread_t tid;
    int worker;
    int threads;
    int cpu;
    char **paths;
    size_t count;
    uint64_t digest;
    int err;
};

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
        struct stat st;
        if (lstat(w->paths[i], &st) != 0) {
            w->err = errno;
            return NULL;
        }
        uint64_t row = (uint64_t)st.st_size * 0xD6E8FEB86659FD93ull;
        row ^= rotl((uint64_t)st.st_mode, 17);
        row ^= rotl((uint64_t)st.st_nlink, 31);
        row ^= digest_path(w->paths[i]);
        digest += row;
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
    // fields after the ")" of comm: state is field 3; utime=14, stime=15
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

// Runs one batch. Returns 0 on success.
static int run_batch(const char *root, int threads, int cpubase,
                     uint64_t *readdir_ns, uint64_t *stat_ns, uint64_t *digest_out) {
    char parent[4096];
    snprintf(parent, sizeof(parent), "%s/large-directory", root);

    uint64_t t0 = now_ns();
    DIR *d = opendir(parent);
    if (!d) { fprintf(stderr, "opendir %s: %s\n", parent, strerror(errno)); return -1; }
    size_t cap = 4096, count = 0;
    char **paths = malloc(cap * sizeof(char *));
    struct dirent *e;
    errno = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' && (e->d_name[1] == 0 || (e->d_name[1] == '.' && e->d_name[2] == 0)))
            continue;
        if (count == cap) { cap *= 2; paths = realloc(paths, cap * sizeof(char *)); }
        size_t len = strlen(parent) + 1 + strlen(e->d_name) + 1;
        char *p = malloc(len);
        snprintf(p, len, "%s/%s", parent, e->d_name);
        paths[count++] = p;
        errno = 0;
    }
    if (errno != 0) { fprintf(stderr, "readdir %s: %s\n", parent, strerror(errno)); return -1; }
    closedir(d);
    uint64_t t1 = now_ns();

    struct worker *ws = calloc((size_t)threads, sizeof(struct worker));
    for (int i = 0; i < threads; i++) {
        ws[i].worker = i;
        ws[i].threads = threads;
        ws[i].cpu = cpubase + i;
        ws[i].paths = paths;
        ws[i].count = count;
        if (pthread_create(&ws[i].tid, NULL, worker_main, &ws[i]) != 0) {
            fprintf(stderr, "pthread_create: %s\n", strerror(errno));
            return -1;
        }
    }
    uint64_t digest = 0;
    int err = 0;
    for (int i = 0; i < threads; i++) {
        pthread_join(ws[i].tid, NULL);
        digest += ws[i].digest;
        if (ws[i].err) err = ws[i].err;
    }
    uint64_t t2 = now_ns();
    if (err) { fprintf(stderr, "worker error: %s\n", strerror(err)); return -1; }

    for (size_t i = 0; i < count; i++) free(paths[i]);
    free(paths);
    free(ws);

    *readdir_ns = t1 - t0;
    *stat_ns = t2 - t1;
    *digest_out = digest;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s ROUNDS THREADS CPUBASE FUSEPID label=dir [label=dir ...]\n", argv[0]);
        return 2;
    }
    int rounds = atoi(argv[1]);
    int threads = atoi(argv[2]);
    int cpubase = atoi(argv[3]);
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

    // Untimed warmup: one batch per arm so every arm's dentry/attr caches are in
    // the same steady state the comparator's warmups establish.
    for (int i = 0; i < narms; i++) {
        uint64_t a, b, dg;
        if (run_batch(dirs[i], threads, cpubase, &a, &b, &dg) != 0) return 1;
        fprintf(stderr, "warmup %s readdir=%.3fms stat=%.3fms digest=%llu\n",
                labels[i], a / 1e6, b / 1e6, (unsigned long long)dg);
    }

    printf("round,pos,arm,readdir_ns,stat_ns,total_ns,digest,daemon_ticks\n");
    for (int r = 0; r < rounds; r++) {
        for (int pos = 0; pos < narms; pos++) {
            int i = (pos + r) % narms;  // rotate arm order per round
            unsigned long long t_before = 0, t_after = 0;
            read_daemon_ticks(fusepid, &t_before);
            uint64_t rd, sn, dg;
            if (run_batch(dirs[i], threads, cpubase, &rd, &sn, &dg) != 0) return 1;
            read_daemon_ticks(fusepid, &t_after);
            printf("%d,%d,%s,%llu,%llu,%llu,%llu,%llu\n", r, pos, labels[i],
                   (unsigned long long)rd, (unsigned long long)sn,
                   (unsigned long long)(rd + sn), (unsigned long long)dg,
                   t_after - t_before);
            fflush(stdout);
        }
    }
    return 0;
}

// pmeta_ab.c — reproduce ffs-mounted-kernel-bench's `parallel-metadata-write` batch
// (crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs:3935
// parallel_metadata_write_batch) against N live mounts INTERLEAVED IN ONE
// INVOCATION, arm order rotated per round.
//
// batch = THREADS workers each `open(O_CREAT|O_EXCL)` `ops/THREADS` files named
// r<seq>-<index> into its OWN parallel-metadata/worker-<n> directory, then the
// driver fsyncs every worker directory. Timed end to end. The unlink that resets
// the tree for the next batch is OUTSIDE the timed region, as in the harness.
//
// usage: pmeta_ab ROUNDS OPS THREADS CPUBASE FUSEPID label=dir [label=dir ...]
// prints CSV: round,pos,arm,create_ns,fsync_ns,total_ns,digest,daemon_ticks

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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
#define MAX_THREADS 64

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t rotl(uint64_t v, unsigned n) {
    n &= 63;
    return n == 0 ? v : (v << n) | (v >> (64 - n));
}

struct worker {
    pthread_t tid;
    int worker;
    int cpu;
    unsigned long ops;
    unsigned long sequence;
    char dir[3072];
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
    char path[4096];
    for (unsigned long i = 0; i < w->ops; i++) {
        snprintf(path, sizeof(path), "%s/r%06lu-%06lu", w->dir, w->sequence, i);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) { w->err = errno; return NULL; }
        close(fd);
        digest ^= rotl(i + 1, (unsigned)(w->worker * 7));
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

// Untimed reset: remove every entry under each worker directory.
static int reset_tree(const char *root, int threads) {
    char dir[3584];
    for (int w = 0; w < threads; w++) {
        snprintf(dir, sizeof(dir), "%s/parallel-metadata/worker-%d", root, w);
        DIR *d = opendir(dir);
        if (!d) { fprintf(stderr, "opendir %s: %s\n", dir, strerror(errno)); return -1; }
        // Collect every name FIRST, then remove: removing while iterating and
        // rewinding is O(n^2) readdirs and would swamp the daemon census even
        // though the reset is untimed.
        struct dirent *e;
        size_t cap = 1024, count = 0;
        char **names = malloc(cap * sizeof(char *));
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            if (count == cap) { cap *= 2; names = realloc(names, cap * sizeof(char *)); }
            names[count++] = strdup(e->d_name);
        }
        closedir(d);
        for (size_t i = 0; i < count; i++) {
            char path[4096];
            snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
            if (remove(path) != 0) {
                fprintf(stderr, "remove %s: %s\n", path, strerror(errno));
                return -1;
            }
            free(names[i]);
        }
        free(names);
    }
    return 0;
}

static int run_batch(const char *root, unsigned long ops, int threads, int cpubase,
                     unsigned long sequence, uint64_t *create_ns, uint64_t *fsync_ns,
                     uint64_t *digest_out) {
    struct worker ws[MAX_THREADS];
    memset(ws, 0, sizeof(ws));
    uint64_t t0 = now_ns();
    for (int i = 0; i < threads; i++) {
        ws[i].worker = i;
        ws[i].cpu = cpubase + i;
        ws[i].ops = ops / (unsigned long)threads + (((unsigned long)i < ops % (unsigned long)threads) ? 1 : 0);
        ws[i].sequence = sequence;
        snprintf(ws[i].dir, sizeof(ws[i].dir), "%s/parallel-metadata/worker-%d", root, i);
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
    }
    uint64_t t1 = now_ns();
    if (err) { fprintf(stderr, "worker error: %s\n", strerror(err)); return -1; }

    for (int i = 0; i < threads; i++) {
        int fd = open(ws[i].dir, O_RDONLY | O_DIRECTORY);
        if (fd < 0) { fprintf(stderr, "open dir: %s\n", strerror(errno)); return -1; }
        if (fsync(fd) != 0) { fprintf(stderr, "fsync dir: %s\n", strerror(errno)); return -1; }
        close(fd);
    }
    uint64_t t2 = now_ns();
    *create_ns = t1 - t0;
    *fsync_ns = t2 - t1;
    *digest_out = digest ^ ops;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr, "usage: %s ROUNDS OPS THREADS CPUBASE FUSEPID label=dir [...]\n", argv[0]);
        return 2;
    }
    int rounds = atoi(argv[1]);
    unsigned long ops = strtoul(argv[2], NULL, 10);
    int threads = atoi(argv[3]);
    int cpubase = atoi(argv[4]);
    int fusepid = atoi(argv[5]);
    int narms = argc - 6;
    if (narms > MAX_ARMS || threads > MAX_THREADS) { fprintf(stderr, "too many\n"); return 2; }
    char *labels[MAX_ARMS];
    char *dirs[MAX_ARMS];
    for (int i = 0; i < narms; i++) {
        char *s = argv[6 + i];
        char *eq = strchr(s, '=');
        if (!eq) { fprintf(stderr, "bad arm spec %s\n", s); return 2; }
        *eq = 0;
        labels[i] = s;
        dirs[i] = eq + 1;
    }

    unsigned long sequence = 0;
    for (int i = 0; i < narms; i++) {
        uint64_t c, f, dg;
        if (run_batch(dirs[i], ops, threads, cpubase, sequence, &c, &f, &dg) != 0) return 1;
        if (reset_tree(dirs[i], threads) != 0) return 1;
        fprintf(stderr, "warmup %s create=%.3fms fsync=%.3fms digest=%llu\n",
                labels[i], c / 1e6, f / 1e6, (unsigned long long)dg);
        sequence++;
    }

    printf("round,pos,arm,create_ns,fsync_ns,total_ns,digest,daemon_ticks\n");
    for (int r = 0; r < rounds; r++) {
        for (int pos = 0; pos < narms; pos++) {
            int i = (pos + r) % narms;
            unsigned long long tb = 0, ta = 0;
            read_daemon_ticks(fusepid, &tb);
            uint64_t c, f, dg;
            if (run_batch(dirs[i], ops, threads, cpubase, sequence, &c, &f, &dg) != 0) return 1;
            read_daemon_ticks(fusepid, &ta);
            printf("%d,%d,%s,%llu,%llu,%llu,%llu,%llu\n", r, pos, labels[i],
                   (unsigned long long)c, (unsigned long long)f,
                   (unsigned long long)(c + f), (unsigned long long)dg, ta - tb);
            fflush(stdout);
            if (reset_tree(dirs[i], threads) != 0) return 1;
            sequence++;
        }
    }
    return 0;
}

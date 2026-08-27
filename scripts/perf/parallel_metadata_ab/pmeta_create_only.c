// One parallel-metadata batch with NO reset, so the tree survives for a
// correctness check: THREADS workers each create ops/THREADS files named
// r000000-<index> in its own parallel-metadata/worker-<n>, then every worker
// directory is fsynced.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct worker {
    pthread_t tid;
    int cpu;
    unsigned long ops;
    char dir[3072];
    int err;
};

static void *worker_main(void *arg) {
    struct worker *w = arg;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(w->cpu, &set);
    pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    char path[4096];
    for (unsigned long i = 0; i < w->ops; i++) {
        snprintf(path, sizeof(path), "%s/r000000-%06lu", w->dir, i);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) { w->err = errno; return NULL; }
        close(fd);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s OPS THREADS CPUBASE ROOT\n", argv[0]); return 2; }
    unsigned long ops = strtoul(argv[1], NULL, 10);
    int threads = atoi(argv[2]);
    int cpubase = atoi(argv[3]);
    const char *root = argv[4];
    struct worker *ws = calloc((size_t)threads, sizeof(struct worker));
    for (int i = 0; i < threads; i++) {
        ws[i].cpu = cpubase + i;
        ws[i].ops = ops / (unsigned long)threads + (((unsigned long)i < ops % (unsigned long)threads) ? 1 : 0);
        snprintf(ws[i].dir, sizeof(ws[i].dir), "%s/parallel-metadata/worker-%d", root, i);
        pthread_create(&ws[i].tid, NULL, worker_main, &ws[i]);
    }
    int err = 0;
    for (int i = 0; i < threads; i++) {
        pthread_join(ws[i].tid, NULL);
        if (ws[i].err) err = ws[i].err;
    }
    if (err) { fprintf(stderr, "worker error: %s\n", strerror(err)); return 1; }
    for (int i = 0; i < threads; i++) {
        int fd = open(ws[i].dir, O_RDONLY | O_DIRECTORY);
        if (fd < 0) { fprintf(stderr, "open dir: %s\n", strerror(errno)); return 1; }
        if (fsync(fd) != 0) { fprintf(stderr, "fsync dir: %s\n", strerror(errno)); return 1; }
        close(fd);
    }
    printf("created %lu files across %d workers\n", ops, threads);
    return 0;
}

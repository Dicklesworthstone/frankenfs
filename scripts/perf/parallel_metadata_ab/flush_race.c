// flush_race.c — drive `flush_to_device_after` CONCURRENTLY WITH COMMITTERS.
//
// FFS_MVCC_FLUSH_BORROW replaces the flush's clone-then-coalesce walk with a
// TWO-PASS walk: pass 1 collects block numbers under each shard's read lock,
// pass 2 re-resolves each block under that block's shard lock and appends the
// borrowed bytes. Its ledger entry says the one untested thing is exactly this:
// "the two-pass shape is a real change to a flush that used to be a single
// snapshot-in-hand walk ... the argument has not been tested against a concurrent
// committer."
//
// This is that test. MUTATOR threads create and remove files continuously while
// FSYNC threads hammer directory fsyncs, so a flush's pass 1 and pass 2 are
// separated by other threads' commits. Runs for SECONDS, then quiesces, removes
// everything, and leaves the tree empty for the caller's fsck/accounting oracle.
//
// usage: flush_race ROOT MUTATORS FSYNCERS SECONDS DIRS

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static atomic_int stop_flag;
static atomic_ullong creates, removes, fsyncs;

struct ctx {
    pthread_t tid;
    int id;
    int dirs;
    char root[3072];
    int err;
};

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void *mutator(void *arg) {
    struct ctx *c = arg;
    char path[4096];
    unsigned long i = 0;
    while (!atomic_load_explicit(&stop_flag, memory_order_relaxed)) {
        int d = (c->id + (int)i) % c->dirs;
        snprintf(path, sizeof(path), "%s/parallel-metadata/worker-%d/fr-%d-%08lu",
                 c->root, d, c->id, i);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) { c->err = errno; return NULL; }
        close(fd);
        atomic_fetch_add_explicit(&creates, 1, memory_order_relaxed);
        // remove the file created two iterations ago so the tree churns instead of
        // only growing — that keeps the shard maps mutating under every flush.
        if (i >= 2) {
            int pd = (c->id + (int)(i - 2)) % c->dirs;
            snprintf(path, sizeof(path), "%s/parallel-metadata/worker-%d/fr-%d-%08lu",
                     c->root, pd, c->id, i - 2);
            if (remove(path) != 0) { c->err = errno; return NULL; }
            atomic_fetch_add_explicit(&removes, 1, memory_order_relaxed);
        }
        i++;
    }
    // drain the two files still outstanding
    for (unsigned long k = (i >= 2 ? i - 2 : 0); k < i; k++) {
        int pd = (c->id + (int)k) % c->dirs;
        snprintf(path, sizeof(path), "%s/parallel-metadata/worker-%d/fr-%d-%08lu",
                 c->root, pd, c->id, k);
        if (remove(path) != 0 && errno != ENOENT) { c->err = errno; return NULL; }
        atomic_fetch_add_explicit(&removes, 1, memory_order_relaxed);
    }
    return NULL;
}

static void *fsyncer(void *arg) {
    struct ctx *c = arg;
    char dir[4096];
    unsigned long i = 0;
    while (!atomic_load_explicit(&stop_flag, memory_order_relaxed)) {
        snprintf(dir, sizeof(dir), "%s/parallel-metadata/worker-%d",
                 c->root, (int)((c->id + i) % (unsigned long)c->dirs));
        int fd = open(dir, O_RDONLY | O_DIRECTORY);
        if (fd < 0) { c->err = errno; return NULL; }
        if (fsync(fd) != 0) { c->err = errno; close(fd); return NULL; }
        close(fd);
        atomic_fetch_add_explicit(&fsyncs, 1, memory_order_relaxed);
        i++;
    }
    return NULL;
}

static long sweep(const char *root, int dirs) {
    long left = 0;
    char dpath[4096], fpath[4096];
    for (int d = 0; d < dirs; d++) {
        snprintf(dpath, sizeof(dpath), "%s/parallel-metadata/worker-%d", root, d);
        DIR *dh = opendir(dpath);
        if (!dh) return -1;
        struct dirent *e;
        size_t cap = 256, n = 0;
        char **names = malloc(cap * sizeof(char *));
        while ((e = readdir(dh)) != NULL) {
            if (e->d_name[0] == '.') continue;
            if (n == cap) { cap *= 2; names = realloc(names, cap * sizeof(char *)); }
            names[n++] = strdup(e->d_name);
        }
        closedir(dh);
        for (size_t k = 0; k < n; k++) {
            snprintf(fpath, sizeof(fpath), "%s/%s", dpath, names[k]);
            if (remove(fpath) != 0 && errno != ENOENT) { left++; }
            free(names[k]);
        }
        free(names);
        int fd = open(dpath, O_RDONLY | O_DIRECTORY);
        if (fd >= 0) { fsync(fd); close(fd); }
    }
    return left;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s ROOT MUTATORS FSYNCERS SECONDS DIRS\n", argv[0]);
        return 2;
    }
    const char *root = argv[1];
    int mut = atoi(argv[2]), fsy = atoi(argv[3]), dirs = atoi(argv[5]);
    double secs = atof(argv[4]);

    struct ctx *m = calloc((size_t)mut, sizeof(struct ctx));
    struct ctx *f = calloc((size_t)fsy, sizeof(struct ctx));
    for (int i = 0; i < mut; i++) { m[i].id = i; m[i].dirs = dirs; snprintf(m[i].root, sizeof(m[i].root), "%s", root); }
    for (int i = 0; i < fsy; i++) { f[i].id = i; f[i].dirs = dirs; snprintf(f[i].root, sizeof(f[i].root), "%s", root); }

    for (int i = 0; i < mut; i++) pthread_create(&m[i].tid, NULL, mutator, &m[i]);
    for (int i = 0; i < fsy; i++) pthread_create(&f[i].tid, NULL, fsyncer, &f[i]);

    double t0 = now_s();
    while (now_s() - t0 < secs) usleep(20000);
    atomic_store(&stop_flag, 1);

    int err = 0;
    for (int i = 0; i < mut; i++) { pthread_join(m[i].tid, NULL); if (m[i].err) err = m[i].err; }
    for (int i = 0; i < fsy; i++) { pthread_join(f[i].tid, NULL); if (f[i].err) err = f[i].err; }
    if (err) { fprintf(stderr, "worker error: %s\n", strerror(err)); return 1; }

    long stuck = sweep(root, dirs);
    printf("mutators=%d fsyncers=%d secs=%.1f creates=%llu removes=%llu fsyncs=%llu unremovable=%ld\n",
           mut, fsy, secs,
           (unsigned long long)atomic_load(&creates),
           (unsigned long long)atomic_load(&removes),
           (unsigned long long)atomic_load(&fsyncs), stuck);
    return stuck == 0 ? 0 : 1;
}

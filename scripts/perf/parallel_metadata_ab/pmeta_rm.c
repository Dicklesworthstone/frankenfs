// pmeta_rm.c — CONCURRENT UNLINK stress for the widened dispatch gate.
//
// `FFS_FUSE_CONCURRENT_MUTATIONS=1` admits Create/Unlink/Flush/FSyncDir to the
// shared dispatch path, and its ceiling measurement validated concurrent
// Create/Flush/FSyncDir into PRIVATE directories only — the ledger flagged
// concurrent Unlink as UNVALIDATED. This exercises it directly, in both the
// disjoint-parent shape the row uses and the shared-parent shape that actually
// races two unlinks against one directory.
//
// usage: pmeta_rm ROOT THREADS OPS MODE
//   MODE = private  -> each worker creates and removes in its own worker-<n> dir
//   MODE = shared   -> ALL workers create and remove in one shared directory
//
// Creates OPS files, fsyncs, then removes them all CONCURRENTLY, then fsyncs.
// Exits non-zero on any error; prints the surviving entry count for the caller
// to check against zero.

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct worker {
    pthread_t tid;
    int worker;
    int threads;
    unsigned long ops;
    char dir[3072];
    int shared;
    int err;
};

static void *create_main(void *arg) {
    struct worker *w = arg;
    char path[4096];
    for (unsigned long i = w->worker; i < w->ops; i += (unsigned long)w->threads) {
        snprintf(path, sizeof(path), "%s/rm-%08lu", w->dir, i);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) { w->err = errno; return NULL; }
        close(fd);
    }
    return NULL;
}

static void *remove_main(void *arg) {
    struct worker *w = arg;
    char path[4096];
    // Stride so adjacent indices land on DIFFERENT threads: in shared mode that
    // puts concurrent unlinks into the same directory block, which is the case
    // the gate was protecting.
    for (unsigned long i = w->worker; i < w->ops; i += (unsigned long)w->threads) {
        snprintf(path, sizeof(path), "%s/rm-%08lu", w->dir, i);
        if (remove(path) != 0) { w->err = errno; return NULL; }
    }
    return NULL;
}

static int fsync_dir(const char *dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return -1;
    int r = fsync(fd);
    close(fd);
    return r;
}

static long count_entries(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    long n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        n++;
    }
    closedir(d);
    return n;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s ROOT THREADS OPS private|shared\n", argv[0]);
        return 2;
    }
    const char *root = argv[1];
    int threads = atoi(argv[2]);
    unsigned long ops = strtoul(argv[3], NULL, 10);
    int shared = strcmp(argv[4], "shared") == 0;

    struct worker *ws = calloc((size_t)threads, sizeof(struct worker));
    for (int i = 0; i < threads; i++) {
        ws[i].worker = i;
        ws[i].threads = threads;
        ws[i].ops = ops;
        ws[i].shared = shared;
        if (shared) {
            snprintf(ws[i].dir, sizeof(ws[i].dir), "%s/parallel-metadata/worker-0", root);
        } else {
            snprintf(ws[i].dir, sizeof(ws[i].dir), "%s/parallel-metadata/worker-%d", root, i);
        }
    }

    for (int phase = 0; phase < 2; phase++) {
        void *(*fn)(void *) = phase == 0 ? create_main : remove_main;
        for (int i = 0; i < threads; i++) {
            if (pthread_create(&ws[i].tid, NULL, fn, &ws[i]) != 0) {
                fprintf(stderr, "pthread_create: %s\n", strerror(errno));
                return 1;
            }
        }
        int err = 0;
        for (int i = 0; i < threads; i++) {
            pthread_join(ws[i].tid, NULL);
            if (ws[i].err) err = ws[i].err;
        }
        if (err) {
            fprintf(stderr, "%s phase failed: %s\n", phase == 0 ? "create" : "remove",
                    strerror(err));
            return 1;
        }
        // fsync every distinct directory touched
        int dirs = shared ? 1 : threads;
        for (int i = 0; i < dirs; i++) {
            if (fsync_dir(ws[i].dir) != 0) {
                fprintf(stderr, "fsync %s: %s\n", ws[i].dir, strerror(errno));
                return 1;
            }
        }
    }

    long left = 0;
    int dirs = shared ? 1 : threads;
    for (int i = 0; i < dirs; i++) {
        long n = count_entries(ws[i].dir);
        if (n < 0) { fprintf(stderr, "readdir %s: %s\n", ws[i].dir, strerror(errno)); return 1; }
        left += n;
    }
    printf("mode=%s threads=%d ops=%lu surviving_entries=%ld\n",
           shared ? "shared" : "private", threads, ops, left);
    return left == 0 ? 0 : 1;
}

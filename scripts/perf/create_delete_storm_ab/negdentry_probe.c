// negdentry_probe.c — does suppressing the create-side entry invalidation leave a
// STALE NEGATIVE DENTRY behind?
//
// `FFS_FUSE_CREATE_INVAL=0` rests on an argument about the kernel dcache: a CREATE
// reply hands the kernel a positive entry for the same (parent, name) the earlier
// negative lookup cached, and there is one dentry per (parent, name), so the
// negative reply is already gone by the time we would invalidate it. If that is
// wrong, a `stat` right after the create returns ENOENT out of the kernel's cache
// while the file plainly exists.
//
// This drives exactly that sequence and checks it, which is the only thing that
// can decide the argument:
//
//     stat(name)   -> must MISS  (installs the negative dentry)
//     create(name) -> must succeed
//     stat(name)   -> must HIT   (the whole test; a MISS here is the stale reply)
//     remove(name)
//     stat(name)   -> must MISS  (the removal path's own invalidation still works)
//
// The first stat is what makes the probe sharp: without it the mount never
// remembers a negative hint, so the code under test is never reached and the run
// would "pass" having tested nothing. The count of remembered-then-created names
// is therefore reported, and a run where it is zero must be treated as INVALID.
//
// usage: negdentry_probe ROOT ITERATIONS
// exit 0 = every check held; 1 = a stale reply was observed; 2 = usage.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s ROOT ITERATIONS\n", argv[0]);
        return 2;
    }
    const char *root = argv[1];
    long iters = atol(argv[2]);

    char path[4096];
    struct stat st;
    long premiss = 0, stale = 0, resurrect = 0;

    for (long i = 0; i < iters; i++) {
        snprintf(path, sizeof(path), "%s/parallel-metadata/worker-0/neg-%08ld", root, i);

        // 1. must miss, and this is what installs the negative dentry
        if (lstat(path, &st) == 0) {
            fprintf(stderr, "iter %ld: name already exists before create\n", i);
            return 1;
        }
        if (errno != ENOENT) {
            fprintf(stderr, "iter %ld: pre-stat: %s\n", i, strerror(errno));
            return 1;
        }
        premiss++;

        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) {
            fprintf(stderr, "iter %ld: create: %s\n", i, strerror(errno));
            return 1;
        }
        close(fd);

        // 2. THE TEST: the file exists, so this must not come back ENOENT
        if (lstat(path, &st) != 0) {
            if (errno == ENOENT) {
                stale++;
                fprintf(stderr, "iter %ld: STALE NEGATIVE DENTRY — stat says ENOENT for a "
                                "file that was just created\n", i);
                return 1;
            }
            fprintf(stderr, "iter %ld: post-stat: %s\n", i, strerror(errno));
            return 1;
        }

        if (remove(path) != 0) {
            fprintf(stderr, "iter %ld: remove: %s\n", i, strerror(errno));
            return 1;
        }

        // 3. the removal path's invalidation is untouched by the knob and must
        //    still work, or a removed name would keep answering from cache
        if (lstat(path, &st) == 0) {
            resurrect++;
            fprintf(stderr, "iter %ld: STALE POSITIVE DENTRY — stat succeeds for a removed "
                            "file\n", i);
            return 1;
        }
        if (errno != ENOENT) {
            fprintf(stderr, "iter %ld: post-remove stat: %s\n", i, strerror(errno));
            return 1;
        }
    }

    // Phase 2: the case a single process cannot distinguish. A dcache entry is
    // keyed by (parent dentry, name), not by task, so a negative reply cached by
    // ONE process must be replaced by ANOTHER process's create. If instead each
    // task held its own negative dentry, phase 1 would pass and this would fail.
    long cross = iters / 10 + 1;
    long cross_ok = 0;
    for (long i = 0; i < cross; i++) {
        snprintf(path, sizeof(path), "%s/parallel-metadata/worker-0/xneg-%08ld", root, i);

        pid_t looker = fork();
        if (looker == 0) {
            struct stat cst;
            _exit(lstat(path, &cst) == 0 ? 10 : (errno == ENOENT ? 0 : 11));
        }
        int status = 0;
        waitpid(looker, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "cross %ld: child pre-stat did not MISS (status %d)\n", i, status);
            return 1;
        }

        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) { fprintf(stderr, "cross %ld: create: %s\n", i, strerror(errno)); return 1; }
        close(fd);

        pid_t checker = fork();
        if (checker == 0) {
            struct stat cst;
            _exit(lstat(path, &cst) == 0 ? 0 : (errno == ENOENT ? 12 : 13));
        }
        waitpid(checker, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 12) {
                fprintf(stderr, "cross %ld: STALE NEGATIVE DENTRY ACROSS TASKS — a second "
                                "process still sees ENOENT after the create\n", i);
            } else {
                fprintf(stderr, "cross %ld: child post-stat failed (status %d)\n", i, status);
            }
            return 1;
        }
        cross_ok++;
        if (remove(path) != 0) { fprintf(stderr, "cross %ld: remove: %s\n", i, strerror(errno)); return 1; }
    }

    printf("negdentry_probe iterations=%ld negative_dentries_installed=%ld stale_negative=%ld "
           "stale_positive=%ld cross_task_ok=%ld/%ld\n",
           iters, premiss, stale, resurrect, cross_ok, cross);
    return (stale == 0 && resurrect == 0 && premiss == iters && cross_ok == cross) ? 0 : 1;
}

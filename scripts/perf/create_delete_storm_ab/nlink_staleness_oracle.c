// nlink_staleness_oracle.c — an oracle that should FAIL when inode-attribute
// invalidation is disabled.
//
// The staleness oracle written for the entry/create/parent knobs passed in EVERY
// arm including the baseline, so it discriminated nothing and could not license
// any of them. Its shape was the problem: create -> remove -> re-check, all
// single-client and immediate, which only exercises cases the kernel already learns
// about from the reply to the very syscall the client just made.
//
// The case it never reached is a mutation that changes inode A's attributes while
// the kernel is only told about inode B. `link(a, b)` is exactly that: it creates a
// NEW dentry b, and the kernel learns b's attributes from the reply — but a's
// cached st_nlink silently goes from 1 to 2 with nothing in that reply mentioning a.
// If the daemon does not invalidate a's attributes, a stat(a) inside the attribute
// TTL must return the STALE nlink=1.
//
// That makes this a discriminating oracle rather than a smoke test: it has a
// specific reason to fail with FFS_FUSE_INODE_INVAL=0 and to pass with it on. An
// oracle with no failing arm proves nothing, which is the lesson this file exists
// to apply.
//
// usage: nlink_staleness_oracle DIR N
// prints: checked=%d stale_nlink=%d stale_after_remove=%d

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s DIR N\n", argv[0]);
        return 2;
    }
    const char *dir = argv[1];
    int n = atoi(argv[2]);
    char a[4096], b[4096];
    struct stat st;
    int checked = 0, stale_link = 0, stale_unlink = 0;

    for (int i = 0; i < n; i++) {
        snprintf(a, sizeof(a), "%s/storm/nl-a-%06d", dir, i);
        snprintf(b, sizeof(b), "%s/storm/nl-b-%06d", dir, i);

        int fd = open(a, O_CREAT | O_WRONLY | O_EXCL, 0644);
        if (fd < 0) { fprintf(stderr, "create: %s\n", strerror(errno)); break; }
        close(fd);

        // Prime the kernel's attribute cache for `a` so a later stat can be served
        // from it. Without this the test would prove nothing: an uncached stat
        // always goes to the daemon and is never stale.
        if (stat(a, &st) != 0) { fprintf(stderr, "prime: %s\n", strerror(errno)); break; }
        if (st.st_nlink != 1) { fprintf(stderr, "unexpected initial nlink %lu\n",
                                        (unsigned long)st.st_nlink); break; }

        // The mutation the kernel cannot attribute to `a`: it is told about `b`.
        if (link(a, b) != 0) { fprintf(stderr, "link: %s\n", strerror(errno)); break; }

        if (stat(a, &st) != 0) { fprintf(stderr, "recheck: %s\n", strerror(errno)); break; }
        if (st.st_nlink != 2) stale_link++;

        // The mirror case: dropping the link must take it back to 1.
        if (remove(b) != 0) { fprintf(stderr, "remove b: %s\n", strerror(errno)); break; }
        if (stat(a, &st) != 0) { fprintf(stderr, "recheck2: %s\n", strerror(errno)); break; }
        if (st.st_nlink != 1) stale_unlink++;

        remove(a);
        checked++;
    }

    printf("checked=%d stale_nlink=%d stale_after_remove=%d\n", checked, stale_link,
           stale_unlink);
    return (stale_link || stale_unlink) ? 1 : 0;
}

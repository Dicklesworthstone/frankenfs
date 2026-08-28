// rdblockprobe.c — the deterministic decomposition of the readdir+stat row.
//
// Same instrument as the warm-stat and xattr rows (bd-4iqg6): count the crossings
// the client actually WAITS on via getrusage(RUSAGE_SELF).ru_nvcsw, so the row can
// be placed on the campaign's blocking-crossings-per-operation scale rather than on
// a wall-time ratio this host keeps voiding for load.
//
// Workload: one opendir/readdir sweep of the directory, then stat() every entry —
// the shape the banked row measures. readdir and stat are counted separately,
// because the campaign's other rows showed the two have very different costs (a
// warm stat is 1.000 blocking crossings, all of it the audit capability probe,
// while readdir amortises many entries into one round trip).
//
// usage: rdblockprobe DIR
// prints: entries=%d nvcsw_readdir=%ld nvcsw_stat=%ld nvcsw_per_stat=%.4f digest=%llu

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_ENTRIES 65536

static long nvcsw(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1;
    return ru.ru_nvcsw;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s DIR\n", argv[0]);
        return 2;
    }
    char dirpath[4096];
    snprintf(dirpath, sizeof(dirpath), "%s/large-directory", argv[1]);

    static char names[MAX_ENTRIES][64];
    int n = 0;

    // Warm the mount outside the counted region so the first lookup's cost is not
    // charged to the sweep.
    DIR *warm = opendir(dirpath);
    if (warm) { readdir(warm); closedir(warm); }

    long v0 = nvcsw();
    DIR *d = opendir(dirpath);
    if (!d) {
        fprintf(stderr, "opendir %s: %s\n", dirpath, strerror(errno));
        return 1;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL && n < MAX_ENTRIES) {
        if (de->d_name[0] == '.') continue;
        snprintf(names[n], sizeof(names[0]), "%s", de->d_name);
        n++;
    }
    closedir(d);
    long v1 = nvcsw();

    uint64_t digest = 0x9E3779B97F4A7C15ull;
    struct stat st;
    char path[4200];
    int statted = 0;
    for (int i = 0; i < n; i++) {
        snprintf(path, sizeof(path), "%s/%s", dirpath, names[i]);
        if (stat(path, &st) != 0) continue;
        // Fold metadata only, never the path, so two arms on different mountpoints
        // must agree and the digest is a real cross-arm parity oracle.
        digest = digest * 1099511628211ull ^ (uint64_t)st.st_mode;
        digest ^= (uint64_t)st.st_size;
        statted++;
    }
    long v2 = nvcsw();

    printf("entries=%d statted=%d nvcsw_readdir=%ld nvcsw_stat=%ld nvcsw_per_stat=%.4f "
           "digest=%llu\n",
           n, statted, v1 - v0, v2 - v1, statted ? (double)(v2 - v1) / statted : 0.0,
           (unsigned long long)digest);
    return 0;
}

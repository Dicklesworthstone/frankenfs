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

    // INTERLEAVED mode: stat each entry as readdir yields it, the way `ls -l` and
    // every real directory-listing client behaves. The kernel chooses READDIRPLUS
    // adaptively -- it stops issuing it when the entries it prefetched go unused --
    // so a probe that reads ALL names first and stats them afterwards can talk the
    // kernel out of plus and then bill us for the lookups plus never had a chance
    // to avoid. This mode is the control for that instrument risk (bd-4iqg6).
    int interleave = getenv("RDPROBE_INTERLEAVE") != NULL;

    uint64_t digest = 0x9E3779B97F4A7C15ull;

    long v0 = nvcsw();
    DIR *d = opendir(dirpath);
    if (!d) {
        fprintf(stderr, "opendir %s: %s\n", dirpath, strerror(errno));
        return 1;
    }
    struct dirent *de;
    int inline_statted = 0;
    while ((de = readdir(d)) != NULL && n < MAX_ENTRIES) {
        if (de->d_name[0] == '.') continue;
        snprintf(names[n], sizeof(names[0]), "%.63s", de->d_name);
        if (interleave) {
            struct stat ist;
            char ipath[4200];
            snprintf(ipath, sizeof(ipath), "%s/%.63s", dirpath, names[n]);
            if (stat(ipath, &ist) == 0) {
                digest = digest * 1099511628211ull ^ (uint64_t)ist.st_mode;
                digest ^= (uint64_t)ist.st_size;
                inline_statted++;
            }
        }
        n++;
    }
    closedir(d);
    long v1 = nvcsw();

    struct stat st;
    char path[4200];
    int statted = 0;
    for (int i = 0; interleave ? 0 : (i < n); i++) {
        snprintf(path, sizeof(path), "%s/%.63s", dirpath, names[i]);
        if (stat(path, &st) != 0) continue;
        // Fold metadata only, never the path, so two arms on different mountpoints
        // must agree and the digest is a real cross-arm parity oracle.
        digest = digest * 1099511628211ull ^ (uint64_t)st.st_mode;
        digest ^= (uint64_t)st.st_size;
        statted++;
    }
    long v2 = nvcsw();

    long swept = interleave ? inline_statted : statted;
    double per = swept ? (double)((interleave ? (v1 - v0) : (v2 - v1))) / swept : 0.0;
    printf("mode=%s entries=%d statted=%ld nvcsw_readdir=%ld nvcsw_stat=%ld "
           "nvcsw_per_stat=%.4f digest=%llu\n",
           interleave ? "interleaved" : "phased", n, swept, v1 - v0, v2 - v1, per,
           (unsigned long long)digest);
    return 0;
}

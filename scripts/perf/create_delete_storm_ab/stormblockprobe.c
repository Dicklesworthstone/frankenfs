// stormblockprobe.c — the create/delete storm on the campaign's deterministic scale.
//
// Every row decomposed so far is either a READ row (~99% FUSE round trip, daemon
// nearly idle) or bulk durable WRITE (where our own memcpy/allocator dominate). The
// storm is neither: it is MUTATING METADATA, which on this codebase routes through
// `DispatchGate::exclusive()` — a different serialisation regime from anything the
// model has been tested against.
//
// Counts voluntary context switches for the create phase and the unlink phase
// SEPARATELY, because they are different opcodes with different dispatch rules and
// the campaign has already been caught once treating a two-phase workload as one
// number (readdir+stat, where readdir was at parity and the stat phase carried the
// whole loss).
//
// usage: stormblockprobe DIR N
// prints: files=%d nvcsw_create=%ld nvcsw_unlink=%ld per_create=%.4f per_unlink=%.4f

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

static long nvcsw(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1;
    return ru.ru_nvcsw;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s DIR N\n", argv[0]);
        return 2;
    }
    const char *dir = argv[1];
    int n = atoi(argv[2]);
    char path[4096];

    // Warm the directory outside the counted region: the first create pays the
    // parent lookup, which is not per-file cost.
    snprintf(path, sizeof(path), "%s/storm/warm.tmp", dir);
    int w = open(path, O_CREAT | O_WRONLY, 0644);
    if (w >= 0) { close(w); unlink(path); }

    int no_close = getenv("STORMPROBE_NO_CLOSE") != NULL;
    int use_mkdir = getenv("STORMPROBE_MKDIR") != NULL;
    static int held[4096];
    int nfd = 0;

    long v0 = nvcsw();
    int created = 0;
    for (int i = 0; i < n; i++) {
        snprintf(path, sizeof(path), "%s/storm/f-%06d", dir, i);
        // MKDIR mode: creation with NO file descriptor at all. If the post-create
        // getattr survives here it follows creation itself, not fd handling -- and
        // holding fds open already showed it is not a close-time artifact.
        if (use_mkdir) {
            if (mkdir(path, 0755) != 0) { fprintf(stderr, "mkdir %d: %s\n", i, strerror(errno)); break; }
            created++;
            continue;
        }
        int fd = open(path, O_CREAT | O_WRONLY | O_EXCL, 0644);
        if (fd < 0) {
            fprintf(stderr, "create %d: %s\n", i, strerror(errno));
            break;
        }
        // NO-CLOSE mode: the post-create getattr is 1.0 per create, unmoved by every
        // invalidation knob, and its source is unidentified. The probe issues exactly
        // two syscalls per file -- open(O_CREAT|O_EXCL) and close -- so holding the
        // descriptor open attributes the getattr to one of them without guessing and
        // without kernel tracing. Bounded N required: the fds stay open until exit.
        if (!no_close) close(fd); else if (nfd < (int)(sizeof(held)/sizeof(held[0]))) held[nfd++] = fd;
        created++;
    }
    long v1 = nvcsw();

    // CREATE-ONLY mode: the invalidation knobs were measured to leave the create
    // phase FLAT (6.03/6.00/6.00/6.01), so create's six blocking crossings are
    // something else entirely -- and the census read so far has been aggregated
    // over both phases, which cannot show what one create actually costs. Skipping
    // the removal phase makes the daemon's per-opcode census attributable to
    // creates alone.
    int no_remove = getenv("STORMPROBE_CREATE_ONLY") != NULL;

    int removed = 0;
    for (int i = 0; !no_remove && i < created; i++) {
        snprintf(path, sizeof(path), "%s/storm/f-%06d", dir, i);
        if (unlink(path) == 0) removed++;
    }
    long v2 = nvcsw();

    printf("files=%d removed=%d nvcsw_create=%ld nvcsw_unlink=%ld per_create=%.4f "
           "per_unlink=%.4f\n",
           created, removed, v1 - v0, v2 - v1, created ? (double)(v1 - v0) / created : 0.0,
           removed ? (double)(v2 - v1) / removed : 0.0);
    return 0;
}

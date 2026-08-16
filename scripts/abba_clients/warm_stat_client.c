#define _GNU_SOURCE
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* Minimal warm-stat client: read the name list once, chdir, then stat in a tight
 * loop. No formatting, no per-file allocation, no output. This is as close to the
 * bare syscall floor as a userspace client gets, which is the point: it gives the
 * client-floor model a third and much lower C. */
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    if (chdir(argv[1])) return 3;
    FILE *f = fopen(argv[2], "r");
    if (!f) return 4;
    static char names[20001][256];
    int n = 0;
    while (n < 20001 && fgets(names[n], sizeof(names[0]), f)) {
        char *nl = strchr(names[n], '\n'); if (nl) *nl = 0;
        if (names[n][0]) n++;
    }
    fclose(f);
    struct stat st;
    volatile long sink = 0;
    for (int i = 0; i < n; i++) { if (stat(names[i], &st) == 0) sink += st.st_size; }
    return sink == -1 ? 1 : 0;
}

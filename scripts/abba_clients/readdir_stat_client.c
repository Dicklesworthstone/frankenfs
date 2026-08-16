#define _GNU_SOURCE
#include <dirent.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
/* Minimal readdir+stat client: enumerate the directory once, stat every entry.
 * This is the `ls -lU` workload with the formatting, sorting, column layout and
 * xattr probing of coreutils removed, so the client floor is as close to the
 * bare getdents+stat syscalls as userspace gets. */
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    DIR *d = opendir(argv[1]);
    if (!d) return 3;
    if (chdir(argv[1])) return 4;
    struct dirent *e;
    struct stat st;
    volatile long sink = 0; long n = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.' && (!e->d_name[1] || (e->d_name[1]=='.' && !e->d_name[2]))) continue;
        if (stat(e->d_name, &st) == 0) { sink += st.st_size; n++; }
    }
    closedir(d);
    return (n < 0) ? 1 : 0;
}

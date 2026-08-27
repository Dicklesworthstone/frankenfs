# readdir_stat_btrfs_ab

The btrfs twin of `../readdir_stat_ab/`. Same client (`rdstat_ab.c`), same
32,768-entry directory, same 8 client threads — only the filesystem differs, so
the two rows' crossing censuses are directly comparable.

`mkfixture_btrfs.sh` builds the directory THROUGH A KERNEL MOUNT so btrfs lays
out its own `DIR_INDEX`/`DIR_ITEM` keys rather than any FrankenFS write path,
exactly as the ext4 fixture does.

    WORK=<scratch> bash mkfixture_btrfs.sh
    gcc -O2 -o $WORK/rdstat_ab rdstat_ab.c -lpthread
    WORK=<scratch> ELF=<ffs-cli> ROUNDS=24 THREADS=8 CPUBASE=8 \
      FA_CPUS=18 FB_CPUS=19 FA_LABEL=base FB_LABEL=spin \
      FB_ENV="FFS_FUSE_RECEIVE_SPIN=2000" TAG=bf1 bash run_multi_btrfs.sh
    python3 analyze.py <body.csv>

Daemon CPUs 18/19 — never 16, which is a defective core on this host.

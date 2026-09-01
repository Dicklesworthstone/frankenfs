#!/bin/bash
# Variant C: saturate the DEVICE while leaving the CPUs idle -- the blind-spot
# shape bd-xhl2g's description predicts (busy near zero, device pinned).
DUR=${1:-60}
READERS=${2:-24}
R=/data/tmp/claude-1000/-data-projects-frankenfs/349b4f92-ecfa-43bf-b2b4-18c4127338a8/scratchpad/direct_reader.py
FILES=(/data/tmp/.tmprZbnUB/bd5vis3.btrfs /data/tmp/.tmpcwoTRE/test.btrfs /data/tmp/rch-clean-overlay-8sCz2f.tar)
for i in $(seq 1 "$READERS"); do
  python3 "$R" "${FILES[$(( i % ${#FILES[@]} ))]}" "$DUR" 8 &
done
echo "storm C: $READERS in-process 8MiB O_DIRECT readers for ${DUR}s"
wait

#!/usr/bin/env bash
# build-perf.sh — produce a maximally-optimized ffs-cli binary by stacking the
# three perf-stat-verified build-config levers (docs/NEGATIVE_EVIDENCE.md,
# 2026-07-03): fat LTO (already the release-perf default) + target-cpu=x86-64-v3
# + PGO (profile-guided optimization).
#
# Measured instruction-count wins over the plain release-perf (fat-LTO) build,
# via `perf stat` (deterministic; wall-clock was too noisy to see them):
#   - target-cpu=x86-64-v3 : ~8.5% fewer create instructions, ~3% lookup
#   - PGO (on top)         : ~10% fewer create instructions, ~24% lookup
# All behavior-preserving (create-bench -> e2fsck clean). Both stack.
#
# WHY this is a script and not the default build:
#   - target-cpu=x86-64-v3 REQUIRES a 2015+ CPU (AVX2/BMI2/FMA); it removes the
#     runtime scalar fallback frankenfs deliberately keeps, so it must be opt-in.
#   - PGO is a two-stage process needing a training workload + a .profdata file;
#     it is not expressible as a Cargo.toml profile field.
#
# Output: target/release-perf/ffs-cli, optimized. The .profdata is left in
# $PGO_DIR so re-runs can reuse it (skip retraining with SKIP_TRAIN=1).
#
# Usage:  scripts/build-perf.sh [TRAINING_EXT4_IMAGE]
#   TRAINING_EXT4_IMAGE : an ext4 image to train on. If omitted, a throwaway one
#                         is built with `create-bench` on a copy of the first
#                         *.img found under ./ or /data/tmp (override with
#                         FFS_TRAIN_IMG). Portability: v3 is safe on any server
#                         CPU since Haswell (2015).

set -euo pipefail
cd "$(dirname "$0")/.."

TARGET_CPU="${FFS_TARGET_CPU:-x86-64-v3}"
PGO_DIR="${PGO_DIR:-/tmp/ffs-pgo}"
PROFILE="release-perf"
BIN="ffs-cli"
# Respect CARGO_TARGET_DIR (this repo commonly redirects it, e.g. /data/tmp/...).
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
OUT="$TARGET_DIR/${PROFILE}/${BIN}"

# Locate llvm-profdata (rustup component OR system).
PROFDATA="$(find "${RUSTUP_HOME:-$HOME/.rustup}" -name llvm-profdata 2>/dev/null | head -1)"
[ -z "$PROFDATA" ] && PROFDATA="$(command -v llvm-profdata llvm-profdata-18 2>/dev/null | head -1)"
if [ -z "$PROFDATA" ]; then
  echo "!! llvm-profdata not found. Run: rustup component add llvm-tools-preview" >&2
  exit 1
fi
echo ">> using llvm-profdata: $PROFDATA ; target-cpu=$TARGET_CPU"

TRAIN_IMG="${1:-${FFS_TRAIN_IMG:-}}"

if [ "${SKIP_TRAIN:-0}" != "1" ]; then
  echo ">> [1/4] instrumented build (profile-generate, target-cpu=$TARGET_CPU)"
  # The reclaim-protection marker (written below) must not count as "existing PGO
  # artifacts", or protecting a directory would permanently block retraining into
  # it. Mirrors how prepare_scratch_dir ignores its own marker.
  if [ -d "$PGO_DIR" ] && find "$PGO_DIR" -mindepth 1 ! -name .sbh-protect -print -quit | grep -q .; then
    echo "!! refusing to mix a new training run with existing PGO artifacts in $PGO_DIR" >&2
    echo "!! choose an empty PGO_DIR, or set SKIP_TRAIN=1 to reuse its merged.profdata" >&2
    exit 1
  fi
  mkdir -p "$PGO_DIR"
  RUSTFLAGS="-C target-cpu=$TARGET_CPU -C profile-generate=$PGO_DIR" \
    cargo build --profile "$PROFILE" -p "$BIN"
  INSTR="$OUT"

  if [ -z "$TRAIN_IMG" ]; then
    SRC="$(ls -1 ./*.img /data/tmp/*ext*.img 2>/dev/null | head -1 || true)"
    [ -z "$SRC" ] && { echo "!! no training image; pass one as \$1" >&2; exit 1; }
    TRAIN_IMG="$PGO_DIR/train.img"; cp "$SRC" "$TRAIN_IMG"
    "$INSTR" create-bench "$TRAIN_IMG" / --count 40000 --threads 1 >/dev/null 2>&1 || true
  fi
  echo ">> [2/4] training on $TRAIN_IMG (exercise the hot paths)"
  "$INSTR" create-bench "$TRAIN_IMG" / --count 20000 --threads 1 >/dev/null 2>&1 || true
  "$INSTR" lookup-bench "$TRAIN_IMG" / --count 3000000            >/dev/null 2>&1 || true
  "$INSTR" rename-bench "$TRAIN_IMG" / --count 20000              >/dev/null 2>&1 || true
  "$INSTR" delbench     "$TRAIN_IMG" / --count 20000              >/dev/null 2>&1 || true
  "$INSTR" walk         "$TRAIN_IMG" --no-stat                    >/dev/null 2>&1 || true

  echo ">> [3/4] merge profiles"
  find "$PGO_DIR" -name '*.profraw' > "$PGO_DIR/list.txt"
  "$PROFDATA" merge -f "$PGO_DIR/list.txt" -o "$PGO_DIR/merged.profdata"
fi

[ -s "$PGO_DIR/merged.profdata" ] || {
  echo "!! missing or empty merged PGO profile: $PGO_DIR/merged.profdata" >&2
  exit 1
}
PROFILE_SHA256="$(sha256sum "$PGO_DIR/merged.profdata" | awk '{print $1}')"
[ "${#PROFILE_SHA256}" -eq 64 ] || {
  echo "!! failed to compute merged PGO profile SHA-256" >&2
  exit 1
}

# Keep the profile across disk-pressure reclamation (bd-v0igv, bd-o6iiw).
#
# Measured, not precautionary: on 2026-08-08 the banked profile directory
# /data/tmp/ffs-pgo-ftev0 was GONE, along with every .profdata anywhere under
# /data/tmp, so bd-o6iiw's "SKIP_TRAIN=1, ~5 min, reuses the banked 5c6530a0
# profile" recipe could not run as written and its build became a full ~20 min
# retrain. This marker is byte-for-byte what `sbh protect` writes, so it needs no
# sbh dependency and no root.
#
# Protect the PROFILE, not the built binary: regenerating this costs a ~20 min
# training run, whereas rebuilding the binary from it costs ~5 min. That asymmetry
# is also what lets a build and its measurement live in DIFFERENT windows, which
# the mounted-comparator recipes currently forbid for exactly this reason.
#
# Caveat, stated because it is not free: this pins everything in $PGO_DIR,
# including the .profraw files and any train.img the script copied in — which can
# be hundreds of MB. The size is printed so the choice is visible; prune the
# intermediates by hand if the directory needs to be small.
if [ ! -e "$PGO_DIR/.sbh-protect" ]; then
  cat > "$PGO_DIR/.sbh-protect" <<'MARKER'
frankenfs PGO profile (bd-o6iiw / bd-v0igv). merged.profdata costs a ~20 minute
training run to regenerate; the binary built from it costs ~5. Reclaiming this
directory is what forced the mounted-comparator recipes to demand that a build and
its measurement share one window. Written by scripts/build-perf.sh, equivalent to
`sbh protect`.
MARKER
  echo ">> protected $PGO_DIR from disk-pressure reclamation ($(du -sh "$PGO_DIR" 2>/dev/null | cut -f1) pinned)"
fi

echo ">> [4/4] optimized build (profile-use + fat LTO + target-cpu=$TARGET_CPU)"
FFS_PGO_PROFILE_SHA256="$PROFILE_SHA256" \
  RUSTFLAGS="-C target-cpu=$TARGET_CPU -C profile-use=$PGO_DIR/merged.profdata -Cllvm-args=-pgo-warn-missing-function" \
  cargo build --profile "$PROFILE" -p "$BIN"

echo ">> done: $OUT  (fat LTO + target-cpu=$TARGET_CPU + PGO profile=$PROFILE_SHA256)"
"$OUT" bench-evidence

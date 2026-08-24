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

# OBSERVED DEFECT, 2026-08-15: this script was writing into the shared
# cross-repo target dir on every run.
#
# This host exports CARGO_TARGET_DIR=/data/tmp/cargo-target GLOBALLY — one
# directory shared by every project on the box, measured at 338 GB, and it has
# filled the disk before (see bd-v0igv; / was at 8.86% free with the sbh ballast
# pool fully released when this was found). The old line here was
# `TARGET_DIR="${CARGO_TARGET_DIR:-target}"`, which deliberately honoured that
# inherited value, so a perf build silently landed multiple GB of LTO artifacts
# in the shared dir instead of in frankenfs.
#
# Building locally is correct and expected for this script — the mounted-kernel
# comparator mounts a real FUSE filesystem and compares against the live kernel,
# and rch cannot retrieve a compiled binary anyway. The defect was never
# "builds locally"; it was "builds into a directory it does not own".
#
# So: honour an inherited CARGO_TARGET_DIR only when it is NOT the shared path.
# Anything at or beneath the shared root is refused and replaced with the
# repo-local default, loudly, so the next agent inherits the fix rather than
# rediscovering it.
SHARED_TARGET_DIR="${FFS_SHARED_TARGET_DIR:-/data/tmp/cargo-target}"
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  # Compare with trailing slashes stripped, and reject subdirectories of the
  # shared root too — /data/tmp/cargo-target/frankenfs is still the shared dir.
  _ctd="${CARGO_TARGET_DIR%/}"
  _shared="${SHARED_TARGET_DIR%/}"
  if [ "$_ctd" = "$_shared" ] || case "$_ctd" in "$_shared"/*) true ;; *) false ;; esac; then
    echo ">> CARGO_TARGET_DIR=$CARGO_TARGET_DIR is the SHARED cross-repo target dir; ignoring it." >&2
    echo ">> Building into the repo-local target/ instead (set FFS_SHARED_TARGET_DIR to change)." >&2
    unset CARGO_TARGET_DIR
  fi
  unset _ctd _shared
fi
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
OUT="$TARGET_DIR/${PROFILE}/${BIN}"

# --- cargo must be a REAL cargo, not the rch offload shim ---------------------
#
# OBSERVED DEFECT, 2026-08-15 (same session as the shared-target-dir defect above):
# `command -v cargo` on this host resolves to /home/ubuntu/.local/bin/cargo, an rch
# shim that transparently ships the build to a remote worker. Two runs of this
# script were silently offloaded to worker vmi1153651 before it was noticed.
#
# That is fatal HERE specifically, and quietly: rch has no artifact-retrieval
# mechanism, so a remote build leaves NOTHING in the local target dir. Stage [1/4]
# then "succeeds", $INSTR does not exist, every training command is `|| true` so
# they all no-op, no .profraw is ever written, and the run dies much later at the
# empty-profile check -- roughly twenty minutes downstream of the actual cause.
#
# This script exists to produce a LOCAL binary: its output is measured by
# ffs-mounted-kernel-bench, which mounts FUSE against the live kernel in one
# process and must run on this machine. So resolve cargo through rustup, which
# honours rust-toolchain.toml (pinned nightly-2026-07-20) and returns the real
# toolchain binary. Note `ls ~/.rustup/toolchains/nightly-*/bin/cargo | head -1`
# is NOT a substitute -- it sorts the FLOATING `nightly` ahead of the pin.
CARGO="${FFS_CARGO:-}"
if [ -z "$CARGO" ] && command -v rustup >/dev/null 2>&1; then
  CARGO="$(rustup which cargo 2>/dev/null || true)"
fi
[ -x "${CARGO:-}" ] || CARGO="$(command -v cargo || true)"
if [ -z "$CARGO" ]; then
  echo "!! no cargo found" >&2
  exit 1
fi
case "$CARGO" in
  "$HOME"/.local/bin/*)
    echo "!! resolved cargo is the rch offload shim ($CARGO); a remote build leaves" >&2
    echo "!! no local binary and this script's output must be measured locally." >&2
    echo "!! Install the rustup toolchain or set FFS_CARGO to a real cargo." >&2
    exit 1
    ;;
esac
# Every other tool the build shells out to (rustc, rustdoc) is otherwise
# resolved from PATH, where it is a RUSTUP PROXY, not a binary. That proxy
# re-resolves the toolchain on every invocation, so a concurrent `rustup` run
# anywhere on this shared box can change what "rustc" means in the middle of a
# build. Observed 2026-08-15, in one run:
#
#   error[E0514]: found crate `thiserror` compiled by an incompatible version of rustc
#   info: rolling back changes
#   error: failed to install component: 'rust-docs-x86_64-unknown-linux-gnu',
#          detected conflict: 'share/doc/rust/html'
#
# i.e. a component install by another agent failed and rolled back WHILE this
# build was running, and the artifacts ended up compiled by two different rustcs.
# rust-toolchain.toml already documents the same class of failure (a floating
# `nightly` being restamped mid-build) as the reason the channel is pinned.
#
# Pinning the toolchain's own bin directory ahead of PATH and setting RUSTC
# explicitly takes rustup out of the loop entirely for the duration of the build.
TOOLCHAIN_BIN="$(dirname "$CARGO")"
if [ -x "$TOOLCHAIN_BIN/rustc" ]; then
  export RUSTC="$TOOLCHAIN_BIN/rustc"
  export PATH="$TOOLCHAIN_BIN:$PATH"
fi
echo ">> using cargo: $CARGO"
echo ">> using rustc: ${RUSTC:-<PATH>} ($("${RUSTC:-rustc}" --version 2>/dev/null))"

# Locate llvm-profdata, PREFERRING THE TOOLCHAIN WE ARE BUILDING WITH.
#
# OBSERVED DEFECT, 2026-08-23 (bd-svhrq): this was
# `find "$RUSTUP_HOME" -name llvm-profdata | head -1`, which is the very trap the
# cargo-resolution comment above documents and guards against -- the guard was
# applied to cargo and rustc and not to this. `find` returns the FLOATING
# `nightly` toolchain's copy first, and stage [3/4] then dies with
#
#   error: raw profile version mismatch: Profile uses raw profile format
#          version = 10; expected version = 11
#
# because the pinned nightly-2026-07-20 emits v10 raw profiles and today's
# floating nightly ships a v11 reader. A twenty-minute training run is already
# spent by the time that fires.
#
# The profile reader must match the compiler that WROTE the profile, so take it
# from $CARGO's own toolchain root first and only then fall back to a search.
TOOLCHAIN_ROOT="$(dirname "$(dirname "$CARGO")")"
PROFDATA="$(find "$TOOLCHAIN_ROOT" -name llvm-profdata 2>/dev/null | head -1)"
[ -z "$PROFDATA" ] && PROFDATA="$(find "${RUSTUP_HOME:-$HOME/.rustup}" -name llvm-profdata 2>/dev/null | head -1)"
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
  # env -u plus an explicit --target-dir: the guard above already unset a shared
  # CARGO_TARGET_DIR, and these make the destination independent of the
  # environment even if this script is sourced or that guard is edited later.
  env -u CARGO_TARGET_DIR \
    RUSTFLAGS="-C target-cpu=$TARGET_CPU -C profile-generate=$PGO_DIR" \
    "$CARGO" build --profile "$PROFILE" -p "$BIN" --target-dir "$TARGET_DIR"
  INSTR="$OUT"
  [ -x "$INSTR" ] || {
    echo "!! instrumented build produced no local binary at $INSTR" >&2
    echo "!! (a remotely-offloaded build leaves nothing here; see the cargo note above)" >&2
    exit 1
  }

  if [ -z "$TRAIN_IMG" ]; then
    SRC="$(ls -1 ./*.img /data/tmp/*ext*.img 2>/dev/null | head -1 || true)"
    [ -z "$SRC" ] && { echo "!! no training image; pass one as \$1" >&2; exit 1; }
    TRAIN_IMG="$PGO_DIR/train.img"; cp "$SRC" "$TRAIN_IMG"
    "$INSTR" create-bench "$TRAIN_IMG" / --count 40000 --threads 1 >/dev/null 2>&1 || true
  fi
  # Each training command still tolerates its own failure -- one bad bench must
  # not abort a 20-minute build -- but the failure is now RECORDED instead of
  # discarded by `|| true`, and the gate below decides. Exit status alone is not
  # enough: a command can exit 0 and write no profile at all, which is exactly
  # what an offloaded build does (see the cargo note above), so each command also
  # reports how many .profraw files appeared while it ran.
  TRAIN_RESULTS="$PGO_DIR/training-results.tsv"
  : > "$TRAIN_RESULTS"
  #
  # EACH COMMAND WRITES ITS OWN PROFILE FILE, and that is load-bearing rather
  # than tidy. OBSERVED DEFECT, 2026-08-23 (bd-svhrq): without the explicit
  # LLVM_PROFILE_FILE below, rustc's default `-Cprofile-generate=<dir>` pattern
  # is `default_%m_0.profraw`, and `%m` names a MERGE POOL keyed by the binary's
  # signature. All five commands run the SAME instrumented binary, so all five
  # merge IN PLACE into ONE file: the file count rises exactly once, on the
  # first command, and this gate reported
  #
  #   PGO training gate FAILED: 4 of 5 training commands did not train
  #     (lookup-bench, rename-bench, delbench, walk)
  #
  # for a run in which every command exited 0 and did real work
  # (`lookupbench_done count=100000 dir_entries=40004 found=100000`), and whose
  # merged profile demonstrably contained `lookupbench_cmd`, `renamebench_cmd`
  # and `walk_cmd`. The gate was right to fail closed on the evidence it had;
  # the evidence was being collected wrongly.
  #
  # `%p` gives every RUN its own file, so "a new profile appeared" is once again
  # the thing this is counting. The gate's threshold is untouched: this repairs
  # its input rather than relaxing what it demands.
  train() { # $1 label, rest: command
    local label="$1"; shift
    local before after rc
    before=$(find "$PGO_DIR" -name '*.profraw' | wc -l)
    # `if`, not `cmd; rc=$?`: this script runs under `set -e`, which aborts on a
    # failing simple command BEFORE the next one can read `$?`. The comment above
    # promises that "one bad bench must not abort a 20-minute build" and that the
    # gate decides -- but as written a single failing bench killed the script
    # outright, with an empty results file and nothing for the gate to adjudicate
    # (observed 2026-08-23: a second run against an already-trained image failed
    # `create-bench ... file exists` and took the whole build down at stage 2).
    # A command inside an `if` condition is exempt from `set -e`, so the failure
    # is recorded and the gate gets to rule on it, as intended.
    if LLVM_PROFILE_FILE="$PGO_DIR/${label}_%m_%p.profraw" "$@" >/dev/null 2>&1; then
      rc=0
    else
      rc=$?
    fi
    after=$(find "$PGO_DIR" -name '*.profraw' | wc -l)
    printf '%s\t%s\t%s\n' "$label" "$rc" "$((after - before))" >> "$TRAIN_RESULTS"
  }

  echo ">> [2/4] training on $TRAIN_IMG (exercise the hot paths)"
  train create-bench "$INSTR" create-bench "$TRAIN_IMG" / --count 20000 --threads 1
  train lookup-bench "$INSTR" lookup-bench "$TRAIN_IMG" / --count 3000000           
  train rename-bench "$INSTR" rename-bench "$TRAIN_IMG" / --count 20000             
  train delbench "$INSTR" delbench     "$TRAIN_IMG" / --count 20000             
  train walk "$INSTR" walk         "$TRAIN_IMG" --no-stat                   

  # Fail closed on a profile that trained only part of the hot paths. The
  # pre-existing `[ -s merged.profdata ]` check below catches only the case where
  # EVERY command failed; this catches the case where four of five did, which
  # still produces a non-empty profile and a binary that every row would describe
  # as "real PGO".
  if ! python3 "$(dirname "$0")/pgo_training_gate.py" "$TRAIN_RESULTS" \
       ${FFS_PGO_ALLOW_PARTIAL:+--allow-partial}; then
    echo "!! refusing to build from a partially-trained profile" >&2
    echo "!! set FFS_PGO_ALLOW_PARTIAL=1 to accept it deliberately; the artifact is" >&2
    echo "!! then NOT the standard one and any row measured from it must say so" >&2
    exit 1
  fi

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
env -u CARGO_TARGET_DIR \
  FFS_PGO_PROFILE_SHA256="$PROFILE_SHA256" \
  RUSTFLAGS="-C target-cpu=$TARGET_CPU -C profile-use=$PGO_DIR/merged.profdata -Cllvm-args=-pgo-warn-missing-function" \
  "$CARGO" build --profile "$PROFILE" -p "$BIN" --target-dir "$TARGET_DIR"

echo ">> done: $OUT  (fat LTO + target-cpu=$TARGET_CPU + PGO profile=$PROFILE_SHA256)"
"$OUT" bench-evidence

#!/usr/bin/env bash
# make_ext4_fixtures.sh - Generate ext4 golden fixture images
#
# This script creates reproducible ext4 filesystem images for conformance testing.
# It uses debugfs for rootless population (no sudo required for basic content).
#
# Usage: ./scripts/fixtures/make_ext4_fixtures.sh [--images-only]
#
# Output:
#   tests/fixtures/images/ext4_small.img   (16 MiB)
#   tests/fixtures/images/ext4_medium.img  (64 MiB)
#   tests/fixtures/images/ext4_large.img   (128 MiB)
#   tests/fixtures/golden/ext4_*.json      (legacy summary inspect output)
#   tests/fixtures/golden/checksums.txt    (SHA-256 verification)

set -euo pipefail
IFS=$'\n\t'

IMAGES_ONLY=0
if [[ $# -gt 0 ]]; then
    if [[ $# -ne 1 || "$1" != "--images-only" ]]; then
        echo "Usage: $0 [--images-only]" >&2
        exit 2
    fi
    IMAGES_ONLY=1
fi

# Navigate to repo root
cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"

# Paths
IMAGES_DIR="tests/fixtures/images"
GOLDEN_DIR="tests/fixtures/golden"
LOG_FILE="${GOLDEN_DIR}/generation.log"
FFS_USE_RCH="${FFS_USE_RCH:-1}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_VISIBILITY="${RCH_VISIBILITY:-summary}"
RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:-CARGO_TARGET_DIR}"
RCH_AGENT_TARGET_SUFFIX="${AGENT_NAME:-${USER:-agent}}"
RCH_CARGO_TARGET_DIR="${RCH_CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_frankenfs_ext4_fixtures_$RCH_AGENT_TARGET_SUFFIX}"

# Ensure directories exist
mkdir -p "$IMAGES_DIR"
if [[ "$IMAGES_ONLY" == "0" ]]; then
    mkdir -p "$GOLDEN_DIR"
fi

rch_allow_env() {
    local name="$1"
    if [[ ",$RCH_ENV_ALLOWLIST," != *",$name,"* ]]; then
        RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST},$name"
    fi
}

rch_allow_env CARGO_TARGET_DIR

run_cargo() {
    if [[ "$FFS_USE_RCH" == "1" ]]; then
        if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
            echo "ERROR: FFS_USE_RCH=1 requires $RCH_BIN; set FFS_USE_RCH=0 for an explicit local cargo run" >&2
            exit 127
        fi
        CARGO_TARGET_DIR="$RCH_CARGO_TARGET_DIR" \
            RCH_ENV_ALLOWLIST="$RCH_ENV_ALLOWLIST" \
            RCH_VISIBILITY="$RCH_VISIBILITY" \
            "$RCH_BIN" exec -- cargo "$@"
    else
        cargo "$@"
    fi
}

write_golden_checksums() {
    (
        cd "$GOLDEN_DIR"
        mapfile -t json_files < <(find . -maxdepth 1 -type f -name '*.json' -printf '%f\n' | sort)
        if [[ ${#json_files[@]} -eq 0 ]]; then
            echo "ERROR: no JSON fixtures found in $GOLDEN_DIR" >&2
            return 1
        fi
        sha256sum "${json_files[@]}" > checksums.txt
    )
}

# Start logging
if [[ "$IMAGES_ONLY" == "0" ]]; then
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

echo "=============================================="
echo "ext4 Fixture Generation"
echo "=============================================="
echo "Start time: $(date -Iseconds)"
echo "Repository: $REPO_ROOT"
echo ""

# Print tool versions
echo "=== Tool Versions ==="
echo "mkfs.ext4:"
mkfs.ext4 -V 2>&1 | head -2
echo ""
echo "debugfs:"
debugfs -V 2>&1 | head -2
echo ""
echo "dd: $(dd --version 2>&1 | head -1)"
echo "sha256sum: $(sha256sum --version 2>&1 | head -1)"
echo ""

# Function to create an ext4 image
create_image() {
    local name="$1"
    local size_mb="$2"
    local features="$3"
    local img_path="${IMAGES_DIR}/${name}.img"

    echo "=== Creating $name ($size_mb MiB) ==="
    echo "Features: $features"
    echo ""

    # Create zero-filled image
    echo "  [1/4] Creating empty image..."
    if [[ "$IMAGES_ONLY" == "1" ]]; then
        # Clean-checkout provisioning must refuse an existing fixture.
        dd if=/dev/zero of="$img_path" bs=1M count="$size_mb" conv=excl status=progress 2>&1
    else
        dd if=/dev/zero of="$img_path" bs=1M count="$size_mb" status=progress 2>&1
    fi
    echo ""

    # Format as ext4
    echo "  [2/4] Formatting as ext4..."
    mkfs.ext4 -F -O "$features" -L "$name" "$img_path" 2>&1
    echo ""

    # Populate with known content using debugfs
    echo "  [3/4] Populating with test content..."
    populate_image "$img_path" "$name"
    echo ""

    echo "  [4/4] Image complete: $img_path"
    ls -lh "$img_path"
    echo ""
}

# Function to populate image with known content using debugfs
populate_image() {
    local img_path="$1"
    local name="$2"

    # Create temporary files for content
    local tmp_dir
    tmp_dir=$(mktemp -d)
    echo "  Retained native producer content: $tmp_dir"

    # README.txt content
    cat > "$tmp_dir/README.txt" << 'EOF'
FrankenFS Test Fixture
======================
This filesystem image was created for conformance testing.
It contains a known directory structure for validation.

Created by: scripts/fixtures/make_ext4_fixtures.sh
EOF

    # Binary file (256 bytes of deterministic pattern)
    dd if=/dev/zero bs=256 count=1 2>/dev/null | tr '\0' '\xFF' > "$tmp_dir/file1.bin"

    # Text file
    cat > "$tmp_dir/file2.txt" << 'EOF'
Nested text file for testing directory traversal.
Line 2
Line 3
EOF

    # Use debugfs to populate the filesystem
    debugfs -w "$img_path" << DEBUGFS_CMDS
mkdir dir1
mkdir dir1/dir2
write $tmp_dir/README.txt README.txt
write $tmp_dir/file1.bin dir1/file1.bin
write $tmp_dir/file2.txt dir1/dir2/file2.txt
symlink symlink dir1/file1.bin
ls -l /
ls -l /dir1
ls -l /dir1/dir2
DEBUGFS_CMDS

    echo "  Content structure:"
    debugfs -R "ls -l /" "$img_path" 2>/dev/null || true
}

# Create three images with different feature combinations
echo "=== Phase 1: Creating Images ==="
echo ""

# Small: minimal features (extent + filetype required by FrankenFS V1)
create_image "ext4_small" 16 "extent,filetype"

# Medium: add dir_index (htree directories)
create_image "ext4_medium" 64 "extent,filetype,dir_index"

# Large: add sparse_super (optimized superblock placement)
create_image "ext4_large" 128 "extent,filetype,dir_index,sparse_super"

if [[ "$IMAGES_ONLY" == "1" ]]; then
    echo "Native ext4 input images are ready; expected golden files are unchanged."
    exit 0
fi

echo "=== Phase 2: Building FrankenFS CLI ==="
echo ""
run_cargo build -p ffs-cli --release 2>&1

echo ""
echo "=== Phase 3: Generating Golden Outputs ==="
echo ""

for img in "$IMAGES_DIR"/ext4_*.img; do
    name=$(basename "$img" .img)
    golden="${GOLDEN_DIR}/${name}.json"

    echo "Generating: $golden"
    # Redirect stderr to hide cargo build output, capture only JSON
    run_cargo run -p ffs-cli --release -- inspect "$img" --json 2>/dev/null > "$golden"

    # Show summary
    echo "  Size: $(wc -c < "$golden") bytes"
    echo "  Preview: $(head -c 200 "$golden")..."
    echo ""
done

echo "=== Phase 4: Creating Checksums ==="
echo ""

write_golden_checksums
cd "$GOLDEN_DIR"
echo "Checksums:"
cat checksums.txt
echo ""

echo "=== Verification ==="
echo ""
if sha256sum -c checksums.txt; then
    echo ""
    echo "All checksums verified successfully."
else
    echo ""
    echo "ERROR: Checksum verification failed!"
    exit 1
fi

echo ""
echo "=============================================="
echo "Generation Complete"
echo "=============================================="
echo "End time: $(date -Iseconds)"
echo ""
echo "Artifacts created:"
for f in "$REPO_ROOT/$IMAGES_DIR"/ext4_*.img; do
    echo "  - $f ($(du -h "$f" | cut -f1))"
done
for f in "$REPO_ROOT/$GOLDEN_DIR"/ext4_*.json; do
    echo "  - $f ($(wc -c < "$f") bytes)"
done
echo "  - $REPO_ROOT/$GOLDEN_DIR/checksums.txt"
echo "  - $REPO_ROOT/$GOLDEN_DIR/generation.log"
echo ""
echo "To verify: ( cd $GOLDEN_DIR && sha256sum -c checksums.txt )"

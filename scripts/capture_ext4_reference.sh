#!/usr/bin/env bash
# capture_ext4_reference.sh — Generate ext4 kernel-reference golden JSON files.
#
# Usage:
#   scripts/capture_ext4_reference.sh [output_dir]
#   scripts/capture_ext4_reference.sh --variant <name> [output_dir]
#   scripts/capture_ext4_reference.sh --all [output_dir]
#
# Variants:
#   ext4_8mb_reference
#   ext4_64mb_reference
#   ext4_dir_index_reference
#
# Requires: mkfs.ext4, debugfs, dumpe2fs (e2fsprogs package)
#
# Notes:
# - JSON files are checked in under conformance/golden/.
# - Raw .ext4 images are generated for local verification and are git-ignored.
set -euo pipefail

timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

log() {
    echo "[$(timestamp)] $*" >&2
}

run() {
    log "RUN: $*"
    "$@"
}

capture() {
    log "RUN (capture): $*"
    "$@"
}

usage() {
    cat >&2 <<'USAGE_EOF'
Usage:
  scripts/capture_ext4_reference.sh [output_dir]
  scripts/capture_ext4_reference.sh --variant <name> [output_dir]
  scripts/capture_ext4_reference.sh --all [output_dir]

Variants:
  ext4_8mb_reference
  ext4_64mb_reference
  ext4_dir_index_reference
USAGE_EOF
}

MODE="single"
SELECTED_VARIANT="ext4_8mb_reference"
OUTPUT_DIR="conformance/golden"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)
            MODE="all"
            shift
            ;;
        --variant)
            MODE="single"
            shift
            if [[ $# -eq 0 ]]; then
                usage
                exit 1
            fi
            SELECTED_VARIANT="$1"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            OUTPUT_DIR="$1"
            shift
            ;;
    esac
done

mkdir -p "$OUTPUT_DIR"

BASE_CONTENT_FILE="$(mktemp)"
METRICS_CONTENT_FILE="$(mktemp)"
DIR_INDEX_CONTENT_FILE="$(mktemp)"
trap 'rm -f "$BASE_CONTENT_FILE" "$METRICS_CONTENT_FILE" "$DIR_INDEX_CONTENT_FILE"' EXIT

printf 'hello from FrankenFS reference test\n' > "$BASE_CONTENT_FILE"
printf 'hello from FrankenFS 64mb geometry variant\n' > "$METRICS_CONTENT_FILE"
printf 'hello from FrankenFS dir_index variant\n' > "$DIR_INDEX_CONTENT_FILE"

DIR_INDEX_FILE_COUNT=180

log "Tool versions:"
log "mkfs.ext4: $(mkfs.ext4 -V 2>&1 | sed -n '1p')"
log "debugfs: $(debugfs -V 2>&1 | sed -n '1p')"
log "dumpe2fs: $(dumpe2fs -V 2>&1 | sed -n '1p')"

parse_field() {
    local dump="$1"
    local name="$2"
    printf '%s\n' "$dump" | grep "^${name}:" | sed -n '1{s/^'"${name}"':[[:space:]]*//;p;}'
}

hex_to_json_array() {
    local hex="$1"
    local len=${#hex}
    local i=0
    local first=true
    echo -n "["
    while [[ $i -lt $len ]]; do
        local byte="${hex:$i:2}"
        local dec=$((16#$byte))
        if [[ "$first" = true ]]; then
            first=false
        else
            echo -n ","
        fi
        echo -n "$dec"
        i=$((i + 2))
    done
    echo -n "]"
}

capture_dir_entries_json() {
    local image="$1"
    local dir="$2"
    local output
    output="$(capture debugfs -R "ls -l $dir" "$image")"
    local first=true
    echo "["
    while IFS= read -r line; do
        line="$(echo "$line" | sed 's/^[[:space:]]*//')"
        [[ -z "$line" ]] && continue
        [[ "$line" == debugfs* ]] && continue

        local inode mode name
        inode="$(echo "$line" | awk '{print $1}')"
        mode="$(echo "$line" | awk '{print $2}')"
        name="$(echo "$line" | awk '{print $NF}')"
        [[ "$inode" =~ ^[0-9]+$ ]] || continue

        local mode_dec=$((8#$mode))
        local type_bits=$(( mode_dec & 8#170000 ))
        local file_type="unknown"
        case "$type_bits" in
            $((8#040000))) file_type="directory" ;;
            $((8#100000))) file_type="regular" ;;
            $((8#020000))) file_type="character" ;;
            $((8#060000))) file_type="block" ;;
            $((8#010000))) file_type="fifo" ;;
            $((8#140000))) file_type="socket" ;;
            $((8#120000))) file_type="symlink" ;;
        esac

        if [[ "$first" = true ]]; then
            first=false
        else
            echo ","
        fi
        printf '        {"name": "%s", "file_type": "%s"}' "$name" "$file_type"
    done <<< "$output"
    echo
    echo "      ]"
}

emit_files_json() {
    local -n file_paths_ref="$1"
    local -n file_sources_ref="$2"
    local first=true
    echo "  \"files\": ["
    for idx in "${!file_paths_ref[@]}"; do
        local path="${file_paths_ref[$idx]}"
        local source="${file_sources_ref[$idx]}"
        local hex size bytes_json
        hex="$(xxd -p "$source" | tr -d '\n')"
        size="$(wc -c < "$source" | tr -d ' ')"
        bytes_json="$(hex_to_json_array "$hex")"
        if [[ "$first" = true ]]; then
            first=false
        else
            echo ","
        fi
        cat <<FILE_EOF
    {
      "path": "$path",
      "size": $size,
      "content": $bytes_json
    }
FILE_EOF
    done
    echo
    echo "  ]"
}

emit_directories_json() {
    local image="$1"
    local -n dirs_ref="$2"
    local first=true
    echo "  \"directories\": ["
    for dir in "${dirs_ref[@]}"; do
        local entries_json
        entries_json="$(capture_dir_entries_json "$image" "$dir")"
        if [[ "$first" = true ]]; then
            first=false
        else
            echo ","
        fi
        cat <<DIR_EOF
    {
      "path": "$dir",
      "entries": $entries_json
    }
DIR_EOF
    done
    echo
    echo "  ],"
}

generate_variant() {
    local variant="$1"
    local size_mb block_size label mkfs_feature_opt
    local -a mkdir_cmds=()
    local -a file_targets=()
    local -a file_sources=()
    local -a dirs_to_capture=()

    case "$variant" in
        ext4_8mb_reference)
            size_mb=8
            block_size=4096
            label="ffs-ref"
            mkfs_feature_opt=""
            mkdir_cmds=("mkdir /testdir")
            file_targets=("/testdir/hello.txt" "/readme.txt")
            file_sources=("$BASE_CONTENT_FILE" "$BASE_CONTENT_FILE")
            dirs_to_capture=("/" "/testdir")
            ;;
        ext4_64mb_reference)
            size_mb=64
            block_size=4096
            label="ffs-ref-64"
            mkfs_feature_opt=""
            mkdir_cmds=("mkdir /deep" "mkdir /deep/nested")
            file_targets=("/deep/nested/data.txt" "/readme64.txt")
            file_sources=("$METRICS_CONTENT_FILE" "$METRICS_CONTENT_FILE")
            dirs_to_capture=("/" "/deep" "/deep/nested")
            ;;
        ext4_dir_index_reference)
            size_mb=64
            block_size=4096
            label="ffs-ref-dx"
            mkfs_feature_opt="dir_index"
            mkdir_cmds=("mkdir /htree")
            dirs_to_capture=("/" "/htree")
            for ((idx=0; idx<DIR_INDEX_FILE_COUNT; idx++)); do
                file_targets+=("$(printf '/htree/file_%03d.txt' "$idx")")
                file_sources+=("$DIR_INDEX_CONTENT_FILE")
            done
            file_targets+=("/readme-dx.txt")
            file_sources+=("$DIR_INDEX_CONTENT_FILE")
            ;;
        *)
            log "Unknown variant: $variant"
            exit 1
            ;;
    esac

    local image="$OUTPUT_DIR/${variant}.ext4"
    local golden="$OUTPUT_DIR/${variant}.json"
    local size_bytes=$((size_mb * 1024 * 1024))

    log "=== Capturing variant: $variant ==="
    log "Recipe: size_mb=$size_mb block_size=$block_size label=$label mkfs_feature_opt=${mkfs_feature_opt:-<default>}"

    run dd if=/dev/zero of="$image" bs=1M count="$size_mb" status=none
    if [[ -n "$mkfs_feature_opt" ]]; then
        run mkfs.ext4 -L "$label" -b "$block_size" -q -O "$mkfs_feature_opt" "$image"
    else
        run mkfs.ext4 -L "$label" -b "$block_size" -q "$image"
    fi

    for cmd in "${mkdir_cmds[@]}"; do
        run debugfs -w -R "$cmd" "$image"
    done
    for idx in "${!file_targets[@]}"; do
        run debugfs -w -R "write ${file_sources[$idx]} ${file_targets[$idx]}" "$image"
    done

    local dumpe2fs_out
    dumpe2fs_out="$(capture dumpe2fs -h "$image")"
    local parsed_block_size parsed_blocks_count parsed_inodes_count parsed_volume_name parsed_free_blocks parsed_free_inodes
    parsed_block_size="$(parse_field "$dumpe2fs_out" "Block size")"
    parsed_blocks_count="$(parse_field "$dumpe2fs_out" "Block count")"
    parsed_inodes_count="$(parse_field "$dumpe2fs_out" "Inode count")"
    parsed_volume_name="$(parse_field "$dumpe2fs_out" "Filesystem volume name")"
    parsed_free_blocks="$(parse_field "$dumpe2fs_out" "Free blocks")"
    parsed_free_inodes="$(parse_field "$dumpe2fs_out" "Free inodes")"

    log "Writing golden JSON: $golden"
    {
        echo "{"
        echo "  \"version\": 1,"
        echo "  \"source\": \"Linux e2fsprogs (mkfs.ext4 + debugfs + dumpe2fs)\","
        echo "  \"image_params\": {"
        echo "    \"size_bytes\": $size_bytes,"
        echo "    \"block_size\": $parsed_block_size,"
        echo "    \"volume_name\": \"$label\""
        echo "  },"
        echo "  \"superblock\": {"
        echo "    \"block_size\": $parsed_block_size,"
        echo "    \"blocks_count\": $parsed_blocks_count,"
        echo "    \"inodes_count\": $parsed_inodes_count,"
        echo "    \"volume_name\": \"$parsed_volume_name\","
        echo "    \"free_blocks_count\": $parsed_free_blocks,"
        echo "    \"free_inodes_count\": $parsed_free_inodes"
        echo "  },"
        emit_directories_json "$image" dirs_to_capture
        emit_files_json file_targets file_sources
        echo "}"
    } > "$golden"

    log "Done: $golden"
    log "Image (git-ignored): $image"
}

if [[ "$MODE" = "all" ]]; then
    generate_variant "ext4_8mb_reference"
    generate_variant "ext4_64mb_reference"
    generate_variant "ext4_dir_index_reference"
else
    generate_variant "$SELECTED_VARIANT"
fi

log "Capture complete."

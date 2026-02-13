#!/usr/bin/env bash
# capture_ext4_references.sh — Generate all ext4 golden reference JSON files.
#
# Usage:
#   scripts/capture_ext4_references.sh [output_dir]
#
# Produces:
#   <output_dir>/ext4_8mb_reference.json
#   <output_dir>/ext4_64mb_reference.json
#   <output_dir>/ext4_dir_index_reference.json
#   <output_dir>/checksums.sha256
#
# Binary .ext4 images are generated alongside the JSON files but are gitignored.
set -euo pipefail

OUTPUT_DIR="${1:-conformance/golden}"
mkdir -p "$OUTPUT_DIR"
DIR_INDEX_FILE_COUNT=180

log() {
    printf '[%s] %s\n' "$(date -Iseconds)" "$*" >&2
}

run() {
    log "+ $*"
    "$@"
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log "missing required command: $1"
        exit 1
    fi
}

for cmd in mkfs.ext4 debugfs dumpe2fs dd sha256sum; do
    require_cmd "$cmd"
done

log "mkfs.ext4: $(mkfs.ext4 -V 2>&1 | sed -n '1p')"
log "debugfs:   $(debugfs -V 2>&1 | sed -n '1p')"
log "dumpe2fs:  $(dumpe2fs -V 2>&1 | sed -n '1p')"

parse_field() {
    local dumpe2fs_out="$1"
    local field="$2"
    printf '%s\n' "$dumpe2fs_out" | sed -n "s/^${field}:[[:space:]]*//p" | sed -n '1p'
}

capture_dir() {
    local image="$1"
    local dir="$2"
    local output
    output="$(debugfs -R "ls -l $dir" "$image" 2>/dev/null)"

    local first=true
    echo "["
    while IFS= read -r line; do
        line="$(printf '%s' "$line" | sed 's/^[[:space:]]*//')"
        [[ -z "$line" ]] && continue
        [[ "$line" == debugfs* ]] && continue

        local inode mode name
        inode="$(printf '%s' "$line" | awk '{print $1}')"
        mode="$(printf '%s' "$line" | awk '{print $2}')"
        name="$(printf '%s' "$line" | awk '{print $NF}')"

        [[ "$inode" =~ ^[0-9]+$ ]] || continue

        local ftype="unknown"
        local mode_dec=$((8#$mode))
        local type_bits=$((mode_dec & 8#170000))
        case "$type_bits" in
            $((8#040000))) ftype="directory" ;;
            $((8#100000))) ftype="regular" ;;
            $((8#020000))) ftype="character" ;;
            $((8#060000))) ftype="block" ;;
            $((8#010000))) ftype="fifo" ;;
            $((8#140000))) ftype="socket" ;;
            $((8#120000))) ftype="symlink" ;;
            *) ftype="unknown" ;;
        esac

        if [ "$first" = true ]; then
            first=false
        else
            echo ","
        fi
        printf '    {"name": "%s", "file_type": "%s"}' "$name" "$ftype"
    done <<< "$output"
    echo
    echo "  ]"
}

bytes_json_from_file() {
    local file="$1"
    od -An -t u1 -v "$file" | awk '
        BEGIN { first = 1; printf "[" }
        {
            for (i = 1; i <= NF; i++) {
                if (!first) { printf "," }
                printf "%s", $i
                first = 0
            }
        }
        END { printf "]" }
    '
}

size_bytes_of_file() {
    wc -c < "$1" | tr -d ' '
}

write_golden_json() {
    local golden="$1"
    local source="$2"
    local image_size_bytes="$3"
    local block_size="$4"
    local volume_name="$5"
    local blocks_count="$6"
    local inodes_count="$7"
    local free_blocks="$8"
    local free_inodes="$9"
    local directories_json="${10}"
    local files_json="${11}"

    cat > "$golden" <<GOLDEN_EOF
{
  "version": 1,
  "source": "$source",
  "image_params": {
    "size_bytes": $image_size_bytes,
    "block_size": $block_size,
    "volume_name": "$volume_name"
  },
  "superblock": {
    "block_size": $block_size,
    "blocks_count": $blocks_count,
    "inodes_count": $inodes_count,
    "volume_name": "$volume_name",
    "free_blocks_count": $free_blocks,
    "free_inodes_count": $free_inodes
  },
  "directories": $directories_json,
  "files": $files_json
}
GOLDEN_EOF
}

generate_8mb_variant() {
    local image="$OUTPUT_DIR/ext4_8mb_reference.ext4"
    local golden="$OUTPUT_DIR/ext4_8mb_reference.json"
    local content_file
    content_file="$(mktemp)"
    trap 'rm -f "$content_file"' RETURN

    printf 'hello from FrankenFS reference test\n' > "$content_file"

    run dd if=/dev/zero of="$image" bs=1M count=8 status=none
    run mkfs.ext4 -L "ffs-ref" -b 4096 -q "$image"
    run debugfs -w -R "mkdir /testdir" "$image"
    run debugfs -w -R "write $content_file /testdir/hello.txt" "$image"
    run debugfs -w -R "write $content_file /readme.txt" "$image"

    local dumpe2fs_out
    dumpe2fs_out="$(dumpe2fs -h "$image" 2>/dev/null)"
    local block_size blocks_count inodes_count volume_name free_blocks free_inodes
    block_size="$(parse_field "$dumpe2fs_out" "Block size")"
    blocks_count="$(parse_field "$dumpe2fs_out" "Block count")"
    inodes_count="$(parse_field "$dumpe2fs_out" "Inode count")"
    volume_name="$(parse_field "$dumpe2fs_out" "Filesystem volume name")"
    free_blocks="$(parse_field "$dumpe2fs_out" "Free blocks")"
    free_inodes="$(parse_field "$dumpe2fs_out" "Free inodes")"

    local root_entries testdir_entries
    root_entries="$(capture_dir "$image" "/")"
    testdir_entries="$(capture_dir "$image" "/testdir")"

    local file_size file_bytes
    file_size="$(size_bytes_of_file "$content_file")"
    file_bytes="$(bytes_json_from_file "$content_file")"

    local directories_json files_json
    directories_json="[
    {
      \"path\": \"/\",
      \"entries\": $root_entries
    },
    {
      \"path\": \"/testdir\",
      \"entries\": $testdir_entries
    }
  ]"

    files_json="[
    {
      \"path\": \"/testdir/hello.txt\",
      \"size\": $file_size,
      \"content\": $file_bytes
    },
    {
      \"path\": \"/readme.txt\",
      \"size\": $file_size,
      \"content\": $file_bytes
    }
  ]"

    write_golden_json \
        "$golden" \
        "Linux e2fsprogs (mkfs.ext4 + debugfs + dumpe2fs); variant=ext4_8mb_reference" \
        "$((8 * 1024 * 1024))" \
        "$block_size" \
        "$volume_name" \
        "$blocks_count" \
        "$inodes_count" \
        "$free_blocks" \
        "$free_inodes" \
        "$directories_json" \
        "$files_json"
}

generate_64mb_variant() {
    local image="$OUTPUT_DIR/ext4_64mb_reference.ext4"
    local golden="$OUTPUT_DIR/ext4_64mb_reference.json"
    local content_file
    content_file="$(mktemp)"
    trap 'rm -f "$content_file"' RETURN

    printf 'hello from FrankenFS 64mb geometry variant\n' > "$content_file"

    run dd if=/dev/zero of="$image" bs=1M count=64 status=none
    run mkfs.ext4 -L "ffs-ref-64" -b 4096 -q "$image"
    run debugfs -w -R "mkdir /deep" "$image"
    run debugfs -w -R "mkdir /deep/nested" "$image"
    run debugfs -w -R "write $content_file /deep/nested/data.txt" "$image"
    run debugfs -w -R "write $content_file /readme64.txt" "$image"

    local dumpe2fs_out
    dumpe2fs_out="$(dumpe2fs -h "$image" 2>/dev/null)"
    local block_size blocks_count inodes_count volume_name free_blocks free_inodes
    block_size="$(parse_field "$dumpe2fs_out" "Block size")"
    blocks_count="$(parse_field "$dumpe2fs_out" "Block count")"
    inodes_count="$(parse_field "$dumpe2fs_out" "Inode count")"
    volume_name="$(parse_field "$dumpe2fs_out" "Filesystem volume name")"
    free_blocks="$(parse_field "$dumpe2fs_out" "Free blocks")"
    free_inodes="$(parse_field "$dumpe2fs_out" "Free inodes")"

    local root_entries deep_entries nested_entries
    root_entries="$(capture_dir "$image" "/")"
    deep_entries="$(capture_dir "$image" "/deep")"
    nested_entries="$(capture_dir "$image" "/deep/nested")"

    local file_size file_bytes
    file_size="$(size_bytes_of_file "$content_file")"
    file_bytes="$(bytes_json_from_file "$content_file")"

    local directories_json files_json
    directories_json="[
    {
      \"path\": \"/\",
      \"entries\": $root_entries
    },
    {
      \"path\": \"/deep\",
      \"entries\": $deep_entries
    },
    {
      \"path\": \"/deep/nested\",
      \"entries\": $nested_entries
    }
  ]"

    files_json="[
    {
      \"path\": \"/deep/nested/data.txt\",
      \"size\": $file_size,
      \"content\": $file_bytes
    },
    {
      \"path\": \"/readme64.txt\",
      \"size\": $file_size,
      \"content\": $file_bytes
    }
  ]"

    write_golden_json \
        "$golden" \
        "Linux e2fsprogs (mkfs.ext4 + debugfs + dumpe2fs); variant=ext4_64mb_reference" \
        "$((64 * 1024 * 1024))" \
        "$block_size" \
        "$volume_name" \
        "$blocks_count" \
        "$inodes_count" \
        "$free_blocks" \
        "$free_inodes" \
        "$directories_json" \
        "$files_json"
}

generate_dir_index_variant() {
    local image="$OUTPUT_DIR/ext4_dir_index_reference.ext4"
    local golden="$OUTPUT_DIR/ext4_dir_index_reference.json"
    local content_file
    content_file="$(mktemp)"
    trap 'rm -f "$content_file"' RETURN

    printf 'hello from FrankenFS dir_index variant\n' > "$content_file"

    run dd if=/dev/zero of="$image" bs=1M count=64 status=none
    run mkfs.ext4 -L "ffs-ref-dx" -b 4096 -q -O dir_index "$image"
    run debugfs -w -R "mkdir /htree" "$image"
    for idx in $(seq -w 0 $((DIR_INDEX_FILE_COUNT - 1))); do
        run debugfs -w -R "write $content_file /htree/file_${idx}.txt" "$image"
    done
    run debugfs -w -R "write $content_file /readme-dx.txt" "$image"

    local dumpe2fs_out
    dumpe2fs_out="$(dumpe2fs -h "$image" 2>/dev/null)"
    local block_size blocks_count inodes_count volume_name free_blocks free_inodes
    block_size="$(parse_field "$dumpe2fs_out" "Block size")"
    blocks_count="$(parse_field "$dumpe2fs_out" "Block count")"
    inodes_count="$(parse_field "$dumpe2fs_out" "Inode count")"
    volume_name="$(parse_field "$dumpe2fs_out" "Filesystem volume name")"
    free_blocks="$(parse_field "$dumpe2fs_out" "Free blocks")"
    free_inodes="$(parse_field "$dumpe2fs_out" "Free inodes")"

    local root_entries htree_entries
    root_entries="$(capture_dir "$image" "/")"
    htree_entries="$(capture_dir "$image" "/htree")"

    local file_size file_bytes
    file_size="$(size_bytes_of_file "$content_file")"
    file_bytes="$(bytes_json_from_file "$content_file")"

    local last_idx
    last_idx="$(printf '%03d' $((DIR_INDEX_FILE_COUNT - 1)))"

    local directories_json files_json
    directories_json="[
    {
      \"path\": \"/\",
      \"entries\": $root_entries
    },
    {
      \"path\": \"/htree\",
      \"entries\": $htree_entries
    }
  ]"

    files_json="[
    {
      \"path\": \"/htree/file_000.txt\",
      \"size\": $file_size,
      \"content\": $file_bytes
    },
    {
      \"path\": \"/htree/file_${last_idx}.txt\",
      \"size\": $file_size,
      \"content\": $file_bytes
    },
    {
      \"path\": \"/readme-dx.txt\",
      \"size\": $file_size,
      \"content\": $file_bytes
    }
  ]"

    write_golden_json \
        "$golden" \
        "Linux e2fsprogs (mkfs.ext4 + debugfs + dumpe2fs); variant=ext4_dir_index_reference" \
        "$((64 * 1024 * 1024))" \
        "$block_size" \
        "$volume_name" \
        "$blocks_count" \
        "$inodes_count" \
        "$free_blocks" \
        "$free_inodes" \
        "$directories_json" \
        "$files_json"
}

generate_8mb_variant
generate_64mb_variant
generate_dir_index_variant

run bash -c "cd '$OUTPUT_DIR' && sha256sum *.json > checksums.sha256"
log "generated ext4 golden references in $OUTPUT_DIR"

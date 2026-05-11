#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_command cargo
require_command dosbox-x
require_command python3

rar250_sfx="${RARS_RAR250_SFX:-/home/gaz/src/tmp/rar/_refs/rarbins/rar250.exe}"
if [[ ! -f "$rar250_sfx" ]]; then
  cat >&2 <<EOF
missing RAR 2.50 DOS SFX: $rar250_sfx

Set RARS_RAR250_SFX to the local RAR 2.50 self-extracting archive.
EOF
  exit 1
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/rars-rar20-ref.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

cargo run -p rars-cli --quiet -- x "$rar250_sfx" "$tmpdir/rar250" >/dev/null
cp "$tmpdir/rar250/UNRAR.EXE" "$tmpdir/UNRAR.EXE"

python3 - "$tmpdir" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
(root / "TEXT.TXT").write_bytes(
    b"RAR20 oracle text alpha beta gamma repeated line.\r\n" * 512
)
(root / "REPEAT.BIN").write_bytes((b"abc123xyz-" * 4096))

state = 0x2468ACE1
binary = bytearray()
for _ in range(64 * 1024):
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= state >> 17
    state ^= (state << 5) & 0xFFFFFFFF
    binary.append(state & 0xFF)
(root / "BINARY.BIN").write_bytes(binary)

pcm = bytearray()
for sample in range(4096):
    left = (sample * 3 + 200) & 0xFFFF
    right = (sample * 3 - 200) & 0xFFFF
    pcm.extend(left.to_bytes(2, "little"))
    pcm.extend(right.to_bytes(2, "little"))
(root / "AUDIO.RAW").write_bytes(pcm)
PY

run_rars_add() {
  cargo run -p rars-cli --quiet -- a "$@"
}

for level in 1 3 5; do
  run_rars_add --format rar20 --level "$level" "$tmpdir/T$level.RAR" "$tmpdir/TEXT.TXT"
  run_rars_add --format rar20 --level "$level" "$tmpdir/R$level.RAR" "$tmpdir/REPEAT.BIN"
  run_rars_add --format rar20 --level "$level" "$tmpdir/B$level.RAR" "$tmpdir/BINARY.BIN"
  run_rars_add --format rar20 --level "$level" "$tmpdir/A$level.RAR" "$tmpdir/AUDIO.RAW"
done

run_dos_unrar() {
  local archive_name=$1
  local output_name=$2
  dosbox-x -silent -exit -time-limit 20 \
    -c "mount c $tmpdir" \
    -c 'c:' \
    -c "unrar t $archive_name > $output_name" \
    -c 'exit' >/dev/null 2>&1
  if ! grep -q 'All OK' "$tmpdir/$output_name"; then
    echo "DOS UnRAR 2.50 rejected $archive_name:" >&2
    cat "$tmpdir/$output_name" >&2
    return 1
  fi
}

index=0
for archive in "$tmpdir"/*.RAR; do
  printf -v output_name 'O%03d.TXT' "$index"
  run_dos_unrar "$(basename "$archive")" "$output_name"
  index=$((index + 1))
done

echo
echo "RAR20 generated writer reference checks passed."

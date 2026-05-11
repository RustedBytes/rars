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
require_command python3
require_command wine

if [[ -z "${RARS_WINRAR290_PREFIX:-}" || -z "${RARS_WINRAR300_PREFIX:-}" || -z "${RARS_WINRAR420_PREFIX:-}" ]]; then
  cat >&2 <<'EOF'
missing reference Wine prefix

Set RARS_WINRAR290_PREFIX, RARS_WINRAR300_PREFIX, and
RARS_WINRAR420_PREFIX before running this script. Set RARS_UNRAR290,
RARS_UNRAR300, or RARS_UNRAR420 as well if UnRAR.exe is not in the
standard Wine install path.
EOF
  exit 1
fi

winrar290_prefix="$RARS_WINRAR290_PREFIX"
winrar300_prefix="$RARS_WINRAR300_PREFIX"
winrar420_prefix="$RARS_WINRAR420_PREFIX"
unrar290="${RARS_UNRAR290:-$winrar290_prefix/drive_c/Program Files (x86)/WinRAR/UnRAR.exe}"
unrar300="${RARS_UNRAR300:-$winrar300_prefix/drive_c/Program Files (x86)/WinRAR/UnRAR.exe}"
unrar420="${RARS_UNRAR420:-$winrar420_prefix/drive_c/Program Files (x86)/WinRAR/UnRAR.exe}"

for tool in "$unrar290" "$unrar300" "$unrar420"; do
  if [[ ! -f "$tool" ]]; then
    cat >&2 <<EOF
missing reference tool: $tool

Set the matching RARS_UNRAR290, RARS_UNRAR300, or RARS_UNRAR420
variable if UnRAR.exe is not in the standard Wine install path.
EOF
    exit 1
  fi
done

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/rars-rar29-level-ref.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

python3 - "$tmpdir" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
(root / "text.txt").write_bytes(
    b'fn repeated_identifier_name() { println!("RAR29 level oracle text"); }\n' * 2048
)

x86 = bytearray(b"RAR29 level oracle x86 payload\n" * 1024)
for base in range(4096, len(x86) - 128, 8192):
    for index in range(12):
        pos = base + index * 32
        x86[pos] = 0xE8
        x86[pos + 1 : pos + 5] = (0x2000 + index * 17).to_bytes(4, "little")
(root / "x86.bin").write_bytes(x86)

state = 0x12345678
binary = bytearray()
for _ in range(64 * 1024):
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= state >> 17
    state ^= (state << 5) & 0xFFFFFFFF
    binary.append(state & 0xFF)
(root / "binary.bin").write_bytes(binary)
PY

run_rars_add() {
  cargo run -p rars-cli --quiet -- a "$@"
}

for level in 1 2 3 4; do
  run_rars_add --format rar29 --level "$level" "$tmpdir/text-m$level.rar" "$tmpdir/text.txt"
  run_rars_add --format rar29 --level "$level" "$tmpdir/x86-m$level.rar" "$tmpdir/x86.bin"
  run_rars_add --format rar29 --level "$level" "$tmpdir/binary-m$level.rar" "$tmpdir/binary.bin"
done

wine_z_path() {
  local path=$1
  printf 'Z:%s' "${path//\//\\}"
}

run_unrar() {
  local prefix=$1
  local unrar=$2
  local archive=$3
  env WINEPREFIX="$prefix" wine "$unrar" t "$(wine_z_path "$archive")"
}

for archive in "$tmpdir"/*.rar; do
  run_unrar "$winrar290_prefix" "$unrar290" "$archive"
  run_unrar "$winrar300_prefix" "$unrar300" "$archive"
  run_unrar "$winrar420_prefix" "$unrar420" "$archive"
done

echo
echo "RAR29 level 1-4 generated writer reference checks passed."

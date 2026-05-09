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

if [[ -z "${RARS_WINRAR420_PREFIX:-}" ]]; then
  cat >&2 <<'EOF'
missing RARS_WINRAR420_PREFIX

Set RARS_WINRAR420_PREFIX to the WinRAR/UnRAR 4.20 Wine prefix before
running this script. Set RARS_UNRAR420 as well if UnRAR.exe is not in the
standard Wine install path.
EOF
  exit 1
fi

winrar420_prefix="$RARS_WINRAR420_PREFIX"
rar420="${RARS_RAR420:-$winrar420_prefix/drive_c/Program Files (x86)/WinRAR/Rar.exe}"
unrar420="${RARS_UNRAR420:-$winrar420_prefix/drive_c/Program Files (x86)/WinRAR/UnRAR.exe}"

if [[ ! -f "$rar420" ]]; then
  cat >&2 <<EOF
missing reference tool: $rar420

Set RARS_RAR420 to the RAR 4.20 executable if it is not in the
standard Wine install path.
EOF
    exit 1
fi
if [[ ! -f "$unrar420" ]]; then
  cat >&2 <<EOF
missing reference tool: $unrar420

Set RARS_UNRAR420 to the UnRAR 4.20 executable if it is not in the
standard Wine install path.
EOF
    exit 1
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/rars-rar3-aes-ref.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

payload="$tmpdir/payload.txt"
filtered_payload="$tmpdir/filtered-payload.bin"
volume_payload="$tmpdir/volume-payload.bin"
solid_one="$tmpdir/solid-one.txt"
solid_two="$tmpdir/solid-two.txt"
long_password_payload="$tmpdir/long-password-payload.txt"
printf 'RAR3 AES generated writer reference payload\n%.0s' {1..10} >"$payload"
printf 'RAR3 AES long password reference payload\n%.0s' {1..4} >"$long_password_payload"
python3 - "$filtered_payload" <<'PY'
from pathlib import Path
import sys

Path(sys.argv[1]).write_bytes((b"\xe8\0\0\0\0RAR29 encrypted E8 filtered payload\n") * 12)
PY
printf 'RAR3 AES solid generated writer shared phrase alpha beta gamma\n%.0s' {1..8} >"$solid_one"
printf 'RAR3 AES solid generated writer shared phrase alpha beta gamma\nsecond\n%.0s' {1..5} >"$solid_two"
python3 - "$volume_payload" <<'PY'
from pathlib import Path
import sys

Path(sys.argv[1]).write_bytes(bytes((i * 73 + i // 3 + 41) & 0xff for i in range(4096)))
PY

run_rars_add() {
  cargo run -p rars-cli --quiet -- a "$@"
}

run_rars_add --password pass --format rar29 "$tmpdir/rar29-encrypted.rar" "$payload"
run_rars_add --password pass --format rar29 --e8-filter \
  "$tmpdir/rar29-encrypted-e8-filtered.rar" "$filtered_payload"
run_rars_add --password pass --format rar30 "$tmpdir/rar30-encrypted.rar" "$payload"
run_rars_add --password pass --format rar40 "$tmpdir/rar40-encrypted.rar" "$payload"
run_rars_add --password pass --format rar30 --volume-size 96 \
  "$tmpdir/rar30-encrypted-volume.rar" "$volume_payload"
run_rars_add --password pass --format rar40 --volume-size 96 \
  "$tmpdir/rar40-encrypted-volume.rar" "$volume_payload"
run_rars_add --password pass --format rar30 --encrypt-headers \
  "$tmpdir/rar30-header-encrypted.rar" "$payload"
run_rars_add --password pass --format rar30 --encrypt-headers --e8-filter \
  "$tmpdir/rar30-header-encrypted-e8-filtered.rar" "$filtered_payload"
run_rars_add --password pass --format rar40 --encrypt-headers \
  "$tmpdir/rar40-header-encrypted.rar" "$payload"
run_rars_add --password pass --format rar30 --encrypt-headers --volume-size 112 \
  "$tmpdir/rar30-header-encrypted-volume.rar" "$volume_payload"
run_rars_add --password pass --format rar40 --encrypt-headers --volume-size 112 \
  "$tmpdir/rar40-header-encrypted-volume.rar" "$volume_payload"
run_rars_add --password pass --format rar30 --solid --encrypt-headers \
  "$tmpdir/rar30-solid-header-encrypted.rar" "$solid_one" "$solid_two"
run_rars_add --password pass --format rar40 --solid --encrypt-headers \
  "$tmpdir/rar40-solid-header-encrypted.rar" "$solid_one" "$solid_two"

run_unrar() {
  local archive=$1
  local wine_archive
  wine_archive="$(wine_z_path "$archive")"
  env WINEPREFIX="$winrar420_prefix" wine "$unrar420" t -ppass "$wine_archive"
}

wine_z_path() {
  local path=$1
  printf 'Z:%s' "${path//\//\\}"
}

for archive in \
  "$tmpdir/rar29-encrypted.rar" \
  "$tmpdir/rar29-encrypted-e8-filtered.rar" \
  "$tmpdir/rar30-encrypted.rar" \
  "$tmpdir/rar40-encrypted.rar" \
  "$tmpdir/rar30-encrypted-volume.rar" \
  "$tmpdir/rar40-encrypted-volume.rar" \
  "$tmpdir/rar30-header-encrypted.rar" \
  "$tmpdir/rar30-header-encrypted-e8-filtered.rar" \
  "$tmpdir/rar40-header-encrypted.rar" \
  "$tmpdir/rar30-header-encrypted-volume.rar" \
  "$tmpdir/rar40-header-encrypted-volume.rar" \
  "$tmpdir/rar30-solid-header-encrypted.rar" \
  "$tmpdir/rar40-solid-header-encrypted.rar"
do
  run_unrar "$archive"
done

long_password='this-password-is-deliberately-long-enough-to-exceed-64-bytes-utf16'

run_winrar_add() {
  local mode=$1
  local archive=$2
  local input=$3
  local wine_archive wine_input
  wine_archive="$(wine_z_path "$archive")"
  wine_input="$(wine_z_path "$input")"
  case "$mode" in
    file)
      env WINEPREFIX="$winrar420_prefix" wine "$rar420" a -ep -m0 "-p$long_password" "$wine_archive" "$wine_input"
      ;;
    header)
      env WINEPREFIX="$winrar420_prefix" wine "$rar420" a -ep -m0 "-hp$long_password" "$wine_archive" "$wine_input"
      ;;
    *)
      echo "unknown WinRAR add mode: $mode" >&2
      exit 1
      ;;
  esac
}

run_rars_test() {
  cargo run -p rars-cli --quiet -- test --password "$long_password" "$1"
}

run_winrar_add file "$tmpdir/winrar420-long-password-file.rar" "$long_password_payload"
run_winrar_add header "$tmpdir/winrar420-long-password-header.rar" "$long_password_payload"
run_rars_test "$tmpdir/winrar420-long-password-file.rar"
run_rars_test "$tmpdir/winrar420-long-password-header.rar"

echo
echo "RAR3/RAR4 AES generated writer reference checks passed."
echo "RAR3/RAR4 AES long-password reader reference checks passed."

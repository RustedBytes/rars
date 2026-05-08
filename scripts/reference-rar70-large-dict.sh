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
require_command mkdir
require_command rar
require_command truncate

tmpdir="${TMPDIR:-/tmp}/rars-unpack70-fixture"
mkdir -p "$tmpdir"

payload="$tmpdir/sparse-4500m.bin"
archive="$tmpdir/sparse-4500m-md5g.rar"

truncate -s 4500M "$payload"
rar a -m5 -md5g -ep -idq -y "$archive" "$payload"

rar vt "$archive"
cargo run -p rars-cli --quiet -- test "$archive"

cat <<EOF

external fixture: $archive

The archive is intentionally not committed. It is a small RAR 7 / Unpack70
archive with a sparse 4.5 GiB all-zero member and a declared 4608 MiB
dictionary.
EOF

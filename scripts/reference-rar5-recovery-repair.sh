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
require_command cp
require_command python3
require_command rar

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/rars-rar5-repair.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

payload="$tmpdir/payload.txt"
python3 -c 'import sys
phrase = b"RAR5 recovery repair oracle payload %06d\n"
for index in range(8192):
    sys.stdout.buffer.write(phrase % index)' >"$payload"
password="1234"

rar a -ma5 -m0 -rr20 "$tmpdir/official.rar" "$payload" >/dev/null
cargo run -p rars-cli --quiet -- a --format rar50 --store --recovery-percent 20 \
  "$tmpdir/rars.rar" "$payload"
rar a -ma5 -m0 -p"$password" -rr20 "$tmpdir/official-encrypted.rar" "$payload" >/dev/null
cargo run -p rars-cli --quiet -- a --format rar50 --store --password "$password" \
  --recovery-percent 20 "$tmpdir/rars-encrypted.rar" "$payload"

damage_archive() {
  local src=$1
  local dst=$2
  cp "$src" "$dst"
  python3 -c 'import sys
p=sys.argv[1]
needle=b"RAR5 recovery repair oracle payload"
data=bytearray(open(p,"rb").read())
off=data.index(needle)
data[off+10] ^= 0x55
data[off+4096] ^= 0xa3
open(p,"wb").write(data)
print(off+10, off+4096)' "$dst" >"$dst.damage-offset"
}

damage_archive "$tmpdir/official.rar" "$tmpdir/damaged-official.rar"
damage_archive "$tmpdir/rars.rar" "$tmpdir/damaged-rars.rar"

damage_first_file_payload() {
  local src=$1
  local dst=$2
  cp "$src" "$dst"
  python3 -c 'import sys
path=sys.argv[1]
data=bytearray(open(path,"rb").read())
sig=b"Rar!\x1a\x07\x01\x00"
pos=data.index(sig)+len(sig)

def vint(at, end):
    value=0
    for i in range(10):
        if at+i >= end:
            raise SystemExit("truncated vint")
        b=data[at+i]
        value |= (b & 0x7f) << (7*i)
        if b < 0x80:
            return value, i+1
    raise SystemExit("overlong vint")

while pos < len(data):
    if pos + 5 > len(data):
        raise SystemExit("truncated block header")
    header_size, size_len = vint(pos+4, len(data))
    header_total = 4 + size_len + header_size
    header_end = pos + header_total
    p = pos + 4 + size_len
    block_type, used = vint(p, header_end); p += used
    flags, used = vint(p, header_end); p += used
    if flags & 1:
        _extra, used = vint(p, header_end); p += used
    data_size = 0
    if flags & 2:
        data_size, used = vint(p, header_end); p += used
    data_start = header_end
    data_end = data_start + data_size
    if block_type == 2 and data_size:
        off = data_start + min(16, data_size - 1)
        off2 = data_start + min(4096, data_size - 1)
        data[off] ^= 0x55
        data[off2] ^= 0xa3
        open(path,"wb").write(data)
        print(off, off2)
        raise SystemExit(0)
    pos = data_end
raise SystemExit("no file payload found")' "$dst" >"$dst.damage-offset"
}

damage_first_file_payload "$tmpdir/official-encrypted.rar" "$tmpdir/damaged-official-encrypted.rar"
damage_first_file_payload "$tmpdir/rars-encrypted.rar" "$tmpdir/damaged-rars-encrypted.rar"

(cd "$tmpdir" && rar r -y damaged-official.rar > official-repair.log 2>&1)
if ! rar t "$tmpdir/fixed.damaged-official.rar" >"$tmpdir/official-fixed-test.log" 2>&1; then
  echo "RAR-authored recovery archive did not produce a valid repaired archive" >&2
  cat "$tmpdir/official-repair.log" >&2
  cat "$tmpdir/official-fixed-test.log" >&2
  exit 1
fi

(cd "$tmpdir" && rar r -y damaged-rars.rar > rars-repair.log 2>&1 || true)
if ! rar t "$tmpdir/fixed.damaged-rars.rar" >"$tmpdir/rars-fixed-test.log" 2>&1; then
  echo "rars recovery archive did not produce a valid repaired archive" >&2
  cat "$tmpdir/rars-repair.log" >&2
  cat "$tmpdir/rars-fixed-test.log" >&2
  exit 1
fi

(cd "$tmpdir" && rar r -y damaged-official-encrypted.rar > official-encrypted-repair.log 2>&1)
if ! rar t -p"$password" "$tmpdir/fixed.damaged-official-encrypted.rar" \
  >"$tmpdir/official-encrypted-fixed-test.log" 2>&1; then
  echo "RAR-authored encrypted recovery archive did not produce a valid repaired archive" >&2
  cat "$tmpdir/official-encrypted-repair.log" >&2
  cat "$tmpdir/official-encrypted-fixed-test.log" >&2
  exit 1
fi

(cd "$tmpdir" && rar r -y damaged-rars-encrypted.rar > rars-encrypted-repair.log 2>&1 || true)
if ! rar t -p"$password" "$tmpdir/fixed.damaged-rars-encrypted.rar" \
  >"$tmpdir/rars-encrypted-fixed-test.log" 2>&1; then
  echo "rars encrypted recovery archive did not produce a valid repaired archive" >&2
  cat "$tmpdir/rars-encrypted-repair.log" >&2
  cat "$tmpdir/rars-encrypted-fixed-test.log" >&2
  exit 1
fi

echo
echo "RAR5 recovery repair reference check passed."
echo "RAR-authored and rars-authored archives both repair stored and encrypted stored payload damage spanning multiple recovery shards."

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
require_command find
require_command rustc
require_command rustup
require_command tee

host="$(rustc -vV | sed -n 's/^host: //p')"
sysroot="$(rustc --print sysroot)"
llvm_tools="$sysroot/lib/rustlib/$host/bin"
llvm_profdata="$llvm_tools/llvm-profdata"
llvm_cov="$llvm_tools/llvm-cov"

if [[ ! -x "$llvm_profdata" || ! -x "$llvm_cov" ]]; then
  cat >&2 <<'EOF'
missing llvm coverage tools

Install them with:
  rustup component add llvm-tools-preview
EOF
  exit 1
fi

coverage_dir="$root/target/coverage"
profraw_dir="$coverage_dir/profraw"
profdata="$coverage_dir/coverage.profdata"

rm -rf "$coverage_dir"
mkdir -p "$profraw_dir"

export CARGO_TARGET_DIR="$coverage_dir"
export RUSTFLAGS="${RUSTFLAGS:-} -Cinstrument-coverage"
export LLVM_PROFILE_FILE="$profraw_dir/%p-%m.profraw"

test_status=0
cargo test --workspace --all-targets --no-fail-fast || test_status=$?

shopt -s nullglob
profraw_files=("$profraw_dir"/*.profraw)
shopt -u nullglob

if [[ "${#profraw_files[@]}" -eq 0 ]]; then
  echo "no coverage profiles were produced" >&2
  exit "$test_status"
fi

"$llvm_profdata" merge -sparse "${profraw_files[@]}" -o "$profdata"

mapfile -t object_files < <(
  find "$coverage_dir/debug/deps" -maxdepth 1 -type f -executable \
    ! -name '*.d' \
    ! -name '*.rlib' \
    ! -name '*.rmeta' \
    | sort
)
production_binary="$coverage_dir/debug/rars"
if [[ -x "$production_binary" ]]; then
  object_files+=("$production_binary")
fi

if [[ "${#object_files[@]}" -eq 0 ]]; then
  echo "no coverage objects found" >&2
  exit 1
fi

object_args=("${object_files[0]}")
for object in "${object_files[@]:1}"; do
  object_args+=("--object" "$object")
done

ignore_regex='/.cargo/registry|/rustc/|/tests/'

detail="$("$llvm_cov" report \
  --ignore-filename-regex="$ignore_regex" \
  --instr-profile="$profdata" \
  "${object_args[@]}" 2>&1)"

{
  echo "Coverage by crate"
  printf '%-16s  %14s  %8s  %14s  %8s  %14s  %8s\n' \
    "Crate" "Regions" "Region%" "Lines" "Line%" "Functions" "Func%"
  echo "----------------------------------------------------------------------------------------------"
  awk '
    /^[A-Za-z]/ && $1 ~ /\// {
      split($1, parts, "/")
      crate = parts[1]
      regions[crate]   += $2
      missed_r[crate]  += $3
      funcs[crate]     += $5
      missed_f[crate]  += $6
      lines[crate]     += $8
      missed_l[crate]  += $9
      seen[crate] = 1
    }
    END {
      n = 0
      for (c in seen) names[++n] = c
      # sort by name
      for (i = 1; i <= n; i++)
        for (j = i + 1; j <= n; j++)
          if (names[i] > names[j]) { t = names[i]; names[i] = names[j]; names[j] = t }
      for (i = 1; i <= n; i++) {
        c = names[i]
        cr = regions[c] - missed_r[c]
        cl = lines[c]   - missed_l[c]
        cf = funcs[c]   - missed_f[c]
        rp = regions[c] ? (cr * 100.0 / regions[c]) : 0
        lp = lines[c]   ? (cl * 100.0 / lines[c])   : 0
        fp = funcs[c]   ? (cf * 100.0 / funcs[c])   : 0
        printf "%-16s  %14s  %7.2f%%  %14s  %7.2f%%  %14s  %7.2f%%\n", \
          c, cr"/"regions[c], rp, cl"/"lines[c], lp, cf"/"funcs[c], fp
      }
    }
  ' <<<"$detail"
  echo
  echo "Per-file detail"
  echo "$detail"
} | tee "$coverage_dir/summary.txt"

"$llvm_cov" show \
  --format=html \
  --ignore-filename-regex="$ignore_regex" \
  --instr-profile="$profdata" \
  --output-dir="$coverage_dir/html" \
  "${object_args[@]}"

echo
echo "Text summary: $coverage_dir/summary.txt"
echo "HTML report:  $coverage_dir/html/index.html"

exit "$test_status"

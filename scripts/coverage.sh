#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

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

cargo test --workspace --all-targets

"$llvm_profdata" merge -sparse "$profraw_dir"/*.profraw -o "$profdata"

mapfile -t library_objects < <(
  find "$coverage_dir/debug/deps" -maxdepth 1 -type f -executable \
    ! -name '*.d' \
    ! -name '*.rlib' \
    ! -name '*.rmeta' \
    ! -name 'cli-*' \
    ! -name 'rars-[0-9a-f]*' \
    | sort
)
cli_object="$coverage_dir/debug/rars"

if [[ "${#library_objects[@]}" -eq 0 || ! -x "$cli_object" ]]; then
  echo "coverage objects not found" >&2
  exit 1
fi

coverage_object_args() {
  local -n input_objects=$1
  local -n output_args=$2

  output_args=("${input_objects[0]}")
  for object in "${input_objects[@]:1}"; do
    output_args+=("--object" "$object")
  done
}

coverage_object_args library_objects library_args

{
  echo "Library coverage"
  "$llvm_cov" report \
    --ignore-filename-regex='/.cargo/registry|/rustc/|/tests/' \
    --instr-profile="$profdata" \
    "${library_args[@]}"
  echo
  echo "CLI coverage"
  "$llvm_cov" report \
    --ignore-filename-regex='/.cargo/registry|/rustc/|/tests/' \
    --instr-profile="$profdata" \
    "$cli_object"
} | tee "$coverage_dir/summary.txt"

"$llvm_cov" show \
  --format=html \
  --ignore-filename-regex='/.cargo/registry|/rustc/|/tests/' \
  --instr-profile="$profdata" \
  --output-dir="$coverage_dir/html/library" \
  "${library_args[@]}"

"$llvm_cov" show \
  --format=html \
  --ignore-filename-regex='/.cargo/registry|/rustc/|/tests/' \
  --instr-profile="$profdata" \
  --output-dir="$coverage_dir/html/cli" \
  "$cli_object"

echo
echo "Text summary: $coverage_dir/summary.txt"
echo "Library HTML report: $coverage_dir/html/library/index.html"
echo "CLI HTML report: $coverage_dir/html/cli/index.html"

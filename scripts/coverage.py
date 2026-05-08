#!/usr/bin/env python3
"""Run workspace coverage and report production-only numbers.

Replaces the older coverage.sh. Same workflow (cargo test with
-Cinstrument-coverage, profile merge, llvm-cov for HTML), but the per-crate
and per-file summary is computed from the JSON export with inline
`#[cfg(test)] mod tests` blocks excluded — i.e. demangled symbols whose
path contains `::tests::` are dropped before aggregation.

Region/line/function totals are taken from llvm-cov's per-file summary and
reduced by the test-mod contribution. Covered counts are aggregated from
function-level region data, which can drift from llvm-cov's display by
roughly 1% because the underlying aggregation rules differ; absolute totals
match exactly.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES_PREFIX = str(ROOT / "crates") + "/"
IGNORE_REGEX = "/.cargo/registry|/rustc/|/tests/"


def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)


def require(cmd: str) -> None:
    if shutil.which(cmd) is None:
        die(f"missing required command: {cmd}")


def llvm_tool_paths() -> tuple[Path, Path]:
    host = ""
    for line in subprocess.check_output(["rustc", "-vV"], text=True).splitlines():
        if line.startswith("host: "):
            host = line[len("host: "):].strip()
            break
    if not host:
        die("could not determine rustc host triple")
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    bindir = sysroot / "lib" / "rustlib" / host / "bin"
    profdata = bindir / "llvm-profdata"
    cov = bindir / "llvm-cov"
    if not profdata.is_file() or not cov.is_file():
        die("missing llvm coverage tools\n\nInstall them with:\n  rustup component add llvm-tools-preview")
    return profdata, cov


def collect_objects(coverage_dir: Path) -> list[Path]:
    deps = coverage_dir / "debug" / "deps"
    objects: list[Path] = []
    if deps.is_dir():
        for entry in sorted(deps.iterdir()):
            if not entry.is_file():
                continue
            if entry.suffix in (".d", ".rlib", ".rmeta"):
                continue
            if not os.access(entry, os.X_OK):
                continue
            objects.append(entry)
    production = coverage_dir / "debug" / "rars"
    if production.is_file() and os.access(production, os.X_OK):
        objects.append(production)
    return objects


def object_args(objects: list[Path]) -> list[str]:
    if not objects:
        return []
    args = [str(objects[0])]
    for obj in objects[1:]:
        args += ["--object", str(obj)]
    return args


def demangle(names: list[str]) -> list[str]:
    if not names:
        return []
    if shutil.which("rustfilt") is None:
        die("missing required command: rustfilt\n\nInstall it with:\n  cargo install rustfilt")
    proc = subprocess.run(
        ["rustfilt"],
        input="\n".join(names),
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.splitlines()


def is_test_symbol(demangled: str) -> bool:
    # Inline #[cfg(test)] mod tests blocks render as "::tests::" in demangled paths.
    # Catch helper functions inside that mod (e.g. block_header_with) too.
    return "::tests::" in demangled


def relative_to_crates(path: str) -> str:
    if path.startswith(CRATES_PREFIX):
        return path[len(CRATES_PREFIX):]
    return path


def aggregate(data: dict, name_map: dict[str, str]) -> dict[str, dict]:
    """Return per-file stats with both raw and production-only totals.

    Each file entry contains:
        regions / lines / funcs        — total / covered (raw, from llvm-cov)
        prod_regions / prod_lines / prod_funcs — test-mod stripped

    A line is considered "test-only" if every region of every function that
    spans it sits in a test mod. Test-only lines are subtracted from the file
    totals; lines also touched by production code stay on the production side.
    """
    files: dict[str, dict] = {}
    for f in data["files"]:
        s = f["summary"]
        files[f["filename"]] = {
            "regions_total": s["regions"]["count"],
            "regions_covered": s["regions"]["covered"],
            "lines_total": s["lines"]["count"],
            "lines_covered": s["lines"]["covered"],
            "funcs_total": s["functions"]["count"],
            "funcs_covered": s["functions"]["covered"],
            "test_regions": {},  # (l1, c1, l2, c2) -> max count
            "test_funcs": {},  # (start_line, start_col) -> covered bool
            "line_test": defaultdict(int),  # line -> non-test region count
            "line_prod": defaultdict(int),
            "line_test_covered": defaultdict(int),  # max count contributed by test regions
            "line_prod_covered": defaultdict(int),
        }

    for fn in data["functions"]:
        if not fn["regions"]:
            continue
        is_test = is_test_symbol(name_map[fn["name"]])
        for r in fn["regions"]:
            l1, c1, l2, c2, count, file_id, _expanded, _kind = r
            fname = fn["filenames"][file_id]
            entry = files.get(fname)
            if entry is None:
                continue
            if is_test:
                key = (l1, c1, l2, c2)
                cur = entry["test_regions"].get(key, 0)
                if count > cur:
                    entry["test_regions"][key] = count
            for line in range(l1, l2 + 1):
                if is_test:
                    entry["line_test"][line] += 1
                    if count > entry["line_test_covered"][line]:
                        entry["line_test_covered"][line] = count
                else:
                    entry["line_prod"][line] += 1
                    if count > entry["line_prod_covered"][line]:
                        entry["line_prod_covered"][line] = count

        if is_test:
            first = next((r for r in fn["regions"] if fn["filenames"][r[5]] in files), None)
            if first is not None:
                fname = fn["filenames"][first[5]]
                entry = files[fname]
                fkey = (first[0], first[1])
                prev = entry["test_funcs"].get(fkey, False)
                entry["test_funcs"][fkey] = prev or fn["count"] > 0

    out: dict[str, dict] = {}
    for fname, e in files.items():
        test_regions_total = len(e["test_regions"])
        test_regions_covered = sum(1 for c in e["test_regions"].values() if c > 0)
        test_funcs_total = len(e["test_funcs"])
        test_funcs_covered = sum(1 for v in e["test_funcs"].values() if v)

        # Lines exclusive to test mods: touched by test regions but not production.
        test_only_lines = set(e["line_test"]) - set(e["line_prod"])
        test_only_covered = sum(
            1 for line in test_only_lines if e["line_test_covered"][line] > 0
        )

        out[fname] = {
            "regions_total": e["regions_total"],
            "regions_covered": e["regions_covered"],
            "lines_total": e["lines_total"],
            "lines_covered": e["lines_covered"],
            "funcs_total": e["funcs_total"],
            "funcs_covered": e["funcs_covered"],
            "prod_regions_total": max(0, e["regions_total"] - test_regions_total),
            "prod_regions_covered": max(0, e["regions_covered"] - test_regions_covered),
            "prod_lines_total": max(0, e["lines_total"] - len(test_only_lines)),
            "prod_lines_covered": max(0, e["lines_covered"] - test_only_covered),
            "prod_funcs_total": max(0, e["funcs_total"] - test_funcs_total),
            "prod_funcs_covered": max(0, e["funcs_covered"] - test_funcs_covered),
        }
    return out


def crate_of(rel_path: str) -> str:
    return rel_path.split("/", 1)[0]


def fmt_ratio(covered: int, total: int) -> tuple[str, str]:
    pct = f"{covered * 100.0 / total:6.2f}%" if total else "     -"
    return (f"{covered}/{total}", pct)


def render(stats: dict[str, dict], filtered: bool) -> str:
    rows: list[tuple[str, int, int, int, int, int, int]] = []
    crate_totals: dict[str, dict] = defaultdict(lambda: {
        "rt": 0, "rc": 0, "lt": 0, "lc": 0, "ft": 0, "fc": 0,
    })

    pfx = "prod_" if filtered else ""
    keys = (
        f"{pfx}regions_total", f"{pfx}regions_covered",
        f"{pfx}lines_total", f"{pfx}lines_covered",
        f"{pfx}funcs_total", f"{pfx}funcs_covered",
    )

    for fname in sorted(stats):
        if not fname.startswith(CRATES_PREFIX):
            continue
        rel = relative_to_crates(fname)
        s = stats[fname]
        rt, rc, lt, lc, ft, fc = (s[k] for k in keys)
        rows.append((rel, rt, rc, lt, lc, ft, fc))
        c = crate_totals[crate_of(rel)]
        c["rt"] += rt; c["rc"] += rc
        c["lt"] += lt; c["lc"] += lc
        c["ft"] += ft; c["fc"] += fc

    crate_total = {
        "rt": sum(c["rt"] for c in crate_totals.values()),
        "rc": sum(c["rc"] for c in crate_totals.values()),
        "lt": sum(c["lt"] for c in crate_totals.values()),
        "lc": sum(c["lc"] for c in crate_totals.values()),
        "ft": sum(c["ft"] for c in crate_totals.values()),
        "fc": sum(c["fc"] for c in crate_totals.values()),
    }

    def line(name: str, name_w: int, rc: int, rt: int, lc: int, lt: int, fc: int, ft: int) -> str:
        rg, rp = fmt_ratio(rc, rt)
        lg, lp = fmt_ratio(lc, lt)
        fg, fp = fmt_ratio(fc, ft)
        return f"{name:<{name_w}}  {rg:>13} {rp:>8}  {lg:>13} {lp:>8}  {fg:>11} {fp:>8}"

    def header(name: str, name_w: int) -> list[str]:
        head = (
            f"{name:<{name_w}}  {'Regions':>13} {'Region%':>8}  "
            f"{'Lines':>13} {'Line%':>8}  {'Functions':>11} {'Func%':>8}"
        )
        return [head, "-" * len(head)]

    label = "production code only" if filtered else "all code, including inline tests"
    out = [f"Coverage by crate ({label})"]
    out.extend(header("Crate", 16))
    for crate in sorted(crate_totals):
        c = crate_totals[crate]
        out.append(line(crate, 16, c["rc"], c["rt"], c["lc"], c["lt"], c["fc"], c["ft"]))
    out.append("-" * len(out[1]))
    out.append(line("TOTAL", 16, crate_total["rc"], crate_total["rt"],
                    crate_total["lc"], crate_total["lt"],
                    crate_total["fc"], crate_total["ft"]))
    out.append("")
    out.append("Per-file detail")
    out.extend(header("File", 48))
    for rel, rt, rc, lt, lc, ft, fc in rows:
        out.append(line(rel, 48, rc, rt, lc, lt, fc, ft))
    out.append("-" * len(out[-1]))
    out.append(line("TOTAL", 48, crate_total["rc"], crate_total["rt"],
                    crate_total["lc"], crate_total["lt"],
                    crate_total["fc"], crate_total["ft"]))
    return "\n".join(out)


def main() -> int:
    require("cargo")
    require("rustc")

    profdata_tool, cov_tool = llvm_tool_paths()

    coverage_dir = ROOT / "target" / "coverage"
    profraw_dir = coverage_dir / "profraw"
    profdata = coverage_dir / "coverage.profdata"

    if coverage_dir.exists():
        shutil.rmtree(coverage_dir)
    profraw_dir.mkdir(parents=True)

    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(coverage_dir)
    rustflags = env.get("RUSTFLAGS", "")
    env["RUSTFLAGS"] = f"{rustflags} -Cinstrument-coverage".strip()
    env["LLVM_PROFILE_FILE"] = str(profraw_dir / "%p-%m.profraw")

    test_status = subprocess.call(
        ["cargo", "test", "--workspace", "--all-targets", "--no-fail-fast"],
        cwd=ROOT,
        env=env,
    )

    profraw_files = sorted(profraw_dir.glob("*.profraw"))
    if not profraw_files:
        die("no coverage profiles were produced", test_status or 1)

    subprocess.run(
        [str(profdata_tool), "merge", "-sparse", *map(str, profraw_files), "-o", str(profdata)],
        check=True,
    )

    objects = collect_objects(coverage_dir)
    if not objects:
        die("no coverage objects found")
    obj_args = object_args(objects)

    json_blob = subprocess.check_output(
        [str(cov_tool), "export",
         "--instr-profile", str(profdata),
         "--ignore-filename-regex", IGNORE_REGEX,
         *obj_args],
    )
    data = json.loads(json_blob)["data"][0]

    name_map = dict(zip(
        [fn["name"] for fn in data["functions"]],
        demangle([fn["name"] for fn in data["functions"]]),
    ))

    stats = aggregate(data, name_map)

    summary_path = coverage_dir / "summary.txt"
    filtered = render(stats, filtered=True)
    raw = render(stats, filtered=False)
    text = filtered + "\n\n" + raw + "\n"
    summary_path.write_text(text)
    print(text)

    # HTML stays unfiltered (matches llvm-cov's view of every counter).
    subprocess.run(
        [str(cov_tool), "show",
         "--format=html",
         "--ignore-filename-regex", IGNORE_REGEX,
         "--instr-profile", str(profdata),
         "--output-dir", str(coverage_dir / "html"),
         *obj_args],
        check=True,
    )

    print()
    print(f"Text summary: {summary_path}")
    print(f"HTML report:  {coverage_dir / 'html' / 'index.html'}")

    return test_status


if __name__ == "__main__":
    sys.exit(main())

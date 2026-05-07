# rars

A Rust implementation of RAR.

## Current Status

`rars` covers the RAR lineage from early `RE~^` archives through RAR 7:

- auto-detect archive families, including SFX-prefixed archives;
- parse RAR 1.3/1.4, RAR 1.5-4.x, RAR 5.0, and RAR 7.x headers;
- stream extraction through callback writers instead of buffering full archives;
- decode historical LZ codecs, RAR 2.9/RAR 3.x PPMd, RARVM filters, solid
  archives, encrypted members, comments, and split volumes;
- write selectable RAR versions with stored and compressed members, encryption,
  comments, RARVM filters, solid mode, volumes, and RAR5 recovery records;
- repair supported RAR 2.x/3.x recovery records and RAR5 inline/REV recovery
  data.

Some advanced compatibility targets remain active research areas: compression
policy parity with WinRAR, full historical AV verification, SFX writer/stub
generation, and external oracle maintenance.

## CLI

Inspect, test, and extract archives:

```sh
rars info archive.rar
rars test archive.rar
rars x archive.rar out/
```

Create archives by selecting the target RAR generation explicitly:

```sh
rars a --format rar29 archive.rar files...
rars a --format rar50 --solid --auto-filter archive.rar files...
rars a --format rar70 --store --volume-size 10m archive.part1.rar files...
```

The writer supports stored and compressed members, split volumes, passwords,
header encryption where implemented, comments, RARVM filters, RAR5 quick-open
records, and supported recovery records. Run `rars --help` for the exact option
set.

## Development

Run the test suite:

```sh
cargo test --workspace --all-targets
```

Generate a local coverage report:

```sh
rustup component add llvm-tools-preview
./scripts/coverage.sh
```

The script prints a line-coverage summary, saves it to
`target/coverage/summary.txt`, and writes HTML output to
`target/coverage/html/library/index.html` and `target/coverage/html/cli/index.html`.

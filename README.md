# rars

A Rust implementation of RAR.

## Current Status

The first supported vertical slice is RAR 1.3/1.4 archives:

- detect `RE~^` archives, including SFX-prefixed archives;
- parse main/file headers, directory entries, comments extensions, and
  old-style volume flags;
- extract stored files, including the historical 3-byte password cipher;
- extract Unpack15 compressed files, including encrypted and solid archives;
- verify the RAR 1.3 rolling sum+rotate checksum;
- reassemble stored old-style multi-volume archives;
- write stored and compressed RAR 1.4 archives.

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

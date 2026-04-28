# rars implementation plan

`rars` is a Rust RAR library and command line tool. The design target is broad
format coverage first: decode historical archives reliably, write valid archives
for selectable RAR versions, and keep encoder policy separate from wire-format
mechanics so byte-close WinRAR compatibility can be improved later without
rewriting the core.

## Workspace layout

```text
rars/
  Cargo.toml
  crates/
    rars/              public library facade
    rars-cli/          command line interface
    rars-format/       signatures, headers, flags, version detection, raw I/O
    rars-codec/        LZ/Huffman/PPMd/RARVM/filter codecs
    rars-crypto/       legacy ciphers, AES/KDF/HMAC
    rars-recovery/     RR/REV recovery data and repair logic
    rars-testkit/      fixture helpers and reference-tool integration
```

## Version model

Readers auto-detect the archive family from the signature:

- RAR 1.3/1.4: `RE~^`
- RAR 1.5-4.x: `Rar!\x1a\x07\x00`
- RAR 5.0/7.x: `Rar!\x1a\x07\x01\x00`

Writers require an explicit target version. Feature options are validated against
that version before bytes are emitted. Unsupported combinations should fail early
with a structured error rather than being silently downgraded.

## API shape

The facade crate should expose stable concepts:

- `ArchiveReader`: auto-detects version and streams entries.
- `ArchiveWriter`: takes `WriterOptions { target, features, policy }`.
- `ArchiveVersion`: exact write target and detected read family.
- `FeatureSet`: solid mode, encryption, comments, recovery, SFX, filters, etc.
- `EncoderPolicy`: compression decisions independent of format serialization.

Encoder policy is intentionally pluggable. A conservative `StoreOnlyPolicy`
should be available immediately. Later policies can add LZ, PPMd, filters, and
WinRAR-like heuristics.

## Initial implementation order

1. [done] Scaffold workspace and public facade.
2. [done] Implement signature detection and version-family dispatch.
3. [done] Implement RAR 1.3/1.4 read-side container parsing:
   main header, file headers, stored entries, metadata, and validation.
4. [done] Implement RAR 1.3/1.4 stored writer with version-constrained options.
5. [done] Add RAR 1.3 encryption/decryption for stored files.
6. [done] Add Unpack15 decompression for RAR 1.3/1.4 entries, including solid
   carry-over.
7. [done] Add a baseline legal Unpack15 encoder. Output now covers Huff
   literals, repeated StMode exit handling, ShortLZ matches, LongLZ matches,
   and solid-state carry between members.
8. Expand to RAR 1.5-4.x container, then RAR 5.0.

## Current RAR 1.3/1.4 status

This slice is now good enough to act as the first backend for a CLI:

- Container: `RE~^` signature detection, optional SFX prefix scan, main-header
  parsing, file-header parsing, directory entries, archive-comment and
  file-comment header extension decode/skip, and old-style multi-volume
  reassembly.
- Read/extract: stored, encrypted stored, compressed, encrypted compressed,
  solid compressed, old-style compressed multi-volume archives, directory
  entries, and SFX-prefixed archives.
- Write: valid stored archives, encrypted stored archives, compressed archives,
  encrypted compressed archives, and solid compressed archives using Huff
  literals, ShortLZ matches, LongLZ matches, and solid-state carry, with
  version and feature validation.
- CLI: `info`, `test`, `x`, and `a --format rar14` (compressed by default,
  `--store` to force stored output, `--solid` for solid compressed output).
- Negative coverage: wrong password rejection, corrupt stored payload checksum
  rejection, truncated compressed payload rejection, and unsafe extraction path
  rejection. Positive fixture coverage includes packed archive-comment and
  file-comment decode.

## RAR 1.3/1.4 scope

The first version slice should be useful without attempting WinRAR byte identity:

- Read: stored files, encrypted stored files, compressed files, encrypted
  compressed files, solid compressed archives, SFX-prefixed archives, directory
  entries, stored/compressed multi-volume archives, archive comments, and file
  comments are implemented.
- Write: stored files, encrypted stored files, compressed files, encrypted
  compressed files, and solid compressed files using Huff literals plus
  ShortLZ/LongLZ matches are implemented. The compressed writer handles longer
  literal runs by exiting StMode and is accepted by RAR 1.402 for the covered
  paths.
- Defer: AV emission and byte-identical historical compressor
  heuristics.

## Remaining RAR 1.3/1.4 gaps

Read-side gaps:

- AV payload parsing/verification. The spec repository has structural notes, but
  `rars` does not expose or validate AV records yet.
- Error typing. Current errors are structured enough for tests, but CLI messages
  will need refinement before the tool is friendly.

Write-side gaps:

- Archive and file comment writer support.
- Old-style multi-volume writer.
- SFX writer/stub support.
- AV writer. Likely defer unless a concrete compatibility need appears.

Recommended next task after compaction: add archive/file comment writing.

## Testing strategy

Use the specification repository fixtures as black-box compatibility tests. The
library should not require those fixtures at runtime; fixture-driven tests belong
in `rars-testkit` or integration tests gated on a fixture path.

Core tests should cover:

- signature detection for all archive families,
- RAR 1.3 header parse/write round-trips,
- stored RAR 1.3 archive write then read,
- version/feature validation failures,
- extraction against historical RAR 1.402 stored fixture payloads,
- CLI smoke tests for info/test/extract/create.

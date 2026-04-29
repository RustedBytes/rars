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
    rars-codec/        LZ/Huffman/PPMd/RARVM/filter codecs (Unpack15 lives here)
    rars-crypto/       legacy ciphers, AES/KDF/HMAC (RAR 1.3 cipher lives here)
    rars-recovery/     RR/REV recovery data and repair logic
    rars-testkit/      fixture helpers and reference-tool integration scaffold
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
8. [done] Re-align the workspace with the intended crate boundaries after the
   RAR 1.3/1.4 vertical slice was proven: `rars-codec` owns Unpack15,
   `rars-crypto` owns the legacy RAR 1.3 cipher, `rars-format` owns container
   parsing/writing, and `rars-testkit` is scaffolded for reference-tool checks.
9. [in progress] Expand to RAR 1.5-4.x container, then RAR 5.0. The first
   RAR 1.5-4.x reader slice parses marker/main/file/end blocks, RAR 3.x
   `NEWSUB` service headers, solid and volume flags, and RAR 4.x extended-time
   header payloads.

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
  encrypted compressed archives, solid compressed archives, packed archive
  comments, file comments, and old-style single-file multi-volume archives
  using Huff literals, ShortLZ matches, LongLZ matches, and solid-state carry,
  with version and feature validation.
- CLI: `info`, `test`, `x`, and `a --format rar14` (compressed by default,
  `--store` to force stored output, `--solid` for solid compressed output,
  `--comment` and `--file-comment` for comment writing, `--volume-size` for
  old-style single-file volumes).
- Architecture: the RAR 1.3/1.4 container remains in `rars-format::rar13`,
  while Unpack15 codec state now lives in `rars-codec` and the legacy password
  cipher lives in `rars-crypto`. The facade crate exposes `ArchiveReader`,
  `Archive`, and a small `ArchiveWriter` wrapper so callers have an auto-detect
  path instead of only version-specific entry points.
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
  compressed files, solid compressed files, packed archive comments, and file
  comments, plus stored/compressed old-style single-file multi-volume output,
  using Huff literals plus ShortLZ/LongLZ matches are implemented. The
  compressed writer handles longer literal runs by exiting StMode and is
  accepted by RAR 1.402 for the covered paths.
- Defer: AV emission, cryptographic AV verification without a real registered
  signature fixture, and byte-identical historical compressor heuristics.

## Remaining RAR 1.3/1.4 gaps

Read-side gaps:

- Full cryptographic AV verification. RAR 1.40 inline AV records are detected
  and structurally parsed from the paired shape fixtures, but the available
  AV-bearing fixture uses a registration-patched binary with BSS-zero
  registration data, so it is not a real registered-signature oracle.
- Error typing. CLI paths now add file/operation context, but the library error
  enum is still intentionally small and may need richer variants before a stable
  public API.

Write-side gaps:

- SFX writer/stub support.
- AV writer. Likely defer unless a concrete compatibility need appears.

Recommended next task after compaction: decide whether to polish RAR 1.3/1.4
error/reporting edges or move on to the RAR 1.5-4.x container slice.

## Current RAR 1.5-4.x status

The first reader slice is implemented:

- `rars-format::rar15_40::Archive::parse` handles `Rar!\x1a\x07\x00` marker
  blocks, main headers, file headers, `NEWSUB` service headers, end headers,
  and unknown-block skipping by `HEAD_SIZE + ADD_SIZE`.
- Parsed metadata includes file names, packed/unpacked sizes, host OS, CRC32,
  DOS mtime, method, `UNP_VER`, attributes, salt presence, and raw extended-time
  bytes.
- Stored files can be extracted through the public facade and CLI, with full
  file-data CRC32 verification.
- Non-AV/SIGN block headers are validated with `HEAD_CRC = CRC32(header[2..]) &
  0xFFFF`.
- `NEWSUB` service headers are classified at parse time. The current typed
  cases are archive comments (`CMT`) and recovery records (`RR`), with other
  names preserved as unknown service headers.
- Stored split files can be reassembled across RAR 3.x volume sets, including
  old-style `.r00` numbering, with final full-data CRC32 verification.
- Fixture coverage includes RAR 3.00 archive comments (`NEWSUB` name `CMT`),
  stored file metadata, solid archive flags, old/new multivolume numbering,
  split-after flags, RAR 4.20 extended-time headers, corrupt header checksum
  rejection, corrupt stored-payload CRC32 rejection, incomplete stored-volume
  rejection, and compressed-volume rejection pending the codec.
- The public facade dispatches `ArchiveReader::read` to RAR 1.5-4.x parsing,
  and `rars info`, `rars test`, and `rars x` work for stored RAR 1.5-4.x
  archives, including stored volume sets when all parts are supplied in order.

Next RAR 1.5-4.x tasks:

- Decode RAR 3.x archive-comment payloads once the Unpack20/29 codec exists.
- Start Unpack20/29 decompression in `rars-codec`.

## Testing strategy

Use the specification repository fixtures as black-box compatibility tests. The
library should not require those fixtures at runtime; fixture-driven tests belong
in `rars-testkit` or integration tests gated on a fixture path.

Coverage reporting is available via `./scripts/coverage.sh`. It uses Rust's
native LLVM source coverage (`-Cinstrument-coverage`) and writes the HTML report
to `target/coverage/html/index.html`.

Core tests should cover:

- signature detection for all archive families,
- RAR 1.3 header parse/write round-trips,
- stored RAR 1.3 archive write then read,
- version/feature validation failures,
- extraction against historical RAR 1.402 stored fixture payloads,
- CLI smoke tests for info/test/extract/create.

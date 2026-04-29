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

Extraction APIs should keep streaming as the primary path: `extract_to` and
`extract_volumes_to` write to caller-provided sinks, while Vec-returning
`extract` helpers are convenience wrappers for tests and small archives.

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
   parsing/writing, and fixture/reference-tool checks live in focused
   integration tests or local support modules.
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
  path instead of only version-specific entry points. Parsed entries store
  packed byte ranges into the archive backing source rather than cloning packed
  payloads into every entry. `Archive::parse_path` supports file-backed parsing
  without loading the whole archive. `Archive::extract_to` writes entries to
  caller-provided writers. Stored entries can be copied and checksum-verified
  without materializing the file data, and Unpack15 now has a writer-backed
  decode path so compressed output does not need a full decoded-member buffer.
  Unpack15 can also read packed input incrementally from the archive range.
  Legacy encrypted entries are decrypted in fixed-size chunks on the way into
  either the stored writer path or the compressed decoder. Volume-aware
  `extract_volumes_to` streams old-style stored and compressed split members
  across chained archive ranges without reassembling the packed stream in
  memory.
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
- Stored files, RAR 1.5 `UNP_VER=15` Unpack15-compressed files, basic non-solid
  RAR 2.9/3.x LZ-compressed files, and the standard RARVM
  E8/E8E9/DELTA/ITANIUM filter fixtures can be extracted through the public
  facade and CLI, with full file-data CRC32 verification.
- Non-AV/SIGN block headers are validated with `HEAD_CRC = CRC32(header[2..]) &
  0xFFFF`.
- `NEWSUB` service headers are classified at parse time. The current typed
  cases are archive comments (`CMT`) and recovery records (`RR`), with other
  names preserved as unknown service headers. RAR 3.x compressed archive
  comments are decoded through the same Unpack29 path.
- Stored split files can be reassembled across RAR 3.x volume sets, including
  old-style `.r00` numbering, with final full-data CRC32 verification.
- `rars-codec::rar29::Unpack29` is reusable and preserves table/history,
  pending matches, and unread bits across caller-selected output slices. It
  parses RARVM filter records, recognizes standard bytecode by length+CRC32,
  and applies native E8/E8E9/DELTA/ITANIUM transforms to returned data while
  keeping raw dictionary history separate. It also clamps RAR3 Huffman table
  run lengths to the table boundary, matching the reference readers, and handles
  the early zero repeat-distance slot as a one-byte-back match.
- Fixture coverage includes RAR 1.54 Unpack15 extraction, RAR 2.50 Unpack20
  LZ-mode extraction, RAR 3.00 archive comments (`NEWSUB` name `CMT`), stored
  file metadata, solid archive flags, old/new multivolume
  numbering, split-after flags, RAR 4.20 extended-time headers, corrupt header
  checksum rejection, corrupt stored-payload CRC32 rejection, incomplete
  stored-volume rejection, standalone Unpack29 LZ extraction, reusable
  decoder-state regression coverage, compressed archive-comment decode, four
  standard RARVM filter fixtures, RGB/AUDIO CRC-mismatch guards, and
  compressed-volume rejection pending cross-volume codec state.
- The public facade dispatches `ArchiveReader::read` to RAR 1.5-4.x parsing,
  and `rars info`, `rars test`, and `rars x` work for stored, RAR 1.5
  Unpack15, and basic non-solid LZ-compressed RAR 2.9/3.x archives, including
  stored volume sets when all parts are supplied in order. Parsed file/service
  headers store
  packed byte ranges into the archive backing source rather than cloned
  payloads, so parsing no longer duplicates the compressed data for each entry.
  `Archive::parse_path` supports file-backed parsing without loading the whole
  archive, and the CLI uses the path-backed facade for read-side commands.
  `Archive::extract_to` writes entries to caller-provided writers, so stored
  entries can be copied and CRC32-verified without materializing the file data.
  Unpack29 also has a reader/writer-backed extraction path; file-backed
  archives feed packed bytes to the decoder incrementally, decode compressed
  output in bounded chunks, delay flushing across incomplete RARVM filter
  blocks, and retain only the sliding history needed by later matches. Normal
  vector-returning extraction and direct-to-writer extraction now share the same
  per-archive decoder session. That session owns a codec-state enum rather than
  a dedicated Unpack29 field: `UNP_VER=15` uses Unpack15, `UNP_VER=20/26` uses
  Unpack20 LZ mode, and `UNP_VER>=29` uses Unpack29. Volume-aware
  `extract_volumes_to` streams stored split members across chained archive
  ranges without reassembling the packed stream in memory.

Next RAR 1.5-4.x tasks:

- Finish RARVM/LZ parity for the RGB and AUDIO fixture archives. The old
  match-distance failure is fixed; these archives now decode to the requested
  size and fail only at final CRC32 verification, so the remaining work is byte
  parity in the LZ/filter output.
- Finish compressed split-volume extraction; the current guard shows additional
  split stream semantics beyond simple packed-byte concatenation.
- Extend RAR 2.0/Unpack20 beyond the initial LZ-mode decoder: add audio-block
  mode and more fixtures for solid/multiblock state.
- Add PPMd coverage for RAR 2.9+ method 0x35.
- Add RAR 1.5-4.x file/header encryption modules.

Architectural debt to address before the RAR 5.0 streaming slice:

- Keep RAR 5 reader-backed from the start. The older RAR 1.3/1.4 and RAR
  1.5-4.x direct-to-writer paths now stream stored data, compressed output, and
  packed codec input for file-backed archives, including legacy encrypted
  RAR 1.3/1.4 entries.
- Extend the codec-state session to RAR 1.5-4.x compressed split-volume
  extraction. Stored split volumes stream through `extract_volumes_to`, but
  compressed split volumes remain guarded by fixture tests until the split stream
  semantics are understood and wired through the session.
- Enrich library errors with archive offsets and block context before treating
  the public API as stable.

## Testing strategy

Use the specification repository fixtures as black-box compatibility tests. The
library should not require those fixtures at runtime; fixture-driven tests should
live in integration tests gated on a fixture path, with local support modules
when shared setup is needed.

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

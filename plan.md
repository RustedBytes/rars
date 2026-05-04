# rars implementation plan

`rars` is a Rust RAR library and command line tool. The design target is broad
format coverage first: decode historical archives reliably, write valid archives
for selectable RAR versions, and keep encoder policy separate from wire-format
mechanics so byte-close WinRAR compatibility can improve later without rewriting
the core.

## Architecture

```text
rars/
  crates/
    rars/              public library facade
    rars-cli/          command line interface
    rars-format/       signatures, headers, flags, version detection, raw I/O
    rars-codec/        LZ/Huffman/PPMd/RARVM/filter codecs
    rars-crypto/       legacy ciphers, AES/KDF/HMAC
    rars-recovery/     RR/REV recovery data and repair logic
```

Readers auto-detect the archive family from the signature:

- RAR 1.3/1.4: `RE~^`
- RAR 1.5-4.x: `Rar!\x1a\x07\x00`
- RAR 5.0/7.x: `Rar!\x1a\x07\x01\x00`

Writers require an explicit target version. Feature options must be validated
against that version before bytes are emitted.

Streaming is the primary extraction API. `extract_to` and `extract_volumes_to`
write to caller-provided sinks; Vec-returning `extract` helpers are convenience
wrappers for tests and small archives only.

Encoder policy should remain pluggable. The baseline policy can be simple and
legal; WinRAR-like match finding, filter choice, and block-splitting heuristics
belong behind policy interfaces rather than inside format serialization.

Keep `rars-format` as the crate boundary for now, but split large family
modules internally before adding more RAR5 encryption or RAR7 work. The target
shape is wire parsing and typed block models in the family root module, with
extraction/session/multivolume orchestration in sibling modules such as
`rar15_40/extract.rs` and `rar50/extract.rs`; writers should get the same
treatment when they become the review bottleneck.

## Current Baseline

Keep this section short. Detailed behavioural claims belong in tests.

- RAR 1.3/1.4 has a working vertical slice: parse, extract, create, comments,
  legacy password handling, Unpack15 read/write, solid mode, SFX-prefix read,
  and old-style stored/compressed volumes.
- RAR 1.5-4.x can parse the container family, service headers, extended-time
  payloads, RAR 1.54 Unpack15 members, RAR 2.50 Unpack20 LZ-mode members, and
  common RAR 2.9/3.x Unpack29 members. Current Unpack29 coverage includes
  LZ-mode members, a native Rust PPMd text fixture, and the standard
  E8/E8E9/DELTA/ITANIUM/RGB/AUDIO native RARVM filters. Generic RARVM
  bytecode has parser/executor unit coverage and an archive-level fixture that
  exercises the generic fallback path end to end.
  Current Unpack20 coverage includes plain LZ, `-mm` multimedia-switch inputs
  that still select LZ, solid member state carry-over, audio-shaped/text
  archives, a larger LZ history/table-stress fixture, explicit multiblock
  streams, synthetic codec-level one-channel and archive-level 1..4-channel
  audio blocks, and RAR 2.0 Feistel-encrypted file members. The RAR 1.5
  `CRYPT_RAR15` stream cipher is implemented and covered
  by crypto vectors plus a WinRAR 1.54-derived archive fixture that is accepted
  by RAR 3.93.
  RAR 3.x/4.x AES encryption is covered for normal encrypted file members and
  `MHD_PASSWORD` header-encrypted archives, including small RAR4 junrar
  fixtures with encrypted compressed data and compact Unicode filenames, plus
  old-numbered and new-numbered encrypted/header-encrypted RAR 3.00 volume
  sets.
  Current PPMd coverage includes a normal text member, literal escape-byte
  handling, a mixed text/binary multi-file archive, solid PPMd model reuse, and
  PPMd-embedded RARVM filter records. RAR 1.54 coverage includes single-file,
  multi-file, solid-flagged, audio-shaped WAV payloads with Windows and DOS
  names, and old-numbered multivolume Unpack15 archives. RAR 1.5 store-only
  and basic compressed writing, including solid mode, old-numbered
  multivolumes, old-style archive comments, and RAR 1.5 per-file encryption
  including encrypted split volumes, are exposed through the public facade and
  CLI, with reader round-trip tests for small generated archives.
- Extraction is reader-backed for normal archive paths and avoids cloning packed
  payloads into parsed entries. Stored, compressed, and encrypted RAR 1.5-4.x
  volume sets stream through `extract_volumes_to`; encrypted split sets use a
  decrypting reader that carries RAR15 byte-stream state and RAR20/RAR30
  16-byte block state across fragment boundaries.
- RAR 5.0 has an initial read/extract vertical slice: marker and block walking,
  main/file/service/end header parsing, vint bounds, header CRC32 validation,
  main-header Locator extra parsing, file compression-info bitfield decoding,
  compressed-block framing/checksum parsing in `rars-codec`, stored file
  extraction, Unpack50 LZ extraction for `m1/m3/m5` fixtures, all four RAR5
  fixed filters, single-archive solid state carry-over, compressed
  multivolume extraction for the promoted `multivol.part*.rar` fixture,
  optional file CRC32 validation, BLAKE2sp hash-record parsing and
  verification, and clear rejections for encrypted headers and encrypted
  files. RAR 7.x remains format-detected but codec-unsupported beyond the
  shared RAR 5 signature family.

## Priority Backlog

### 1. RAR 1.5-4.x Decoder Watchlist

- Blocked on external/vintage-encoder evidence:
  - Find or generate RAR 2.50-authored true audio-block fixtures. Current
    RAR 2.50 `-mm` probes,
    including the historical `AUDIO.RAR`, have bit 15 clear in the first
    table-read peek word and therefore exercise normal LZ blocks rather than
    the Unpack20 audio predictor. The code has synthetic one-channel audio
    coverage at codec level and synthetic archive-level coverage for channel
    counts 1, 2, 3, and 4. The spec repo's
    `scripts/find-rar20-audio-candidates.py` scanned the local external
    corpus, spec fixtures, promoted crate fixtures, and old numbered volumes
    (517 archive/volume files total, excluding hidden scratch directories) and
    found only encrypted/solid/stored false positives for raw
    bit-15-at-data-start, so promoted vintage-encoder fixtures should still
    pin bit 15 set at a fresh table-read boundary and the selected channel
    count.
- Watch for new corpus bugs:
  - Keep `FHD_LARGE` parser coverage synthetic until a real >4 GiB fixture is
    worth committing. The current parser combines high/low sizes and uses the
    full 64-bit packed size for archive extents, including low-32-bits-zero
    cases.
  - Add more adversarial PPMd fixtures as corpus bugs appear.
  - Continue treating `node-unrar-js/FileEncByName.rar` as a partial oracle:
    metadata, visible compact Unicode names, the unencrypted stored member, and
    wrong-password/NeedPassword behaviour are covered; encrypted payload success
    still needs the unknown member passwords. A local corpus search and an
    upstream `node-unrar.js` README/test-file audit found no password hints, so
    this should stay a partial oracle unless the original passwords turn up.
    The libarchive mixed encrypted fixture covers its RAR 3.93-validated
    positive member `b.txt`; its later `d.txt` member is intentionally excluded
    from the success oracle because RAR 3.93 reports a CRC/password failure.

### 2. RAR 5.0/7.x Reader

- Add RAR 5 compression decode:
  - Current crate fixtures include successful extraction tests for
    `m1_fastest.rar`, `m3_default.rar`, `m5_max.rar`, `filter_delta.rar`,
    `filter_e8.rar`, `filter_e8e9.rar`, and `filter_arm.rar`.
  - Compression-info bitfield parsing is implemented and tested; use it as the
    Unpack50/70 dispatch input instead of re-decoding raw header bits in the
    codec.
  - Compressed-block framing and XOR checksum parsing is implemented in
    `rars-codec::rar50` and pinned against a real WinRAR-authored compressed
    fixture; use it as the input boundary for table parsing.
  - Level-table length parsing is implemented and tested, including the
    RAR5-specific literal-15 escape and zero-run count semantics.
  - Unpack50/70 second-level Huffman table length parsing is implemented and
    tested, including repeat-previous validation and the 64-vs-80 distance
    table count split.
  - Main/Distance/Align/Length decode-table construction is implemented, with
    align-mode detection, and pinned against a real WinRAR-authored compressed
    fixture.
  - A narrow literal-only decode loop is implemented and covered with a
    synthetic compressed block that exercises block framing, table parsing, and
    Main Huffman symbol decoding together.
  - RAR5 length-slot and distance-slot helper formulas, output-window copying,
    new-match decoding, last-length repeats, and repeat-distance matches are
    implemented and unit-tested with synthetic compressed blocks.
  - The decode loop extracts real non-filtered WinRAR-authored RAR5 compressed
    fixtures for methods `m1`, `m3`, and `m5`.
  - RAR5 filter-control symbol handling and all four RAR5 fixed filters
    (DELTA, E8, E8E9, ARM) are implemented and fixture-tested.
  - Single-archive solid RAR5 extraction is implemented and fixture-tested;
    decoder tables, repeat distances, last length, and output history carry
    across files in the same archive.
  - RAR 7 distance/table-size changes.
- Add RAR 5 encryption:
  - password KDF, AES-256-CBC, header encryption, password-check records.
- Extend RAR 5 multivolume extraction:
  - Compressed split extraction is implemented for the promoted
    `multivol.part*.rar` fixture and preserves the Unpack50 decoder across the
    archive set.
  - Compressed split extraction feeds a chained fragment reader into Unpack50
    instead of concatenating the packed stream first. Stored split entries
    stream fragments directly to the caller's writer while checking size,
    CRC32, and BLAKE2sp hash records.
  - Add explicit stored-split and solid-across-volume fixtures.
- Add RAR 5 recovery parsing after normal decode is stable:
  - inline RR service blocks.
  - `.rev` volume handling.

### 3. Writer Work

- Keep RAR 1.3/1.4 writer stable while expanding tests.
- Keep the RAR 1.5 writer covered by public-reader oracles. The current
  baseline writes store-only, Unpack15 compressed, solid, old-numbered
  multivolume, old-style archive/file comments, and CRYPT_RAR15 encrypted
  archives, including encrypted split volumes. Small generated outputs are
  promoted under `fixtures/1.5-4.x/rars-generated/` in the spec repo and
  mirrored into crate fixture tests, where both decoded payloads and fixture
  bytes are pinned.
- Add later RAR 1.5-4.x writer families only where the corresponding read-side
  codec is already strong enough to validate the output:
  - RAR 2.0/2.6 Unpack20 writer.
  - RAR 2.9/3.x Unpack29 writer, including PPMd and RARVM filter records.
  - RAR 3.x/4.x AES per-file and header-encrypted writer.
- Add RAR 5 writer after the RAR 5 reader is proven.
- Keep byte-identical WinRAR output out of scope for baseline writers; expose
  policy hooks so better heuristics can be added without changing wire writers.

### 4. API And Error Quality

- Extend the facade-level `ArchiveReadOptions` context into lower-level
  format parsing and extraction once RAR 5 encryption lands, so derived
  decryptors can be owned instead of threading raw passwords through every
  call. Existing no-password and `_with_password` helpers remain compatibility
  shims for now.
- Continue enriching library errors with block type and broader operation
  context before treating the public API as stable. RAR 5 block parse errors
  already carry archive-relative offsets, and RAR 5 extraction errors carry
  entry name plus decode/verify context.
- Keep low-level parsed format structs public for inspection, but mark them
  non-exhaustive so future encryption, recovery, and timestamp fields can be
  added without freezing the parser object model.
- Consider deprecating Vec-returning extraction APIs once integration tests and
  examples primarily use streaming APIs.
- Keep archive equality undefined unless a clear value semantics is needed.

### 5. Fixture And Coverage Work

- Keep useful spec-repo fixtures copied into crate tests when they validate a
  stable behaviour.
- Keep generated spec-repo fixture inventories, `rars-generated` SHA tables,
  and RAR 3.x/4.x `rar lt` listing oracles covered by
  `scripts/verify-fixtures.py` when adding or regenerating fixtures.
  For historical-reader coverage, run the optional verifier path with both
  the WinRAR/UnRAR 3.00 and 4.20 Wine prefixes.
- Add failing tests before changing format or codec behaviour.
- Add coverage for:
  - RAR 5 encrypted, multivolume, and recovery cases.
- Use `./scripts/coverage.sh` periodically; it writes HTML coverage to
  `target/coverage/html/index.html`.

## Deferred Or Optional

- Full cryptographic AV verification for RAR 1.4/2.x. Existing fixtures cover
  structure, but not a real registered-signature oracle.
- AV writing.
- SFX writer/stub generation.
- Recovery repair, as distinct from recovery metadata parsing.
- Byte-identical compressor heuristics: filter selection, match-finder tuning,
  solid reset thresholds, and exact block partitioning.

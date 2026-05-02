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
  Current Unpack20 coverage includes plain LZ, 2-channel audio, solid member
  state carry-over, a larger LZ history/table-stress fixture, and RAR 2.0
  Feistel-encrypted file members.
  Current PPMd coverage includes a normal text member, literal escape-byte
  handling, a mixed text/binary multi-file archive, solid PPMd model reuse, and
  PPMd-embedded RARVM filter records.
- RAR 3.x header-encrypted archives are detected from `MHD_PASSWORD` and
  rejected with a clear unsupported-feature error before encrypted block bytes
  are parsed.
- Extraction is reader-backed for normal archive paths and avoids cloning packed
  payloads into parsed entries. Stored and compressed RAR 3.x volume sets stream
  through `extract_volumes_to`.
- RAR 5.0 has an initial read/extract vertical slice: marker and block walking,
  main/file/service/end header parsing, vint bounds, header CRC32 validation,
  stored file extraction, optional file CRC32 validation, BLAKE2sp hash-record
  parsing, and clear rejections for encrypted headers, encrypted files,
  compression, and multivolume extraction. RAR 7.x remains format-detected but
  codec-unsupported beyond the shared RAR 5 signature family.

## Priority Backlog

### 1. RAR 1.5-4.x Decoder Coverage

- Finish Unpack20:
  - Add more audio fixtures if examples with 1, 3, or 4 channels become
    available; current coverage pins normal 2-channel RAR 2.50 audio blocks.
- Broaden PPMd coverage for RAR 2.9+:
  - Add more adversarial PPMd fixtures as corpus bugs appear.
- Add RAR 1.5-4.x encryption:
  - RAR 3.x/4.x AES file encryption.
  - Header encryption (`MHD_PASSWORD`) decryption, including salt/KDF handling
    and parsing decrypted block streams.

### 2. RAR 5.0/7.x Reader

- Harden the initial RAR 5 reader:
  - Parse and expose main-header extra records, especially locator metadata for
    quick-open and recovery-record offsets.
  - Expand service-header tests for `CMT`, `QO`, `RR`, and mixed service
    archives before relying on service metadata publicly.
  - Add tests for SFX-prefixed RAR 5 archives and malformed/overlong vint
    encodings.
- Implement RAR 5 checksums:
  - CRC32 is verified when present.
  - Add BLAKE2sp verification for file hash extra records; records are parsed
    today but not cryptographically checked.
- Add RAR 5 compression decode:
  - Unpack50/70 table parsing.
  - RAR 5 filters: x86 E8/E8E9, ARM, delta, and version-specific differences.
  - RAR 7 distance/table-size changes.
- Add RAR 5 encryption:
  - password KDF, AES-256-CBC, header encryption, password-check records.
- Add RAR 5 multivolume extraction:
  - Stored and compressed split entries are currently rejected through the
    public facade.
  - Preserve decoder/checksum state across `.partN.rar` sets once split stream
    semantics are implemented.
- Add RAR 5 recovery parsing after normal decode is stable:
  - inline RR service blocks.
  - `.rev` volume handling.

### 3. Writer Work

- Keep RAR 1.3/1.4 writer stable while expanding tests.
- Add RAR 1.5 writer only after read-side Unpack15/20/29 coverage is solid:
  - store-only first,
  - then legal LZ blocks with simple Huffman table generation,
  - then optional comments, volumes, and encryption.
- Add RAR 5 writer after the RAR 5 reader is proven.
- Keep byte-identical WinRAR output out of scope for baseline writers; expose
  policy hooks so better heuristics can be added without changing wire writers.

### 4. API And Error Quality

- Enrich library errors with archive offsets, block type, entry name, and
  operation context before treating the public API as stable.
- Review which low-level format structs should remain public.
- Consider deprecating Vec-returning extraction APIs once integration tests and
  examples primarily use streaming APIs.
- Keep archive equality undefined unless a clear value semantics is needed.

### 5. Fixture And Coverage Work

- Keep useful spec-repo fixtures copied into crate tests when they validate a
  stable behaviour.
- Add failing tests before changing format or codec behaviour.
- Add coverage for:
  - RAR 1.54 multi-file and multivolume fixtures,
  - RAR 2.0 explicitly observed multiblock fixtures,
  - RAR 3.x PPMd,
  - RAR 3.x encrypted file/header cases,
  - RAR 5 compressed, encrypted, service-heavy, SFX-prefixed, multivolume, and
    recovery cases.
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

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

Writer APIs should not grow by cartesian-product function names. The intended
shape is:

- A builder captures user intent and ergonomic defaults.
- A resolver validates that intent against the selected archive version and
  produces a resolved emission plan. Validation belongs here, not in every
  builder setter.
- The resolved plan describes the concrete block sequence, encryption material,
  service records, recovery layout, and locator/extent placeholders needed for
  emission. It is not a renamed struct of option booleans.
- Layout resolution may use bounded passes for coupled features such as Quick
  Open locators, inline recovery records, encrypted headers, and volumes. Passes
  must have a fixed cap and return a clear error if they do not converge.
- The emitter consumes the resolved plan and performs mechanical serialization
  and final patching. Mechanical work includes computing bytes implied by the
  resolved layout, such as recovery parity shards, header checksums, HMACs, and
  locator fields; it must not re-run feature policy.
- Parallel tests for a new writer path must keep the existing behavioural and
  reference-oracle coverage. Reference parity means generated archives are
  accepted by the relevant `rar t`/reader oracle and decode to the expected
  metadata and payloads; byte-identical WinRAR output is not required.

Keep `rars-format` as the crate boundary for now, but split large family
modules internally before adding more RAR5 encryption or RAR7 work. The target
shape is wire parsing and typed block models in the family root module, with
extraction/session/multivolume orchestration in sibling modules such as
`rar15_40/extract.rs` and `rar50/extract.rs`, and writer serialization in
sibling modules such as `rar15_40/write.rs` when it is large enough to affect
reviewability.

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
  CLI, with reader round-trip tests for small generated archives. RAR 2.0 has
  baseline Unpack20 and Unpack29 compressed writers exposed through the format
  crate, facade, and CLI; they emit literals plus bounded hash-chain matches
  for repeated byte runs and phrases. Current writer search windows are 1 MiB
  for both Unpack20 and Unpack29, including offset-dependent match-length
  compensation for long-distance slots, and generated Unpack20 and Unpack29
  archives are accepted by
  WinRAR/UnRAR 4.20. RAR 2.9 has baseline per-file AES writer support for
  stored and literal-only Unpack29 compressed members, including encrypted
  split volumes. RAR 3.x/4.x has baseline per-file AES writer support for
  stored and literal-only Unpack29 compressed members with OS-randomized salts,
  `MHD_PASSWORD` header-encrypted RAR30/RAR40 compressed archives, encrypted
  and header-encrypted RAR30/RAR40 split volumes, RAR3 `NEWSUB` `CMT`
  archive-comment records, solid
  RAR29/RAR30/RAR40 compressed archives whose writer can match against prior
  member history, and solid `MHD_PASSWORD` header-encrypted RAR30/RAR40
  compressed archives, exposed through the format crate, facade, and CLI;
  generated RAR30 and RAR40 archives are accepted by
  WinRAR/UnRAR 4.20.
- Codec-level writer coverage explicitly pins Unpack20 and Unpack29 match
  finding against previous solid-member history, in addition to same-member
  repeated-byte, repeated-sequence, and long-distance match cases.
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
  verification, per-file AES-256-CBC encrypted stream extraction with
  password-check records and CRC32/BLAKE2sp HashMAC verification,
  archive-wide `HEAD_CRYPT` encrypted-header parsing, and encrypted compressed
  multivolume extraction. Encrypted service payloads are covered by a
  header-encrypted archive-comment fixture. RAR 7.x shared-format archives are
  handled through the RAR 5 reader, and the WinRAR 7 `-ams` archive metadata
  main-extra record is parsed. RAR 5.0 has a baseline store-only writer with
  CRC32+BLAKE2sp file integrity records, per-file AES-256 encrypted stored
  members with password-check and hash-MAC records, OS-randomized salts and IVs
  covered for encrypted file payloads, encrypted services, `HEAD_CRYPT`
  headers, and encrypted volumes, archive-comment `CMT` service records
  including stored, compressed, encrypted compressed, and header-encrypted
  compressed comments, archive metadata main-extra records including compressed,
  encrypted, and header-encrypted archive outputs, stored Quick Open `QO`
  service records with locator offsets
  and CRC-wrapped cached headers, stored `ACL`/`STM` file-service headers, and
  stored file-comment `CMT` service records including encrypted and
  header-encrypted stored comments, and structural stored, compressed,
  encrypted, and header-encrypted `RR` recovery service records with locator
  offsets through the format crate, facade, and CLI,
  archive-wide header encryption for stored encrypted members, and stored split
  volumes with optional file encryption including header encryption, plus a
  match-capable RAR5 compressed writer, including compressed split volumes,
  encrypted compressed members, encrypted compressed volumes, header-encrypted
  compressed archive/volume outputs, DELTA/E8/E8E9/ARM filter-control records
  for compressed members, plain solid compressed archives, and
  encrypted/header-encrypted solid compressed archives and solid compressed
  volume sets, exposed through the format crate, facade, and CLI. Inline `RR`
  recovery service records are emitted per volume for stored, compressed, and
  encrypted split volume sets and are covered by format, CLI, and `rar t`
  reference-script oracles. Header-encrypted recovery volumes remain gated off:
  a local RAR 7.12 check rejected the first generated compressed
  header-encrypted recovery volume after testing the file body. The current
  RAR5 match
  encoder covers same-member matches, repeat-distance matches, and plain
  solid-history matches, including multi-file solid partitioning across split
  volume sets. Non-QO generated archives and volume sets are accepted by
  WinRAR/UnRAR 7.21; generated QO, compressed archive/volume, and
  solid-compressed archive output, including DELTA/E8/E8E9/ARM-filtered compressed
  archives, encrypted/header-encrypted solid compressed archives, solid volume
  sets, ACL/STM file-service output, and CRC64-protected `{RB}` recovery
  service chunks, including header-encrypted archives, is accepted by RAR 7.12.
  Generated RR output now passes `rar t` recovery-record validation and repairs
  stored and encrypted stored payload mutations spanning multiple recovery
  shards under `rar r -y`.
  The `rars-recovery` crate now contains the RAR 5 GF(2^16) field,
  Cauchy encoder matrix, scalar parity-shard primitive, inline-RR shard
  dimension planner, CRC64/XZ chunk checksum, prefix shard splitting, and
  inline `{RB}` chunk construction with the per-data-shard raw CRC64 state
  fields observed in WinRAR-authored output. The format writer now uses those
  primitives instead of percent-sized zero placeholders. Remaining work is
  broadening the repair oracle beyond the current stored and encrypted stored
  payload mutation cases spanning multiple recovery shards.
  True Unpack70 remains fixture-blocked because it
  requires a >4 GiB dictionary input.

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
  - RAR 7 Unpack70 distance/table-size changes remain synthetic-only until a
    practical >4 GiB fixture is worth committing. Small WinRAR 7 archives still
    use Unpack50-compatible streams; the current promoted RAR 7 fixture covers
    the `-ams` archive metadata main-extra record instead.
- Extend RAR 5 multivolume extraction:
  - Compressed split extraction is implemented for the promoted
    `multivol.part*.rar` fixture and preserves the Unpack50 decoder across the
    archive set.
  - RAR5 extraction now uses a named decoder session to own the Unpack50
    decoder and password context across single-archive and multivolume member
    extraction, matching the RAR 1.5-4.x vocabulary for solid/stateful decode
    without forcing a cross-version trait yet.
  - Compressed split extraction feeds a chained fragment reader into Unpack50
    instead of concatenating the packed stream first. Stored split entries
    stream fragments directly to the caller's writer while checking size,
    CRC32, and BLAKE2sp hash records.
  - Explicit WinRAR-authored stored-split and solid-across-volume fixtures are
    promoted into crate tests.
- RAR 5 recovery metadata parsing is implemented for inline `RR` service
  headers and RAR 5 `.rev` recovery volumes. Writer-side inline RR output now
  has a stored-payload repair oracle; reader-side repair/reconstruction APIs and
  REV-based reconstruction remain deferred.

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
  - Improve the RAR 2.0/2.6 Unpack20 writer beyond the current literal plus
    bounded hash-chain baseline: broader solid/table-boundary stress coverage.
  - Improve the RAR 2.9/3.x Unpack29 writer beyond the current literal plus
    bounded hash-chain baseline: PPMd and additional RARVM filter records.
    The first RARVM writer slices emit whole-member standard AUDIO, DELTA, E8,
    E8E9, ITANIUM, and RGB filter records for non-solid RAR 2.9/3.x/4.x
    compressed archives, plus segmented AUDIO/DELTA/E8/E8E9/ITANIUM/RGB filter
    placement. Whole-member and segmented records are accepted by WinRAR/UnRAR
    3.00 and 4.20. The filtered writer also honors RAR 2.9/3.x/4.x solid
    archive flags for multi-member outputs and per-file encrypted filtered
    members, including RAR 3.x header-encrypted filtered archives. A
    deterministic `AutoSize` writer path compares plain Unpack29 against
    E8/E8E9 whole-member filters plus a bounded set of dense segmented x86
    ranges, whole-member DELTA candidates for channel counts 1..4, and
    whole-member AUDIO candidates for channel counts 1..4, plus whole-member
    RGB candidates for a small set of common scanline byte widths and a
    whole-member ITANIUM candidate, then keeps the smallest packed member.
    Remaining work is broader filter placement with real heuristics for
    segmented non-x86 ranges.
  - Improve the RAR 3.x/4.x AES writer beyond the current baseline only when
    new combinations are added. Current generated per-file encrypted,
    encrypted split-volume, header-encrypted, header-encrypted split-volume,
    and solid header-encrypted RAR30/RAR40 archives are accepted by
    WinRAR/UnRAR 4.20.
- Improve the RAR 5 writer beyond the current store/encrypted-store baseline:
  real recovery repair data and fully repaired RR writer output.
  The first recovery implementation slice is in `rars-recovery`: GF(2^16)
  arithmetic with polynomial `0x1100b`, Cauchy encoder matrix construction,
  byte-shard parity generation, the WinRAR 6.02 inline-RR dimension formula,
  CRC64/XZ checksums, protected-prefix shard splitting, and structural `{RB}`
  chunk construction, raw per-data-shard CRC64 state fields, and
  `chunk_data_extent` are unit-tested or reference-checked. `rars-format` uses
  this to emit real parity chunks for RAR5 RR service records; RAR 7.12 accepts
  both normal and header-encrypted records in `rar t`, and `rar r -y` repairs
  stored and encrypted stored payload damage spanning multiple recovery shards.
  Remaining work is broader repair coverage across compressed payloads,
  header-encrypted archives, split-volume payloads, and heavier damage within
  the available recovery budget. A local RAR 7.12 probe against
  RAR-authored compressed `-rr20` output found the recovery record but could
  not repair the same packed-payload mutation pattern used by the stored oracle,
  so compressed repair needs a more careful damage model before it can be used
  as a rars correctness oracle.
  WinRAR-authored chunks use one
  shared final state across all `{RB}` chunks; the writer now does the same,
  using the first parity shard's raw CRC64 state as the shared value because
  RAR validates and repairs when the field is consistent.
  The current compressed writer emits deterministic method-1 Unpack50 blocks
  with bounded hash-chain matches. It is covered for single archives, split
  volumes, encrypted compressed archives, encrypted compressed volumes,
  header-encrypted compressed archives, header-encrypted compressed volumes,
  DELTA/E8/E8E9/ARM-filtered compressed archives, compressed/encrypted/header-encrypted
  compressed archives with `RR` service records, plain solid compressed archives,
  encrypted/header-encrypted solid compressed archives, and single-entry plus
  multi-file solid compressed volume sets by codec, format, facade, CLI, and
  `rar t` reference-script oracles. A deterministic `AutoSize`
  filter-selection policy hook tries the implemented fixed filters and keeps
  the smallest packed member when it beats plain LZ. The next compression work
  is richer policy tuning.
- Keep byte-identical WinRAR output out of scope for baseline writers; expose
  policy hooks so better heuristics can be added without changing wire writers.

### 4. API And Error Quality

- Keep pushing `ArchiveReadOptions` into lower-level parsing as formats need
  it. `ArchiveReadOptions` now lives in `rars-format` and is re-exported by the
  facade. The public facade reader uses `read_with_options` and
  `read_path_with_options`, and RAR 1.5-4.x plus RAR5 format parsers and
  multivolume extractors have option-based entry points. The old
  `ArchiveReader::*with_password` compatibility methods are gone. RAR 5
  `parse_with_password` / `parse_path_with_password` still attach derived
  per-file decryptor state to parsed entries, so encrypted files and split
  payloads can extract without re-threading raw passwords. Remaining
  password-specific lower-level helpers are compatibility wrappers or
  member-level helpers.
- Keep collapsing writer option combinations into policy objects rather than
  named functions. The codec layer now exposes RAR29/RAR50 filter specs, and
  the RAR 2.9/3.x/4.x plus RAR5 public writer surfaces use filter-policy entry
  points instead of per-filter wrapper functions. RAR5 CLI add-path option
  construction now builds one feature/options value per invocation instead of
  rebuilding it inside every stored/compressed/encrypted branch. Plain
  stored/compressed RAR5 recovery archives, stored quick-open archives, and
  stored/compressed single archives, including header-encrypted single
  archives without recovery records, now route through the resolved writer plan
  so member payloads are prepared once and only the bounded locator/QO/RR
  layout pass is repeated. Stored file-service archive paths, including
  header-encrypted stored file-service archives, also use the resolved writer
  plan. The old RAR5 single-archive `write_*_archive*` public shims and
  facade `ArchiveWriter::write_rar50_*` mirrors have been removed. Callers use
  `Rar50Writer` or `ArchiveWriter::rar50_writer()` for single archives and
  `Rar50VolumeWriter` for multi-part archives. The internal volume emitter is
  still separate because it produces multiple archive parts, but the public
  surface is a builder rather than named combinations; encrypted/header-encrypted
  and recovery combinations share the same header-key and split-layout
  mechanics instead of rejecting header-encrypted recovery volumes. RAR 1.5-4.x
  remains on its small set of named writer functions for now:
  stored/compressed, optional archive comment, RAR29 filter policy, and
  stored/compressed volumes. That surface is not yet growing cartesianly;
  introduce a `Rar15_40Writer` only if encryption,
  recovery, per-file services, or another independent option axis lands there.
  RAR5 facade tests exercise `Rar50Writer` or `Rar50VolumeWriter` directly
  rather than preserving private compatibility shims; keep new RAR5 writer
  tests grouped by behaviour rather than by helper method names.
- Keep the filter abstraction at the semantic transform layer. `rars-codec`
  shares the byte transforms for E8, E8E9, and DELTA through one internal
  `FilterOp` path. Version-specific wire records remain separate: RAR29 emits
  RARVM standard-filter records and keeps ITANIUM/RGB/AUDIO as RAR29-only
  operations, while RAR5 emits filter-control records and keeps ARM as a
  RAR5-only operation. Auto-filter policy is still per writer for now; any
  future shared policy should lower into these version-specific record formats
  rather than trying to unify the records themselves.
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
- The per-family `ExtractedEntry` and `ExtractedEntryMeta` types remain for
  extraction compatibility, but the facade now exposes `Archive::members()` as
  the common inspection view. It returns shared member metadata plus a typed
  per-family detail enum, avoiding a loose catch-all bucket while keeping
  common fields like size, attributes, encryption, storage, and split state in
  one place.

### 5. Fixture And Coverage Work

- Keep useful spec-repo fixtures copied into crate tests when they validate a
  stable behaviour.
- Keep generated spec-repo fixture inventories, `rars-generated` SHA tables,
  and RAR 3.x/4.x `rar lt` listing oracles covered by
  `scripts/verify-fixtures.py` when adding or regenerating fixtures.
  For historical-reader coverage, run the optional verifier path with both
  the WinRAR/UnRAR 3.00 and 4.20 Wine prefixes.
- Use `bash scripts/reference-rar5-writer.sh` when checking generated RAR 5
  writer output against a local RAR/WinRAR command-line tool. It verifies
  stored, Quick Open, encrypted, header-encrypted, and RR outputs with `rar t`.
- Use `bash scripts/reference-rar5-recovery-repair.sh` for the current RAR5
  repair oracle. It proves both RAR-authored and rars-authored stored and
  encrypted stored archives with RR can repair payload damage spanning multiple
  recovery shards.
- Use `bash scripts/reference-rar29-rarvm-writer.sh` when checking generated
  RAR 2.9 standard RARVM filter records against the local WinRAR/UnRAR 3.00
  and 4.20 Wine prefixes.
- Use `bash scripts/reference-rar3-aes-writer.sh` when checking generated
  RAR 2.9/3.x/4.x AES file encryption, header encryption, and encrypted split
  outputs against the local WinRAR/UnRAR 4.20 Wine prefix.
- Add failing tests before changing format or codec behaviour.
- Use `./scripts/coverage.sh` periodically; it writes HTML coverage to
  `target/coverage/html/index.html`.

## Deferred Or Optional

- Full cryptographic AV verification for RAR 1.4/2.x. Existing fixtures cover
  structure, but not a real registered-signature oracle.
- AV writing.
- SFX writer/stub generation.
- General recovery repair APIs, including RAR 5 REV reconstruction. The current
  writer has narrow inline-RR repair oracles for stored and encrypted stored
  payload damage spanning multiple recovery shards, but no public repair
  command/API yet.
- Byte-identical compressor heuristics: filter selection, match-finder tuning,
  solid reset thresholds, and exact block partitioning.

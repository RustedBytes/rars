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

- RAR 1.3/1.4 has a working read/write vertical slice, including comments,
  legacy password handling, Unpack15, solid mode, SFX-prefix reads, and
  old-style stored/compressed volumes.
- RAR 1.5-4.x has broad read coverage across Unpack15, Unpack20 LZ,
  Unpack29 LZ/PPMd/RARVM filters, RAR 1.5/2.0/3.x/4.x encryption, header
  encryption, old/new multivolume naming, comments, compact Unicode names, and
  solid state. Writers cover stored and baseline compressed outputs across
  RAR 1.5/2.0/2.9/3.x/4.x, including comments, encryption, header encryption,
  filters, solid archives, and split volumes.
- RAR 5.0/7.x has read coverage for block walking, stored and Unpack50
  compressed members, fixed filters, solid state, multivolume extraction,
  BLAKE2sp/CRC32 integrity, AES-256 file encryption, header encryption,
  service records, Quick Open, metadata extras, and RAR7 shared-format metadata.
  Writers cover stored and baseline compressed RAR5/RAR7 archives, encryption,
  header encryption, services, Quick Open, fixed filters, solid archives,
  split volumes, and inline recovery records.
- Normal archive extraction is reader-backed and streaming-first. Split-volume
  extraction uses shared split-state and chained-reader primitives. RAR 1.5-4.x
  and RAR5 both have named decoder sessions for stateful solid extraction.
- Shared domain vocabulary exists for archive members, split-volume state,
  fragment streams, semantic filter transforms, and decoder sessions. Keep
  adding abstractions only when new work proves the repeated concept.

## Priority Backlog

### 1. RAR 1.5-4.x Decoder Watchlist

- Find or generate a real RAR 2.50-authored Unpack20 audio-predictor fixture.
  Synthetic codec/archive coverage exists, but no promoted vintage archive has
  yet hit the true audio-block bit pattern at a fresh table-read boundary.
- Keep `FHD_LARGE` parser coverage synthetic until a real >4 GiB fixture is
  worth committing.
- Add adversarial PPMd fixtures as corpus bugs appear.
- Keep the libarchive mixed encrypted fixture as a partial oracle only for the
  RAR 3.93-validated `b.txt` member; its later `d.txt` member fails under the
  historical reference reader.

### 2. RAR 5.0/7.x Reader

- True Unpack70 remains fixture-blocked. Commit this only when a practical
  >4 GiB dictionary fixture is worth carrying.
- Add public reader-side recovery/repair APIs for RAR5 inline `RR` and `.rev`
  recovery data. Metadata parsing exists; reconstruction does not.

### 3. Writer Work

- Keep RAR 1.3/1.4 and RAR 1.5 writers stable; add tests only when new bugs or
  fixtures justify them.
- Improve the Unpack20 writer beyond the current bounded hash-chain baseline:
  broader solid and table-boundary stress coverage.
- Improve the Unpack29 writer beyond the current bounded hash-chain baseline:
  PPMd writing and richer real-data filter-placement heuristics.
- Improve RAR5 compressed-writer policy beyond the deterministic method-1
  bounded hash-chain baseline. Next useful work is better match/filter tuning,
  not new named writer entry points.
- Broaden RAR5 recovery writer repair oracles beyond stored/encrypted-stored
  payload damage: compressed payloads, header-encrypted archives, split-volume
  payloads, and heavier damage within the available recovery budget.
- Keep byte-identical WinRAR output out of scope for baseline writers; expose
  policy hooks so better heuristics can be added without changing wire writers.

### 4. API And Error Quality

- Continue enriching library errors with block type and broader operation
  context before treating the public API as stable.
- Keep low-level parsed format structs public for inspection, but mark them
  non-exhaustive so future encryption, recovery, and timestamp fields can be
  added without freezing the parser object model.
- Consider deprecating Vec-returning extraction APIs once integration tests and
  examples primarily use streaming APIs.
- Introduce a `Rar15_40Writer` builder only if another independent writer
  option axis lands there. Do not add cartesian named writer functions.
- Consider a shared auto-filter policy only if writer work proves RAR29 and
  RAR5 policy can share meaningful logic above their different wire records.
- Extract a cross-version decoder-session trait only if a real generic caller
  appears. The local RAR 1.5-4.x and RAR5 sessions are enough for now.

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
- Byte-identical compressor heuristics: filter selection, match-finder tuning,
  solid reset thresholds, and exact block partitioning.

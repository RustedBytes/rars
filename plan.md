# rars implementation plan

`rars` is a Rust RAR library and command line tool. The goal is broad format
coverage first: decode historical archives reliably, write valid archives for
selectable RAR versions, and keep compression policy separate from wire-format
serialization so byte-close WinRAR compatibility can improve incrementally.

## Architecture Rules

- Readers auto-detect archive families from signatures. Writers require an
  explicit target version and must validate requested features against it before
  emitting bytes.
- Streaming extraction is the primary API. `extract_to` and
  `extract_volumes_to` write to caller-provided sinks; Vec-returning helpers are
  convenience APIs for tests and small archives.
- Avoid cartesian-product writer APIs. New independent option axes should flow
  through builders/resolvers or policy types, not more named functions.
- Keep wire parsing/types version-specific where the formats really differ.
  Name shared domain concepts when they are real: members, split-volume state,
  fragment readers, filter transforms, and decoder sessions.
- Keep `rars-format` as the crate boundary for now, but split large family
  modules internally when a file starts mixing parsing, extraction, recovery,
  and writing in a way that hurts reviewability.
- Add failing tests before changing format or codec behaviour.

## Active Objectives

### 1. Compression Quality

- Keep RAR 1.3/1.4 compression parity-close with DOS RAR 1.402 `-m5`. Current
  output is close enough for baseline use; add tests only for new regressions or
  corpus bugs.
- Improve RAR29/RAR30/RAR40 policy quality beyond the current default auto
  selector. Remaining wins are likely filter-block boundary tuning, match-finder
  quality, lazy parsing, and PPMd tuning.
- Improve RAR5/RAR7 compressed-writer policy beyond the deterministic method-1
  bounded hash-chain baseline. RAR5 auto mode now considers ranged x86 filters;
  remaining useful work is audio/filter placement and match selection, not new
  writer entry points.
- Keep byte-identical WinRAR output out of scope for baseline writers. Reference
  parity means generated archives are accepted by relevant readers and extract
  to expected metadata/payloads.

### 2. RAR 1.5-4.x Reader And Recovery

- Keep `FHD_LARGE` parser coverage synthetic until a real >4 GiB fixture is
  worth committing.
- Add adversarial PPMd fixtures as corpus bugs appear.
- RAR 3 NewSub recovery repair currently supports stored recovery records only.
  A synthetic compressed-RR header fixture exists; implement compressed RR
  payload decoding before enabling repair for that case.
- Add or find a fixture demonstrating the `PROTECT_HEAD` stable repairable
  prefix when recovery metadata overlaps the protected prefix.
- Keep the libarchive mixed encrypted fixture as a partial oracle only for the
  RAR 3.93-validated `b.txt` member.

### 3. RAR 5.0/7.x Reader And Recovery

- True Unpack70 remains fixture-blocked. Commit this only when a practical
  >4 GiB dictionary fixture is worth carrying.
- Add heavier RAR5 recovery writer/repair oracles only where they cover a new
  damage shape or feature interaction not already exercised by current inline-RR
  and REV tests.
- Decide whether REV repair needs a streaming output API instead of returning
  all repaired volume files as `Vec<Vec<u8>>`.
- Split RAR5 REV parsing into metadata-only and payload-carrying forms if REV
  parse throughput or memory use matters.

### 4. API And Error Quality

- Continue enriching library errors with block type and operation context before
  treating the public API as stable.
- Keep low-level parsed format structs public for inspection, but mark them
  non-exhaustive before public stabilization.
- Consider deprecating Vec-returning extraction APIs once integration tests and
  examples primarily use streaming APIs.
- Introduce a `Rar15_40Writer` builder only if another independent writer option
  axis lands there.
- Extract a cross-version decoder-session trait only if a real generic caller
  appears.

### 5. Fixtures And Oracles

- Keep useful spec-repo fixtures copied into crate tests when they validate
  stable behaviour.
- Keep generated fixture inventories, `rars-generated` SHA tables, and RAR
  listing oracles covered by `scripts/verify-fixtures.py` when adding or
  regenerating fixtures.
- Use the reference scripts for optional local-oracle checks:
  `reference-rar5-writer.sh`, `reference-rar5-recovery-repair.sh`,
  `reference-rar29-rarvm-writer.sh`, and `reference-rar3-aes-writer.sh`.
- Use `./scripts/coverage.sh` periodically; it writes HTML coverage to
  `target/coverage/html/index.html`.

## Deferred

- Full cryptographic AV verification for RAR 1.4/2.x.
- AV writing.
- SFX writer/stub generation.
- Byte-identical compressor heuristics: exact filter selection, match-finder
  tuning, solid reset thresholds, and block partitioning.

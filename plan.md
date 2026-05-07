# rars implementation plan

`rars` is a Rust RAR library and command line tool. The goal is broad format
coverage first: decode historical archives reliably, write valid archives for
selectable RAR versions, and keep compression policy separate from wire-format
serialization.

## Working Rules

- Readers auto-detect archive families from signatures. Writers require an
  explicit target version.
- Streaming extraction is the primary API. `extract_to` and
  `extract_volumes_to` write to caller-provided sinks.
- Keep wire parsing/types version-specific where the formats differ. Share
  named domain concepts when they are real.
- Add failing tests before changing format or codec behaviour.

## Active Development

These are review, architecture, consistency, and refactoring tasks that can move
forward independently of compression benchmark harness work.

### 1. API And Error Model

- Apply the RAR5 builder pattern to RAR 1.5-4.x writing if another independent
  option axis lands there.
- Split `rars-cli/src/main.rs` into command modules when touching the CLI next.

### 2. RAR 1.5-4.x Reader And Recovery

- Add adversarial PPMd fixtures as corpus bugs appear.
- Keep the libarchive mixed encrypted fixture as a partial oracle only for the
  RAR 3.93-validated `b.txt` member.

### 3. RAR 5.0/7.x Reader And Recovery

- Keep the external Unpack70 large-dictionary oracle reproducible with
  `reference-rar70-large-dict.sh`; the generated sparse fixture stays outside
  the repository.
- Keep external-oracle coverage for RAR5 filter records: real RAR-created E8,
  E8E9, Delta, and ARM fixtures for reading, plus reference checks for
  rars-written filtered archives.

### 4. Refactoring

- Add comments/provenance for transliterated Unpack15 state names and embedded
  RAR3 standard-filter bytecode blobs.

## Optimization Track

Park these until the benchmark/test harness is ready.

- Improve RAR29/RAR30/RAR40 policy quality beyond the current default auto
  selector. Remaining wins are likely filter-block boundary tuning, match-finder
  quality, lazy parsing, and PPMd tuning.
- Improve RAR5/RAR7 compressed-writer policy beyond the deterministic method-1
  bounded hash-chain baseline. RAR5 auto mode now considers ranged x86 filters;
  remaining useful work is audio/filter placement and match selection.

## Productionization And Hardening

- Add streaming decryptors for encrypted payload paths. RAR15/20/30 and RAR5
  currently decrypt payload bytes into bounded in-memory buffers before feeding
  codecs because the cipher APIs are in-place.
- Reduce remaining codec-level buffers where the decoder state machines still
  require whole-member decode paths: encrypted RAR15/RAR20/RAR29 entries and
  any compressed split-volume path that must decrypt before chaining.
- Add fuzz targets for `Archive::parse`, `Unpack29::decode_member`, the PPMd
  decoder, and RARVM program parsing/execution. Seed them with the fixture
  corpus.
- Add rustdoc for the public `rars`, `rars-format`, and CLI-facing API before
  publishing.

## Fixtures And Oracles

- Keep useful spec-repo fixtures copied into crate tests when they validate
  stable behaviour.
- Use the reference scripts for optional local-oracle checks:
  `reference-rar5-writer.sh`, `reference-rar5-recovery-repair.sh`,
  `reference-rar29-rarvm-writer.sh`, `reference-rar3-aes-writer.sh`, and
  `reference-rar70-large-dict.sh`.
- Use `./scripts/coverage.sh` periodically; it writes HTML coverage to
  `target/coverage/html/index.html`.

## Deferred

- Full cryptographic AV verification for RAR 1.4/2.x.
- AV writing.
- SFX writer/stub generation.

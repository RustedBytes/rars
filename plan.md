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

## Active Objectives

### 1. Compression Quality

- Improve RAR29/RAR30/RAR40 policy quality beyond the current default auto
  selector. Remaining wins are likely filter-block boundary tuning, match-finder
  quality, lazy parsing, and PPMd tuning.
- Improve RAR5/RAR7 compressed-writer policy beyond the deterministic method-1
  bounded hash-chain baseline. RAR5 auto mode now considers ranged x86 filters;
  remaining useful work is audio/filter placement and match selection.

### 2. RAR 1.5-4.x Reader And Recovery

- Add adversarial PPMd fixtures as corpus bugs appear.
- Keep the libarchive mixed encrypted fixture as a partial oracle only for the
  RAR 3.93-validated `b.txt` member.

### 3. RAR 5.0/7.x Reader And Recovery

- True Unpack70 remains fixture-blocked until a practical >4 GiB dictionary
  fixture is worth carrying.

### 4. Hardening And Coverage

- Consider adding fuzz targets for `Archive::parse`, `Unpack29::decode_member`,
  and the PPMd decoder.

### 5. Fixtures And Oracles

- Keep useful spec-repo fixtures copied into crate tests when they validate
  stable behaviour.
- Use the reference scripts for optional local-oracle checks:
  `reference-rar5-writer.sh`, `reference-rar5-recovery-repair.sh`,
  `reference-rar29-rarvm-writer.sh`, and `reference-rar3-aes-writer.sh`.
- Use `./scripts/coverage.sh` periodically; it writes HTML coverage to
  `target/coverage/html/index.html`.

## Deferred

- Full cryptographic AV verification for RAR 1.4/2.x.
- AV writing.
- CLI module split into command-specific files once the next CLI feature needs
  non-trivial edits.
- SFX writer/stub generation.

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

### 1. Pre-release Hardening

- Make RAR5 large-output streaming handle filter records, or fall back to a
  documented bounded buffered path instead of rejecting filtered members above
  the streaming threshold.
- Audit extraction paths that still buffer decoded output despite the streaming
  API: sub-128 MiB RAR5 compressed members, RAR 1.5-4.x compressed members,
  encrypted entries, and compressed split-volume reassembly.

### 2. CLI Password And Repair UX

- Add tty password prompting when an encrypted command needs a password and no
  explicit password source was supplied. `--password-file` and `--password -`
  are implemented; keep documenting that `--password` is mainly for tests and
  explicit scripting because it can leak through process listings.
- Add a streaming recovery-repair API for large archives instead of returning
  only a full repaired `Vec<u8>`.

### 3. Compression Quality

- Improve RAR29/RAR30/RAR40 policy quality beyond the current default auto
  selector. Remaining wins are likely filter-block boundary tuning, match-finder
  quality, lazy parsing, and PPMd tuning.
- Improve RAR5/RAR7 compressed-writer policy beyond the deterministic method-1
  bounded hash-chain baseline. RAR5 auto mode now considers ranged x86 filters;
  remaining useful work is audio/filter placement and match selection.

### 4. RAR 1.5-4.x Reader And Recovery

- Add adversarial PPMd fixtures as corpus bugs appear.
- Keep the libarchive mixed encrypted fixture as a partial oracle only for the
  RAR 3.93-validated `b.txt` member.
- Rename or reshape authenticity-verification APIs so structural AV presence is
  not confused with cryptographic verification.

### 5. RAR 5.0/7.x Reader And Recovery

- Keep the external Unpack70 large-dictionary oracle reproducible with
  `reference-rar70-large-dict.sh`; the generated sparse fixture stays outside
  the repository.
- Keep external-oracle coverage for RAR5 filter records: real RAR-created E8,
  E8E9, Delta, and ARM fixtures for reading, plus reference checks for
  rars-written filtered archives.

### 6. API And Error Model

- Pick one `extract_to` shape across the facade and per-version modules.
- Widen facade-level extracted file attributes to `u64` so RAR5 attributes do
  not need a synthetic overflow error.
- Rework `rars-format::Error::Io` so callers can inspect at least
  `io::ErrorKind`, and consider preserving structured codec/recovery/crypto
  errors instead of flattening them all to `InvalidHeader`.
- Decide whether the umbrella `ArchiveWriter` should remain public or whether
  callers should use per-version writer builders directly.
- Apply the RAR5 builder pattern to RAR 1.5-4.x writing if another independent
  option axis lands there.
- Refactor `cmd_add` into a parsed write plan plus one dispatcher, then split
  `rars-cli/src/main.rs` into command modules when touching the CLI next.

### 7. Crypto And Secret Handling

- Replace straight RAR5 SHA-256/HMAC code with audited `sha2`/`hmac` crates
  unless a format-specific hook is identified, and add WinRAR-derived KDF known
  answer tests.
- Add direct equivalence tests for the RAR3/RAR4 AES KDF fast and slow paths, or
  remove the fast path.
- Add `zeroize` for passwords, derived keys, AES state, and temporary KDF
  buffers where ownership makes that practical.
- Tighten low-level crypto APIs that expose block primitives unnecessarily
  (for example RAR3 AES block encrypt/decrypt should be private or take
  `&mut [u8; 16]`).

### 8. Hardening And Coverage

- Add fuzz targets for `Archive::parse`, `Unpack29::decode_member`, the PPMd
  decoder, and RARVM program parsing/execution. Seed them with the fixture
  corpus.
- Add rustdoc for the public `rars`, `rars-format`, and CLI-facing API before
  publishing.
- Confirm the workspace `repository` field before publishing.
- Add comments/provenance for transliterated Unpack15 state names and embedded
  RAR3 standard-filter bytecode blobs.
- Split `rars-recovery/src/lib.rs` into `rar3.rs` and `rar5.rs` modules.
- Add a note or explicit zero handling around `Gf16` multiplication so its
  zero-result behaviour does not depend silently on over-allocated tables.

### 9. Fixtures And Oracles

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

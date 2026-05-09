# rars plan

## Hardening

- Verify RAR 2.x `PROTECT_HEAD` parity semantics when the declared protected
  range extends past the recovery block. Add an oracle fixture if possible;
  either repair those overlap sectors correctly or document the unsupported
  layout explicitly.
- Pin an exact RAR3 AES KDF vector for long password material that forces the
  custom SHA-1 block path, not just round-trip encryption/decryption.
- Add adversarial PPMd fixtures as corpus bugs appear.
- Harden PPMd hostile-state arithmetic paths (`make_esc_freq`,
  `update_model`) with focused malformed-stream regression tests.
- Add fuzz targets for `Archive::parse`, `Unpack29::decode_member`, PPMd decode,
  and RARVM program parsing/execution.

## Compression Work

- Revisit RAR 1.4 old-distance token emission with DOS RAR 1.402 oracle
  coverage. The writer currently avoids that compatibility-sensitive
  vocabulary and relies on repeat-last, short-LZ, and long-LZ matches.
- Improve RAR 1.4 compressed-writer quality after the DOS compatibility path
  is stable: match selection, safe old-distance reuse, and text-heavy corpus
  tuning.
- Add WinRAR 2.90 oracle coverage before enabling RAR20 repeat-distance,
  old-distance, short-distance, or audio writer tokens. The current writer
  deliberately emits only literals and fresh LZ matches.
- Improve RAR29/RAR30/RAR40 max-level policy after `--level` is wired:
  filter-block boundary tuning, match-finder quality, and PPMd tuning against
  WinRAR 2.90/3.x/4.x oracles.
- Improve RAR50/RAR70 level policy beyond wire-level method stamping:
  match-finder effort, incompressible-member store fallback, and filter
  selection should be tuned against WinRAR 6.x/7.x oracles.
- Add RAR7-specific writer policy once fixtures/oracles identify useful
  version-7-only behaviour. RAR70 currently uses the RAR5 writer shape and
  emits byte-identical archives for the benchmark corpus.
- Add an explicit dictionary-size writer option and CLI knob once oracle data
  shows which legacy targets should default above the current per-target
  mapping.
- Refine non-zero `--level` mappings for RAR13/RAR15 after the bench
  harness reports which policy differences matter.
- Add real RAR-created RAR5 filter fixtures for E8, E8E9, Delta, and ARM
  reader coverage.

## Optional Oracles

- Keep stable spec-repo fixtures copied into crate tests when they validate
  stable behaviour.
- Maintain local oracle scripts:
  `reference-rar5-writer.sh`, `reference-rar5-recovery-repair.sh`,
  `reference-rar29-rarvm-writer.sh`, `reference-rar3-aes-writer.sh`, and
  `reference-rar70-large-dict.sh`.
- Run `./scripts/coverage.sh` periodically.

## Deferred

- Split `rars-cli/src/main.rs` into command modules when the CLI is next edited
  heavily.
- Define legacy byte-encoding policy for RAR3 passwords and archive names.
  Avoid silent `from_utf8_lossy` derivation; either reject non-UTF-8 bytes
  clearly or implement the intended legacy byte-to-wide/code-page mapping.
- Add a RAR 1.5-4.x writer builder only if another independent option axis
  lands there.
- Keep `reference-rar70-large-dict.sh` reproducible for external Unpack70
  large-dictionary checks. The generated sparse fixture stays outside the repo.
- Keep the libarchive mixed encrypted fixture as a partial oracle for the
  RAR 3.93-validated `b.txt` member.
- Full cryptographic AV verification for RAR 1.4/2.x.
- AV writing.
- SFX writer/stub generation.

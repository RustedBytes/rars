# rars plan

## Active Tasks

- Add adversarial PPMd fixtures as corpus bugs appear.
- Add real RAR-created RAR5 filter fixtures for E8, E8E9, Delta, and ARM
  reader coverage.
- Keep `reference-rar70-large-dict.sh` reproducible for external Unpack70
  large-dictionary checks. The generated sparse fixture stays outside the repo.
- Keep the libarchive mixed encrypted fixture as a partial oracle for the
  RAR 3.93-validated `b.txt` member.
- Split `rars-cli/src/main.rs` into command modules when the CLI is next edited
  heavily.
- Add a RAR 1.5-4.x writer builder only if another independent option axis
  lands there.

## Optimization

- Improve RAR29/RAR30/RAR40 writer policy beyond the current default auto
  selector: filter-block boundary tuning, match-finder quality, lazy parsing,
  and PPMd tuning.
- Improve RAR5/RAR7 compressed-writer policy beyond the deterministic method-1
  bounded hash-chain baseline: audio/filter placement and match selection.

## Hardening

- Add streaming decryptors for encrypted payload paths.
- Reduce remaining whole-member codec buffers for encrypted RAR15/RAR20/RAR29
  entries and compressed split-volume decrypt-before-chain paths.
- Add fuzz targets for `Archive::parse`, `Unpack29::decode_member`, PPMd decode,
  and RARVM program parsing/execution.

## Optional Oracles

- Keep stable spec-repo fixtures copied into crate tests when they validate
  stable behaviour.
- Maintain local oracle scripts:
  `reference-rar5-writer.sh`, `reference-rar5-recovery-repair.sh`,
  `reference-rar29-rarvm-writer.sh`, `reference-rar3-aes-writer.sh`, and
  `reference-rar70-large-dict.sh`.
- Run `./scripts/coverage.sh` periodically.

## Deferred

- Full cryptographic AV verification for RAR 1.4/2.x.
- AV writing.
- SFX writer/stub generation.

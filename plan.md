# rars plan

## Hardening
- Add adversarial PPMd fixtures as corpus bugs appear.

## Optional Oracles

- Keep stable spec-repo fixtures copied into crate tests when they validate
  stable behaviour.
- Maintain local oracle scripts:
  `reference-rar5-writer.sh`, `reference-rar5-recovery-repair.sh`,
  `reference-rar14-writer.sh`, `reference-rar20-writer.sh`,
  `reference-rar29-rarvm-writer.sh`, `reference-rar29-level-writer.sh`,
  `reference-rar3-aes-writer.sh`, and `reference-rar70-large-dict.sh`.
- Run `./scripts/coverage.py` periodically.

## Deferred

- Add a RAR 1.5-4.x writer builder only if another independent option axis
  lands there.
- Keep `reference-rar70-large-dict.sh` reproducible for external Unpack70
  large-dictionary checks. The generated sparse fixture stays outside the repo.
- Keep the libarchive mixed encrypted fixture as a partial oracle for the
  RAR 3.93-validated `b.txt` member.
- Full cryptographic AV verification for RAR 1.4/2.x.
- AV writing.
- SFX writer/stub generation.

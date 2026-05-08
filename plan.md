# rars plan

## Active Tasks

- Review pass 3, batch 5: RAR5 extraction/parser correctness.
  - Add a corrupt encrypted-padding regression and validate discarded RAR5
    decrypted padding bytes.
  - Move RAR5 streaming repeated-byte CRC/hash accounting so it only advances
    after bytes are successfully written to the caller sink.
  - Make REV5 metadata parsing use slice reads and tolerate trailing
    forward-compatible metadata bytes.
  - Validate minimum sizes for legacy AV/SIGN blocks even when their header
    CRCs are intentionally not trusted.
- Review pass 3, batch 6: codec hardening and state hygiene.
  - Reduce the RAR29 filtered-range O(N^2) filter clone pattern.
  - Add an explicit non-solid reset API or guard for reusable `Unpack29`
    decoder instances.
  - Align filter validation edges: cap DELTA decode channel counts, document
    the Itanium tail requirement, and reject malformed RGB register values
    before applying the filter.
- Review pass 3, batch 7: API and resource cleanup.
  - Preserve `std::io::Error` sources instead of flattening them to strings.
  - Remove the unnecessary `Result` wrapper from total facade metadata
    conversions.
  - Add owned-buffer parse entry points or equivalent plumbing to avoid
    cloning caller-owned archive bytes.
  - Decide whether RAR5 recovery repair needs a streaming sector path before
    large-archive repair is considered production-ready.
- Review pass 3, batch 8: workspace, scripts, and remaining test polish.
  - Add workspace MSRV/dependency/docs metadata suitable for publishing.
  - Add uniform tool prechecks to oracle scripts and make coverage keep
    running after individual test failures.
  - Continue consolidating CLI writer round-trip helpers and add exact byte
    assertions to the remaining representative writer families.
  - Tighten password-error CLI probes so they assert the diagnostic, not only
    non-zero exit status.
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

# rars plan

## Active Tasks

- Review pass 2, batch 1:
  - Guard PPMd range decoding against `total == 0`; add a malformed-stream
    regression.
  - Fix RARVM output range validation so an exclusive end at `MEMORY_SIZE` is
    accepted; add a boundary regression.
  - Verify RARVM zero-count shifts against the spec and fix the VM if they are
    no-ops; add a regression either way.
  - Bound Itanium filter loops by data position as well as encoded file offset;
    add a termination regression.
  - Make RAR5 `FileHeader::verify_crc32` reject encrypted entries without MAC
    keys, or route encrypted integrity checks through the keyed verifier.
- Review pass 2, batch 2:
  - Protect CLI extraction from pre-existing symlinks inside the output
    directory.
  - Make RAR20 cipher encrypt/decrypt reject partial 16-byte tails instead of
    leaving them unchanged.
  - Enforce an explicit PPMd model/context memory cap from the dictionary-size
    header.
  - Mark remaining public writer option structs `#[non_exhaustive]`.
- Review pass 2, batch 3:
  - Replace fuzz-bait slice-to-array `unwrap()` sites in recovery/header parsing
    with checked errors where the input is archive-controlled.
  - Add pinned known-answer tests for RAR 1.3, RAR 1.5, RAR 2.0, and RAR 3.x
    ciphers.
  - Add a RAR5 encrypted integrity API regression covering the public
    `verify_crc32`/`verify_integrity` path.
  - Add tests for file-backed encrypted-header parsing.
- Review pass 2, release polish:
  - Add rustdoc for the public `rars`, `rars-format`, and CLI-facing APIs before
    publishing.
  - Add Cargo package metadata required for publication.
  - Decide whether ignored oracle tests should read tool paths from environment
    variables and skip cleanly when unavailable.
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
- Add rustdoc for the public `rars`, `rars-format`, and CLI-facing APIs before
  publishing.

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

# rars plan

## Hardening
- Verify RAR 2.x `PROTECT_HEAD` parity semantics when the declared protected
  range extends past the recovery block. Add an oracle fixture if possible;
  either repair those overlap sectors correctly or document the unsupported
  layout explicitly.
- Add adversarial PPMd fixtures as corpus bugs appear.
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
- Tune RAR29/RAR30/RAR40 lower-level policy: `m5` is already strong, and
  cost-aware lazy lookahead, repeat-distance candidates, dictionary-bounded
  match search, multi-range x86 filtering, ranged Delta filtering, and
  `m1..m4` LZ-filter auto policy are present.
  Remaining work is deeper filter-block boundary tuning and match-finder
  strategy against WinRAR 2.90/3.x/4.x oracles.
- Reintroduce RAR29/RAR30/RAR40 frequency-weighted Huffman lengths only with
  independent decoder-oracle coverage. The current writer deliberately uses
  uniform LZ Huffman tables after weighted Main tables produced streams that
  rars could decode but `rar` rejected on real recompress payloads.
- Improve RAR50/RAR70 ratio policy beyond the current baseline. Wire-level
  method stamping, stored fallback, lazy matching, state-aware match costs,
  repeat-distance candidates, bounded cost-aware lookahead, frequency-weighted
  Huffman lengths, dictionary sizing, multi-range x86 filtering, ranged Delta
  filtering, and conservative solid reset policy are present. Remaining work is
  deeper optimal parsing and oracle-guided filter range tuning against WinRAR
  6.x/7.x oracles.
- Add split-aware RAR50/RAR70 filtered-block writing. Auto-filter currently
  falls back to unfiltered split blocks for members larger than 4 MiB, and
  explicit filters reject those large members rather than writing streams that
  external decoders corrupt.
- Expand RAR7-specific writer policy beyond the current dictionary-field
  upgrade path. RAR70 now uses v1 compression-info fields when `--dict-size`
  cannot be represented as RAR5 v0, with writer and CLI coverage, but the
  default benchmark corpus still emits RAR5-compatible streams.
- Refine non-zero `--level` mappings for RAR13/RAR15 after the bench
  harness reports which policy differences matter.

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

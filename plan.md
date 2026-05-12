# rars plan

## Hardening
- Add adversarial PPMd fixtures as corpus bugs appear.

## Compression Work

- Tune RAR29/RAR30/RAR40 lower-level policy: `m5` is already strong, and
  cost-aware lazy lookahead, repeat-distance candidates, dictionary-bounded
  match search, multi-range x86 filtering, ranged Delta filtering, and
  `m1..m4` LZ-filter auto policy are present.
  Remaining work is deeper filter-block boundary tuning and match-finder
  strategy against WinRAR 2.90/3.x/4.x oracles.
- Improve RAR20/RAR29 audio-filter policy after correctness is stable. RAR29
  auto now gates AUDIO candidates with a cheap PCM-shape test before paying for
  full filter encoding, and RAR20 can emit frequency-weighted audio blocks when
  they beat LZ. The `BoatModernEnglish` RAR20 fixture is no longer a regression;
  remaining work is oracle-guided tuning for hybrid audio/LZ switching on PCM
  fixtures and other wild audio regressions.
- Improve RAR50/RAR70 ratio policy beyond the current baseline. Wire-level
  method stamping, stored fallback, lazy matching, state-aware match costs,
  repeat-distance candidates, bounded cost-aware lookahead, frequency-weighted
  Huffman lengths, dictionary sizing, multi-range x86 filtering, ranged Delta
  filtering, and conservative solid reset policy are present. Remaining work is
  deeper optimal parsing and oracle-guided filter range tuning against WinRAR
  6.x/7.x oracles.
- Refine non-zero `--level` mappings for RAR13/RAR15 after the bench
  harness reports which policy differences matter.

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

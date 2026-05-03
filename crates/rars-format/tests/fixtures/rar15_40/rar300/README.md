# RAR 3.00 Container Fixtures

RAR 3.00 fixtures for the RAR 1.5-4.x container. Most files are copied from the
spec repository's `fixtures/1.5-4.x/rar300/` and `fixtures/rarvm/archives-rar300/`
sets; several compact multivolume and solid fixtures are local regression
cases.

| Fixture group | Purpose |
|---|---|
| `with_comment_rar300.rar` | Stored `hello.txt` plus RAR 3.x archive comment subblock. |
| `header_encrypted_multivol_rar300*`, `header_encrypted_newnaming_rar300*` | Header-encrypted old/new-numbered multi-volume extraction. |
| `compressed_text_rar300.rar` | Basic Unpack29 LZ compressed text member. |
| `solid_rar300.rar`, `solid_simple_rar300.rar` | Solid Unpack29 state and table reuse. |
| `multivol_*_rar300*` | Old/new RAR 3 volume naming flags and split-file extraction. |
| `stored_multivol_rar300*`, `compressed_multivol_prng_rar300*`, `encrypted_multivol_rar300*`, `encrypted_newnaming_rar300*` | Streaming stored, compressed, and AES-encrypted split-volume extraction. |
| `rarvm_*_rar300.rar` | Standard RARVM filters: E8, E8E9, DELTA, ITANIUM, RGB, AUDIO. |

Expected payloads and CRCs are asserted directly in
`rar15_40_fixtures.rs`.

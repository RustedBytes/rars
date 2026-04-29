use rars_format::rar15_40::{crc32, Archive};
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar15_40/ppmd")
        .join(name)
}

#[test]
fn ppmd_block_can_emit_embedded_lz_distance_matches() {
    let expected = std::fs::read(fixture("ppmd_lz_match.txt")).unwrap();
    let archive = Archive::parse_path(fixture("ppmd_lz_match_rar300.rar")).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"repeated_phrase_64k.txt");
    assert_eq!(files[0].method, 0x35);
    assert_eq!(files[0].unp_ver, 29);
    assert_eq!(files[0].pack_size, 193);
    assert_eq!(files[0].unp_size, 44_544);
    assert_eq!(files[0].file_crc, 0x884fab33);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, expected);
    assert_eq!(crc32(&extracted[0].data), 0x884fab33);
}

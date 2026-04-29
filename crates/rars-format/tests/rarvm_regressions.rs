use rars_format::rar15_40::Archive;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar15_40/rarvm")
        .join(name)
}

#[test]
fn solid_e8_filters_use_member_relative_offsets() {
    let expected_lead = std::fs::read(fixture("solid_e8_filter_lead.txt")).unwrap();
    let expected_exe = std::fs::read(fixture("solid_e8_filter_payload.exe")).unwrap();
    let archive = Archive::parse_path(fixture("solid_e8_filter_member_offset.rar")).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"lead.txt");
    assert_eq!(files[0].pack_size, 76);
    assert_eq!(files[0].unp_size, 800);
    assert_eq!(files[1].name, b"tiny_e8e9.exe");
    assert_eq!(files[1].pack_size, 295);
    assert_eq!(files[1].unp_size, 5_884);
    assert!(files[1].is_solid());

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, expected_lead);
    assert_eq!(extracted[1].data, expected_exe);
}

#[test]
fn vm_filter_control_stream_accepts_32_bit_encoded_integers() {
    let archive = Archive::parse_path(fixture("vm_encoded_u32_filter.rar")).unwrap();
    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"bsdcat.exe");

    let mut extracted = Vec::new();
    archive
        .extract_to(|meta| {
            extracted.push(meta.name.clone());
            Ok(Box::new(std::io::sink()))
        })
        .unwrap();

    assert_eq!(extracted, vec![b"bsdcat.exe".to_vec()]);
}

use rars_format::rar15_40::Archive;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar15_40/rarvm")
        .join(name)
}

#[test]
fn solid_exe_e8e9_filters_use_member_relative_offsets() {
    let archive = Archive::parse_path(fixture("solid_exe_e8e9_offsets.rar")).unwrap();
    assert!(archive.main.is_solid());

    let mut saw_exe = false;
    archive
        .extract_to(|meta| {
            if meta.name == b"Far.exe" {
                saw_exe = true;
            }
            Ok(Box::new(std::io::sink()))
        })
        .unwrap();

    assert!(saw_exe);
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

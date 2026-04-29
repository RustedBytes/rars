use rars_format::rar50::Archive;
use rars_format::{detect_archive_family, ArchiveFamily, Error};
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar50")
        .join(name)
}

#[test]
fn detects_rar50_signature_family() {
    let bytes = std::fs::read(fixture("stored.rar")).unwrap();
    let sig = detect_archive_family(&bytes).unwrap();

    assert_eq!(sig.family, ArchiveFamily::Rar50Plus);
    assert_eq!(sig.offset, 0);
    assert_eq!(sig.length, 8);
}

#[test]
fn parses_and_extracts_rar50_stored_file() {
    let bytes = std::fs::read(fixture("stored.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(archive.sfx_offset, 0);
    assert_eq!(archive.main.archive_flags, 0);

    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"hello.txt");
    assert!(files[0].is_stored());
    assert_eq!(files[0].packed_size(), 30);
    assert_eq!(files[0].unpacked_size, 30);
    assert_eq!(files[0].data_crc32, Some(0x83b2_7227));
    assert_eq!(files[0].attributes, 0x20);
    assert_eq!(files[0].host_os, 0);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"hello.txt");
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

#[test]
fn parses_and_extracts_rar50_stored_file_from_path() {
    let archive = Archive::parse_path(fixture("stored.rar")).unwrap();

    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"hello.txt");
    assert_eq!(files[0].packed_size(), 30);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

#[test]
fn extracts_rar50_empty_file_with_blake2_hash_record() {
    let bytes = std::fs::read(fixture("empty_file.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"empty.bin");
    assert!(file.is_stored());
    assert_eq!(file.packed_size(), 0);
    assert_eq!(file.unpacked_size, 0);
    assert_eq!(file.data_crc32, None);
    assert_eq!(file.hash.as_ref().unwrap().hash_type, 0);
    assert_eq!(file.hash.as_ref().unwrap().data.len(), 32);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"empty.bin");
    assert!(extracted[0].data.is_empty());
}

#[test]
fn parses_rar50_multifile_stored_archive() {
    let bytes = std::fs::read(fixture("multifile.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 3);
    assert_eq!(files[0].name, b"hello.txt");
    assert_eq!(files[1].name, b"tiny.txt");
    assert_eq!(files[2].name, b"random_4k.bin");
    assert!(files.iter().all(|file| file.is_stored()));
    assert_eq!(files[0].packed_size(), 30);
    assert_eq!(files[1].packed_size(), 9);
    assert_eq!(files[2].packed_size(), 4096);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 3);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
    assert_eq!(extracted[1].data, b"AAAAAAAA\n");
    assert_eq!(extracted[2].data.len(), 4096);
}

#[test]
fn rejects_corrupt_rar50_header_checksum() {
    let mut bytes = std::fs::read(fixture("stored.rar")).unwrap();
    bytes[13] ^= 0x01;

    assert!(matches!(
        Archive::parse(&bytes),
        Err(Error::Crc32Mismatch { .. })
    ));
}

#[test]
fn rejects_corrupt_rar50_stored_payload_checksum_when_crc32_is_present() {
    let mut bytes = std::fs::read(fixture("stored.rar")).unwrap();
    let needle = b"Hello, RAR 5.0 fixture world.\n";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("stored payload in fixture");
    bytes[offset] ^= 0x01;
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(
        archive.extract(),
        Err(Error::Crc32Mismatch { .. })
    ));
}

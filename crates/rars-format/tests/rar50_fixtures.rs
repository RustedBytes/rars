use rars_codec::rar50::{decode_lz, parse_compressed_block, read_table_lengths, DecodeTables};
use rars_format::rar50::{extract_volumes, Archive};
use rars_format::{detect_archive_family, ArchiveFamily, Error};
use std::io::Write;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar50")
        .join(name)
}

fn service_names(archive: &Archive) -> Vec<String> {
    archive
        .services()
        .map(|service| service.name_lossy())
        .collect()
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
    assert_eq!(archive.main.extras.len(), 1);
    let locator = archive.main.locator().unwrap();
    assert_eq!(locator.flags, 0x0001);
    assert_eq!(locator.quick_open_offset, Some(0));
    assert_eq!(locator.recovery_record_offset, None);

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
fn decrypts_rar50_crc32_mac_file_with_password() {
    let bytes = std::fs::read(fixture("password_crc32.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"hello.txt");
    assert!(files[0].encrypted);
    assert_eq!(files[0].packed_size(), 48);
    assert!(matches!(
        archive.extract(),
        Err(Error::AtEntry {
            name,
            operation: "decoding",
            source
        }) if name == b"hello.txt" && matches!(*source, Error::NeedPassword)
    ));

    let extracted = archive.extract_with_password(Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

#[test]
fn decrypts_rar50_blake2_mac_file_with_password() {
    let bytes = std::fs::read(fixture("password_aes.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"hello.txt");
    assert!(files[0].encrypted);

    let extracted = archive.extract_with_password(Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

#[test]
fn rejects_wrong_password_for_rar50_encrypted_file() {
    let bytes = std::fs::read(fixture("password_crc32.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(
        archive.extract_with_password(Some(b"wrong")),
        Err(Error::AtEntry {
            name,
            operation: "decoding",
            source
        }) if name == b"hello.txt" && matches!(*source, Error::WrongPasswordOrCorruptData)
    ));
}

#[test]
fn rejects_rar50_header_encrypted_archive_until_head_crypt_lands() {
    let bytes = std::fs::read(fixture("header_encrypted.rar")).unwrap();

    assert!(matches!(
        Archive::parse(&bytes),
        Err(Error::UnsupportedFeature {
            version: rars_format::ArchiveVersion::Rar50,
            feature: "RAR 5 encrypted headers"
        })
    ));
}

#[test]
fn extract_to_reports_rar50_entry_context_on_write_failure() {
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("sink failed"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let bytes = std::fs::read(fixture("stored.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(
        archive.extract_to(|_| Ok(Box::new(FailingWriter))),
        Err(Error::AtEntry {
            name,
            operation: "writing",
            source
        }) if name == b"hello.txt" && matches!(*source, Error::Io(_))
    ));
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
fn parses_rar50_sfx_prefixed_stored_file() {
    let mut bytes = b"small fake sfx prefix".to_vec();
    bytes.extend_from_slice(&std::fs::read(fixture("stored.rar")).unwrap());
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(archive.sfx_offset, b"small fake sfx prefix".len());
    assert_eq!(archive.main.block.offset, archive.sfx_offset + 8);
    assert_eq!(archive.main.locator().unwrap().quick_open_offset, Some(0));

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
fn verifies_rar50_blake2_hash_record_on_stored_file() {
    let archive = Archive::parse_path(fixture("stored_blake2.rar")).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"hello.txt");
    assert_eq!(file.data_crc32, None);
    assert_eq!(file.hash.as_ref().unwrap().hash_type, 0);
    assert_eq!(file.hash.as_ref().unwrap().data.len(), 32);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

#[test]
fn rejects_corrupt_rar50_stored_payload_hash_when_blake2_is_present() {
    let mut bytes = std::fs::read(fixture("stored_blake2.rar")).unwrap();
    let needle = b"Hello, RAR 5.0 fixture world.\n";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("stored payload in fixture");
    bytes[offset] ^= 0x01;
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(
        archive.extract(),
        Err(Error::AtEntry {
            name,
            operation: "verifying",
            source
        }) if name == b"hello.txt" && matches!(*source, Error::HashMismatch { hash_type: 0 })
    ));
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
fn extracts_rar50_solid_archive() {
    let archive = Archive::parse_path(fixture("solid.rar")).unwrap();

    assert!(archive.main.is_solid());
    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 2);
    assert!(files
        .iter()
        .any(|file| file.decoded_compression_info().unwrap().solid));

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 2);
    assert!(extracted.iter().all(|entry| !entry.data.is_empty()));
}

#[test]
fn rar50_solid_extraction_uses_file_compression_info_flag() {
    let mut archive = Archive::parse_path(fixture("solid.rar")).unwrap();
    archive.main.archive_flags = 0;

    assert!(!archive.main.is_solid());
    assert!(archive
        .files()
        .any(|file| file.decoded_compression_info().unwrap().solid));

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 2);
    assert!(extracted.iter().all(|entry| !entry.data.is_empty()));
}

#[test]
fn extracts_rar50_compressed_multivolume_archive() {
    let volumes = [
        Archive::parse_path(fixture("multivol.part1.rar")).unwrap(),
        Archive::parse_path(fixture("multivol.part2.rar")).unwrap(),
        Archive::parse_path(fixture("multivol.part3.rar")).unwrap(),
    ];

    assert!(volumes.iter().all(|archive| archive.main.is_volume()));
    assert!(volumes[0].files().next().unwrap().is_split_after());
    assert!(volumes[1].files().next().unwrap().is_split_before());
    assert!(volumes[1].files().next().unwrap().is_split_after());
    assert!(volumes[2].files().next().unwrap().is_split_before());
    assert!(!volumes[2].files().next().unwrap().is_split_after());

    let extracted = extract_volumes(&volumes).unwrap();

    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"random_4k.bin");
    assert_eq!(extracted[0].data.len(), 4096);
}

#[test]
fn decodes_rar50_compression_info_bitfield() {
    let stored = Archive::parse_path(fixture("stored.rar")).unwrap();
    let stored_file = stored.files().next().unwrap();
    let info = stored_file.decoded_compression_info().unwrap();
    assert_eq!(info.algorithm_version, 0);
    assert_eq!(info.method, 0);
    assert!(!info.solid);
    assert_eq!(info.dictionary_fraction, 0);
    assert!(!info.rar5_compat);

    for (name, method) in [
        ("m1_fastest.rar", 1),
        ("m3_default.rar", 3),
        ("m5_max.rar", 5),
    ] {
        let archive = Archive::parse_path(fixture(name)).unwrap();
        let file = archive.files().next().unwrap();
        let info = file.decoded_compression_info().unwrap();
        assert_eq!(info.algorithm_version, 0, "{name}");
        assert_eq!(info.method, method, "{name}");
        assert!(!info.solid, "{name}");
        assert_eq!(info.dictionary_fraction, 0, "{name}");
        assert!(!info.rar5_compat, "{name}");
        assert!(info.dictionary_size >= 128 * 1024, "{name}");
    }
}

#[test]
fn parses_rar50_comment_service_archive() {
    let archive = Archive::parse_path(fixture("with_comment.rar")).unwrap();

    assert_eq!(archive.files().count(), 1);
    assert_eq!(service_names(&archive), ["CMT"]);
    let comment = archive.services().next().unwrap();
    assert_eq!(comment.packed_size(), 30);
    assert_eq!(comment.unpacked_size, 30);
    assert!(comment.is_stored());
}

#[test]
fn parses_rar50_quick_open_service_archive() {
    let archive = Archive::parse_path(fixture("with_quickopen.rar")).unwrap();

    assert_eq!(archive.files().count(), 2);
    assert_eq!(service_names(&archive), ["QO"]);
    let quick_open = archive.services().next().unwrap();
    assert_eq!(quick_open.packed_size(), 162);
    assert_eq!(quick_open.unpacked_size, 162);
    assert!(quick_open.is_stored());
}

#[test]
fn parses_rar50_recovery_service_archive() {
    let archive = Archive::parse_path(fixture("with_recovery.rar")).unwrap();

    assert!(archive.main.has_recovery_record());
    assert_eq!(archive.files().count(), 1);
    assert_eq!(service_names(&archive), ["RR"]);
    let recovery = archive.services().next().unwrap();
    assert_eq!(recovery.packed_size(), 210);
    assert_eq!(recovery.unpacked_size, 210);
}

#[test]
fn parses_rar50_mixed_service_archive() {
    let archive = Archive::parse_path(fixture("with_all_services.rar")).unwrap();

    assert!(archive.main.has_recovery_record());
    assert_eq!(archive.files().count(), 2);
    assert_eq!(service_names(&archive), ["CMT", "QO", "RR"]);
    let services: Vec<_> = archive.services().collect();
    assert_eq!(services[0].packed_size(), 30);
    assert_eq!(services[1].packed_size(), 162);
    assert_eq!(services[2].packed_size(), 526);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
    assert_eq!(extracted[1].data, b"AAAAAAAA\n");
}

#[test]
fn extracts_rar50_compressed_members() {
    for name in ["m1_fastest.rar", "m3_default.rar", "m5_max.rar"] {
        let archive = Archive::parse_path(fixture(name)).unwrap();
        let files: Vec<_> = archive.files().collect();

        assert_eq!(files.len(), 1, "{name}");
        assert!(!files[0].is_stored(), "{name}");
        let extracted = archive.extract().unwrap();
        assert_eq!(extracted.len(), 1, "{name}");
        assert_eq!(
            extracted[0].data.len(),
            files[0].unpacked_size as usize,
            "{name}"
        );
    }
}

#[test]
fn parses_real_rar50_compressed_block_framing() {
    let archive = Archive::parse_path(fixture("m1_fastest.rar")).unwrap();
    let file = archive.files().next().unwrap();
    let packed = file.packed_data(&archive).unwrap();

    let block = parse_compressed_block(&packed).unwrap();

    assert_eq!(block.payload.start, block.header_len);
    assert!(block.payload.end <= packed.len());
    assert!(block.header.has_tables);
    assert!(block.header.payload_size > 0);
    assert!(block.header.payload_bits <= block.header.payload_size * 8);
}

#[test]
fn parses_real_rar50_compressed_block_tables() {
    let archive = Archive::parse_path(fixture("m1_fastest.rar")).unwrap();
    let file = archive.files().next().unwrap();
    let info = file.decoded_compression_info().unwrap();
    let packed = file.packed_data(&archive).unwrap();
    let block = parse_compressed_block(&packed).unwrap();
    let payload = &packed[block.payload];

    assert!(block.header.has_tables);
    let (lengths, table_bits) = read_table_lengths(payload, info.algorithm_version).unwrap();
    let tables = DecodeTables::from_lengths(&lengths).unwrap();

    assert!(table_bits < block.header.payload_bits);
    assert!(!tables.main.is_empty());
    assert!(!tables.distance.is_empty());
    assert!(!tables.length.is_empty());
}

#[test]
fn decodes_rar50_m1_fastest_with_lz_codec() {
    let archive = Archive::parse_path(fixture("m1_fastest.rar")).unwrap();
    let file = archive.files().next().unwrap();
    let info = file.decoded_compression_info().unwrap();
    let packed = file.packed_data(&archive).unwrap();

    let decoded = decode_lz(&packed, info.algorithm_version, file.unpacked_size as usize).unwrap();

    file.verify_integrity(&decoded).unwrap();
}

#[test]
fn extracts_rar50_filter_candidate_members() {
    for name in [
        "filter_arm.rar",
        "filter_delta.rar",
        "filter_e8.rar",
        "filter_e8e9.rar",
    ] {
        let archive = Archive::parse_path(fixture(name)).unwrap();
        let files: Vec<_> = archive.files().collect();

        assert_eq!(files.len(), 1, "{name}");
        assert!(!files[0].is_stored(), "{name}");
        let extracted = archive.extract().unwrap();
        assert_eq!(extracted.len(), 1, "{name}");
        assert_eq!(
            extracted[0].data.len(),
            files[0].unpacked_size as usize,
            "{name}"
        );
    }
}

#[test]
fn rejects_corrupt_rar50_header_checksum() {
    let mut bytes = std::fs::read(fixture("stored.rar")).unwrap();
    bytes[13] ^= 0x01;

    assert!(matches!(
        Archive::parse(&bytes),
        Err(Error::AtArchiveOffset {
            offset: 8,
            source
        }) if matches!(*source, Error::Crc32Mismatch { .. })
    ));
}

#[test]
fn rejects_overlong_rar50_header_size_vint() {
    let mut bytes = std::fs::read(fixture("stored.rar")).unwrap();
    bytes[12..22].fill(0x80);

    assert!(matches!(
        Archive::parse(&bytes),
        Err(Error::AtArchiveOffset {
            offset: 8,
            source
        }) if matches!(*source, Error::InvalidHeader("RAR 5 vint is too long"))
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
        Err(Error::AtEntry {
            name,
            operation: "verifying",
            source
        }) if name == b"hello.txt" && matches!(*source, Error::Crc32Mismatch { .. })
    ));
}

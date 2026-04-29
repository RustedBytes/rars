use rars_format::rar15_40::{crc32, extract_volumes, Archive, Block, NewSubKind};
use rars_format::{detect_archive_family, ArchiveFamily, Error};
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar15_40")
        .join(name)
}

#[test]
fn detects_rar15_40_signature_family() {
    let bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let sig = detect_archive_family(&bytes).unwrap();

    assert_eq!(sig.family, ArchiveFamily::Rar15To40);
    assert_eq!(sig.offset, 0);
    assert_eq!(sig.length, 7);
}

#[test]
fn parses_rar300_comment_subblock_and_stored_file() {
    let bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(archive.sfx_offset, 0);
    assert_eq!(archive.main.flags, 0);

    let subblocks: Vec<_> = archive.new_subs().collect();
    assert_eq!(subblocks.len(), 1);
    assert_eq!(subblocks[0].kind, NewSubKind::ArchiveComment);
    assert_eq!(subblocks[0].file.name, b"CMT");
    assert_eq!(subblocks[0].file.method, 0x33);
    assert_eq!(subblocks[0].file.unp_ver, 29);
    assert_eq!(subblocks[0].file.pack_size, 42);
    assert_eq!(subblocks[0].file.unp_size, 29);

    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"hello.txt");
    assert!(files[0].is_stored());
    assert_eq!(files[0].method, 0x30);
    assert_eq!(files[0].unp_ver, 29);
    assert_eq!(files[0].pack_size, 30);
    assert_eq!(files[0].unp_size, 30);
    assert_eq!(files[0].file_crc, 0xa538535e);
    assert_eq!(files[0].packed_data, b"Hello, RAR 3.x fixture world.\n");
}

#[test]
fn extracts_rar300_stored_file_and_verifies_crc32() {
    let bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let extracted = archive.extract_stored().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"hello.txt");
    assert_eq!(extracted[0].data, b"Hello, RAR 3.x fixture world.\n");
    assert_eq!(extracted[0].host_os, 2);
    assert!(!extracted[0].is_directory);

    let file = archive.files().next().unwrap();
    file.verify_crc32(&extracted[0].data).unwrap();
    assert_eq!(crc32(&extracted[0].data), 0xa538535e);
}

#[test]
fn rejects_corrupt_rar15_40_header_checksum() {
    let mut bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let main_flags_offset = 7 + 3;
    bytes[main_flags_offset] ^= 0x01;

    assert!(matches!(
        Archive::parse(&bytes),
        Err(Error::CrcMismatch { .. })
    ));
}

#[test]
fn rejects_corrupt_rar15_40_stored_payload_checksum() {
    let mut bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let needle = b"Hello, RAR 3.x fixture world.\n";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("stored payload in fixture");
    bytes[offset] ^= 0x01;
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(
        archive.extract_stored(),
        Err(Error::Crc32Mismatch { .. })
    ));
}

#[test]
fn rejects_large_solid_rar300_until_table_edge_case_is_fixed() {
    let bytes = std::fs::read(fixture("rar300/solid_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(
        archive.extract(),
        Err(Error::InvalidHeader("RAR 2.9 level length run is too long"))
    ));
}

#[test]
fn extracts_simple_solid_rar300_entries_with_codec_state() {
    let bytes = std::fs::read(fixture("rar300/solid_simple_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"one.txt");
    assert_eq!(
        extracted[0].data,
        b"shared prefix shared prefix shared prefix alpha\n"
    );
    assert_eq!(crc32(&extracted[0].data), 0x11cc9fbb);
    assert_eq!(extracted[1].name, b"two.txt");
    assert_eq!(
        extracted[1].data,
        b"shared prefix shared prefix shared prefix beta\n"
    );
    assert_eq!(crc32(&extracted[1].data), 0xf4fd09e8);
}

#[test]
fn stored_only_extract_rejects_compressed_rar300_lz_file() {
    let bytes = std::fs::read(fixture("rar300/compressed_text_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(
        archive.extract_stored(),
        Err(Error::InvalidHeader(
            "RAR 1.5 compressed file extraction is not implemented"
        ))
    ));
}

#[test]
fn extracts_compressed_rar300_lz_file() {
    let bytes = std::fs::read(fixture("rar300/compressed_text_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"text.txt");
    assert_eq!(extracted[0].data, expected_compressed_text_payload());
    assert_eq!(crc32(&extracted[0].data), 0x6a0d746d);
}

#[test]
fn extracts_rar300_standard_rarvm_filter_fixtures() {
    for (name, entry_name, size, expected_crc) in [
        (
            "rar300/rarvm_x86_e8_rar300.rar",
            b"x86_e8_stream.bin".as_slice(),
            196_608,
            0xe0f3971f,
        ),
        (
            "rar300/rarvm_x86_e8e9_rar300.rar",
            b"x86_e8e9_stream.bin".as_slice(),
            196_608,
            0xdc573e1b,
        ),
        (
            "rar300/rarvm_delta_4ch_rar300.rar",
            b"delta_4ch_ramp.bin".as_slice(),
            262_144,
            0xa303b91f,
        ),
        (
            "rar300/rarvm_itanium_synthetic_rar300.rar",
            b"itanium_synthetic_bundles.bin".as_slice(),
            1_048_576,
            0x39086451,
        ),
    ] {
        let bytes = std::fs::read(fixture(name)).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let extracted = archive.extract().unwrap();
        assert_eq!(extracted.len(), 1, "{name}");
        assert_eq!(extracted[0].name, entry_name, "{name}");
        assert_eq!(extracted[0].data.len(), size, "{name}");
        assert_eq!(crc32(&extracted[0].data), expected_crc, "{name}");
    }
}

#[test]
fn rejects_rar300_rgb_and_audio_filter_fixtures_until_lz_edge_case_is_fixed() {
    for name in [
        "rar300/rarvm_rgb_gradient_rar300.rar",
        "rar300/rarvm_audio_stereo_rar300.rar",
    ] {
        let bytes = std::fs::read(fixture(name)).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(matches!(
            archive.extract(),
            Err(Error::InvalidHeader(
                "RAR 2.9 match distance is out of range"
            ))
        ));
    }
}

#[test]
fn decodes_rar300_compressed_archive_comment() {
    let bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(
        archive.archive_comment().unwrap().as_deref(),
        Some(b"This is the archive comment.\n".as_slice())
    );
}

#[test]
fn rejects_split_rar15_40_entries_until_volume_reassembly_exists() {
    let bytes = std::fs::read(fixture("rar300/multivol_oldnaming_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(
        archive.extract_stored(),
        Err(Error::InvalidHeader(
            "RAR 1.5 split entry requires multivolume extraction"
        ))
    ));
}

#[test]
fn extracts_stored_rar300_old_numbered_volume_set() {
    let archives: Vec<_> = [
        "rar300/stored_multivol_rar300.rar",
        "rar300/stored_multivol_rar300.r00",
        "rar300/stored_multivol_rar300.r01",
        "rar300/stored_multivol_rar300.r02",
    ]
    .into_iter()
    .map(|name| Archive::parse(&std::fs::read(fixture(name)).unwrap()).unwrap())
    .collect();

    let extracted = extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"stored-volume.txt");
    assert_eq!(extracted[0].data, expected_stored_volume_payload());
    assert_eq!(crc32(&extracted[0].data), 0x4a832ebd);
}

#[test]
fn rejects_incomplete_rar300_stored_volume_set() {
    let archives: Vec<_> = [
        "rar300/stored_multivol_rar300.rar",
        "rar300/stored_multivol_rar300.r00",
    ]
    .into_iter()
    .map(|name| Archive::parse(&std::fs::read(fixture(name)).unwrap()).unwrap())
    .collect();

    assert!(matches!(
        extract_volumes(&archives),
        Err(Error::InvalidHeader("RAR 1.5 split entry is incomplete"))
    ));
}

#[test]
fn rejects_compressed_rar300_old_numbered_volume_set_until_split_codec_state_exists() {
    let archives: Vec<_> = [
        "rar300/compressed_multivol_prng_rar300.rar",
        "rar300/compressed_multivol_prng_rar300.r00",
        "rar300/compressed_multivol_prng_rar300.r01",
        "rar300/compressed_multivol_prng_rar300.r02",
        "rar300/compressed_multivol_prng_rar300.r03",
    ]
    .into_iter()
    .map(|name| Archive::parse(&std::fs::read(fixture(name)).unwrap()).unwrap())
    .collect();

    assert!(matches!(
        extract_volumes(&archives),
        Err(Error::InvalidHeader(
            "RAR 1.5 compressed file extraction is not implemented"
        ))
    ));
}

#[test]
fn parses_rar300_solid_flags() {
    let bytes = std::fs::read(fixture("rar300/solid_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(archive.main.is_solid());
    let files: Vec<_> = archive.files().collect();
    assert!(files.len() >= 2);
    assert!(!files[0].is_solid());
    assert!(files[1..].iter().all(|file| file.is_solid()));
}

#[test]
fn parses_old_and_new_volume_numbering_flags() {
    let old_bytes = std::fs::read(fixture("rar300/multivol_oldnaming_rar300.rar")).unwrap();
    let old = Archive::parse(&old_bytes).unwrap();
    assert!(old.main.is_volume());
    assert!(old.main.is_first_volume());
    assert!(!old.main.uses_new_numbering());
    assert!(old.files().any(|file| file.is_split_after()));

    let new_bytes = std::fs::read(fixture("rar300/multivol_newnaming_rar300.part01.rar")).unwrap();
    let new = Archive::parse(&new_bytes).unwrap();
    assert!(new.main.is_volume());
    assert!(new.main.is_first_volume());
    assert!(new.main.uses_new_numbering());
    assert!(new.files().any(|file| file.is_split_after()));
}

#[test]
fn parses_rar420_extended_time_header_bytes() {
    let bytes = std::fs::read(fixture("rar420/ext_time_rar420.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 1);
    assert!(files.iter().all(|file| file.has_ext_time()));
    assert!(files.iter().all(|file| !file.ext_time.is_empty()));
    assert_eq!(files[0].unp_ver, 29);
}

#[test]
fn parses_end_of_archive_block() {
    let bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(archive.blocks.last(), Some(Block::End(_))));
}

#[test]
fn crc32_matches_standard_check_value() {
    assert_eq!(crc32(b""), 0x00000000);
    assert_eq!(crc32(b"123456789"), 0xcbf43926);
}

fn expected_stored_volume_payload() -> Vec<u8> {
    "RAR 3.00 stored multivolume fixture line.\n"
        .repeat(80)
        .into_bytes()
}

fn expected_compressed_text_payload() -> Vec<u8> {
    "Hello, RAR 3.x fixture world.\n".repeat(80).into_bytes()
}

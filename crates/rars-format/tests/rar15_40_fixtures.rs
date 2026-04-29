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
    assert_eq!(
        files[0].packed_data(&archive).unwrap(),
        b"Hello, RAR 3.x fixture world.\n"
    );
}

#[test]
fn parses_rar202_main_header_with_embedded_comment_subblock() {
    let bytes = std::fs::read(fixture("rar202/comment_nopsw.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(archive.main.head_crc, 0x01bd);
    assert_eq!(archive.main.head_size, 51);
    assert!(archive.main.flags & 0x0002 != 0);
    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"FILE1.TXT");
    assert_eq!(files[1].name, b"FILE2.TXT");
    assert_eq!(files[0].unp_ver, 20);
    assert_eq!(files[1].unp_ver, 20);
    assert!(files.iter().all(|file| file.block.flags & 0x0008 != 0));
}

#[test]
fn rejects_rar3_header_encryption_with_clear_error() {
    let bytes = std::fs::read(fixture("encrypted/header_enc_1234.rar")).unwrap();

    assert!(matches!(
        Archive::parse(&bytes),
        Err(Error::InvalidHeader(
            "RAR 1.5 encrypted headers are not implemented"
        ))
    ));
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
        Err(Error::InvalidHeader("RAR 2.9 bitstream is truncated"))
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
fn extracts_rar154_unp15_compressed_file() {
    let bytes = std::fs::read(fixture("rar154/readme_154_normal.rar")).unwrap();
    let expected = std::fs::read(fixture("rar154/README.md")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"README.md");
    assert_eq!(file.method, 0x33);
    assert_eq!(file.unp_ver, 15);
    assert_eq!(file.pack_size, 2068);
    assert_eq!(file.unp_size, 4198);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"README.md");
    assert_eq!(extracted[0].data, expected);
    assert_eq!(crc32(&extracted[0].data), 0x509e5e3c);
}

#[test]
fn extracts_rar154_unp15_solid_flagged_file() {
    let bytes = std::fs::read(fixture("rar154/readme_154_store_solid.rar")).unwrap();
    let expected = std::fs::read(fixture("rar154/README.md")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(archive.main.is_solid());
    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"README.md");
    assert_eq!(extracted[0].data, expected);
}

#[test]
fn extracts_rar250_unp20_lz_file() {
    let bytes = std::fs::read(fixture("rar250/AUTOREJ.RAR")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"PLAIN.TXT");
    assert_eq!(file.method, 0x35);
    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.pack_size, 54);
    assert_eq!(file.unp_size, 2300);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"PLAIN.TXT");
    assert_eq!(extracted[0].data.len(), 2300);
    assert_eq!(crc32(&extracted[0].data), 0xafc0db74);
}

#[test]
fn extracts_rar250_unp20_audio_file() {
    let bytes = std::fs::read(fixture("rar250/AUDIO.RAR")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"PCM_LR.WAV");
    assert_eq!(file.method, 0x35);
    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.pack_size, 1938);
    assert_eq!(file.unp_size, 32768);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"PCM_LR.WAV");
    assert_eq!(extracted[0].data, expected_rar250_audio_payload());
    assert_eq!(crc32(&extracted[0].data), 0x713ef34b);
}

#[test]
fn extracts_rar250_unp20_solid_members() {
    let bytes = std::fs::read(fixture("rar250/SOLID.RAR")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"SOLID1.TXT");
    assert_eq!(files[1].name, b"SOLID2.TXT");
    assert_eq!(files[0].unp_ver, 20);
    assert_eq!(files[1].unp_ver, 20);
    assert!(!files[0].is_solid());
    assert!(files[1].is_solid());

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, expected_rar250_solid1_payload());
    assert_eq!(extracted[1].data, expected_rar250_solid2_payload());
    assert_eq!(crc32(&extracted[0].data), 0x97668cf2);
    assert_eq!(crc32(&extracted[1].data), 0x28833332);
}

#[test]
fn extracts_rar250_unp20_large_lz_file() {
    let bytes = std::fs::read(fixture("rar250/BIGLZ.RAR")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"BIGLZ.BIN");
    assert_eq!(file.method, 0x35);
    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.unp_size, 167_936);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"BIGLZ.BIN");
    assert_eq!(extracted[0].data, expected_rar250_big_lz_payload());
    assert_eq!(crc32(&extracted[0].data), 0x46ce9077);
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
        (
            "rar300/rarvm_rgb_gradient_rar300.rar",
            b"rgb_gradient_24bit.bmp".as_slice(),
            196_662,
            0xbf03aa49,
        ),
        (
            "rar300/rarvm_audio_stereo_rar300.rar",
            b"audio_stereo_pcm.wav".as_slice(),
            705_644,
            0x8ad44141,
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
fn extracts_rar300_ppmd_text_file() {
    let bytes = std::fs::read(fixture("ppmd/ppmd_lorem_rar300.rar")).unwrap();
    let expected = std::fs::read(fixture("ppmd/lorem_127k.txt")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"lorem_127k.txt");
    assert_eq!(file.method, 0x35);
    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.pack_size, 13_276);
    assert_eq!(file.unp_size, 130_048);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"lorem_127k.txt");
    assert_eq!(extracted[0].data, expected);
    assert_eq!(crc32(&extracted[0].data), 0xc119b4e5);
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
fn decodes_node_unrar_js_utf16_archive_comment() {
    let bytes = std::fs::read(fixture("node_unrar_js/with_comment.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let comment = archive.archive_comment().unwrap().unwrap();
    let expected: Vec<u8> = "Test Comments for rar files.\r\n\r\n测试一下中文注释。\r\n日本語のコメントもテストしていまし。"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();

    assert_eq!(comment, expected);
    assert_eq!(crc32(&comment), 0xe96e8fcf);
    assert_eq!(comment.len(), 122);
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

fn expected_rar250_audio_payload() -> Vec<u8> {
    let mut pcm = Vec::with_capacity(32 * 1024);
    for i in 0..8192 {
        let left = (20000.0 * ((i as f64) * 2.0 * std::f64::consts::PI / 256.0).sin()) as i32;
        let right =
            (15000.0 * ((i as f64) * 2.0 * std::f64::consts::PI / 384.0 + 1.0).sin()) as i32;
        pcm.extend_from_slice(&(left as u16).to_le_bytes());
        pcm.extend_from_slice(&(right as u16).to_le_bytes());
    }
    pcm
}

fn expected_rar250_solid1_payload() -> Vec<u8> {
    rar250_solid_shared_line().repeat(180).into_bytes()
}

fn expected_rar250_solid2_payload() -> Vec<u8> {
    let mut data = rar250_solid_shared_line().repeat(90).into_bytes();
    data.extend_from_slice(
        "second member unique tail after shared history.\r\n"
            .repeat(120)
            .as_bytes(),
    );
    data
}

fn rar250_solid_shared_line() -> &'static str {
    "RAR 2.50 solid dictionary carry-over line with repeated tokens alpha beta gamma delta.\r\n"
}

fn expected_rar250_big_lz_payload() -> Vec<u8> {
    let mut data = Vec::with_capacity(167_936);
    for i in 0..4096 {
        data.extend_from_slice(format!("{i:04x}: unpack20 block refresh fixture ").as_bytes());
        data.extend_from_slice(&[(i * 17) as u8, (i * 31) as u8, b'\r', b'\n']);
    }
    data
}

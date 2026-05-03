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
fn extracts_rar202_encrypted_files_with_rar20_cipher() {
    let bytes = std::fs::read(fixture("rar202/comment_psw.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|file| file.is_encrypted()));
    assert!(matches!(archive.extract(), Err(Error::NeedPassword)));

    let extracted = archive.extract_with_password(Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"FILE1.TXT");
    assert_eq!(extracted[0].data, b"file1\r\n");
    assert_eq!(extracted[1].name, b"FILE2.TXT");
    assert_eq!(extracted[1].data, b"file2\r\n");
    assert_eq!(crc32(&extracted[0].data), files[0].file_crc);
    assert_eq!(crc32(&extracted[1].data), files[1].file_crc);
}

#[test]
fn rejects_wrong_password_for_rar20_encrypted_file_as_password_error() {
    let bytes = std::fs::read(fixture("rar202/comment_psw.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(
        archive.extract_with_password(Some(b"wrong-password")),
        Err(Error::WrongPasswordOrCorruptData)
    );
}

#[test]
fn header_encrypted_rar3_archive_requires_password_to_parse() {
    let bytes = std::fs::read(fixture("encrypted/header_enc_1234.rar")).unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
}

#[test]
fn extracts_rar300_header_encrypted_archive_with_password() {
    let bytes = std::fs::read(fixture("encrypted/header_rar300_password.rar")).unwrap();
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let file = archive.files().next().unwrap();

    assert!(archive.main.has_encrypted_headers());
    assert_eq!(file.name, b"hello.txt");
    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);

    let extracted = archive.extract_with_password(Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 3.x fixture world.\n");
    assert_eq!(crc32(&extracted[0].data), 0xa538535e);
}

#[test]
fn extracts_rar420_header_encrypted_archive_with_password() {
    let bytes = std::fs::read(fixture("encrypted/header_rar420_password.rar")).unwrap();
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let file = archive.files().next().unwrap();

    assert!(archive.main.has_encrypted_headers());
    assert_eq!(file.name, b"hello.txt");
    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);

    let extracted = archive.extract_with_password(Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 3.x fixture world.\n");
    assert_eq!(crc32(&extracted[0].data), 0xa538535e);
}

#[test]
fn extracts_rar300_aes_encrypted_file_with_password() {
    let bytes = std::fs::read(fixture("encrypted/per_file_rar300_password.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"hello.txt");
    assert!(file.is_encrypted());
    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    assert_eq!(
        file.salt,
        Some([0x4a, 0x81, 0x67, 0x7d, 0xc0, 0x3d, 0x5f, 0x83])
    );
    assert!(matches!(archive.extract(), Err(Error::NeedPassword)));

    let extracted = archive.extract_with_password(Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"hello.txt");
    assert_eq!(extracted[0].data, b"Hello, RAR 3.x fixture world.\n");
    assert_eq!(crc32(&extracted[0].data), 0xa538535e);
}

#[test]
fn rejects_wrong_password_for_rar3_encrypted_file_as_password_error() {
    let bytes = std::fs::read(fixture("encrypted/per_file_rar300_password.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(
        archive.extract_with_password(Some(b"wrong-password")),
        Err(Error::WrongPasswordOrCorruptData)
    );
}

#[test]
fn extracts_rar4_aes_encrypted_compressed_member() {
    let bytes = std::fs::read(fixture("encrypted/per_file_rar4_libarchive_mixed.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 4);
    assert_eq!(files[1].name, b"b.txt");
    assert!(files[1].is_encrypted());
    assert_eq!(files[1].unp_ver, 29);
    assert_eq!(files[1].method, 0x33);

    let data = files[1]
        .unpacked_data_with_password(&archive, Some(b"password"))
        .unwrap();
    assert_eq!(data, b"This is from b.txt");
    assert_eq!(crc32(&data), 0xa9fa1485);
}

#[test]
fn extracts_rar4_junrar_encrypted_member_with_correct_password() {
    let bytes = std::fs::read(fixture("encrypted/rar4_junrar_password.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"file1.txt");
    assert!(file.is_encrypted());
    assert_eq!(file.method, 0x33);
    assert_eq!(file.unp_ver, 29);
    assert!(matches!(archive.extract(), Err(Error::NeedPassword)));

    let extracted = archive.extract_with_password(Some(b"junrar")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"file1.txt");
    assert_eq!(extracted[0].data, b"file1\n");
    assert_eq!(crc32(&extracted[0].data), 0xe229f704);
}

#[test]
fn rejects_wrong_password_for_rar4_encrypted_file_as_password_error() {
    let bytes = std::fs::read(fixture("encrypted/rar4_junrar_password.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(
        archive.extract_with_password(Some(b"wrong-password")),
        Err(Error::WrongPasswordOrCorruptData)
    );
}

#[test]
fn extracts_rar4_junrar_header_encrypted_member_with_correct_password() {
    let bytes = std::fs::read(fixture("encrypted/rar4_junrar_header_encrypted.rar")).unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    let archive = Archive::parse_with_password(&bytes, Some(b"junrar")).unwrap();
    assert!(archive.main.has_encrypted_headers());

    let extracted = archive.extract_with_password(Some(b"junrar")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"file1.txt");
    assert_eq!(extracted[0].data, b"file1\n");
    assert_eq!(crc32(&extracted[0].data), 0xe229f704);
}

#[test]
fn decodes_rar4_compact_unicode_name_before_extraction() {
    let bytes = std::fs::read(fixture(
        "encrypted/rar4_junrar_file_content_encrypted_unicode.rar",
    ))
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, "新建文本文档.txt".as_bytes());
    assert!(file.is_encrypted());

    let extracted = archive.extract_with_password(Some(b"test")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, "新建文本文档.txt".as_bytes());
    assert_eq!(extracted[0].data, b"aaaaaaaaaa");
    assert_eq!(crc32(&extracted[0].data), 0x4c11cdf0);
}

#[test]
fn extracts_rar4_sharpcompress_encrypted_files_only_archive() {
    let bytes = std::fs::read(fixture("encrypted/rar4_sharpcompress_files_only.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 6);
    assert_eq!(files[0].name, b"exe\\test.exe");
    assert_eq!(files[1].name, b"jpg\\test.jpg");
    assert_eq!(files[2].name, "тест.txt".as_bytes());
    assert_eq!(files[3].name, b"Empty");
    assert_eq!(files[4].name, b"exe");
    assert_eq!(files[5].name, b"jpg");
    assert!(files[..3].iter().all(|file| file.is_encrypted()));
    assert!(files[3..].iter().all(|file| file.is_directory()));

    let extracted = archive.extract_with_password(Some(b"test")).unwrap();
    assert_eq!(extracted.len(), 6);
    assert_eq!(extracted[0].name, b"exe\\test.exe");
    assert_eq!(extracted[0].data.len(), 45056);
    assert_eq!(crc32(&extracted[0].data), 0xcfb109c8);
    assert_eq!(extracted[1].name, b"jpg\\test.jpg");
    assert_eq!(extracted[1].data.len(), 40372);
    assert_eq!(crc32(&extracted[1].data), 0x088814e3);
    assert_eq!(extracted[2].name, "тест.txt".as_bytes());
    assert_eq!(extracted[2].data.len(), 15498);
    assert_eq!(crc32(&extracted[2].data), 0x9bd160fa);
    assert!(extracted[3..].iter().all(|entry| entry.is_directory));
}

#[test]
fn parses_rar4_mixed_visible_names_unknown_password_fixture() {
    let bytes = std::fs::read(fixture(
        "encrypted/rar4_mixed_visible_names_unknown_password.rar",
    ))
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 3);
    assert_eq!(files[0].name, b"1File.txt");
    assert_eq!(files[1].name, "2中文.txt".as_bytes());
    assert_eq!(files[2].name, b"3Sec.txt");
    assert!(!files[0].is_encrypted());
    assert!(files[1].is_encrypted());
    assert!(files[2].is_encrypted());

    let stored = files[0].extract_stored(&archive).unwrap();
    assert_eq!(stored.data, b"1File");
    assert_eq!(crc32(&stored.data), 0x578a2019);

    assert!(matches!(archive.extract(), Err(Error::NeedPassword)));
    assert_eq!(
        archive.extract_with_password(Some(b"wrong-password")),
        Err(Error::WrongPasswordOrCorruptData)
    );
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
fn extracts_large_solid_rar300_with_reused_tables() {
    let bytes = std::fs::read(fixture("rar300/solid_rar300.rar")).unwrap();
    let expected_big = std::fs::read(fixture("rar300/bigtext_64k.bin")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert_eq!(files.len(), 3);
    assert_eq!(files[0].name, b"hello.txt");
    assert_eq!(files[1].name, b"tiny.txt");
    assert_eq!(files[2].name, b"bigtext_64k.bin");
    assert_eq!(files[0].pack_size, 45);
    assert_eq!(files[1].pack_size, 3);
    assert_eq!(files[2].pack_size, 9_753);
    assert_eq!(files[0].unp_size, 30);
    assert_eq!(files[1].unp_size, 9);
    assert_eq!(files[2].unp_size, 65_536);
    assert!(!files[0].is_solid());
    assert!(files[1].is_solid());
    assert!(files[2].is_solid());
    assert!(files.iter().all(|file| file.method == 0x33));
    assert!(files.iter().all(|file| file.unp_ver == 29));

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 3);
    assert_eq!(extracted[0].name, b"hello.txt");
    assert_eq!(extracted[0].data, b"Hello, RAR 3.x fixture world.\n");
    assert_eq!(crc32(&extracted[0].data), 0xa538535e);
    assert_eq!(extracted[1].name, b"tiny.txt");
    assert_eq!(extracted[1].data, b"AAAAAAAA\n");
    assert_eq!(crc32(&extracted[1].data), 0xd27b5891);
    assert_eq!(extracted[2].name, b"bigtext_64k.bin");
    assert_eq!(extracted[2].data, expected_big);
    assert_eq!(crc32(&extracted[2].data), 0xddc95682);
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
    let expected = std::fs::read(fixture("rar154/expected/README.md")).unwrap();
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
fn extracts_rar154_crypt15_encrypted_compressed_file() {
    let bytes = std::fs::read(fixture("rar154/readme_154_password.rar")).unwrap();
    let expected = std::fs::read(fixture("rar154/expected/README.md")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"README.md");
    assert!(file.is_encrypted());
    assert_eq!(file.method, 0x33);
    assert_eq!(file.unp_ver, 15);
    assert!(matches!(archive.extract(), Err(Error::NeedPassword)));

    let extracted = archive.extract_with_password(Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"README.md");
    assert_eq!(extracted[0].data, expected);
    assert_eq!(crc32(&extracted[0].data), 0x509e5e3c);
}

#[test]
fn rejects_wrong_password_for_rar15_encrypted_file_as_password_error() {
    let bytes = std::fs::read(fixture("rar154/readme_154_password.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(
        archive.extract_with_password(Some(b"wrong-password")),
        Err(Error::WrongPasswordOrCorruptData)
    );
}

#[test]
fn extracts_rar154_unp15_solid_flagged_file() {
    let bytes = std::fs::read(fixture("rar154/readme_154_store_solid.rar")).unwrap();
    let expected = std::fs::read(fixture("rar154/expected/README.md")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(archive.main.is_solid());
    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"README.md");
    assert_eq!(extracted[0].data, expected);
}

#[test]
fn extracts_rar154_unp15_multi_file_archive() {
    let bytes = std::fs::read(fixture("rar154/doc_154_best.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 17);
    assert!(files.iter().all(|file| file.unp_ver == 15));

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 17);
    let expected = expected_doc_154_best_manifest();
    for (entry, (name, size, crc)) in extracted.iter().zip(expected) {
        assert_eq!(entry.name, name.as_bytes());
        assert_eq!(entry.data.len(), size);
        assert_eq!(crc32(&entry.data), crc, "{name}");
    }
}

#[test]
fn extracts_rar154_unp15_audio_shaped_windows_archive() {
    let bytes = std::fs::read(fixture("rar154/audio_win_names_unpack15.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let extracted = archive.extract().unwrap();

    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"BoatModernEnglish.wav");
    assert_eq!(extracted[0].data.len(), 56_464);
    assert_eq!(crc32(&extracted[0].data), 0x82d2ed89);
    assert_eq!(extracted[1].name, b"LICENSE.txt");
    assert_eq!(extracted[1].data.len(), 107);
    assert_eq!(crc32(&extracted[1].data), 0x8eaf20c4);
}

#[test]
fn extracts_rar154_unp15_audio_shaped_dos_archive() {
    let bytes = std::fs::read(fixture("rar154/audio_dos_names_unpack15.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let extracted = archive.extract().unwrap();

    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"BOATMO~1.WAV");
    assert_eq!(extracted[0].data.len(), 56_464);
    assert_eq!(crc32(&extracted[0].data), 0x82d2ed89);
    assert_eq!(extracted[1].name, b"LICENSE.TXT");
    assert_eq!(extracted[1].data.len(), 107);
    assert_eq!(crc32(&extracted[1].data), 0x8eaf20c4);
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
fn extracts_rar250_unp20_multimedia_switch_lz_file() {
    let bytes = std::fs::read(fixture("rar250/AUDIO.RAR")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"PCM_LR.WAV");
    assert_eq!(file.method, 0x35);
    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.pack_size, 1938);
    assert_eq!(file.unp_size, 32768);
    assert_eq!(rar15_first_file_data_peek(&bytes), 0x0040);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"PCM_LR.WAV");
    assert_eq!(extracted[0].data, expected_rar250_multimedia_payload());
    assert_eq!(crc32(&extracted[0].data), 0x713ef34b);
}

#[test]
fn extracts_synthetic_unp20_audio_block_archive() {
    for channels in 1..=4 {
        let samples = channels * 4;
        let bytes = synthetic_rar20_audio_archive(channels, samples);
        let peek = rar15_first_file_data_peek(&bytes);
        assert_eq!(peek & 0x8000, 0x8000);
        assert_eq!(((peek >> 12) & 3) + 1, channels as u16);

        let archive = Archive::parse(&bytes).unwrap();
        let file = archive.files().next().unwrap();
        assert_eq!(file.name, format!("AUDIO{channels}.BIN").as_bytes());
        assert_eq!(file.method, 0x35);
        assert_eq!(file.unp_ver, 20);
        assert_eq!(file.unp_size, samples as u64);

        let extracted = archive.extract().unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, format!("AUDIO{channels}.BIN").as_bytes());
        assert_eq!(extracted[0].data, vec![0; samples]);
    }
}

#[test]
fn extracts_rar250_unp20_audio_shaped_and_text_lz_archive() {
    let bytes = std::fs::read(fixture("rar250/unpack20_audio_text.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"BoatModernEnglish.wav");
    assert_eq!(files[1].name, b"LICENSE.txt");
    assert!(files.iter().all(|file| file.unp_ver == 20));
    assert_eq!(rar15_first_file_data_peek(&bytes), 0x2221);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"BoatModernEnglish.wav");
    assert_eq!(crc32(&extracted[0].data), files[0].file_crc);
    assert_eq!(extracted[1].name, b"LICENSE.txt");
    assert_eq!(crc32(&extracted[1].data), files[1].file_crc);
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
fn extracts_rar250_unp20_keep_tables_archive() {
    let bytes = std::fs::read(fixture("rar250/unpack20_keep_tables.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"unrar");
    assert_eq!(files[0].method, 0x33);
    assert_eq!(files[0].unp_ver, 20);
    assert_eq!(files[0].pack_size, 25_077);
    assert_eq!(files[0].unp_size, 54_212);
    assert_eq!(files[0].file_crc, 0xbf94ba22);
    assert_eq!(files[1].name, b"file_id.diz");
    assert_eq!(files[1].method, 0x33);
    assert_eq!(files[1].unp_ver, 20);
    assert_eq!(files[1].pack_size, 85);
    assert_eq!(files[1].unp_size, 76);
    assert_eq!(files[1].file_crc, 0x497a718f);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(crc32(&extracted[0].data), 0xbf94ba22);
    assert_eq!(crc32(&extracted[1].data), 0x497a718f);
}

#[test]
fn extracts_rar250_unp20_explicit_multiblock_archive() {
    let bytes = std::fs::read(fixture("rar250/unpack20_multiblock.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"multiblock.bin");
    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.method, 0x35);
    assert_eq!(file.pack_size, 4_761);
    assert_eq!(file.unp_size, 16_384);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data.len(), 16_384);
    assert_eq!(crc32(&extracted[0].data), 0xa24d_a8f8);
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
fn extracts_rar300_ppmd_escape_literal_file() {
    let bytes = std::fs::read(fixture("ppmd/ppmd_escape_rar300.rar")).unwrap();
    let expected = std::fs::read(fixture("ppmd/escape_64k.bin")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"escape_64k.bin");
    assert_eq!(file.method, 0x35);
    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.unp_size, 65_536);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"escape_64k.bin");
    assert_eq!(extracted[0].data, expected);
    assert_eq!(crc32(&extracted[0].data), 0x9a945756);
}

#[test]
fn extracts_rar300_ppmd_mixed_archive() {
    let bytes = std::fs::read(fixture("ppmd/ppmd_mixed_rar300.rar")).unwrap();
    let expected_text = std::fs::read(fixture("ppmd/lorem_127k.txt")).unwrap();
    let expected_binary = std::fs::read(fixture("ppmd/binary_64k.bin")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"lorem_127k.txt");
    assert_eq!(files[1].name, b"binary_64k.bin");
    assert_eq!(files[0].unp_ver, 29);
    assert_eq!(files[1].unp_ver, 29);

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, expected_text);
    assert_eq!(extracted[1].data, expected_binary);
    assert_eq!(crc32(&extracted[0].data), 0xc119b4e5);
    assert_eq!(crc32(&extracted[1].data), 0x9d672acd);
}

#[test]
fn extracts_rar300_solid_ppmd_archive() {
    let bytes = std::fs::read(fixture("ppmd/ppmd_solid_rar300.rar")).unwrap();
    let expected_a = std::fs::read(fixture("ppmd/solid_lorem_a.txt")).unwrap();
    let expected_b = std::fs::read(fixture("ppmd/solid_lorem_b.txt")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"solid_lorem_a.txt");
    assert_eq!(files[1].name, b"solid_lorem_b.txt");
    assert!(!files[0].is_solid());
    assert!(files[1].is_solid());

    let extracted = archive.extract().unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, expected_a);
    assert_eq!(extracted[1].data, expected_b);
    assert_eq!(crc32(&extracted[0].data), 0x14284201);
    assert_eq!(crc32(&extracted[1].data), 0xca4cac47);
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
fn extracts_compressed_rar300_old_numbered_volume_set() {
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

    let extracted = extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"cvolume.bin");
    assert_eq!(extracted[0].data.len(), 4096);
    assert_eq!(crc32(&extracted[0].data), 0x96de2bef);
}

#[test]
fn extracts_rar154_unp15_old_numbered_volume_set() {
    let archives: Vec<_> = [
        "rar154/random.rar",
        "rar154/random.r00",
        "rar154/random.r01",
    ]
    .into_iter()
    .map(|name| Archive::parse(&std::fs::read(fixture(name)).unwrap()).unwrap())
    .collect();

    let extracted = extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"random.bin");
    assert_eq!(extracted[0].data.len(), 2_097_152);
    assert_eq!(crc32(&extracted[0].data), 0x1c9e_b697);
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

fn expected_doc_154_best_manifest() -> [(&'static str, usize, u32); 17] {
    [
        ("ARCH~Y3X.MD", 53_262, 0x5ab9_a7da),
        ("CRC3~F4U.MD", 5_271, 0xad7e_2a11),
        ("ENCR~BXO.MD", 30_796, 0xc5d3_da4f),
        ("FILT~XX0.MD", 27_069, 0x89e6_3874),
        ("HUFF~BID.MD", 11_958, 0xc4b2_3356),
        ("IMPL~KS0.MD", 8_846, 0x0def_58b4),
        ("INTE~BSL.MD", 32_722, 0xcb56_7947),
        ("LZ_M~HYW.MD", 14_181, 0xf5e6_4896),
        ("PATH~EJS.MD", 13_819, 0x3c0d_6e22),
        ("PPMD~D4Q.MD", 38_140, 0xffd9_b31f),
        ("RAR1~FHU.MD", 40_371, 0xaac1_91a8),
        ("RAR1~OEK.MD", 101_788, 0x292f_35d1),
        ("RAR5~YP0.MD", 71_276, 0xe52c_f5ec),
        ("RARV~0F3.MD", 12_429, 0xab07_a4a6),
        ("README.md", 4_198, 0x509e_5e3c),
        ("READ~0WB.MD", 22_024, 0xd987_5535),
        ("TEST~FAD.MD", 14_811, 0xb55b_a84a),
    ]
}

fn expected_rar250_multimedia_payload() -> Vec<u8> {
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

fn rar15_first_file_data_peek(bytes: &[u8]) -> u16 {
    let file_header = 7 + 13;
    let head_size = u16::from_le_bytes([bytes[file_header + 5], bytes[file_header + 6]]) as usize;
    let data = file_header + head_size;
    u16::from_be_bytes([bytes[data], bytes[data + 1]])
}

fn synthetic_rar20_audio_archive(channels: usize, samples: usize) -> Vec<u8> {
    let packed = synthetic_rar20_audio_block(channels, samples);
    let unpacked = vec![0; samples];
    let name = format!("AUDIO{channels}.BIN").into_bytes();

    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&rar15_header(0x73, 0, &[0; 6]));

    let mut file_body = Vec::new();
    push_u32(&mut file_body, packed.len() as u32);
    push_u32(&mut file_body, samples as u32);
    file_body.push(2); // host OS: Win32.
    push_u32(&mut file_body, crc32(&unpacked));
    push_u32(&mut file_body, 0x4a83_a11d);
    file_body.push(20);
    file_body.push(0x35);
    push_u16(&mut file_body, name.len() as u16);
    push_u32(&mut file_body, 0x20);
    file_body.extend_from_slice(&name);

    archive.extend_from_slice(&rar15_header(0x74, 0x8000, &file_body));
    archive.extend_from_slice(&packed);
    archive
}

fn rar15_header(head_type: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    push_u16(&mut header, 0);
    header.push(head_type);
    push_u16(&mut header, flags);
    push_u16(&mut header, (7 + body.len()) as u16);
    header.extend_from_slice(body);

    let crc = (crc32(&header[2..]) & 0xffff) as u16;
    header[0..2].copy_from_slice(&crc.to_le_bytes());
    header
}

fn synthetic_rar20_audio_block(channels: usize, samples: usize) -> Vec<u8> {
    let mut bits = TestBitWriter::default();

    bits.write_bits(0b10, 2); // audio block, do not keep previous tables.
    bits.write_bits((channels - 1) as u32, 2);

    for symbol in 0..19 {
        let len = if symbol == 1 || symbol == 18 { 1 } else { 0 };
        bits.write_bits(len, 4);
    }

    for _ in 0..channels {
        bits.write_bit(false); // level symbol 1: audio delta 0 has code length 1.
        bits.write_bit(true); // level symbol 18: 138 zeros.
        bits.write_bits(127, 7);
        bits.write_bit(true); // level symbol 18: 118 zeros.
        bits.write_bits(107, 7);
    }

    for _ in 0..samples {
        bits.write_bit(false); // audio delta 0.
    }

    bits.finish()
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[derive(Default)]
struct TestBitWriter {
    bytes: Vec<u8>,
    bit_pos: usize,
}

impl TestBitWriter {
    fn write_bit(&mut self, bit: bool) {
        if self.bit_pos.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if bit {
            let shift = 7 - (self.bit_pos % 8);
            *self.bytes.last_mut().unwrap() |= 1 << shift;
        }
        self.bit_pos += 1;
    }

    fn write_bits(&mut self, value: u32, count: u8) {
        for shift in (0..count).rev() {
            self.write_bit(((value >> shift) & 1) != 0);
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
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

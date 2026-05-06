use rars::rar13::{write_stored_archive, StoredEntry, WriterOptions};
use rars::rar15_40;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rars-format/tests/fixtures/rar13")
        .join(name)
}

fn fixture_rar15_40(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rars-format/tests/fixtures/rar15_40")
        .join(name)
}

fn fixture_rar50(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rars-format/tests/fixtures/rar50")
        .join(name)
}

fn scratch(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rars-cli-{name}-{nonce}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn rars() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rars"))
}

#[test]
fn info_lists_rar13_entries() {
    let output = rars()
        .arg("info")
        .arg(fixture("README_store.rar"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("Rar13"));
    assert!(stdout.contains("README"));
    assert!(stdout.contains("checksum=0xe079"));
}

#[test]
fn info_lists_packed_archive_comment() {
    let output = rars()
        .arg("info")
        .arg(fixture("COMMENT.RAR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("comment: This is the archive comment."));
}

#[test]
fn info_lists_file_comment() {
    let output = rars()
        .arg("info")
        .arg(fixture("FCOMM.RAR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("comment: FCOM"));
}

#[test]
fn info_reports_inline_av_shape_fixture() {
    let output = rars()
        .arg("info")
        .arg(fixture("rar140_av/rar140_av_patched.rar"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("authenticity verification: structural"));
    assert!(stdout.contains("status=not-cryptographically-verified"));
}

#[test]
fn info_lists_rar15_40_metadata() {
    let output = rars()
        .arg("info")
        .arg(fixture_rar15_40("rar300/with_comment_rar300.rar"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("Rar15To40"));
    assert!(stdout.contains("rar15-40 main"));
    assert!(stdout.contains("hello.txt"));
    assert!(stdout.contains("comment: This is the archive comment."));
    assert!(stdout.contains("subblock: ArchiveComment CMT"));
}

#[test]
fn test_verifies_rar15_40_stored_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture_rar15_40("rar300/with_comment_rar300.rar"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK hello.txt"));
}

#[test]
fn test_verifies_rar15_40_header_encrypted_fixture() {
    for fixture in [
        "encrypted/header_rar300_password.rar",
        "encrypted/header_rar420_password.rar",
    ] {
        let output = rars()
            .args(["test", "--password", "password"])
            .arg(fixture_rar15_40(fixture))
            .output()
            .unwrap();
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert!(stdout(&output).contains("OK hello.txt"));
    }
}

#[test]
fn rejects_wrong_password_for_rar15_40_encrypted_fixture() {
    let output = rars()
        .args(["test", "--password", "wrong-password"])
        .arg(fixture_rar15_40("encrypted/per_file_rar300_password.rar"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("failed to test archive"));
    assert!(stderr.contains("wrong password or corrupt encrypted data"));
}

#[test]
fn extracts_rar15_40_stored_fixture() {
    let out_dir = scratch("extract-rar15-40");
    let output = rars()
        .arg("x")
        .arg(fixture_rar15_40("rar300/with_comment_rar300.rar"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        fs::read(out_dir.join("hello.txt")).unwrap(),
        b"Hello, RAR 3.x fixture world.\n"
    );
}

#[test]
fn extracts_rar15_40_header_encrypted_fixture() {
    for (case, fixture) in [
        (
            "extract-rar15-40-header-encrypted-rar300",
            "encrypted/header_rar300_password.rar",
        ),
        (
            "extract-rar15-40-header-encrypted-rar420",
            "encrypted/header_rar420_password.rar",
        ),
    ] {
        let out_dir = scratch(case);
        let output = rars()
            .args(["x", "--password", "password"])
            .arg(fixture_rar15_40(fixture))
            .arg(&out_dir)
            .output()
            .unwrap();
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert_eq!(
            fs::read(out_dir.join("hello.txt")).unwrap(),
            b"Hello, RAR 3.x fixture world.\n"
        );
    }
}

#[test]
fn extracts_rar15_40_compressed_fixture() {
    let out_dir = scratch("extract-rar15-40-compressed");
    let output = rars()
        .arg("x")
        .arg(fixture_rar15_40("rar300/compressed_text_rar300.rar"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        fs::read(out_dir.join("text.txt")).unwrap(),
        expected_rar15_40_compressed_text_payload()
    );
}

#[test]
fn test_verifies_encrypted_stored_fixture() {
    let output = rars()
        .args(["test", "--password", "password"])
        .arg(fixture("STOREPWD.RAR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK SECRET.TXT"));
}

#[test]
fn test_reassembles_multivolume_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture("MULTIVOL.RAR"))
        .arg(fixture("MULTIVOL.R00"))
        .arg(fixture("MULTIVOL.R01"))
        .arg(fixture("MULTIVOL.R02"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK RANDOM.BIN"));
}

#[test]
fn test_reassembles_compressed_multivolume_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture("CMULTIV.RAR"))
        .arg(fixture("CMULTIV.R00"))
        .arg(fixture("CMULTIV.R01"))
        .arg(fixture("CMULTIV.R02"))
        .arg(fixture("CMULTIV.R03"))
        .arg(fixture("CMULTIV.R04"))
        .arg(fixture("CMULTIV.R05"))
        .arg(fixture("CMULTIV.R06"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK CMULTI.TXT"));
}

#[test]
fn test_reassembles_rar15_40_stored_multivolume_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.rar"))
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.r00"))
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.r01"))
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.r02"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK stored-volume.txt"));
}

#[test]
fn extracts_rar15_40_stored_multivolume_fixture() {
    let out_dir = scratch("extract-rar15-40-multivol");
    let output = rars()
        .arg("x")
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.rar"))
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.r00"))
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.r01"))
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.r02"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        fs::read(out_dir.join("stored-volume.txt")).unwrap(),
        expected_rar15_40_stored_volume_payload()
    );
}

#[test]
fn extracts_rar15_40_compressed_multivolume_fixture() {
    let out_dir = scratch("extract-rar15-40-compressed-multivol");
    let output = rars()
        .arg("x")
        .arg(fixture_rar15_40(
            "rar300/compressed_multivol_prng_rar300.rar",
        ))
        .arg(fixture_rar15_40(
            "rar300/compressed_multivol_prng_rar300.r00",
        ))
        .arg(fixture_rar15_40(
            "rar300/compressed_multivol_prng_rar300.r01",
        ))
        .arg(fixture_rar15_40(
            "rar300/compressed_multivol_prng_rar300.r02",
        ))
        .arg(fixture_rar15_40(
            "rar300/compressed_multivol_prng_rar300.r03",
        ))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let data = fs::read(out_dir.join("cvolume.bin")).unwrap();
    assert_eq!(data.len(), 4096);
    assert_eq!(rar15_40::crc32(&data), 0x96de2bef);
}

#[test]
fn test_verifies_compressed_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture("README.RAR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK README"));
}

#[test]
fn test_verifies_solid_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture("SOLID.RAR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("OK BIG80K.TXT"));
    assert!(stdout.contains("OK HELLO.TXT"));
    assert!(stdout.contains("OK TINY.TXT"));
}

#[test]
fn test_verifies_sfx_prefixed_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture("SFXSRC.EXE"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK HELLO.TXT"));
}

#[test]
fn extracts_compressed_multivolume_fixture() {
    let out_dir = scratch("extract-compressed-multivolume");
    let output = rars()
        .arg("x")
        .arg(fixture("CMULTIV.RAR"))
        .arg(fixture("CMULTIV.R00"))
        .arg(fixture("CMULTIV.R01"))
        .arg(fixture("CMULTIV.R02"))
        .arg(fixture("CMULTIV.R03"))
        .arg(fixture("CMULTIV.R04"))
        .arg(fixture("CMULTIV.R05"))
        .arg(fixture("CMULTIV.R06"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        fs::read(out_dir.join("CMULTI.TXT")).unwrap(),
        fs::read(fixture("CMULTI.TXT")).unwrap()
    );
}

#[test]
fn extracts_stored_fixture() {
    let out_dir = scratch("extract");
    let output = rars()
        .arg("x")
        .arg(fixture("WITHDIR.RAR"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        fs::read(out_dir.join("SUBDIR").join("INNER.TXT")).unwrap(),
        b"Inside subdir.\r\n"
    );
}

#[test]
fn extracts_encrypted_compressed_fixture() {
    let out_dir = scratch("extract-compressed");
    let output = rars()
        .args(["x", "--password", "password"])
        .arg(fixture("README_password=password.rar"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(fs::read(out_dir.join("README")).unwrap().len(), 2016);
}

#[test]
fn rejects_wrong_password() {
    let output = rars()
        .args(["test", "--password", "wrong-password"])
        .arg(fixture("README_password=password.rar"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("failed to test archive"));
    assert!(stderr.contains("invalid header") || stderr.contains("checksum mismatch"));
}

#[test]
fn rejects_unsafe_output_path() {
    let dir = scratch("unsafe-extract");
    let archive = dir.join("unsafe.rar");
    let out_dir = dir.join("out");
    let bytes = write_stored_archive(
        &[StoredEntry {
            name: b"../evil.txt",
            data: b"unsafe path fixture\n",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }],
        WriterOptions::default(),
    )
    .unwrap();
    fs::write(&archive, bytes).unwrap();

    let extract = rars()
        .arg("x")
        .arg(&archive)
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(!extract.status.success());
    let stderr = stderr(&extract);
    assert!(stderr.contains("failed to write extracted entry"));
    assert!(stderr.contains("unsafe archive path"));
}

#[test]
fn reports_missing_archive_path_with_context() {
    let dir = scratch("missing-archive");
    let missing = dir.join("missing.rar");

    let output = rars().arg("info").arg(&missing).output().unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("failed to read archive"));
    assert!(stderr.contains("missing.rar"));
}

#[test]
fn reports_missing_input_path_with_context() {
    let dir = scratch("missing-input");
    let archive = dir.join("out.rar");
    let missing = dir.join("missing.txt");

    let output = rars()
        .args(["a", "--format", "rar14"])
        .arg(&archive)
        .arg(&missing)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("failed to stat input"));
    assert!(stderr.contains("missing.txt"));
}

#[test]
fn prints_usage_without_command() {
    let output = rars().output().unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stderr(&output).contains("usage:"));
}

#[test]
fn prints_usage_for_help_command() {
    let output = rars().arg("--help").output().unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stderr(&output).contains("rars info <archive>"));
}

#[test]
fn rejects_unknown_command() {
    let output = rars().arg("wat").output().unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown command: wat"));
}

#[test]
fn rejects_missing_subcommand_arguments() {
    for args in [&["info"][..], &["test"][..], &["x"][..]] {
        let output = rars().args(args).output().unwrap();
        assert!(!output.status.success(), "args: {args:?}");
        assert!(stderr(&output).contains("usage:"), "args: {args:?}");
    }
}

#[test]
fn rejects_non_rar_input_to_info() {
    let dir = scratch("non-rar-info");
    let input = dir.join("plain.txt");
    fs::write(&input, b"not a rar archive").unwrap();

    let output = rars().arg("info").arg(&input).output().unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("failed to identify archive"));
    assert!(stderr.contains("unsupported archive signature"));
}

#[test]
fn rejects_bad_add_invocation_shape() {
    let output = rars().args(["a", "--format", "rar5"]).output().unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("usage: rars a"));
}

#[test]
fn rejects_missing_add_option_values() {
    for args in [
        &["a", "--format", "rar14", "--comment"][..],
        &["a", "--format", "rar14", "--file-comment"][..],
        &["a", "--format", "rar50", "--recovery-percent"][..],
        &["a", "--format", "rar14", "--volume-size"][..],
        &["a", "--password"][..],
    ] {
        let output = rars().args(args).output().unwrap();
        assert!(!output.status.success(), "args: {args:?}");
        assert!(stderr(&output).contains("missing"), "args: {args:?}");
    }
}

#[test]
fn rejects_invalid_volume_size() {
    let dir = scratch("invalid-volume-size");
    let source = dir.join("hello.txt");
    let archive = dir.join("bad.rar");
    fs::write(&source, b"hello").unwrap();

    let output = rars()
        .args(["a", "--format", "rar14", "--volume-size", "nope"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("invalid digit"));
}

#[test]
fn rejects_multivolume_with_multiple_inputs() {
    let dir = scratch("multivolume-multiple-inputs");
    let first = dir.join("first.txt");
    let second = dir.join("second.txt");
    let archive = dir.join("bad.rar");
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();

    let output = rars()
        .args(["a", "--format", "rar14", "--volume-size", "10"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("multivolume writer currently supports one input file"));
}

#[test]
fn creates_rar50_header_encrypted_recovery_volumes() {
    let dir = scratch("rar50-header-encrypted-recovery-volume");
    let source = dir.join("payload.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar50 header encrypted recovery volume cli payload\n".repeat(10),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--password",
            "pass",
            "--encrypt-headers",
            "--recovery-percent",
            "8",
            "--volume-size",
            "16",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    let missing = rars().arg("test").args(&parts).output().unwrap();
    assert!(!missing.status.success());
    assert!(stderr(&missing).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&parts)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_stored_archive_that_can_be_tested() {
    let dir = scratch("create");
    let source = dir.join("hello.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"hello from cli\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar14", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK hello.txt"));
}

#[test]
fn creates_rar15_stored_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-store");
    let source = dir.join("hello.txt");
    let archive = dir.join("created15.rar");
    fs::write(&source, b"hello from rar15 cli\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar15", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("Rar15To40"));
    assert!(info_stdout.contains("method=0x30"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK hello.txt"));
}

#[test]
fn creates_rar15_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-compressed");
    let source = dir.join("hello.txt");
    let archive = dir.join("created15.rar");
    fs::write(&source, b"hello from rar15 cli hello from rar15 cli\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar15"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=0x33"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK hello.txt"));
}

#[test]
fn creates_rar20_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar20-compressed");
    let source = dir.join("hello.txt");
    let archive = dir.join("created20.rar");
    fs::write(&source, b"hello from rar20 cli hello from rar20 cli\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar20"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("method=0x33"));
    assert!(info_stdout.contains("ver=20"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK hello.txt"));
}

#[test]
fn creates_rar20_encrypted_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar20-encrypted-compressed");
    let source = dir.join("secret.txt");
    let archive = dir.join("created20-secret.rar");
    fs::write(
        &source,
        b"hello from encrypted rar20 cli hello from encrypted rar20 cli\n",
    )
    .unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar20"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar29_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-compressed");
    let source = dir.join("hello.txt");
    let archive = dir.join("created29.rar");
    fs::write(&source, b"hello from rar29 cli hello from rar29 cli\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar29"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("method=0x33"));
    assert!(info_stdout.contains("ver=29"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK hello.txt"));
}

#[test]
fn creates_rar29_solid_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-solid");
    let first = dir.join("one.txt");
    let second = dir.join("two.txt");
    let archive = dir.join("rar29-solid.rar");
    fs::write(&first, b"solid cli baseline one alpha beta gamma\n").unwrap();
    fs::write(&second, b"solid cli baseline two alpha beta gamma\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar29", "--solid"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("rar15-40 main: flags=0x0008"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    let test_stdout = stdout(&test);
    assert!(test_stdout.contains("OK one.txt"));
    assert!(test_stdout.contains("OK two.txt"));
}

#[test]
fn creates_rar20_solid_archive_that_tests() {
    let dir = scratch("create-rar20-solid");
    let first = dir.join("one.txt");
    let second = dir.join("two.txt");
    let archive = dir.join("rar20-solid.rar");
    fs::write(&first, b"rar20 shared phrase alpha beta gamma\n".repeat(64)).unwrap();
    fs::write(
        &second,
        b"rar20 shared phrase alpha beta gamma\nsecond member\n".repeat(32),
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar20", "--solid"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("rar15-40 main: flags=0x0008"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    let test_stdout = stdout(&test);
    assert!(test_stdout.contains("OK one.txt"));
    assert!(test_stdout.contains("OK two.txt"));
}

#[test]
fn creates_rar15_archive_comment() {
    let dir = scratch("create-rar15-comment");
    let source = dir.join("commented.txt");
    let archive = dir.join("commented.rar");
    fs::write(&source, b"rar15 commented payload\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar15", "--comment", "rar15 note"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: rar15 note"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK commented.txt"));
}

#[test]
fn creates_rar15_file_comment() {
    let dir = scratch("create-rar15-file-comment");
    let source = dir.join("commented.txt");
    let archive = dir.join("file-comment.rar");
    fs::write(&source, b"rar15 file commented payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar15",
            "--file-comment",
            "rar15 file note",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: rar15 file note"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK commented.txt"));
}

#[test]
fn creates_rar20_archive_and_file_comments() {
    let dir = scratch("create-rar20-comments");
    let source = dir.join("commented.txt");
    let archive = dir.join("commented20.rar");
    fs::write(&source, b"rar20 commented payload\n").unwrap();

    let archive_comment = rars()
        .args(["a", "--format", "rar20", "--comment", "rar20 note"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        archive_comment.status.success(),
        "stderr: {}",
        stderr(&archive_comment)
    );
    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: rar20 note"));

    let file_comment_archive = dir.join("file-comment20.rar");
    let file_comment = rars()
        .args([
            "a",
            "--format",
            "rar20",
            "--file-comment",
            "rar20 file note",
        ])
        .arg(&file_comment_archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        file_comment.status.success(),
        "stderr: {}",
        stderr(&file_comment)
    );
    let info = rars()
        .arg("info")
        .arg(&file_comment_archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: rar20 file note"));

    let test = rars()
        .arg("test")
        .arg(&file_comment_archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK commented.txt"));
}

#[test]
fn creates_rar29_archive_and_file_comments() {
    let dir = scratch("create-rar29-comments");
    let source = dir.join("commented.txt");
    let archive = dir.join("commented29.rar");
    fs::write(&source, b"rar29 commented payload\n").unwrap();

    let archive_comment = rars()
        .args(["a", "--format", "rar29", "--comment", "rar29 note"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        archive_comment.status.success(),
        "stderr: {}",
        stderr(&archive_comment)
    );
    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: rar29 note"));

    let file_comment_archive = dir.join("file-comment29.rar");
    let file_comment = rars()
        .args([
            "a",
            "--format",
            "rar29",
            "--file-comment",
            "rar29 file note",
        ])
        .arg(&file_comment_archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        file_comment.status.success(),
        "stderr: {}",
        stderr(&file_comment)
    );
    let info = rars()
        .arg("info")
        .arg(&file_comment_archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: rar29 file note"));

    let test = rars()
        .arg("test")
        .arg(&file_comment_archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK commented.txt"));
}

#[test]
fn creates_rar30_newsub_archive_comment() {
    let dir = scratch("create-rar30-newsub-comment");
    let source = dir.join("commented.txt");
    let archive = dir.join("commented30.rar");
    fs::write(&source, b"rar30 NEWSUB commented payload\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar30", "--comment", "rar30 NEWSUB note"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("comment: rar30 NEWSUB note"));
    assert!(info_stdout.contains("subblock: ArchiveComment CMT"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK commented.txt"));
}

#[test]
fn creates_literal_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-compressed");
    let source = dir.join("tiny.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"tiny payload over sixteen").unwrap();

    let create = rars()
        .args(["a", "--format", "rar14"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=5"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK tiny.txt"));
}

#[test]
fn creates_solid_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-solid-compressed");
    let first = dir.join("first.txt");
    let second = dir.join("second.txt");
    let archive = dir.join("solid.rar");
    fs::write(&first, b"first member primes the adaptive unpack15 state").unwrap();
    fs::write(
        &second,
        b"second member is encoded without resetting that state",
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar14", "--solid"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("rar13 main: flags=0x88"));
    assert!(info_stdout.contains("flags=0x10"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    let stdout = stdout(&test);
    assert!(stdout.contains("OK first.txt"));
    assert!(stdout.contains("OK second.txt"));
}

#[test]
fn creates_rar15_solid_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-solid-compressed");
    let first = dir.join("first.txt");
    let second = dir.join("second.txt");
    let archive = dir.join("solid15.rar");
    fs::write(&first, b"shared prefix shared prefix alpha").unwrap();
    fs::write(&second, b"shared prefix shared prefix beta").unwrap();

    let create = rars()
        .args(["a", "--format", "rar15", "--solid"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("rar15-40 main: flags=0x0008"));
    assert!(info_stdout.contains("flags=0x8010"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    let stdout = stdout(&test);
    assert!(stdout.contains("OK first.txt"));
    assert!(stdout.contains("OK second.txt"));
}

#[test]
fn creates_rar15_encrypted_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-encrypted-compressed");
    let source = dir.join("secret.txt");
    let archive = dir.join("secret15.rar");
    fs::write(&source, b"secret rar15 compressed payload\n").unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar15"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let without_password = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!without_password.status.success());

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_encrypted_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-encrypted-compressed");
    let source = dir.join("secret.txt");
    let archive = dir.join("secret.rar");
    fs::write(&source, b"secret compressed payload over sixteen").unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar14"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let without_password = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!without_password.status.success());

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_archive_and_file_comments() {
    let dir = scratch("create-comments");
    let source = dir.join("commented.txt");
    let archive = dir.join("comments.rar");
    fs::write(&source, b"commented payload over sixteen").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar14",
            "--comment",
            "archive note",
            "--file-comment",
            "file note",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let stdout = stdout(&info);
    assert!(stdout.contains("comment: archive note"));
    assert!(stdout.contains("comment: file note"));
}

#[test]
fn creates_stored_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-stored-multivolume");
    let source = dir.join("payload.bin");
    let archive = dir.join("split.rar");
    fs::write(&source, b"abcdefghijklmnopqrstuvwxyz0123456789").unwrap();

    let create = rars()
        .args(["a", "--format", "rar14", "--store", "--volume-size", "10"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());
    assert!(dir.join("split.r01").exists());
    assert!(dir.join("split.r02").exists());

    let test = rars()
        .arg("test")
        .arg(&archive)
        .arg(dir.join("split.r00"))
        .arg(dir.join("split.r01"))
        .arg(dir.join("split.r02"))
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-compressed-multivolume");
    let source = dir.join("repeat.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, b"abcabcabcabcabcabcabcabcabcabcabcabcabcabc").unwrap();

    let create = rars()
        .args(["a", "--format", "rar14", "--volume-size", "8"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());

    let test = rars()
        .arg("test")
        .arg(&archive)
        .arg(dir.join("split.r00"))
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK repeat.txt"));
}

#[test]
fn creates_rar15_stored_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-stored-multivolume");
    let source = dir.join("payload.bin");
    let archive = dir.join("split.rar");
    fs::write(&source, b"abcdefghijklmnopqrstuvwxyz0123456789").unwrap();

    let create = rars()
        .args(["a", "--format", "rar15", "--store", "--volume-size", "10"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());
    assert!(dir.join("split.r01").exists());
    assert!(dir.join("split.r02").exists());

    let test = rars()
        .arg("test")
        .arg(&archive)
        .arg(dir.join("split.r00"))
        .arg(dir.join("split.r01"))
        .arg(dir.join("split.r02"))
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar15_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-compressed-multivolume");
    let source = dir.join("repeat.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, b"abcabcabcabcabcabcabcabcabcabcabcabcabcabc").unwrap();

    let create = rars()
        .args(["a", "--format", "rar15", "--volume-size", "8"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());

    let test = rars()
        .arg("test")
        .arg(&archive)
        .arg(dir.join("split.r00"))
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK repeat.txt"));
}

#[test]
fn creates_rar20_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar20-compressed-multivolume");
    let source = dir.join("repeat.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar20 split phrase alpha beta gamma rar20 split phrase alpha beta gamma\n".repeat(24),
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar20", "--volume-size", "8"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());

    let mut volume_args = vec![archive];
    for index in 0.. {
        let path = dir.join(format!("split.r{index:02}"));
        if !path.exists() {
            break;
        }
        volume_args.push(path);
    }
    let test = rars().arg("test").args(&volume_args).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK repeat.txt"));
}

#[test]
fn creates_rar29_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-compressed-multivolume");
    let source = dir.join("repeat.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar29 split phrase alpha beta gamma rar29 split phrase alpha beta gamma\n".repeat(24),
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar29", "--volume-size", "8"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());

    let mut volume_args = vec![archive];
    for index in 0.. {
        let path = dir.join(format!("split.r{index:02}"));
        if !path.exists() {
            break;
        }
        volume_args.push(path);
    }
    let test = rars().arg("test").args(&volume_args).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK repeat.txt"));
}

#[test]
fn creates_rar15_encrypted_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-encrypted-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"secret split compressed secret split compressed\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar15",
            "--volume-size",
            "8",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());
    let mut volume_args = vec![archive.clone()];
    for index in 0.. {
        let path = dir.join(format!("split.r{index:02}"));
        if !path.exists() {
            break;
        }
        volume_args.push(path);
    }

    let missing_password = rars().arg("test").args(&volume_args).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&volume_args)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar30_encrypted_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar30-encrypted-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar30 secret split compressed rar30 secret split compressed\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar30",
            "--volume-size",
            "8",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());
    let mut volume_args = vec![archive.clone()];
    for index in 0.. {
        let path = dir.join(format!("split.r{index:02}"));
        if !path.exists() {
            break;
        }
        volume_args.push(path);
    }

    let missing_password = rars().arg("test").args(&volume_args).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&volume_args)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar29_encrypted_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-encrypted-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar29 secret split compressed rar29 secret split compressed\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar29",
            "--volume-size",
            "8",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());
    let mut volume_args = vec![archive.clone()];
    for index in 0.. {
        let path = dir.join(format!("split.r{index:02}"));
        if !path.exists() {
            break;
        }
        volume_args.push(path);
    }

    let missing_password = rars().arg("test").args(&volume_args).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&volume_args)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar30_header_encrypted_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar30-header-encrypted-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar30 header encrypted split compressed payload payload payload\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar30",
            "--encrypt-headers",
            "--volume-size",
            "8",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());
    let mut volume_args = vec![archive.clone()];
    for index in 0.. {
        let path = dir.join(format!("split.r{index:02}"));
        if !path.exists() {
            break;
        }
        volume_args.push(path);
    }

    let missing_password = rars().arg("test").args(&volume_args).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&volume_args)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar30_aes_encrypted_archive_that_can_be_tested() {
    let dir = scratch("create-rar30-aes-encrypted");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar30 aes encrypted cli payload\n").unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar30"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar29_aes_encrypted_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-aes-encrypted");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar29 aes encrypted cli payload\n").unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar29"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar30_header_encrypted_archive_that_can_be_tested() {
    let dir = scratch("create-rar30-header-encrypted");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar30 header encrypted cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar30",
            "--encrypt-headers",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("info").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar30_solid_header_encrypted_archive_that_can_be_tested() {
    let dir = scratch("create-rar30-solid-header-encrypted");
    let one = dir.join("one.txt");
    let two = dir.join("two.txt");
    let archive = dir.join("created.rar");
    fs::write(&one, b"rar30 solid header encrypted one one one\n").unwrap();
    fs::write(&two, b"rar30 solid header encrypted two two two\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar30",
            "--solid",
            "--encrypt-headers",
        ])
        .arg(&archive)
        .arg(&one)
        .arg(&two)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("info").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    let stdout = stdout(&test);
    assert!(stdout.contains("OK one.txt"));
    assert!(stdout.contains("OK two.txt"));
}

#[test]
fn creates_rar50_stored_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-stored");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 stored cli payload\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_quick_open_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-quick-open");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 quick-open cli payload\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store", "--quick-open"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: QO"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_recovery_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 recovery cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--store",
            "--recovery-percent",
            "8",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("rar50 main: flags=0x0008"));
    assert!(info_stdout.contains("service: RR"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_compressed_recovery_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-compressed-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 compressed recovery cli payload repeated repeated repeated\n",
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--recovery-percent", "8"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("rar50 main: flags=0x0008"));
    assert!(info_stdout.contains("service: RR"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_encrypted_recovery_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-encrypted-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 encrypted recovery cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--recovery-percent",
            "5",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));

    let info_without_password = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info_without_password.status.success());
    assert!(stdout(&info_without_password).contains("service: RR"));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_encrypted_compressed_recovery_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-encrypted-compressed-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 encrypted compressed recovery cli payload repeated repeated\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--recovery-percent",
            "5",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));

    let info_without_password = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info_without_password.status.success());
    assert!(stdout(&info_without_password).contains("service: RR"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_header_encrypted_recovery_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-header-encrypted-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 header encrypted recovery cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--encrypt-headers",
            "--recovery-percent",
            "4",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));

    let info_without_password = rars().arg("info").arg(&archive).output().unwrap();
    assert!(!info_without_password.status.success());
    assert!(stderr(&info_without_password).contains("password is required"));

    let info = rars()
        .args(["info", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("rar50 main: flags=0x0008"));
    assert!(info_stdout.contains("service: RR"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_header_encrypted_compressed_recovery_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-header-encrypted-compressed-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 header encrypted compressed recovery cli payload repeated repeated\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--encrypt-headers",
            "--recovery-percent",
            "4",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));

    let info_without_password = rars().arg("info").arg(&archive).output().unwrap();
    assert!(!info_without_password.status.success());
    assert!(stderr(&info_without_password).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_encrypted_stored_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-encrypted-stored");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 encrypted stored cli payload\n").unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar50", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let wrong = rars()
        .args(["test", "--password", "wrong"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert!(stderr(&wrong).contains("wrong password or corrupt encrypted data"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_encrypted_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-encrypted-compressed");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 encrypted compressed cli payload\nrar50 encrypted compressed cli payload\n",
    )
    .unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar50"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=1"));

    let wrong = rars()
        .args(["test", "--password", "wrong"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(!wrong.status.success());

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_encrypted_solid_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-encrypted-solid-compressed");
    let first = dir.join("one.txt");
    let second = dir.join("two.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &first,
        b"rar50 encrypted solid compressed cli shared phrase alpha beta gamma\n".repeat(12),
    )
    .unwrap();
    fs::write(
        &second,
        b"rar50 encrypted solid compressed cli shared phrase alpha beta gamma\nsecond\n".repeat(6),
    )
    .unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar50", "--solid"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let wrong = rars()
        .args(["test", "--password", "wrong"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(!wrong.status.success());

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK one.txt"));
    assert!(stdout(&test).contains("OK two.txt"));
}

#[test]
fn creates_rar50_header_encrypted_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-header-encrypted-compressed");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 header encrypted compressed cli payload\nrar50 header encrypted compressed cli payload\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--encrypt-headers",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!missing.status.success());
    assert!(stderr(&missing).contains("password is required"));

    let info = rars()
        .args(["info", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=1"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_header_encrypted_solid_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-header-encrypted-solid-compressed");
    let first = dir.join("one.txt");
    let second = dir.join("two.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &first,
        b"rar50 header encrypted solid compressed cli shared phrase alpha beta gamma\n".repeat(12),
    )
    .unwrap();
    fs::write(
        &second,
        b"rar50 header encrypted solid compressed cli shared phrase alpha beta gamma\nsecond\n"
            .repeat(6),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--encrypt-headers",
            "--solid",
        ])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!missing.status.success());

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK one.txt"));
    assert!(stdout(&test).contains("OK two.txt"));
}

#[test]
fn creates_rar50_encrypted_stored_archive_comment_service() {
    let dir = scratch("create-rar50-encrypted-comment");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 encrypted comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--comment",
            "Encrypted RAR5 CLI comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let info = rars()
        .args(["info", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: CMT"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_encrypted_compressed_archive_comment_service() {
    let dir = scratch("create-rar50-encrypted-compressed-comment");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 encrypted compressed comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--comment",
            "Encrypted compressed RAR5 CLI comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars()
        .args(["info", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: CMT"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_header_encrypted_stored_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-header-encrypted-stored");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 header encrypted stored cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--encrypt-headers",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let wrong = rars()
        .args(["test", "--password", "wrong"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert!(stderr(&wrong).contains("wrong password or corrupt encrypted data"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_header_encrypted_stored_archive_comment_service() {
    let dir = scratch("create-rar50-header-encrypted-comment");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 header encrypted comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--encrypt-headers",
            "--comment",
            "Header encrypted RAR5 CLI comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("info").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let info = rars()
        .args(["info", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: CMT"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_header_encrypted_compressed_archive_comment_service() {
    let dir = scratch("create-rar50-header-encrypted-compressed-comment");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 header encrypted compressed comment cli payload\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--encrypt-headers",
            "--comment",
            "Header encrypted compressed RAR5 CLI comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("info").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let info = rars()
        .args(["info", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: CMT"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_encrypted_stored_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-encrypted-stored-volume");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 encrypted stored volume cli payload\n".repeat(12),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--volume-size",
            "97",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let part = dir.join(format!("created.part{index}.rar"));
        if !part.exists() {
            break;
        }
        parts.push(part);
    }
    assert!(parts.len() > 1);

    let mut command = rars();
    command.args(["test", "--password", "pass"]);
    for part in &parts {
        command.arg(part);
    }
    let test = command.output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_header_encrypted_stored_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-header-encrypted-stored-volume");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 header encrypted stored volume cli payload\n".repeat(12),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--encrypt-headers",
            "--volume-size",
            "97",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let part = dir.join(format!("created.part{index}.rar"));
        if !part.exists() {
            break;
        }
        parts.push(part);
    }
    assert!(parts.len() > 1);

    let missing_password = rars().arg("test").arg(&parts[0]).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let mut command = rars();
    command.args(["test", "--password", "pass"]);
    for part in &parts {
        command.arg(part);
    }
    let test = command.output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_stored_archive_comment_service() {
    let dir = scratch("create-rar50-comment");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--store",
            "--comment",
            "RAR5 CLI comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: CMT"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_compressed_archive_comment_service() {
    let dir = scratch("create-rar50-compressed-comment");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 compressed comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--comment",
            "RAR5 compressed CLI comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: CMT"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_stored_file_comment_service() {
    let dir = scratch("create-rar50-file-comment");
    let source = dir.join("commented.txt");
    let archive = dir.join("file-comment.rar");
    fs::write(&source, b"rar50 file comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--store",
            "--file-comment",
            "RAR5 CLI file comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: CMT"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK commented.txt"));
}

#[test]
fn creates_rar50_encrypted_stored_file_comment_service() {
    let dir = scratch("create-rar50-encrypted-file-comment");
    let source = dir.join("commented.txt");
    let archive = dir.join("file-comment.rar");
    fs::write(&source, b"rar50 encrypted file comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--file-comment",
            "Encrypted RAR5 CLI file comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let info = rars()
        .args(["info", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: CMT"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK commented.txt"));
}

#[test]
fn creates_rar50_header_encrypted_stored_file_comment_service() {
    let dir = scratch("create-rar50-header-encrypted-file-comment");
    let source = dir.join("commented.txt");
    let archive = dir.join("file-comment.rar");
    fs::write(
        &source,
        b"rar50 header encrypted file comment cli payload\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--encrypt-headers",
            "--file-comment",
            "Header encrypted RAR5 CLI file comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("info").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let info = rars()
        .args(["info", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: CMT"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK commented.txt"));
}

#[test]
fn creates_rar70_stored_archive_metadata() {
    let dir = scratch("create-rar70-metadata");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar70 metadata cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar70",
            "--store",
            "--archive-name",
            "cli-metadata.rar",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("archive name: cli-metadata.rar"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar70_compressed_archive_metadata() {
    let dir = scratch("create-rar70-compressed-metadata");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar70 compressed metadata cli payload repeated\n".repeat(8),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar70",
            "--archive-name",
            "cli-compressed-metadata.rar",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("archive name: cli-compressed-metadata.rar"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar70_encrypted_stored_archive_metadata() {
    let dir = scratch("create-rar70-encrypted-metadata");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar70 encrypted metadata cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar70",
            "--store",
            "--password",
            "pass",
            "--archive-name",
            "cli-encrypted-metadata.rar",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("archive name: cli-encrypted-metadata.rar"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar70_encrypted_compressed_archive_metadata() {
    let dir = scratch("create-rar70-encrypted-compressed-metadata");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar70 encrypted compressed metadata cli payload repeated\n".repeat(8),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar70",
            "--password",
            "pass",
            "--archive-name",
            "cli-encrypted-compressed-metadata.rar",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("archive name: cli-encrypted-compressed-metadata.rar"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar70_header_encrypted_stored_archive_metadata() {
    let dir = scratch("create-rar70-header-encrypted-metadata");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar70 header encrypted metadata cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar70",
            "--store",
            "--password",
            "pass",
            "--encrypt-headers",
            "--archive-name",
            "cli-header-metadata.rar",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("info").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password"));

    let info = rars()
        .args(["info", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("archive name: cli-header-metadata.rar"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar70_header_encrypted_compressed_archive_metadata() {
    let dir = scratch("create-rar70-header-encrypted-compressed-metadata");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar70 header encrypted compressed metadata cli payload repeated\n".repeat(8),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar70",
            "--password",
            "pass",
            "--encrypt-headers",
            "--archive-name",
            "cli-header-compressed-metadata.rar",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars()
        .args(["info", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("archive name: cli-header-compressed-metadata.rar"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_stored_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-stored-multivolume");
    let source = dir.join("payload.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, b"rar50 stored volume cli payload\n".repeat(20)).unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store", "--volume-size", "90"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(dir.join("split.part1.rar").exists());
    assert!(dir.join("split.part2.rar").exists());

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }

    let test = rars().arg("test").args(&parts).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_stored_recovery_multivolume_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-stored-recovery-multivolume");
    let source = dir.join("payload.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar50 stored recovery volume cli payload\n".repeat(20),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--store",
            "--recovery-percent",
            "8",
            "--volume-size",
            "90",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));
    assert!(dir.join("split.part1.rar").exists());
    assert!(dir.join("split.part2.rar").exists());

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }

    let info = rars().arg("info").arg(&parts[0]).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: RR"));

    let test = rars().arg("test").args(&parts).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn repairs_rar50_stored_archive_with_inline_recovery_record() {
    let dir = scratch("repair-rar50-inline-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("recoverable.rar");
    let repaired = dir.join("repaired.rar");
    let payload = b"rar50 repair cli payload with enough bytes for shard damage\n".repeat(64);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--store",
            "--recovery-percent",
            "20",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut damaged = fs::read(&archive).unwrap();
    let payload_at = damaged
        .windows(32)
        .position(|window| window == &payload[..32])
        .expect("stored payload is visible in archive");
    damaged[payload_at + 10..payload_at + 90].fill(0xa5);
    fs::write(&archive, damaged).unwrap();

    let broken = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!broken.status.success());

    let repair = rars()
        .arg("repair")
        .arg(&archive)
        .arg(&repaired)
        .output()
        .unwrap();
    assert!(repair.status.success(), "stderr: {}", stderr(&repair));
    assert!(stdout(&repair).contains("repaired"));

    let test = rars().arg("test").arg(&repaired).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn repairs_rar250_protect_head_archive() {
    let dir = scratch("repair-rar250-protect-head");
    let archive = dir.join("damaged.rar");
    let repaired = dir.join("repaired.rar");
    let original = fs::read(fixture_rar15_40("rar250_protect_head_rr5.rar")).unwrap();
    let mut damaged = original.clone();
    damaged[512 + 16..512 + 80].fill(0xa5);
    fs::write(&archive, damaged).unwrap();

    let broken = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!broken.status.success());

    let repair = rars()
        .arg("repair")
        .arg(&archive)
        .arg(&repaired)
        .output()
        .unwrap();
    assert!(repair.status.success(), "stderr: {}", stderr(&repair));
    assert!(stdout(&repair).contains("repaired"));
    assert_eq!(fs::read(&repaired).unwrap(), original);

    let test = rars().arg("test").arg(&repaired).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK BIG.BIN"));
}

#[test]
fn repairs_rar300_newsub_recovery_archive() {
    let dir = scratch("repair-rar300-newsub-recovery");
    let archive = dir.join("damaged.rar");
    let repaired = dir.join("repaired.rar");
    let original = fs::read(fixture_rar15_40("rar300/with_recovery_rar300.rar")).unwrap();
    let mut damaged = original.clone();
    damaged[512 + 16..512 + 80].fill(0xa5);
    fs::write(&archive, damaged).unwrap();

    let broken = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!broken.status.success());

    let repair = rars()
        .arg("repair")
        .arg(&archive)
        .arg(&repaired)
        .output()
        .unwrap();
    assert!(repair.status.success(), "stderr: {}", stderr(&repair));
    assert!(stdout(&repair).contains("repaired"));
    assert_eq!(fs::read(&repaired).unwrap(), original);

    let test = rars().arg("test").arg(&repaired).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK bigtext_64k.bin"));
}

#[test]
fn repairs_rar50_rev5_missing_data_volume_set() {
    let dir = scratch("repair-rar50-rev5");
    let out_dir = dir.join("out");
    let mut command = rars();
    command.arg("repair");
    for name in [
        "multivol_rev.part1.rar",
        "multivol_rev.part3.rar",
        "multivol_rev.part4.rar",
        "multivol_rev.part5.rar",
        "multivol_rev.part1.rev",
    ] {
        command.arg(fixture_rar50(name));
    }
    let output = command.arg(&out_dir).output().unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("repaired"));

    for index in 1..=5 {
        assert_eq!(
            fs::read(out_dir.join(format!("repaired.part{index}.rar"))).unwrap(),
            fs::read(fixture_rar50(&format!("multivol_rev.part{index}.rar"))).unwrap()
        );
    }
}

#[test]
fn repairs_rar300_old_style_rev_missing_data_volume_set() {
    let dir = scratch("repair-rar300-rev3");
    let out_dir = dir.join("out");
    let mut command = rars();
    command.arg("repair");
    for name in [
        "rar300/rev_oldstyle.part1.rar",
        "rar300/rev_oldstyle.part3.rar",
        "rar300/rev_oldstyle.part4.rar",
        "rar300/rev_oldstyle.part4_2_1.rev",
    ] {
        command.arg(fixture_rar15_40(name));
    }
    let output = command.arg(&out_dir).output().unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("repaired"));
    assert_eq!(
        fs::read(out_dir.join("repaired.part2.rar")).unwrap(),
        fs::read(fixture_rar15_40("rar300/rev_oldstyle.part2.rar")).unwrap()
    );

    let test = rars()
        .arg("test")
        .arg(out_dir.join("repaired.part1.rar"))
        .arg(out_dir.join("repaired.part2.rar"))
        .arg(out_dir.join("repaired.part3.rar"))
        .arg(out_dir.join("repaired.part4.rar"))
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK tmp\\rars-rar3-rev-gen\\payload.bin"));
}

#[test]
fn repairs_rar4_new_style_rev_missing_data_volume_set() {
    let dir = scratch("repair-rar4-rev3-new-style");
    let out_dir = dir.join("out");
    let mut command = rars();
    command.arg("repair");
    for name in [
        "rar300/rev_newstyle.part1.rar",
        "rar300/rev_newstyle.part3.rar",
        "rar300/rev_newstyle.part4.rar",
        "rar300/rev_newstyle.part1.rev",
    ] {
        command.arg(fixture_rar15_40(name));
    }
    let output = command.arg(&out_dir).output().unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("repaired"));
    assert_eq!(
        fs::read(out_dir.join("repaired.part2.rar")).unwrap(),
        fs::read(fixture_rar15_40("rar300/rev_newstyle.part2.rar")).unwrap()
    );

    let test = rars()
        .arg("test")
        .arg(out_dir.join("repaired.part1.rar"))
        .arg(out_dir.join("repaired.part2.rar"))
        .arg(out_dir.join("repaired.part3.rar"))
        .arg(out_dir.join("repaired.part4.rar"))
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK tmp\\rars-rar4-rev-gen\\payload.bin"));
}

#[test]
fn creates_rar50_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-compressed");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 compressed cli payload\nrar50 compressed cli payload\n",
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar50"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=1"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_solid_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-solid-compressed");
    let first = dir.join("one.txt");
    let second = dir.join("two.txt");
    let archive = dir.join("solid.rar");
    fs::write(
        &first,
        b"rar50 solid compressed cli shared phrase alpha beta gamma\n".repeat(16),
    )
    .unwrap();
    fs::write(
        &second,
        b"rar50 solid compressed cli shared phrase alpha beta gamma\nsecond\n".repeat(8),
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--solid"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("rar50 main: flags=0x0004"));
    assert!(stdout(&info).contains("solid=false"));
    assert!(stdout(&info).contains("solid=true"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK one.txt"));
    assert!(stdout(&test).contains("OK two.txt"));
}

#[test]
fn creates_rar50_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-compressed-multivolume");
    let source = dir.join("payload.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar50 compressed split cli payload\nrar50 compressed split cli payload\n".repeat(16),
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--volume-size", "32"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(dir.join("split.part1.rar").exists());
    assert!(dir.join("split.part2.rar").exists());

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }

    let test = rars().arg("test").args(&parts).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_delta_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-delta-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    let payload: Vec<u8> = (0..180)
        .map(|index| (index * 5 + index / 2) as u8)
        .collect();
    fs::write(&source, payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--delta-filter", "3"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=1"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar50_e8_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-e8-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    fs::write(&source, b"\xe8\0\0\0\0rar50 e8 filtered cli payload").unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--e8-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar29_e8_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-e8-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"\xe8\0\0\0\0rar29 e8 filtered cli payload\n".repeat(12),
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--e8-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar29_solid_e8_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-solid-e8-filtered-compressed");
    let first = dir.join("first.bin");
    let second = dir.join("second.bin");
    let archive = dir.join("created.rar");
    fs::write(
        &first,
        b"\xe8\0\0\0\0rar29 solid e8 filtered first cli payload\n".repeat(12),
    )
    .unwrap();
    fs::write(
        &second,
        b"\xe8\0\0\0\0rar29 solid e8 filtered second cli payload\n".repeat(12),
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--solid", "--e8-filter"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK first.bin"));
    assert!(stdout(&test).contains("OK second.bin"));
}

#[test]
fn creates_rar29_encrypted_e8_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-encrypted-e8-filtered-compressed");
    let source = dir.join("secret.bin");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"\xe8\0\0\0\0rar29 encrypted e8 filtered cli payload\n".repeat(12),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar29",
            "--e8-filter",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let wrong = rars()
        .args(["test", "--password", "wrong"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert!(stderr(&wrong).contains("wrong password or corrupt encrypted data"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.bin"));
}

#[test]
fn creates_rar30_header_encrypted_e8_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar30-header-encrypted-e8-filtered-compressed");
    let source = dir.join("secret.bin");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"\xe8\0\0\0\0rar30 header encrypted e8 filtered cli payload\n".repeat(12),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar30",
            "--encrypt-headers",
            "--e8-filter",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("info").arg(&archive).output().unwrap();
    assert!(!missing_password.status.success());
    assert!(stderr(&missing_password).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.bin"));
}

#[test]
fn creates_rar29_e8e9_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-e8e9-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"\xe9\0\0\0\0rar29 e8e9 filtered cli payload\n".repeat(12),
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--e8e9-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar29_delta_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-delta-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    let payload: Vec<u8> = (0..384).map(|index| (index * 23 + 9) as u8).collect();
    fs::write(&source, payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--delta-filter", "3"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar29_itanium_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-itanium-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    let mut payload = vec![0u8; 48];
    payload[16] = 22;
    payload[21] = 20;
    payload.extend_from_slice(b"rar29 itanium filtered cli payload\n");
    fs::write(&source, payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--itanium-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar29_rgb_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-rgb-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    let payload: Vec<u8> = (0..96).map(|index| (index * 41 + 19) as u8).collect();
    fs::write(&source, payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--rgb-filter", "12"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar29_audio_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-audio-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    let payload: Vec<u8> = (0..160)
        .map(|index| (index * 13 + index / 11) as u8)
        .collect();
    fs::write(&source, payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--audio-filter", "2"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar50_e8e9_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-e8e9-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    fs::write(&source, b"\xe9\0\0\0\0rar50 e8e9 filtered cli payload").unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--e8e9-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar50_arm_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-arm-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    fs::write(&source, [0x04, 0x00, 0x00, 0xeb, b'A', b'R', b'M', b'!']).unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--arm-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar50_auto_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-auto-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"\xe8\0\0\0\0rar50 auto filtered cli payload\n".repeat(16),
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--auto-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar29_auto_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-auto-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"\xe8\0\0\0\0rar29 auto filtered cli payload\n".repeat(16),
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--auto-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar29_ppmd_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-ppmd-compressed");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar29 ppmd cli text alpha beta gamma\n".repeat(96),
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--ppmd"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=0x35"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar29_ppmd_filtered_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-ppmd-filtered");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"\xe8\0\0\0\0rar29 ppmd embedded e8 filter cli payload\n".repeat(16),
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--ppmd", "--e8-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let info = rars().arg("info").arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=0x35"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn rejects_ppmd_for_rar5_writer() {
    let dir = scratch("reject-rar5-ppmd");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar5 cannot write ppmd\n").unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--ppmd"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(stderr(&output).contains("--ppmd is only available"));
}

#[test]
fn creates_rar50_solid_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-solid-compressed-multivolume");
    let source = dir.join("payload.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar50 solid compressed split cli payload\nrar50 solid compressed split cli payload\n"
            .repeat(16),
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--solid", "--volume-size", "32"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    let info = rars().arg("info").arg(&parts[0]).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("rar50 main: flags=0x0007"));

    let test = rars().arg("test").args(&parts).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_multi_file_solid_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-multi-file-solid-compressed-multivolume");
    let first = dir.join("one.txt");
    let second = dir.join("two.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &first,
        b"rar50 multi-file solid split cli shared phrase\n".repeat(14),
    )
    .unwrap();
    fs::write(
        &second,
        b"rar50 multi-file solid split cli shared phrase\nsecond\n".repeat(12),
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--solid", "--volume-size", "96"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    let info = rars().arg("info").args(&parts).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("solid=true"));

    let test = rars().arg("test").args(&parts).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK one.txt"));
    assert!(stdout(&test).contains("OK two.txt"));
}

#[test]
fn creates_rar50_encrypted_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-encrypted-compressed-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar50 encrypted compressed split cli payload\nrar50 encrypted compressed split cli payload\n".repeat(16),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--password",
            "pass",
            "--volume-size",
            "32",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&parts)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_encrypted_solid_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-encrypted-solid-compressed-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar50 encrypted solid compressed split cli payload\nrar50 encrypted solid compressed split cli payload\n".repeat(16),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--password",
            "pass",
            "--solid",
            "--volume-size",
            "32",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&parts)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_header_encrypted_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-header-encrypted-compressed-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar50 header encrypted compressed split cli payload\nrar50 header encrypted compressed split cli payload\n".repeat(16),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--password",
            "pass",
            "--encrypt-headers",
            "--volume-size",
            "32",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    let missing = rars().arg("test").args(&parts).output().unwrap();
    assert!(!missing.status.success());
    assert!(stderr(&missing).contains("password is required"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&parts)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_header_encrypted_solid_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-header-encrypted-solid-compressed-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar50 header encrypted solid compressed split cli payload\nrar50 header encrypted solid compressed split cli payload\n".repeat(16),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--password",
            "pass",
            "--encrypt-headers",
            "--solid",
            "--volume-size",
            "32",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    let missing = rars().arg("test").args(&parts).output().unwrap();
    assert!(!missing.status.success());

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&parts)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn rejects_solid_store_output() {
    let dir = scratch("reject-solid-store");
    let source = dir.join("hello.txt");
    let archive = dir.join("bad.rar");
    fs::write(&source, b"hello").unwrap();

    let output = rars()
        .args(["a", "--format", "rar14", "--store", "--solid"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("solid output requires compression"));
}

#[test]
fn rejects_add_without_inputs() {
    let dir = scratch("reject-no-inputs");
    let archive = dir.join("empty.rar");

    let output = rars()
        .args(["a", "--format", "rar14"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("no input files"));
}

#[test]
fn rejects_unknown_add_option() {
    let dir = scratch("reject-unknown-add-option");
    let source = dir.join("hello.txt");
    let archive = dir.join("bad.rar");
    fs::write(&source, b"hello").unwrap();

    let output = rars()
        .args(["a", "--format", "rar14", "--not-a-real-option"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown add option: --not-a-real-option"));
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn expected_rar15_40_stored_volume_payload() -> Vec<u8> {
    "RAR 3.00 stored multivolume fixture line.\n"
        .repeat(80)
        .into_bytes()
}

fn expected_rar15_40_compressed_text_payload() -> Vec<u8> {
    "Hello, RAR 3.x fixture world.\n".repeat(80).into_bytes()
}

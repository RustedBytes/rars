use rars::rar13::{write_stored_archive, StoredEntry, WriterOptions};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rars-format/tests/fixtures/rar13")
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
    assert!(stdout(&info).contains("method=3"));

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
    assert!(stderr(&output).contains("solid RAR 1.4 output requires compression"));
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

use crate::time::{source_dos_mtime, source_unix_mtime};
use crate::{CliResult, DOS_ARCHIVE_ATTR};
use std::fs;
use std::path::Path;

pub(crate) struct OwnedInput {
    pub(crate) name: Vec<u8>,
    pub(crate) data: Vec<u8>,
    pub(crate) file_attr: u8,
    pub(crate) unix_mode: Option<u32>,
    pub(crate) unix_mtime: Option<u32>,
    pub(crate) dos_mtime: u32,
    pub(crate) password: Option<Vec<u8>>,
}

pub(crate) fn read_inputs(paths: &[String], password: Option<&[u8]>) -> CliResult<Vec<OwnedInput>> {
    let mut out = Vec::new();
    for path in paths {
        let path = Path::new(path);
        let name = path
            .file_name()
            .ok_or("input path has no file name")?
            .to_string_lossy()
            .as_bytes()
            .to_vec();
        let meta = fs::metadata(path)
            .map_err(|err| format!("failed to stat input '{}': {err}", path.display()))?;
        let unix_mtime = source_unix_mtime(&meta);
        let dos_mtime = source_dos_mtime(&meta);
        let unix_mode = source_unix_mode(&meta);
        if meta.is_dir() {
            out.push(OwnedInput {
                name,
                data: Vec::new(),
                file_attr: 0x10,
                unix_mode,
                unix_mtime,
                dos_mtime,
                password: None,
            });
        } else {
            out.push(OwnedInput {
                name,
                data: read_file(path, "input")?,
                file_attr: DOS_ARCHIVE_ATTR,
                unix_mode,
                unix_mtime,
                dos_mtime,
                password: password.map(|p| p.to_vec()),
            });
        }
    }
    Ok(out)
}

fn read_file(path: &Path, role: &str) -> CliResult<Vec<u8>> {
    fs::read(path)
        .map_err(|err| format!("failed to read {role} '{}': {err}", path.display()).into())
}

#[cfg(unix)]
fn source_unix_mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;

    Some(metadata.permissions().mode())
}

#[cfg(not(unix))]
fn source_unix_mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

pub(crate) fn rar15_file_attr(entry: &OwnedInput) -> u32 {
    entry
        .unix_mode
        .unwrap_or_else(|| u32::from(entry.file_attr))
}

pub(crate) fn rar50_file_attr(entry: &OwnedInput) -> u64 {
    u64::from(
        entry
            .unix_mode
            .unwrap_or_else(|| u32::from(entry.file_attr)),
    )
}

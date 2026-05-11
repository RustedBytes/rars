use crate::time::{source_dos_mtime, source_unix_mtime};
use crate::{CliResult, DOS_ARCHIVE_ATTR};
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

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
        let base = input_archive_base(path)?;
        collect_input(path, &base, password, &mut out)?;
    }
    if out.is_empty() {
        return Err("no regular input files found".into());
    }
    reject_duplicate_input_names(&out)?;
    Ok(out)
}

fn collect_input(
    path: &Path,
    archive_name: &Path,
    password: Option<&[u8]>,
    out: &mut Vec<OwnedInput>,
) -> CliResult<()> {
    let link_meta = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat input '{}': {err}", path.display()))?;
    if link_meta.file_type().is_symlink() {
        return Err(format!(
            "input '{}' is a symlink; refusing to follow it",
            path.display()
        )
        .into());
    }
    let meta = fs::metadata(path)
        .map_err(|err| format!("failed to stat input '{}': {err}", path.display()))?;
    if meta.is_dir() {
        let mut children = fs::read_dir(path)
            .map_err(|err| format!("failed to read directory '{}': {err}", path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("failed to read directory '{}': {err}", path.display()))?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let child_path = child.path();
            let child_name = archive_name.join(child.file_name());
            collect_input(&child_path, &child_name, password, out)?;
        }
    } else {
        let unix_mtime = source_unix_mtime(&meta);
        let dos_mtime = source_dos_mtime(&meta);
        let unix_mode = source_unix_mode(&meta);
        let name = archive_path_bytes(archive_name)?;
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
    Ok(())
}

fn input_archive_base(path: &Path) -> CliResult<PathBuf> {
    if path.is_absolute() {
        return path
            .file_name()
            .map(PathBuf::from)
            .ok_or_else(|| "input path has no file name".into());
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return Err(format!("unsafe input archive path: {}", path.display()).into()),
        }
    }
    if out.as_os_str().is_empty() {
        return Err("input path has no file name".into());
    }
    Ok(out)
}

fn archive_path_bytes(path: &Path) -> CliResult<Vec<u8>> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return Err(format!("unsafe input archive path: {}", path.display()).into());
        };
        parts.push(part.to_string_lossy().into_owned());
    }
    if parts.is_empty() {
        return Err("input path has no file name".into());
    }
    Ok(parts.join("/").into_bytes())
}

fn reject_duplicate_input_names(entries: &[OwnedInput]) -> CliResult<()> {
    let mut seen = HashSet::new();
    for entry in entries {
        if !seen.insert(entry.name.clone()) {
            return Err(format!(
                "multiple input entries map to archive name '{}'",
                String::from_utf8_lossy(&entry.name)
            )
            .into());
        }
    }
    Ok(())
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

use crate::time::extracted_system_time;
use crate::{CliError, CliResult};
use rars::{Archive as DetectedArchive, ArchiveFamily, Error, ExtractedEntryMeta};
use std::fs::{self, File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

pub(crate) struct ExtractedOutput {
    pub(crate) name: Vec<u8>,
    pub(crate) path: PathBuf,
    pub(crate) meta: ExtractedEntryMeta,
    pub(crate) family: ArchiveFamily,
}

pub(crate) fn open_output_writer(
    out_dir: &Path,
    entry: &ExtractedEntryMeta,
) -> rars::Result<(PathBuf, Box<dyn std::io::Write>)> {
    let rel = output_relative_path(&entry.name)
        .map_err(|_| Error::InvalidHeader("unsafe archive path"))?;
    let mut out_path = checked_output_path(out_dir, &rel)?;
    if entry.is_directory {
        fs::create_dir_all(&out_path)?;
        return Ok((out_path, Box::new(std::io::sink())));
    }
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    out_path = checked_output_path(out_dir, &rel)?;
    Ok((out_path.clone(), Box::new(create_output_file(&out_path)?)))
}

pub(crate) fn restore_output_metadata(outputs: &[ExtractedOutput]) -> std::io::Result<()> {
    for output in outputs.iter().filter(|output| !output.meta.is_directory) {
        if let Some(time) = extracted_system_time(output.family, output.meta.file_time) {
            set_modified_time(&output.path, time)?;
        }
        set_extracted_permissions(&output.path, output.meta.file_attr)?;
    }
    for output in outputs.iter().filter(|output| output.meta.is_directory) {
        set_extracted_permissions(&output.path, output.meta.file_attr)?;
        if let Some(time) = extracted_system_time(output.family, output.meta.file_time) {
            set_modified_time(&output.path, time)?;
        }
    }
    Ok(())
}

fn set_modified_time(path: &Path, time: SystemTime) -> std::io::Result<()> {
    File::open(path)?.set_modified(time)
}

#[cfg(unix)]
fn set_extracted_permissions(path: &Path, file_attr: u64) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if file_attr & 0o170000 != 0 {
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(u32::try_from(file_attr & 0o777).unwrap_or(0o644)),
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_extracted_permissions(_path: &Path, _file_attr: u64) -> std::io::Result<()> {
    Ok(())
}

pub(crate) fn checked_output_path(out_dir: &Path, rel: &Path) -> rars::Result<PathBuf> {
    let mut out_path = out_dir.to_path_buf();
    for component in rel.components() {
        let Component::Normal(part) = component else {
            return Err(Error::InvalidHeader("unsafe archive path"));
        };
        out_path.push(part);
        if fs::symlink_metadata(&out_path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(Error::InvalidHeader("unsafe archive path crosses symlink"));
        }
    }
    Ok(out_path)
}

pub(crate) fn print_ok_entry(entry: &ExtractedEntryMeta) {
    println!(
        "OK {}{}",
        String::from_utf8_lossy(&entry.name),
        if entry.is_directory { "/" } else { "" }
    );
}

pub(crate) fn warn_rar50_redirections(archive: &DetectedArchive) {
    let DetectedArchive::Rar50Plus(archive) = archive else {
        return;
    };
    for file in archive.files().filter(|file| file.redirection.is_some()) {
        eprintln!("{}", redirection_warning(file.name_lossy()));
    }
}

pub(crate) fn redirection_warning(name: impl AsRef<str>) -> String {
    format!(
        "warning: RAR 5 redirection entry '{}' is not recreated; extraction treats only regular file payloads as writable output",
        name.as_ref()
    )
}

pub(crate) fn output_relative_path(name: &[u8]) -> CliResult<PathBuf> {
    if name.contains(&0) {
        return Err("unsafe archive path contains NUL byte".into());
    }
    let text = String::from_utf8(name.to_vec())
        .map_err(|_| CliError::general("archive entry name is not UTF-8"))?
        .replace('\\', "/");
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(format!("unsafe archive path: {text}").into());
    }
    let path = Path::new(&text);
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return Err(format!("unsafe archive path: {text}").into()),
        }
    }
    if out.as_os_str().is_empty() {
        return Err("empty archive path".into());
    }
    Ok(out)
}

fn create_output_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    set_no_follow(&mut options);
    options.open(path)
}

#[cfg(unix)]
fn set_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn set_no_follow(_options: &mut OpenOptions) {
    // checked_output_path validates archive path components before open. The
    // standard library does not expose a cross-platform final-component
    // no-follow flag for this target family.
}

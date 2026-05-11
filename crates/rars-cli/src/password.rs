use crate::{CliError, CliResult};
use rars::{Archive as DetectedArchive, ArchiveReadOptions, ArchiveReader, Error};
use std::fs;
use std::io::IsTerminal;

fn read_options(password: Option<&[u8]>) -> ArchiveReadOptions<'_> {
    match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::new(),
    }
}

pub(crate) fn parse_password(args: &[String]) -> CliResult<(Option<Vec<u8>>, Vec<String>)> {
    let mut password = None;
    let mut rest = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--password" | "-p" => {
                let value = iter
                    .next()
                    .ok_or_else(|| CliError::usage("missing password value"))?;
                set_password(&mut password, read_password_value(value)?)?;
            }
            "--password-file" => {
                let path = iter
                    .next()
                    .ok_or_else(|| CliError::usage("missing --password-file value"))?;
                let bytes = fs::read(path)?;
                set_password(&mut password, trim_password_line(bytes))?;
            }
            _ => rest.push(arg.clone()),
        }
    }
    Ok((password, rest))
}

fn set_password(slot: &mut Option<Vec<u8>>, value: Vec<u8>) -> CliResult<()> {
    if slot.is_some() {
        return Err(CliError::usage("password was provided more than once"));
    }
    *slot = Some(value);
    Ok(())
}

fn read_password_value(value: &str) -> CliResult<Vec<u8>> {
    if value == "-" {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes)?;
        return Ok(trim_password_line(bytes));
    }
    Ok(value.as_bytes().to_vec())
}

fn trim_password_line(mut bytes: Vec<u8>) -> Vec<u8> {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    bytes
}

pub(crate) fn read_archive_path_prompting(
    path: &str,
    password: &mut Option<Vec<u8>>,
) -> CliResult<DetectedArchive> {
    match ArchiveReader::read_path_with_options(path, read_options(password.as_deref())) {
        Ok(archive) => Ok(archive),
        Err(error) if password.is_none() && error_needs_password(&error) => {
            if let Some(prompted) = prompt_password_if_tty()? {
                *password = Some(prompted);
                ArchiveReader::read_path_with_options(path, read_options(password.as_deref()))
                    .map_err(|err| read_archive_cli_error(path, err))
            } else {
                Err(read_archive_cli_error(path, error))
            }
        }
        Err(error) => Err(read_archive_cli_error(path, error)),
    }
}

pub(crate) fn parse_archives_prompting(
    paths: &[String],
    password: &mut Option<Vec<u8>>,
) -> CliResult<Vec<DetectedArchive>> {
    let mut archives = Vec::new();
    for path in paths {
        archives.push(read_archive_path_prompting(path, password)?);
    }
    Ok(archives)
}

pub(crate) fn ensure_password_for_archives_extract(
    archives: &[DetectedArchive],
    password: &mut Option<Vec<u8>>,
) -> CliResult<()> {
    if password.is_none()
        && archives
            .iter()
            .any(|archive| archive.members().any(|member| member.meta.is_encrypted))
    {
        if let Some(prompted) = prompt_password_if_tty()? {
            *password = Some(prompted);
        }
    }
    Ok(())
}

pub(crate) fn ensure_password_for_extract(
    archive: &DetectedArchive,
    password: &mut Option<Vec<u8>>,
) -> CliResult<()> {
    ensure_password_for_archives_extract(std::slice::from_ref(archive), password)
}

fn prompt_password_if_tty() -> CliResult<Option<Vec<u8>>> {
    if !should_prompt_password(std::io::stdin().is_terminal()) {
        return Ok(None);
    }
    let line = rpassword::prompt_password("password: ")?;
    Ok(Some(trim_password_line(line.into_bytes())))
}

pub(crate) fn should_prompt_password(stdin_is_terminal: bool) -> bool {
    stdin_is_terminal
}

pub(crate) fn error_needs_password(error: &Error) -> bool {
    match error {
        Error::NeedPassword => true,
        Error::AtArchiveOffset { source, .. } | Error::AtEntry { source, .. } => {
            error_needs_password(source)
        }
        _ => false,
    }
}

pub(crate) fn error_is_password_class(error: &Error) -> bool {
    match error {
        Error::NeedPassword | Error::WrongPasswordOrCorruptData => true,
        Error::AtArchiveOffset { source, .. } | Error::AtEntry { source, .. } => {
            error_is_password_class(source)
        }
        _ => false,
    }
}

fn read_archive_error(path: &str, err: Error) -> String {
    match err {
        Error::Io(error) => format!("failed to read archive '{path}': {}", error.message),
        Error::UnsupportedSignature => {
            format!(
                "failed to identify archive '{path}': {}",
                Error::UnsupportedSignature
            )
        }
        other => format!("failed to parse archive '{path}': {other}"),
    }
}

fn read_archive_cli_error(path: &str, err: Error) -> CliError {
    let message = read_archive_error(path, err.clone());
    if error_is_password_class(&err) {
        CliError::password(message)
    } else {
        CliError::general(message)
    }
}

pub(crate) fn classify_rars_error(
    error: Error,
    message: impl FnOnce(&Error) -> String,
) -> CliError {
    if error_is_password_class(&error) {
        CliError::password(message(&error))
    } else {
        CliError::general(message(&error))
    }
}

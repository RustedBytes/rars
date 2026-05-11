use crate::CliResult;
use rars_crc32::crc32;
use std::path::{Path, PathBuf};

pub(crate) fn volume_part_path(first_path: &Path, index: usize) -> CliResult<PathBuf> {
    if index == 0 {
        return Ok(first_path.to_path_buf());
    }
    // Extension-based RAR volume names are finite: first .rar, then .r00
    // through .r99. Later RAR families use part-number names instead.
    if index > 100 {
        return Err("RAR 1.4 old-style volume names only support .r00 through .r99 here".into());
    }
    Ok(first_path.with_extension(format!("r{:02}", index - 1)))
}

pub(crate) fn rar50_volume_part_path(first_path: &Path, index: usize) -> CliResult<PathBuf> {
    let parent = first_path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = first_path
        .file_name()
        .ok_or("RAR 5 volume path needs a file name")?
        .to_string_lossy();
    let stem = rar50_volume_stem(&file_name);
    Ok(parent.join(format!("{stem}.part{}.rar", index + 1)))
}

fn rar50_volume_stem(file_name: &str) -> &str {
    let without_rar = file_name
        .strip_suffix(".rar")
        .or_else(|| file_name.strip_suffix(".RAR"))
        .unwrap_or(file_name);
    if let Some((base, digits)) = without_rar.rsplit_once(".part") {
        if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return base;
        }
    }
    without_rar
}

pub(crate) fn path_has_extension(path: &str, extension: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
}

pub(crate) fn parse_rar3_rev_volume(
    path: &Path,
    bytes: &[u8],
) -> Option<(usize, usize, usize, Vec<u8>)> {
    if let Some((recovery_index, recovery_count, data_count)) = parse_rar3_new_style_rev(bytes) {
        let mut payload = bytes[..bytes.len() - 7].to_vec();
        payload.extend_from_slice(&[0; 7]);
        return Some((recovery_index, recovery_count, data_count, payload));
    }
    let (recovery_index, recovery_count, data_count) = parse_rar3_old_style_rev_name(path)?;
    Some((recovery_index, recovery_count, data_count, bytes.to_vec()))
}

fn parse_rar3_new_style_rev(bytes: &[u8]) -> Option<(usize, usize, usize)> {
    if bytes.len() < 7 {
        return None;
    }
    let trailer = &bytes[bytes.len() - 7..];
    let stored_crc = u32::from_le_bytes(trailer[3..7].try_into().ok()?);
    if crc32(&bytes[..bytes.len() - 4]) != stored_crc {
        return None;
    }
    let recovery_index = usize::from(trailer[2]);
    let recovery_count = usize::from(trailer[1]) + 1;
    let data_count = usize::from(trailer[0]) + 1;
    Some((recovery_index, recovery_count, data_count))
}

fn parse_rar3_old_style_rev_name(path: &Path) -> Option<(usize, usize, usize)> {
    let stem = path.file_stem()?.to_string_lossy();
    let bytes = stem.as_bytes();
    let mut cursor = bytes.len();
    let mut numbers = Vec::new();
    while cursor > 0 && numbers.len() < 3 {
        while cursor > 0 && !bytes[cursor - 1].is_ascii_digit() {
            cursor -= 1;
        }
        if cursor == 0 {
            break;
        }
        let end = cursor;
        while cursor > 0 && bytes[cursor - 1].is_ascii_digit() {
            cursor -= 1;
        }
        let number = stem[cursor..end].parse::<usize>().ok()?;
        numbers.push(number);
    }
    if numbers.len() != 3 || numbers.iter().any(|&number| number == 0 || number > 255) {
        return None;
    }
    Some((numbers[0] - 1, numbers[1], numbers[2]))
}

pub(crate) fn infer_part_index(path: &Path, data_count: u16) -> Option<usize> {
    let name = path.file_name()?.to_string_lossy();
    let index = if let Some(part_pos) = name.find(".part") {
        let suffix = &name[part_pos + ".part".len()..];
        if suffix.len() <= 4 || !suffix[suffix.len() - 4..].eq_ignore_ascii_case(".rar") {
            return None;
        }
        let digits = &suffix[..suffix.len() - 4];
        if digits.is_empty() || !digits.chars().all(|ch| ch.is_ascii_digit()) {
            return None;
        }
        digits.parse::<usize>().ok()?.checked_sub(1)?
    } else {
        let ext = path.extension()?.to_str()?;
        if ext.eq_ignore_ascii_case("rar") {
            0
        } else if ext.len() == 3 && ext.starts_with(['r', 'R']) {
            let number = ext[1..].parse::<usize>().ok()?;
            number + 1
        } else {
            return None;
        }
    };
    (index < usize::from(data_count)).then_some(index)
}

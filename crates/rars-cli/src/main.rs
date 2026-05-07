use rars::rar13::{
    self, FileEntry, StoredEntry as Rar13StoredEntry, WriterOptions as Rar13WriterOptions,
};
use rars::rar15_40::{
    FileEntry as Rar15FileEntry, StoredEntry as Rar15StoredEntry,
    WriterOptions as Rar15WriterOptions,
};
use rars::{
    extract_volumes_to, Archive as DetectedArchive, ArchiveReadOptions, ArchiveReader,
    ArchiveVersion, Error, ExtractedEntryMeta, FeatureSet,
};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

type CliResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const ADD_USAGE: &str =
    "usage: rars a [--password <password>] --format <rar14|rar15|rar20|rar29|rar30|rar40|rar50|rar70> [--store] [--solid] [--encrypt-headers] [--quick-open] [--comment <text>] [--archive-name <name>] [--file-comment <text>] [--recovery-percent <1..100>] [--volume-size <bytes>] [--ppmd|--auto-filter|--delta-filter <channels>|--e8-filter|--e8e9-filter|--itanium-filter|--rgb-filter <width>|--audio-filter <channels>|--arm-filter] <archive> <files...>";
const DOS_DIRECTORY_ATTR: u8 = 0x10;
const RAR50_STRUCTURAL_RR_WARNING: &str =
    "warning: RAR 5 recovery writer emits validation-ready RR metadata; WinRAR recovery layout matching is not expected";

fn read_options(password: Option<&[u8]>) -> ArchiveReadOptions<'_> {
    match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::new(),
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> CliResult<()> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        usage();
        return Ok(());
    };
    let rest: Vec<String> = args.collect();

    match command.as_str() {
        "info" => cmd_info(&rest),
        "test" => cmd_test(&rest),
        "x" => cmd_extract(&rest),
        "repair" => cmd_repair(&rest),
        "a" => cmd_add(&rest),
        "-h" | "--help" | "help" => {
            usage();
            Ok(())
        }
        _ => Err(format!("unknown command: {command}").into()),
    }
}

fn cmd_info(args: &[String]) -> CliResult<()> {
    let (password, paths) = parse_password(args)?;
    if paths.is_empty() {
        return Err("usage: rars info [--password <password>] <archive>...".into());
    }

    for path in paths {
        let archive =
            ArchiveReader::read_path_with_options(&path, read_options(password.as_deref()))
                .map_err(|err| read_archive_error(&path, err))?;
        println!(
            "{path}: {:?} at offset {}",
            archive.family(),
            archive.sfx_offset()
        );
        match archive {
            DetectedArchive::Rar13(archive) => {
                println!(
                    "  rar13 main: flags={:#04x} head_size={} sfx_offset={}",
                    archive.main.flags, archive.main.head_size, archive.sfx_offset
                );
                if archive.main.has_archive_comment() {
                    println!(
                        "  archive comment extension: {} bytes{}",
                        archive.main.extra.len(),
                        if archive.main.has_packed_comment() {
                            " (packed)"
                        } else {
                            ""
                        }
                    );
                    if let Some(comment) = archive.archive_comment().map_err(|err| {
                        format!("failed to decode archive comment '{path}': {err}")
                    })? {
                        println!("  comment: {}", String::from_utf8_lossy(&comment));
                    }
                }
                if let Some(av) = archive.authenticity_verification().map_err(|err| {
                    format!("failed to parse authenticity verification in '{path}': {err}")
                })? {
                    println!(
                    "  authenticity verification: structural size={} cipher_body={} status=not-cryptographically-verified",
                    av.size,
                    av.cipher_body.len()
                );
                }
                for (index, entry) in archive.entries.iter().enumerate() {
                    println!(
                    "  #{index}: {} pack={} unp={} method={} flags={:#04x} attr={:#04x} checksum={:#06x}",
                    entry.name_lossy(),
                    entry.header.pack_size,
                    entry.header.unp_size,
                    entry.header.method,
                    entry.header.flags,
                    entry.header.file_attr,
                    entry.header.file_crc
                );
                    if let Some(comment) = entry.file_comment().map_err(|err| {
                        format!(
                            "failed to decode file comment '{}' in '{path}': {err}",
                            entry.name_lossy()
                        )
                    })? {
                        println!("    comment: {}", String::from_utf8_lossy(&comment));
                    }
                }
            }
            DetectedArchive::Rar15To40(archive) => {
                println!(
                    "  rar15-40 main: flags={:#06x} head_size={} sfx_offset={}",
                    archive.main.flags, archive.main.head_size, archive.sfx_offset
                );
                if let Some(comment) = archive
                    .archive_comment()
                    .map_err(|err| format!("failed to decode archive comment '{path}': {err}"))?
                {
                    println!("  comment: {}", String::from_utf8_lossy(&comment));
                }
                for (index, file) in archive.files().enumerate() {
                    println!(
                        "  #{index}: {} pack={} unp={} method={:#04x} flags={:#06x} attr={:#010x} crc={:#010x} ver={}",
                        file.name_lossy(),
                        file.pack_size,
                        file.unp_size,
                        file.method,
                        file.block.flags,
                        file.attr,
                        file.file_crc,
                        file.unp_ver
                    );
                    if let Some(comment) = file.file_comment().map_err(|err| {
                        format!(
                            "failed to decode file comment '{}' in '{path}': {err}",
                            file.name_lossy()
                        )
                    })? {
                        println!("    comment: {}", String::from_utf8_lossy(&comment));
                    }
                }
                for sub in archive.new_subs() {
                    println!(
                        "  subblock: {:?} {} pack={} unp={} method={:#04x} flags={:#06x}",
                        sub.kind,
                        sub.name_lossy(),
                        sub.file.pack_size,
                        sub.file.unp_size,
                        sub.file.method,
                        sub.file.block.flags
                    );
                }
            }
            DetectedArchive::Rar50Plus(archive) => {
                println!(
                    "  rar50 main: flags={:#06x} header_size={} sfx_offset={}",
                    archive.main.archive_flags, archive.main.block.header_size, archive.sfx_offset
                );
                if let Some(metadata) = archive.main.archive_metadata() {
                    if let Some(name) = &metadata.name {
                        println!("  archive name: {}", String::from_utf8_lossy(name));
                    }
                    if let Some(creation_time) = metadata.creation_time {
                        println!("  archive creation time: {creation_time:#018x}");
                    }
                }
                for (index, file) in archive.files().enumerate() {
                    let compression_info = file.decoded_compression_info().map_err(|err| {
                        format!(
                            "failed to decode RAR 5 compression info for '{}': {err}",
                            file.name_lossy()
                        )
                    })?;
                    println!(
                        "  #{index}: {} pack={} unp={} method={} solid={} flags={:#06x} attr={:#010x} crc={}",
                        file.name_lossy(),
                        file.packed_size(),
                        file.unpacked_size,
                        compression_info.method,
                        compression_info.solid,
                        file.block.flags,
                        file.attributes,
                        file.data_crc32
                            .map(|crc| format!("{crc:#010x}"))
                            .unwrap_or_else(|| "none".to_string())
                    );
                }
                for service in archive.services() {
                    println!(
                        "  service: {} pack={} unp={} flags={:#06x}",
                        service.name_lossy(),
                        service.packed_size(),
                        service.unpacked_size,
                        service.block.flags
                    );
                }
            }
            _ => unreachable!("archive family was parsed but is not handled by info output"),
        }
    }

    Ok(())
}

fn cmd_test(args: &[String]) -> CliResult<()> {
    let (password, paths) = parse_password(args)?;
    if paths.is_empty() {
        return Err("usage: rars test [--password <password>] <archive> [parts...]".into());
    }

    if paths.len() == 1 {
        let archive =
            ArchiveReader::read_path_with_options(&paths[0], read_options(password.as_deref()))
                .map_err(|err| read_archive_error(&paths[0], err))?;
        let mut entries = Vec::new();
        archive
            .extract_to(password.as_deref(), |meta| {
                entries.push(meta.clone());
                Ok(Box::new(std::io::sink()))
            })
            .map_err(|err| format!("failed to test archive '{}': {err}", paths[0]))?;
        for entry in &entries {
            print_ok_entry(entry);
        }
    } else {
        let archives = parse_archives(&paths, password.as_deref())?;
        let mut entries = Vec::new();
        extract_volumes_to(&archives, password.as_deref(), |meta| {
            entries.push(meta.clone());
            Ok(Box::new(std::io::sink()))
        })
        .map_err(|err| format!("failed to test volume set '{}': {err}", paths.join(", ")))?;
        for entry in &entries {
            print_ok_entry(entry);
        }
    }
    Ok(())
}

fn cmd_extract(args: &[String]) -> CliResult<()> {
    let (password, mut paths) = parse_password(args)?;
    if paths.len() < 2 {
        return Err("usage: rars x [--password <password>] <archive> [parts...] <outdir>".into());
    }
    let out_dir = PathBuf::from(paths.pop().expect("outdir"));

    if paths.len() == 1 {
        let archive =
            ArchiveReader::read_path_with_options(&paths[0], read_options(password.as_deref()))
                .map_err(|err| read_archive_error(&paths[0], err))?;
        let mut names = Vec::new();
        archive
            .extract_to(password.as_deref(), |meta| {
                names.push(meta.name.clone());
                open_output_writer(&out_dir, meta)
            })
            .map_err(|err| {
                format!(
                    "failed to write extracted entry to '{}': {err}",
                    out_dir.display()
                )
            })?;
        for name in &names {
            println!("x {}", String::from_utf8_lossy(name));
        }
    } else {
        let archives = parse_archives(&paths, password.as_deref())?;
        let mut names = Vec::new();
        extract_volumes_to(&archives, password.as_deref(), |meta| {
            names.push(meta.name.clone());
            open_output_writer(&out_dir, meta)
        })
        .map_err(|err| format!("failed to extract volume set '{}': {err}", paths.join(", ")))?;
        for name in &names {
            println!("x {}", String::from_utf8_lossy(name));
        }
    }
    Ok(())
}

fn cmd_repair(args: &[String]) -> CliResult<()> {
    let (password, paths) = parse_password(args)?;
    if paths.len() < 2 {
        return Err("usage: rars repair [--password <password>] <archive> <repaired-archive>\n       rars repair <rar-parts-and-rev-files...> <outdir>".into());
    }
    if paths.len() > 2 {
        if password.is_some() {
            return Err("REV repair does not use archive passwords".into());
        }
        return cmd_repair_volumes(&paths);
    }
    let archive =
        ArchiveReader::read_path_with_options(&paths[0], read_options(password.as_deref()));
    let repaired = match archive {
        Ok(archive) => archive
            .repair_recovery()
            .map_err(|err| format!("failed to repair archive '{}': {err}", paths[0]))?,
        Err(parse_error) => {
            let bytes = fs::read(&paths[0])?;
            rars::rar50::repair_inline_recovery_bytes(&bytes).map_err(|repair_error| {
                format!(
                    "failed to parse archive '{}': {}; raw inline recovery repair also failed: {}",
                    paths[0], parse_error, repair_error
                )
            })?
        }
    };
    fs::write(&paths[1], repaired)?;
    println!("repaired {}", paths[1]);
    Ok(())
}

fn cmd_repair_volumes(paths: &[String]) -> CliResult<()> {
    let input_paths = &paths[..paths.len() - 1];
    for path in input_paths {
        if path_has_extension(path, "rev") {
            let bytes = fs::read(path)?;
            if rars::rar50::Rev5Volume::parse(&bytes).is_ok() {
                return cmd_repair_rev5(paths);
            }
        }
    }
    cmd_repair_rev3(paths)
}

fn cmd_repair_rev5(paths: &[String]) -> CliResult<()> {
    let out_dir = PathBuf::from(paths.last().expect("outdir"));
    fs::create_dir_all(&out_dir)?;
    let input_paths = &paths[..paths.len() - 1];
    let mut data_inputs = Vec::new();
    let mut recovery = Vec::new();
    for path in input_paths {
        let bytes = fs::read(path)?;
        match rars::rar50::Rev5Volume::parse(&bytes) {
            Ok(rev) => recovery.push(rev),
            Err(Error::UnsupportedSignature) => data_inputs.push((PathBuf::from(path), bytes)),
            Err(error) => {
                return Err(format!("failed to parse REV volume '{path}': {error}").into())
            }
        }
    }
    let first = recovery
        .first()
        .ok_or("RAR 5 REV repair requires at least one .rev file")?;
    let mut slots: Vec<Option<&[u8]>> = vec![None; usize::from(first.data_count)];
    for (path, bytes) in &data_inputs {
        if let Some(index) = infer_part_index(path, first.data_count) {
            slots[index] = Some(bytes.as_slice());
            continue;
        }
        if let Some((index, _)) = first.data_volumes.iter().enumerate().find(|(_, meta)| {
            bytes.len() as u64 == meta.file_size && rars::rar15_40::crc32(bytes) == meta.crc32
        }) {
            slots[index] = Some(bytes.as_slice());
        }
    }

    rars::rar50::repair_rev5_volumes_to(&slots, &recovery, |index, bytes| {
        let path = out_dir.join(format!("repaired.part{}.rar", index + 1));
        fs::write(&path, bytes)?;
        println!("repaired {}", path.display());
        Ok(())
    })
    .map_err(|err| format!("failed to repair RAR 5 REV volume set: {err}"))?;
    Ok(())
}

fn cmd_repair_rev3(paths: &[String]) -> CliResult<()> {
    let out_dir = PathBuf::from(paths.last().expect("outdir"));
    fs::create_dir_all(&out_dir)?;
    let input_paths = &paths[..paths.len() - 1];
    let mut data_inputs = Vec::new();
    let mut recovery_inputs = Vec::new();
    let mut data_count = None;
    let mut recovery_count = None;

    for path in input_paths {
        let bytes = fs::read(path)?;
        if path_has_extension(path, "rev") {
            let (recovery_index, rec_count, dat_count, payload) =
                parse_rar3_rev_volume(Path::new(path), &bytes)
                    .ok_or_else(|| format!("failed to parse RAR 3 REV volume name '{path}'"))?;
            if recovery_count
                .replace(rec_count)
                .is_some_and(|count| count != rec_count)
                || data_count
                    .replace(dat_count)
                    .is_some_and(|count| count != dat_count)
            {
                return Err("RAR 3 REV volume metadata differs across files".into());
            }
            recovery_inputs.push((recovery_index, payload));
        } else {
            data_inputs.push((PathBuf::from(path), bytes));
        }
    }

    let data_count = data_count.ok_or("RAR 3 REV repair requires at least one .rev file")?;
    let recovery_count =
        recovery_count.ok_or("RAR 3 REV repair requires at least one .rev file")?;
    let mut slots: Vec<Option<&[u8]>> = vec![None; data_count];
    for (path, bytes) in &data_inputs {
        if let Some(index) = infer_part_index(path, data_count as u16) {
            slots[index] = Some(bytes.as_slice());
        }
    }
    let recovery: Vec<_> = recovery_inputs
        .iter()
        .map(|(index, bytes)| (*index, bytes.as_slice()))
        .collect();
    rars::rar15_40::repair_rev3_volumes_to(&slots, recovery_count, &recovery, |index, bytes| {
        let path = out_dir.join(format!("repaired.part{}.rar", index + 1));
        fs::write(&path, bytes)?;
        println!("repaired {}", path.display());
        Ok(())
    })
    .map_err(|err| format!("failed to repair RAR 3 REV volume set: {err}"))?;
    Ok(())
}

fn path_has_extension(path: &str, extension: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
}

fn parse_rar3_rev_volume(path: &Path, bytes: &[u8]) -> Option<(usize, usize, usize, Vec<u8>)> {
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
    if rars::rar15_40::crc32(&bytes[..bytes.len() - 4]) != stored_crc {
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

fn infer_part_index(path: &Path, data_count: u16) -> Option<usize> {
    let name = path.file_name()?.to_string_lossy();
    let index = if let Some(part_pos) = name.find(".part") {
        let digits: String = name[part_pos + ".part".len()..]
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect();
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

fn cmd_add(args: &[String]) -> CliResult<()> {
    let (password, args) = parse_password(args)?;
    if args.len() < 3 || args[0] != "--format" {
        return Err(ADD_USAGE.into());
    }
    let target = match args[1].as_str() {
        "rar14" => ArchiveVersion::Rar14,
        "rar15" => ArchiveVersion::Rar15,
        "rar20" => ArchiveVersion::Rar20,
        "rar29" => ArchiveVersion::Rar29,
        "rar30" => ArchiveVersion::Rar30,
        "rar40" => ArchiveVersion::Rar40,
        "rar50" => ArchiveVersion::Rar50,
        "rar70" => ArchiveVersion::Rar70,
        _ => return Err(ADD_USAGE.into()),
    };
    let mut store = false;
    let mut solid = false;
    let mut header_encryption = false;
    let mut quick_open = false;
    let mut archive_comment = None;
    let mut archive_name = None;
    let mut file_comment = None;
    let mut recovery_percent = None;
    let mut volume_size = None;
    let mut delta_filter = None;
    let mut e8_filter = None;
    let mut itanium_filter = false;
    let mut rgb_filter = None;
    let mut audio_filter = None;
    let mut arm_filter = false;
    let mut auto_filter = false;
    let mut ppmd = false;
    let mut archive_index = 2;
    while let Some(arg) = args.get(archive_index) {
        match arg.as_str() {
            "--store" => {
                store = true;
                archive_index += 1;
            }
            "--solid" => {
                solid = true;
                archive_index += 1;
            }
            "--encrypt-headers" => {
                header_encryption = true;
                archive_index += 1;
            }
            "--quick-open" => {
                quick_open = true;
                archive_index += 1;
            }
            "--comment" => {
                let value = args
                    .get(archive_index + 1)
                    .ok_or("missing --comment value")?;
                archive_comment = Some(value.as_bytes().to_vec());
                archive_index += 2;
            }
            "--archive-name" => {
                let value = args
                    .get(archive_index + 1)
                    .ok_or("missing --archive-name value")?;
                archive_name = Some(value.as_bytes().to_vec());
                archive_index += 2;
            }
            "--file-comment" => {
                let value = args
                    .get(archive_index + 1)
                    .ok_or("missing --file-comment value")?;
                file_comment = Some(value.as_bytes().to_vec());
                archive_index += 2;
            }
            "--recovery-percent" => {
                let value = args
                    .get(archive_index + 1)
                    .ok_or("missing --recovery-percent value")?;
                recovery_percent = Some(value.parse::<u64>()?);
                archive_index += 2;
            }
            "--volume-size" => {
                let value = args
                    .get(archive_index + 1)
                    .ok_or("missing --volume-size value")?;
                volume_size = Some(value.parse::<usize>()?);
                archive_index += 2;
            }
            "--delta-filter" => {
                let value = args
                    .get(archive_index + 1)
                    .ok_or("missing --delta-filter value")?;
                delta_filter = Some(value.parse::<usize>()?);
                archive_index += 2;
            }
            "--e8-filter" => {
                e8_filter = Some(false);
                archive_index += 1;
            }
            "--e8e9-filter" => {
                e8_filter = Some(true);
                archive_index += 1;
            }
            "--itanium-filter" => {
                itanium_filter = true;
                archive_index += 1;
            }
            "--rgb-filter" => {
                let value = args
                    .get(archive_index + 1)
                    .ok_or("missing --rgb-filter value")?;
                rgb_filter = Some(value.parse::<usize>()?);
                archive_index += 2;
            }
            "--audio-filter" => {
                let value = args
                    .get(archive_index + 1)
                    .ok_or("missing --audio-filter value")?;
                audio_filter = Some(value.parse::<usize>()?);
                archive_index += 2;
            }
            "--arm-filter" => {
                arm_filter = true;
                archive_index += 1;
            }
            "--auto-filter" => {
                auto_filter = true;
                archive_index += 1;
            }
            "--ppmd" => {
                ppmd = true;
                archive_index += 1;
            }
            unknown if unknown.starts_with('-') => {
                return Err(format!("unknown add option: {unknown}").into());
            }
            _ => break,
        }
    }
    if args.len() <= archive_index {
        return Err(ADD_USAGE.into());
    }
    let compress = !store;
    if solid && store {
        return Err("solid output requires compression".into());
    }
    let archive_path = PathBuf::from(&args[archive_index]);
    let input_paths = &args[archive_index + 1..];
    if input_paths.is_empty() {
        return Err("no input files".into());
    }
    if quick_open && !matches!(target, ArchiveVersion::Rar50 | ArchiveVersion::Rar70) {
        return Err("Quick Open is only available for RAR 5+ writers".into());
    }
    if recovery_percent.is_some()
        && !matches!(target, ArchiveVersion::Rar50 | ArchiveVersion::Rar70)
    {
        return Err("recovery records are only available for RAR 5+ writers".into());
    }
    if matches!(
        target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) {
        validate_rar15_40_add_options(
            target,
            password.as_deref(),
            archive_comment.as_deref(),
            file_comment.as_deref(),
            volume_size,
            header_encryption,
        )?;
    }
    if matches!(
        target,
        ArchiveVersion::Rar14
            | ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) && volume_size.is_some()
        && input_paths.len() != 1
    {
        return Err("multivolume writer currently supports one input file".into());
    }

    let owned = read_inputs(input_paths, password.as_deref())?;
    if matches!(
        target,
        ArchiveVersion::Rar14
            | ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) && (delta_filter.is_some()
        || e8_filter.is_some()
        || itanium_filter
        || rgb_filter.is_some()
        || audio_filter.is_some()
        || arm_filter
        || auto_filter
        || ppmd)
    {
        let filter_count = usize::from(delta_filter.is_some())
            + usize::from(e8_filter.is_some())
            + usize::from(itanium_filter)
            + usize::from(rgb_filter.is_some())
            + usize::from(audio_filter.is_some())
            + usize::from(auto_filter);
        if !matches!(
            target,
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40
        ) || arm_filter
            || (!ppmd && filter_count != 1)
            || (ppmd && (auto_filter || filter_count > 1))
        {
            return Err(
                "RAR 1.5-4.x writer currently supports --ppmd alone, --ppmd with one explicit standard filter, or one of --auto-filter/--delta-filter/--e8-filter/--e8e9-filter/--itanium-filter/--rgb-filter/--audio-filter on RAR 2.9+".into(),
            );
        }
        if store {
            return Err("RAR 2.9 compression policy requires compression".into());
        }
        if volume_size.is_some() {
            return Err("unsupported option combination: RAR 2.9 compression policy cannot currently be used with --volume-size".into());
        }
        if archive_comment.is_some() || file_comment.is_some() {
            return Err("unsupported option combination: RAR 2.9 compression policy cannot currently be combined with archive or file comments".into());
        }
    }
    if matches!(target, ArchiveVersion::Rar50 | ArchiveVersion::Rar70) {
        if ppmd {
            return Err("--ppmd is only available for RAR 2.9/3.x/4.x writers".into());
        }
        let filter_count = usize::from(delta_filter.is_some())
            + usize::from(e8_filter.is_some())
            + usize::from(itanium_filter)
            + usize::from(rgb_filter.is_some())
            + usize::from(audio_filter.is_some())
            + usize::from(arm_filter)
            + usize::from(auto_filter);
        let filtered = filter_count != 0;
        if filter_count > 1 {
            return Err("RAR 5 writer accepts only one explicit filter option".into());
        }
        if filtered && store {
            return Err("RAR 5 filter writer requires compression".into());
        }
        if filtered && password.is_some() {
            return Err("unsupported option combination: RAR 5 filter writers cannot currently be combined with encryption".into());
        }
        if filtered && volume_size.is_some() {
            return Err("unsupported option combination: RAR 5 filter writers cannot currently be used with --volume-size".into());
        }
        if filtered && recovery_percent.is_some() {
            return Err("unsupported option combination: RAR 5 filter writers cannot currently be combined with recovery records".into());
        }
        if filtered && archive_name.is_some() {
            return Err("unsupported option combination: RAR 5 filter writers cannot currently be combined with archive metadata".into());
        }
        if filtered && archive_comment.is_some() {
            return Err("unsupported option combination: RAR 5 filter writers cannot currently be combined with archive comments".into());
        }
        if volume_size.is_some() && store && input_paths.len() != 1 {
            return Err("RAR 5 stored multivolume writer currently supports one input file".into());
        }
        if !store && quick_open {
            return Err("RAR 5 compressed writer cannot be combined with quick-open yet".into());
        }
        if file_comment.is_some()
            && (!store
                || archive_comment.is_some()
                || archive_name.is_some()
                || quick_open
                || recovery_percent.is_some()
                || volume_size.is_some())
        {
            return Err(
                "RAR 5 file comments are currently supported only for plain stored archives".into(),
            );
        }
        if header_encryption && password.is_none() {
            return Err("RAR 5 header encryption requires --password".into());
        }
        if quick_open && password.is_some() {
            return Err("unsupported option combination: RAR 5 quick-open cannot currently be combined with encryption".into());
        }
        if quick_open && volume_size.is_some() {
            return Err("unsupported option combination: RAR 5 quick-open cannot currently be used with --volume-size".into());
        }
        if archive_name.is_some() && volume_size.is_some() {
            return Err("unsupported option combination: RAR 5 archive metadata cannot currently be used with --volume-size".into());
        }
        if recovery_percent.is_some()
            && (archive_comment.is_some() || archive_name.is_some() || quick_open)
        {
            return Err(
                "RAR 5 recovery writer cannot be combined with comments, metadata, or quick-open yet"
                    .into(),
            );
        }
        let entries: Vec<_> = owned
            .iter()
            .map(|entry| {
                if entry.file_attr == DOS_DIRECTORY_ATTR {
                    return Err("RAR 5 writer currently rejects directories");
                }
                Ok(rars::rar50::StoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    mtime: Some(0),
                    attributes: u64::from(entry.file_attr),
                    host_os: 3,
                })
            })
            .collect::<std::result::Result<_, _>>()?;
        let mut features = FeatureSet::store_only();
        features.archive_comment = archive_comment.is_some();
        features.file_comment = file_comment.is_some();
        features.file_encryption = password.is_some();
        features.header_encryption = header_encryption;
        features.quick_open = quick_open;
        features.recovery_record = recovery_percent.is_some();
        features.solid = solid;
        let options = rars::rar50::WriterOptions { target, features };
        if let Some(volume_size) = volume_size {
            if archive_comment.is_some() {
                return Err("RAR 5 writer does not support comments on volumes yet".into());
            }
            let parts = if let Some(password) = password.as_deref() {
                if store {
                    let entry = owned.first().expect("stored volume input checked above");
                    let entry = rars::rar50::EncryptedStoredEntry {
                        name: &entry.name,
                        data: &entry.data,
                        mtime: Some(0),
                        attributes: u64::from(entry.file_attr),
                        host_os: 3,
                        password,
                    };
                    rars::rar50::Rar50VolumeWriter::new(options)
                        .encrypted_stored_entry(entry)
                        .max_payload_per_volume(volume_size)
                        .recovery_percent(recovery_percent)
                        .finish()?
                } else {
                    let compressed_entries: Vec<_> = owned
                        .iter()
                        .map(|entry| rars::rar50::EncryptedCompressedEntry {
                            name: &entry.name,
                            data: &entry.data,
                            mtime: Some(0),
                            attributes: u64::from(entry.file_attr),
                            host_os: 3,
                            password,
                        })
                        .collect();
                    rars::rar50::Rar50VolumeWriter::new(options)
                        .encrypted_compressed_entries(&compressed_entries)
                        .max_payload_per_volume(volume_size)
                        .recovery_percent(recovery_percent)
                        .finish()?
                }
            } else {
                let entry = entries.first().expect("one input checked above");
                if store {
                    rars::rar50::Rar50VolumeWriter::new(options)
                        .stored_entry(*entry)
                        .max_payload_per_volume(volume_size)
                        .recovery_percent(recovery_percent)
                        .finish()?
                } else {
                    let compressed_entries: Vec<_> = owned
                        .iter()
                        .map(|entry| rars::rar50::CompressedEntry {
                            name: &entry.name,
                            data: &entry.data,
                            mtime: Some(0),
                            attributes: u64::from(entry.file_attr),
                            host_os: 3,
                        })
                        .collect();
                    rars::rar50::Rar50VolumeWriter::new(options)
                        .compressed_entries(&compressed_entries)
                        .max_payload_per_volume(volume_size)
                        .recovery_percent(recovery_percent)
                        .finish()?
                }
            };
            write_rar50_volume_parts(&archive_path, &parts).map_err(|err| {
                format!(
                    "failed to write RAR 5 volume set starting at '{}': {err}",
                    archive_path.display()
                )
            })?;
            if recovery_percent.is_some() {
                eprintln!("{RAR50_STRUCTURAL_RR_WARNING}");
            }
            println!("created {} volumes", parts.len());
            return Ok(());
        }
        let bytes = if let Some(password) = password.as_deref() {
            let archive_metadata =
                archive_name
                    .as_deref()
                    .map(|name| rars::rar50::ArchiveMetadataEntry {
                        name: Some(name),
                        creation_time: Some(current_filetime()),
                    });
            let entries: Vec<_> = owned
                .iter()
                .map(|entry| rars::rar50::EncryptedStoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    mtime: Some(0),
                    attributes: u64::from(entry.file_attr),
                    host_os: 3,
                    password,
                })
                .collect();
            let archive_comment = archive_comment
                .as_deref()
                .map(|data| rars::rar50::EncryptedArchiveCommentEntry { data, password });
            if let Some(recovery_percent) = recovery_percent.filter(|_| store) {
                rars::rar50::Rar50Writer::new(options)
                    .encrypted_stored_entries(&entries)
                    .recovery_percent(Some(recovery_percent))
                    .recovery_password(Some(password))
                    .finish()?
            } else if let Some(file_comment) = file_comment.as_deref().filter(|_| store) {
                let services: Vec<_> = owned
                    .iter()
                    .map(|_| {
                        vec![rars::rar50::EncryptedStoredServiceEntry {
                            name: b"CMT",
                            data: file_comment,
                            password,
                        }]
                    })
                    .collect();
                let entries_with_services: Vec<_> = entries
                    .iter()
                    .zip(&services)
                    .map(
                        |(entry, services)| rars::rar50::EncryptedStoredEntryWithServices {
                            entry: *entry,
                            services,
                        },
                    )
                    .collect();
                rars::rar50::Rar50Writer::new(options)
                    .encrypted_stored_entries_with_services(&entries_with_services)
                    .finish()?
            } else if store {
                rars::rar50::Rar50Writer::new(options)
                    .encrypted_stored_entries(&entries)
                    .encrypted_archive_comment(archive_comment)
                    .archive_metadata(archive_metadata)
                    .finish()?
            } else {
                let compressed_entries: Vec<_> = owned
                    .iter()
                    .map(|entry| rars::rar50::EncryptedCompressedEntry {
                        name: &entry.name,
                        data: &entry.data,
                        mtime: Some(0),
                        attributes: u64::from(entry.file_attr),
                        host_os: 3,
                        password,
                    })
                    .collect();
                if let Some(recovery_percent) = recovery_percent {
                    rars::rar50::Rar50Writer::new(options)
                        .encrypted_compressed_entries(&compressed_entries)
                        .recovery_percent(Some(recovery_percent))
                        .finish()?
                } else {
                    rars::rar50::Rar50Writer::new(options)
                        .encrypted_compressed_entries(&compressed_entries)
                        .encrypted_archive_comment(archive_comment)
                        .archive_metadata(archive_metadata)
                        .finish()?
                }
            }
        } else {
            let archive_metadata =
                archive_name
                    .as_deref()
                    .map(|name| rars::rar50::ArchiveMetadataEntry {
                        name: Some(name),
                        creation_time: Some(current_filetime()),
                    });
            if let Some(recovery_percent) = recovery_percent.filter(|_| store) {
                rars::rar50::Rar50Writer::new(options)
                    .stored_entries(&entries)
                    .recovery_percent(Some(recovery_percent))
                    .finish()?
            } else if let Some(file_comment) = file_comment.as_deref().filter(|_| store) {
                let services: Vec<_> = owned
                    .iter()
                    .map(|_| {
                        vec![rars::rar50::StoredServiceEntry {
                            name: b"CMT",
                            data: file_comment,
                        }]
                    })
                    .collect();
                let entries_with_services: Vec<_> = entries
                    .iter()
                    .zip(&services)
                    .map(|(entry, services)| rars::rar50::StoredEntryWithServices {
                        entry: *entry,
                        services,
                    })
                    .collect();
                rars::rar50::Rar50Writer::new(options)
                    .stored_entries_with_services(&entries_with_services)
                    .finish()?
            } else if store {
                rars::rar50::Rar50Writer::new(options)
                    .stored_entries(&entries)
                    .archive_comment(archive_comment.as_deref())
                    .archive_metadata(archive_metadata)
                    .finish()?
            } else {
                let compressed_entries: Vec<_> = owned
                    .iter()
                    .map(|entry| rars::rar50::CompressedEntry {
                        name: &entry.name,
                        data: &entry.data,
                        mtime: Some(0),
                        attributes: u64::from(entry.file_attr),
                        host_os: 3,
                    })
                    .collect();
                if let Some(recovery_percent) = recovery_percent {
                    rars::rar50::Rar50Writer::new(options)
                        .compressed_entries(&compressed_entries)
                        .recovery_percent(Some(recovery_percent))
                        .finish()?
                } else if let Some(channels) = delta_filter {
                    rars::rar50::Rar50Writer::new(options)
                        .compressed_entries(&compressed_entries)
                        .filter_policy(rars::rar50::FilterPolicy::Explicit(
                            rars::rar50::FilterKind::Delta { channels },
                        ))
                        .finish()?
                } else if let Some(include_e9) = e8_filter {
                    let filter = if include_e9 {
                        rars::rar50::FilterKind::E8E9
                    } else {
                        rars::rar50::FilterKind::E8
                    };
                    rars::rar50::Rar50Writer::new(options)
                        .compressed_entries(&compressed_entries)
                        .filter_policy(rars::rar50::FilterPolicy::Explicit(filter))
                        .finish()?
                } else if arm_filter {
                    rars::rar50::Rar50Writer::new(options)
                        .compressed_entries(&compressed_entries)
                        .filter_policy(rars::rar50::FilterPolicy::Explicit(
                            rars::rar50::FilterKind::Arm,
                        ))
                        .finish()?
                } else if auto_filter
                    || (archive_comment.is_none()
                        && archive_metadata.is_none()
                        && !options.features.solid)
                {
                    rars::rar50::Rar50Writer::new(options)
                        .compressed_entries(&compressed_entries)
                        .filter_policy(rars::rar50::FilterPolicy::AutoSize)
                        .finish()?
                } else {
                    rars::rar50::Rar50Writer::new(options)
                        .compressed_entries(&compressed_entries)
                        .archive_comment(archive_comment.as_deref())
                        .archive_metadata(archive_metadata)
                        .finish()?
                }
            }
        };
        fs::write(&archive_path, bytes).map_err(|err| {
            format!(
                "failed to write archive '{}': {err}",
                archive_path.display()
            )
        })?;
        if recovery_percent.is_some() {
            eprintln!("{RAR50_STRUCTURAL_RR_WARNING}");
        }
        println!("created {}", archive_path.display());
        return Ok(());
    }

    if matches!(
        target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) {
        let options = Rar15WriterOptions {
            target,
            features: {
                let mut features = FeatureSet::store_only();
                features.solid = solid;
                features.file_encryption = password.is_some();
                features.header_encryption = header_encryption;
                features.archive_comment = archive_comment.is_some();
                features.file_comment = file_comment.is_some();
                features
            },
        };
        if let Some(volume_size) = volume_size {
            let entry = owned.first().expect("one input checked above");
            if entry.file_attr == DOS_DIRECTORY_ATTR {
                return Err("RAR 1.5 writer currently rejects directories".into());
            }
            let parts = if store {
                let entry = Rar15StoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: 0,
                    file_attr: u32::from(entry.file_attr),
                    host_os: 3,
                    password: entry.password.as_deref(),
                    file_comment: None,
                };
                rars::rar15_40::write_stored_volumes(entry, options, volume_size)?
            } else {
                let entry = Rar15FileEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: 0,
                    file_attr: u32::from(entry.file_attr),
                    host_os: 3,
                    password: entry.password.as_deref(),
                    file_comment: None,
                };
                rars::rar15_40::write_compressed_volumes(entry, options, volume_size)?
            };
            write_volume_parts(&archive_path, &parts).map_err(|err| {
                format!(
                    "failed to write volume set starting at '{}': {err}",
                    archive_path.display()
                )
            })?;
            println!("created {} volumes", parts.len());
            return Ok(());
        }

        let bytes = if store {
            let mut entries = Vec::with_capacity(owned.len());
            for entry in &owned {
                if entry.file_attr == DOS_DIRECTORY_ATTR {
                    return Err("RAR 1.5 writer currently rejects directories".into());
                }
                entries.push(Rar15StoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: 0,
                    file_attr: u32::from(entry.file_attr),
                    host_os: 3,
                    password: entry.password.as_deref(),
                    file_comment: file_comment.as_deref(),
                });
            }
            rars::rar15_40::write_stored_archive_with_comment(
                &entries,
                options,
                archive_comment.as_deref(),
            )?
        } else if e8_filter.is_some()
            || delta_filter.is_some()
            || itanium_filter
            || rgb_filter.is_some()
            || audio_filter.is_some()
            || auto_filter
            || ppmd
        {
            let mut entries = Vec::with_capacity(owned.len());
            for entry in &owned {
                if entry.file_attr == DOS_DIRECTORY_ATTR {
                    return Err("RAR 1.5 writer currently rejects directories".into());
                }
                entries.push(Rar15FileEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: 0,
                    file_attr: u32::from(entry.file_attr),
                    host_os: 3,
                    password: entry.password.as_deref(),
                    file_comment: None,
                });
            }
            let explicit_filter = || {
                if let Some(channels) = delta_filter {
                    rars::rar15_40::FilterSpec::whole(rars::rar15_40::FilterKind::Delta {
                        channels,
                    })
                } else if e8_filter == Some(true) {
                    rars::rar15_40::FilterSpec::whole(rars::rar15_40::FilterKind::E8E9)
                } else if itanium_filter {
                    rars::rar15_40::FilterSpec::whole(rars::rar15_40::FilterKind::Itanium)
                } else if let Some(width) = rgb_filter {
                    rars::rar15_40::FilterSpec::whole(rars::rar15_40::FilterKind::Rgb {
                        width,
                        pos_r: 0,
                    })
                } else if let Some(channels) = audio_filter {
                    rars::rar15_40::FilterSpec::whole(rars::rar15_40::FilterKind::Audio {
                        channels,
                    })
                } else {
                    rars::rar15_40::FilterSpec::whole(rars::rar15_40::FilterKind::E8)
                }
            };
            let policy = if ppmd
                && (delta_filter.is_some()
                    || e8_filter.is_some()
                    || itanium_filter
                    || rgb_filter.is_some()
                    || audio_filter.is_some())
            {
                rars::rar15_40::FilterPolicy::PpmdFiltered(explicit_filter())
            } else if ppmd {
                rars::rar15_40::FilterPolicy::Ppmd
            } else if auto_filter {
                rars::rar15_40::FilterPolicy::Auto
            } else {
                rars::rar15_40::FilterPolicy::Explicit(explicit_filter())
            };
            rars::rar15_40::write_rar29_compressed_archive_with_filter_policy(
                &entries, options, policy,
            )?
        } else {
            let mut entries = Vec::with_capacity(owned.len());
            for entry in &owned {
                if entry.file_attr == DOS_DIRECTORY_ATTR {
                    return Err("RAR 1.5 writer currently rejects directories".into());
                }
                entries.push(Rar15FileEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: 0,
                    file_attr: u32::from(entry.file_attr),
                    host_os: 3,
                    password: entry.password.as_deref(),
                    file_comment: file_comment.as_deref(),
                });
            }
            rars::rar15_40::write_compressed_archive_with_comment(
                &entries,
                options,
                archive_comment.as_deref(),
            )?
        };
        fs::write(&archive_path, bytes).map_err(|err| {
            format!(
                "failed to write archive '{}': {err}",
                archive_path.display()
            )
        })?;
        println!("created {}", archive_path.display());
        return Ok(());
    }

    let mut features = FeatureSet::store_only();
    features.solid = solid;
    let options = Rar13WriterOptions { target, features };
    if let Some(volume_size) = volume_size {
        let entry = owned.first().expect("one input checked above");
        let parts = if compress {
            let entry = FileEntry {
                name: &entry.name,
                data: &entry.data,
                file_time: 0,
                file_attr: entry.file_attr,
                password: entry.password.as_deref(),
                file_comment: file_comment.as_deref(),
            };
            rar13::write_compressed_volumes(entry, options, volume_size)?
        } else {
            let entry = Rar13StoredEntry {
                name: &entry.name,
                data: &entry.data,
                file_time: 0,
                file_attr: entry.file_attr,
                password: entry.password.as_deref(),
                file_comment: file_comment.as_deref(),
            };
            rar13::write_stored_volumes(entry, options, volume_size)?
        };
        write_volume_parts(&archive_path, &parts).map_err(|err| {
            format!(
                "failed to write volume set starting at '{}': {err}",
                archive_path.display()
            )
        })?;
        println!("created {} volumes", parts.len());
        return Ok(());
    }

    let bytes = if compress {
        let entries: Vec<_> = owned
            .iter()
            .map(|entry| FileEntry {
                name: &entry.name,
                data: &entry.data,
                file_time: 0,
                file_attr: entry.file_attr,
                password: entry.password.as_deref(),
                file_comment: file_comment.as_deref(),
            })
            .collect();
        rar13::write_compressed_archive_with_comment(&entries, options, archive_comment.as_deref())?
    } else {
        let entries: Vec<_> = owned
            .iter()
            .map(|entry| Rar13StoredEntry {
                name: &entry.name,
                data: &entry.data,
                file_time: 0,
                file_attr: entry.file_attr,
                password: entry.password.as_deref(),
                file_comment: file_comment.as_deref(),
            })
            .collect();
        rar13::write_stored_archive_with_comment(&entries, options, archive_comment.as_deref())?
    };
    fs::write(&archive_path, bytes).map_err(|err| {
        format!(
            "failed to write archive '{}': {err}",
            archive_path.display()
        )
    })?;
    println!("created {}", archive_path.display());
    Ok(())
}

fn validate_rar15_40_add_options(
    target: ArchiveVersion,
    password: Option<&[u8]>,
    archive_comment: Option<&[u8]>,
    file_comment: Option<&[u8]>,
    volume_size: Option<usize>,
    header_encryption: bool,
) -> CliResult<()> {
    if archive_comment.is_some() && volume_size.is_some() {
        return Err("RAR 1.5 writer does not support comments on volumes yet".into());
    }
    if file_comment.is_some() && volume_size.is_some() {
        return Err("RAR 1.5 writer does not support file comments on volumes yet".into());
    }
    if matches!(
        target,
        ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) {
        if matches!(target, ArchiveVersion::Rar30 | ArchiveVersion::Rar40) && file_comment.is_some()
        {
            return Err("unsupported option combination: RAR 3.x/4.x file comments are not currently writable".into());
        }
        if header_encryption {
            if !matches!(target, ArchiveVersion::Rar30 | ArchiveVersion::Rar40) {
                return Err("RAR 3.x header encryption requires rar30 or rar40".into());
            }
            if password.is_none() {
                return Err("RAR 3.x header encryption requires --password".into());
            }
        }
    }
    Ok(())
}

fn write_volume_parts(first_path: &Path, parts: &[Vec<u8>]) -> CliResult<()> {
    for (index, bytes) in parts.iter().enumerate() {
        let path = volume_part_path(first_path, index)?;
        fs::write(path, bytes)?;
    }
    Ok(())
}

fn write_rar50_volume_parts(first_path: &Path, parts: &[Vec<u8>]) -> CliResult<()> {
    for (index, bytes) in parts.iter().enumerate() {
        let path = rar50_volume_part_path(first_path, index)?;
        fs::write(path, bytes)?;
    }
    Ok(())
}

fn rar50_volume_part_path(first_path: &Path, index: usize) -> CliResult<PathBuf> {
    let parent = first_path.parent().unwrap_or_else(|| Path::new(""));
    let stem = first_path
        .file_stem()
        .ok_or("RAR 5 volume path needs a file name")?
        .to_string_lossy();
    Ok(parent.join(format!("{stem}.part{}.rar", index + 1)))
}

fn current_filetime() -> u64 {
    const FILETIME_UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;
    const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = duration
        .as_secs()
        .saturating_add(FILETIME_UNIX_EPOCH_SECONDS)
        .saturating_mul(FILETIME_TICKS_PER_SECOND);
    seconds.saturating_add(u64::from(duration.subsec_nanos() / 100))
}

fn volume_part_path(first_path: &Path, index: usize) -> CliResult<PathBuf> {
    if index == 0 {
        return Ok(first_path.to_path_buf());
    }
    if index > 100 {
        return Err("RAR 1.4 old-style volume names only support .r00 through .r99 here".into());
    }
    Ok(first_path.with_extension(format!("r{:02}", index - 1)))
}

fn parse_password(args: &[String]) -> CliResult<(Option<Vec<u8>>, Vec<String>)> {
    let mut password = None;
    let mut rest = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--password" || arg == "-p" {
            let value = iter.next().ok_or("missing password value")?;
            password = Some(value.as_bytes().to_vec());
        } else {
            rest.push(arg.clone());
        }
    }
    Ok((password, rest))
}

fn parse_archives(paths: &[String], password: Option<&[u8]>) -> CliResult<Vec<DetectedArchive>> {
    let mut archives = Vec::new();
    for path in paths {
        archives.push(
            ArchiveReader::read_path_with_options(path, read_options(password))
                .map_err(|err| read_archive_error(path, err))?,
        );
    }
    Ok(archives)
}

fn read_archive_error(path: &str, err: Error) -> String {
    match err {
        Error::Io(message) => format!("failed to read archive '{path}': {message}"),
        Error::UnsupportedSignature => {
            format!(
                "failed to identify archive '{path}': {}",
                Error::UnsupportedSignature
            )
        }
        other => format!("failed to parse archive '{path}': {other}"),
    }
}

fn read_file(path: &Path, role: &str) -> CliResult<Vec<u8>> {
    fs::read(path)
        .map_err(|err| format!("failed to read {role} '{}': {err}", path.display()).into())
}

fn open_output_writer(
    out_dir: &Path,
    entry: &ExtractedEntryMeta,
) -> rars::Result<Box<dyn std::io::Write>> {
    let rel = output_relative_path(&entry.name)
        .map_err(|_| Error::InvalidHeader("unsafe archive path"))?;
    let out_path = out_dir.join(rel);
    if entry.is_directory {
        fs::create_dir_all(&out_path)?;
        return Ok(Box::new(std::io::sink()));
    }
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(Box::new(fs::File::create(out_path)?))
}

fn print_ok_entry(entry: &ExtractedEntryMeta) {
    println!(
        "OK {}{}",
        String::from_utf8_lossy(&entry.name),
        if entry.is_directory { "/" } else { "" }
    );
}

fn output_relative_path(name: &[u8]) -> CliResult<PathBuf> {
    let text = String::from_utf8_lossy(name).replace('\\', "/");
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

struct OwnedInput {
    name: Vec<u8>,
    data: Vec<u8>,
    file_attr: u8,
    password: Option<Vec<u8>>,
}

fn read_inputs(paths: &[String], password: Option<&[u8]>) -> CliResult<Vec<OwnedInput>> {
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
        if meta.is_dir() {
            out.push(OwnedInput {
                name,
                data: Vec::new(),
                file_attr: 0x10,
                password: None,
            });
        } else {
            out.push(OwnedInput {
                name,
                data: read_file(path, "input")?,
                file_attr: 0x20,
                password: password.map(|p| p.to_vec()),
            });
        }
    }
    Ok(out)
}

fn usage() {
    eprintln!(
        "usage:
  rars info [--password <password>] <archive>...
  rars test [--password <password>] <archive> [parts...]
  rars x [--password <password>] <archive> [parts...] <outdir>
  rars repair [--password <password>] <archive> <repaired-archive>
  rars repair <rar-parts-and-rev-files...> <outdir>
  {ADD_USAGE}"
    );
}

#[cfg(test)]
mod tests {
    use super::infer_part_index;
    use std::path::Path;

    #[test]
    fn infer_part_index_accepts_new_and_old_numbered_volume_names() {
        assert_eq!(infer_part_index(Path::new("archive.part1.rar"), 4), Some(0));
        assert_eq!(infer_part_index(Path::new("archive.part4.rar"), 4), Some(3));
        assert_eq!(infer_part_index(Path::new("archive.rar"), 4), Some(0));
        assert_eq!(infer_part_index(Path::new("archive.r00"), 4), Some(1));
        assert_eq!(infer_part_index(Path::new("archive.r02"), 4), Some(3));
        assert_eq!(infer_part_index(Path::new("archive.r03"), 4), None);
    }
}

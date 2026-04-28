use rars::rar13::{self, Archive, ExtractedEntry, StoredEntry, WriterOptions};
use rars::{detect_archive_family, ArchiveFamily, ArchiveVersion, Error, FeatureSet};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

type CliResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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
        "a" => cmd_add(&rest),
        "-h" | "--help" | "help" => {
            usage();
            Ok(())
        }
        _ => Err(format!("unknown command: {command}").into()),
    }
}

fn cmd_info(args: &[String]) -> CliResult<()> {
    if args.is_empty() {
        return Err("usage: rars info <archive>...".into());
    }

    for path in args {
        let bytes = fs::read(path)?;
        let sig = detect_archive_family(&bytes).ok_or(Error::UnsupportedSignature)?;
        println!("{path}: {:?} at offset {}", sig.family, sig.offset);
        if sig.family == ArchiveFamily::Rar13 {
            let archive = Archive::parse(&bytes)?;
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
                if let Some(comment) = archive.archive_comment()? {
                    println!("  comment: {}", String::from_utf8_lossy(&comment));
                }
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
                if let Some(comment) = entry.file_comment()? {
                    println!("    comment: {}", String::from_utf8_lossy(&comment));
                }
            }
        }
    }

    Ok(())
}

fn cmd_test(args: &[String]) -> CliResult<()> {
    let (password, paths) = parse_password(args)?;
    if paths.is_empty() {
        return Err("usage: rars test [--password <password>] <archive> [parts...]".into());
    }

    let archives = parse_rar13_archives(&paths)?;
    let extracted = if archives.len() == 1 {
        archives[0].extract(password.as_deref())?
    } else {
        rar13::extract_volumes(&archives, password.as_deref())?
    };

    for entry in &extracted {
        println!(
            "OK {}{}",
            String::from_utf8_lossy(&entry.name),
            if entry.is_directory { "/" } else { "" }
        );
    }
    Ok(())
}

fn cmd_extract(args: &[String]) -> CliResult<()> {
    let (password, mut paths) = parse_password(args)?;
    if paths.len() < 2 {
        return Err("usage: rars x [--password <password>] <archive> [parts...] <outdir>".into());
    }
    let out_dir = PathBuf::from(paths.pop().expect("outdir"));

    let archives = parse_rar13_archives(&paths)?;
    let extracted = if archives.len() == 1 {
        archives[0].extract(password.as_deref())?
    } else {
        rar13::extract_volumes(&archives, password.as_deref())?
    };

    for entry in &extracted {
        write_extracted_entry(&out_dir, entry)?;
        println!("x {}", String::from_utf8_lossy(&entry.name));
    }
    Ok(())
}

fn cmd_add(args: &[String]) -> CliResult<()> {
    let (password, args) = parse_password(args)?;
    if args.len() < 4 || args[0] != "--format" || args[1] != "rar14" || args[2] != "--store" {
        return Err(
            "usage: rars a [--password <password>] --format rar14 --store <archive> <files...>"
                .into(),
        );
    }
    let archive_path = PathBuf::from(&args[3]);
    let input_paths = &args[4..];
    if input_paths.is_empty() {
        return Err("no input files".into());
    }

    let owned = read_inputs(input_paths, password.as_deref())?;
    let entries: Vec<_> = owned
        .iter()
        .map(|entry| StoredEntry {
            name: &entry.name,
            data: &entry.data,
            file_time: 0,
            file_attr: entry.file_attr,
            password: entry.password.as_deref(),
        })
        .collect();

    let bytes = rar13::write_stored_archive(
        &entries,
        WriterOptions {
            target: ArchiveVersion::Rar14,
            features: FeatureSet::store_only(),
        },
    )?;
    fs::write(&archive_path, bytes)?;
    println!("created {}", archive_path.display());
    Ok(())
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

fn parse_rar13_archives(paths: &[String]) -> CliResult<Vec<Archive>> {
    let mut archives = Vec::new();
    for path in paths {
        let bytes = fs::read(path)?;
        archives.push(Archive::parse(&bytes)?);
    }
    Ok(archives)
}

fn write_extracted_entry(out_dir: &Path, entry: &ExtractedEntry) -> CliResult<()> {
    let rel = output_relative_path(&entry.name)?;
    let out_path = out_dir.join(rel);
    if entry.is_directory {
        fs::create_dir_all(&out_path)?;
        return Ok(());
    }
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(out_path, &entry.data)?;
    Ok(())
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
        let meta = fs::metadata(path)?;
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
                data: fs::read(path)?,
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
  rars info <archive>...
  rars test [--password <password>] <archive> [parts...]
  rars x [--password <password>] <archive> [parts...] <outdir>
  rars a [--password <password>] --format rar14 --store <archive> <files...>"
    );
}

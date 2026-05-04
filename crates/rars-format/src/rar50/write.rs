use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterOptions {
    pub target: crate::ArchiveVersion,
    pub features: crate::FeatureSet,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            target: crate::ArchiveVersion::Rar50,
            features: crate::FeatureSet::store_only(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
}

pub fn write_stored_archive(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    validate_options(options)?;

    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    write_block(&mut out, HEAD_MAIN, 0, None, &[0], &[])?;
    for entry in entries {
        write_stored_entry(&mut out, entry)?;
    }
    write_block(&mut out, HEAD_END, 0, None, &[], &[])?;
    Ok(out)
}

fn validate_options(options: WriterOptions) -> Result<()> {
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    if options.features != crate::FeatureSet::store_only() {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 writer feature",
        });
    }
    Ok(())
}

fn write_stored_entry(out: &mut Vec<u8>, entry: &StoredEntry<'_>) -> Result<()> {
    validate_entry(entry)?;

    let mut file_flags = FHFL_CRC32;
    if entry.mtime.is_some() {
        file_flags |= FHFL_MTIME;
    }

    let mut specific = Vec::new();
    write_vint(&mut specific, file_flags);
    write_vint(&mut specific, entry.data.len() as u64);
    write_vint(&mut specific, entry.attributes);
    if let Some(mtime) = entry.mtime {
        specific.extend_from_slice(&mtime.to_le_bytes());
    }
    specific.extend_from_slice(&crc32(entry.data).to_le_bytes());
    write_vint(&mut specific, 0);
    write_vint(&mut specific, entry.host_os);
    write_vint(&mut specific, entry.name.len() as u64);
    specific.extend_from_slice(entry.name);

    write_block(
        out,
        HEAD_FILE,
        HFL_DATA,
        Some(entry.data.len() as u64),
        &specific,
        entry.data,
    )
}

fn validate_entry(entry: &StoredEntry<'_>) -> Result<()> {
    if entry.name.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 file name is empty"));
    }
    Ok(())
}

fn write_block(
    out: &mut Vec<u8>,
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    data: &[u8],
) -> Result<()> {
    let mut body = Vec::new();
    write_vint(&mut body, header_type);
    write_vint(&mut body, flags);
    if let Some(data_size) = data_size {
        write_vint(&mut body, data_size);
    }
    body.extend_from_slice(type_specific);

    let mut header_size = Vec::new();
    write_vint(&mut header_size, body.len() as u64);

    let mut header = Vec::with_capacity(4 + header_size.len() + body.len());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&header_size);
    header.extend_from_slice(&body);
    let header_crc = crc32(&header[4..]);
    header[..4].copy_from_slice(&header_crc.to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    Ok(())
}

fn write_vint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

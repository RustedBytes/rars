use super::*;
use crate::volume_extract::{ChainedReader, SplitVolumeState, SplitVolumeStep};
use std::io::{Read, Write};

enum CodecState {
    Unpack15(Box<Unpack15>),
    Unpack20(Box<Unpack20>),
    Unpack29(Box<Unpack29>),
}

impl CodecState {
    fn new_for(file: &FileHeader) -> Result<Self> {
        if file.unp_ver >= 29 {
            return Ok(Self::Unpack29(Box::default()));
        }
        if file.unp_ver == 20 || file.unp_ver == 26 {
            return Ok(Self::Unpack20(Box::default()));
        }
        if file.unp_ver == 15 {
            return Ok(Self::Unpack15(Box::default()));
        }
        Err(Error::UnsupportedCompression {
            family: "RAR 1.5-4.x",
            unpack_version: file.unp_ver,
            method: file.method,
        })
    }

    fn supports(&self, file: &FileHeader) -> bool {
        match self {
            Self::Unpack15(_) => file.unp_ver == 15,
            Self::Unpack20(_) => file.unp_ver == 20 || file.unp_ver == 26,
            Self::Unpack29(_) => file.unp_ver >= 29,
        }
    }

    fn decode_file_data(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        solid: bool,
        password: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self {
            Self::Unpack15(decoder) => {
                if file.is_encrypted() {
                    decoder
                        .decode_member(
                            &file.packed_data_for_decode(archive, password)?,
                            usize::try_from(file.unp_size).map_err(|_| {
                                Error::InvalidHeader("RAR 1.5 unpacked size overflows usize")
                            })?,
                            solid,
                        )
                        .map_err(Into::into)
                } else {
                    file.unpacked_data_with_unpack15(archive, decoder, solid)
                }
            }
            Self::Unpack20(decoder) => file.unpacked_data_with_unpack20(archive, decoder, password),
            Self::Unpack29(decoder) => {
                if file.is_encrypted() {
                    decoder
                        .decode_member(
                            &file.packed_data_for_decode(archive, password)?,
                            usize::try_from(file.unp_size).map_err(|_| {
                                Error::InvalidHeader("RAR 2.9 unpacked size overflows usize")
                            })?,
                        )
                        .map_err(Into::into)
                } else {
                    file.unpacked_data_with_rar29(archive, decoder)
                }
            }
        }
    }

    fn write_file_to(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        solid: bool,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        match self {
            Self::Unpack15(decoder) => {
                file.write_unpack15_to(archive, decoder, solid, password, out)
            }
            Self::Unpack20(decoder) => file.write_unpack20_to(archive, decoder, password, out),
            Self::Unpack29(decoder) => {
                if file.is_encrypted() {
                    let mut crc = Crc32::new();
                    let mut crc_writer = CrcWriter {
                        inner: out,
                        crc: &mut crc,
                    };
                    let data = decoder
                        .decode_member(
                            &file.packed_data_for_decode(archive, password)?,
                            usize::try_from(file.unp_size).map_err(|_| {
                                Error::InvalidHeader("RAR 1.5 unpacked size overflows usize")
                            })?,
                        )
                        .map_err(Error::from)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))?;
                    crc_writer.write_all(&data)?;
                    let actual = crc.finish();
                    file.crc_result(actual, password)
                } else {
                    file.write_rar29_to(archive, decoder, out)
                }
            }
        }
    }

    fn write_split_to(
        &mut self,
        input: &mut impl Read,
        file: &FileHeader,
        solid: bool,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        let target = usize::try_from(file.unp_size)
            .map_err(|_| Error::InvalidHeader("RAR 1.5 split unpacked size overflows usize"))?;
        match self {
            Self::Unpack15(decoder) => decoder
                .decode_member_from_reader(input, target, solid, &mut crc_writer)
                .map_err(Error::from)
                .map_err(|error| file.map_encrypted_payload_error(password, error))?,
            Self::Unpack20(decoder) => decoder
                .decode_member_from_reader(input, target, &mut crc_writer)
                .map_err(Error::from)
                .map_err(|error| file.map_encrypted_payload_error(password, error))?,
            Self::Unpack29(decoder) => decoder
                .decode_member_from_reader(input, target, &mut crc_writer)
                .map_err(Error::from)
                .map_err(|error| file.map_encrypted_payload_error(password, error))?,
        }
        let actual = crc.finish();
        file.crc_result(actual, password)
    }
}

pub(super) struct DecoderSession<'a> {
    codec: Option<CodecState>,
    solid: bool,
    decoded_files: usize,
    password: Option<&'a [u8]>,
}

impl<'a> DecoderSession<'a> {
    pub(super) fn new(solid: bool) -> Self {
        Self::new_with_password(solid, None)
    }

    pub(super) fn new_with_password(solid: bool, password: Option<&'a [u8]>) -> Self {
        Self {
            codec: None,
            solid,
            decoded_files: 0,
            password,
        }
    }

    pub(super) fn write_file_to(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        out: &mut impl Write,
    ) -> Result<()> {
        let solid = self.solid && self.decoded_files != 0;
        let password = self.password;
        self.codec_for(file)?
            .write_file_to(archive, file, solid, password, out)?;
        self.decoded_files += 1;
        Ok(())
    }

    fn write_split_to(
        &mut self,
        input: &mut impl Read,
        final_file: &FileHeader,
        out: &mut impl Write,
    ) -> Result<()> {
        let solid = self.solid && self.decoded_files != 0;
        let password = self.password;
        self.codec_for(final_file)?
            .write_split_to(input, final_file, solid, password, out)?;
        self.decoded_files += 1;
        Ok(())
    }

    pub(super) fn decode_file_data(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
    ) -> Result<Vec<u8>> {
        let solid = self.solid && self.decoded_files != 0;
        let password = self.password;
        self.codec_for(file)?
            .decode_file_data(archive, file, solid, password)
    }

    fn codec_for(&mut self, file: &FileHeader) -> Result<&mut CodecState> {
        let reset = !self.solid
            || self
                .codec
                .as_ref()
                .is_none_or(|codec| !codec.supports(file));
        if reset {
            self.codec = Some(CodecState::new_for(file)?);
        }
        self.codec
            .as_mut()
            .ok_or(Error::InvalidHeader("RAR 1.5 codec state is missing"))
    }
}

/// Streams a multivolume archive set to caller-provided writers.
pub fn extract_volumes_to<F>(volumes: &[Archive], open: F) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    extract_volumes_to_with_options(volumes, crate::ArchiveReadOptions::default(), open)
}

pub fn extract_volumes_to_with_options<F>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    extract_volumes_to_with_password(volumes, options.password, open)
}

pub fn extract_volumes_to_with_password<F>(
    volumes: &[Archive],
    password: Option<&[u8]>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    if volumes.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.5 volume set is empty"));
    }

    let mut split = SplitVolumeState::new();
    let mut session = DecoderSession::new_with_password(
        volumes
            .first()
            .is_some_and(|archive| archive.main.is_solid()),
        password,
    );
    for (volume_index, archive) in volumes.iter().enumerate() {
        for (file_index, file) in archive.files().enumerate() {
            match split.advance(file.is_split_before(), file.is_split_after()) {
                SplitVolumeStep::Regular => {
                    let meta = file.metadata();
                    if meta.is_directory {
                        let _ = open(&meta)?;
                    } else {
                        let mut writer = open(&meta)?;
                        if file.is_stored() {
                            file.write_stored_to(archive, password, &mut writer)
                                .map_err(|error| file.entry_error("extracting", error))?;
                        } else {
                            session
                                .write_file_to(archive, file, &mut writer)
                                .map_err(|error| file.entry_error("extracting", error))?;
                        }
                    }
                }
                SplitVolumeStep::Start => {
                    validate_split_fragment(file, password)?;
                    split.begin(PendingSplitRefs::new(file, volume_index, file_index));
                }
                SplitVolumeStep::Continue(current) => {
                    validate_split_continuation_refs(current, file, password)?;
                    current.append(file, volume_index, file_index);
                }
                SplitVolumeStep::Finish(mut completed) => {
                    validate_split_continuation_refs(&completed, file, password)?;
                    completed.append(file, volume_index, file_index);
                    completed.write_to(volumes, file, password, &mut session, &mut open)?;
                }
                SplitVolumeStep::MissingFirst => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.5 split entry is missing its first part",
                    ));
                }
                SplitVolumeStep::Interrupted => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.5 split entry is interrupted by a regular entry",
                    ));
                }
            }
        }
    }

    if split.is_pending() {
        return Err(Error::InvalidHeader("RAR 1.5 split entry is incomplete"));
    }

    Ok(())
}

fn validate_split_fragment(file: &FileHeader, password: Option<&[u8]>) -> Result<()> {
    if file.is_directory() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split directory entry is invalid",
        ));
    }
    if file.is_encrypted() && password.is_none() {
        return Err(Error::NeedPassword);
    }
    Ok(())
}

fn validate_split_continuation_refs(
    pending: &PendingSplitRefs,
    file: &FileHeader,
    password: Option<&[u8]>,
) -> Result<()> {
    validate_split_fragment(file, password)?;
    if file.name != pending.name {
        return Err(Error::InvalidHeader("RAR 1.5 split entry name changed"));
    }
    if file.method != pending.method {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split entry compression method changed",
        ));
    }
    if file.unp_ver != pending.unp_ver {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split entry unpack version changed",
        ));
    }
    if file.is_encrypted() != pending.encrypted {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split entry encryption flag changed",
        ));
    }
    if pending.encrypted && pending.unp_ver >= 29 && file.salt != pending.salt {
        return Err(Error::InvalidHeader("RAR 3.x split entry salt changed"));
    }
    Ok(())
}

struct PendingSplitRefs {
    name: Vec<u8>,
    fragments: Vec<(usize, usize)>,
    file_time: u32,
    attr: u32,
    host_os: u8,
    method: u8,
    unp_ver: u8,
    encrypted: bool,
    salt: Option<[u8; 8]>,
}

impl PendingSplitRefs {
    fn new(file: &FileHeader, volume_index: usize, file_index: usize) -> Self {
        Self {
            name: file.name.clone(),
            fragments: vec![(volume_index, file_index)],
            file_time: file.file_time,
            attr: file.attr,
            host_os: file.host_os,
            method: file.method,
            unp_ver: file.unp_ver,
            encrypted: file.is_encrypted(),
            salt: file.salt,
        }
    }

    fn append(&mut self, _file: &FileHeader, volume_index: usize, file_index: usize) {
        self.fragments.push((volume_index, file_index));
    }

    fn write_to<F>(
        self,
        volumes: &[Archive],
        final_file: &FileHeader,
        password: Option<&[u8]>,
        session: &mut DecoderSession,
        open: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let meta = ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.file_time,
            attr: self.attr,
            host_os: self.host_os,
            is_directory: false,
        };
        let mut writer = open(&meta)?;
        let mut reader = self.fragment_reader(volumes, password)?;

        if final_file.is_stored() {
            let expected_len = usize::try_from(final_file.unp_size)
                .map_err(|_| Error::InvalidHeader("RAR 1.5 split unpacked size overflows usize"))?;
            let actual_len = self.packed_size(volumes)?;
            let expected_packed_len =
                if self.encrypted && self.unp_ver >= 20 {
                    expected_len.checked_add(15).map(|len| len & !15).ok_or(
                        Error::InvalidHeader("RAR 2.x encrypted split stored size overflows"),
                    )?
                } else {
                    expected_len
                };
            if actual_len != expected_packed_len {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split stored file has wrong reassembled size",
                ));
            }

            let mut crc = Crc32::new();
            let mut crc_writer = CrcWriter {
                inner: &mut writer,
                crc: &mut crc,
            };
            let copied = std::io::copy(&mut reader.take(expected_len as u64), &mut crc_writer)?;
            if copied != expected_len as u64 {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split stored file ended before unpacked size",
                ));
            }
            let actual = crc.finish();
            final_file
                .crc_result(actual, password)
                .map_err(|error| final_file.entry_error("extracting", error))
        } else {
            session
                .write_split_to(&mut reader, final_file, &mut writer)
                .map_err(|error| final_file.entry_error("extracting", error))
        }
    }

    fn packed_size(&self, volumes: &[Archive]) -> Result<usize> {
        self.fragments
            .iter()
            .try_fold(0usize, |total, &(volume_index, file_index)| {
                let archive = volumes
                    .get(volume_index)
                    .ok_or(Error::InvalidHeader("RAR 1.5 split volume is missing"))?;
                let file = archive
                    .files()
                    .nth(file_index)
                    .ok_or(Error::InvalidHeader("RAR 1.5 split entry is missing"))?;
                total
                    .checked_add(usize::try_from(file.pack_size).map_err(|_| {
                        Error::InvalidHeader("RAR 1.5 split packed size overflows usize")
                    })?)
                    .ok_or(Error::InvalidHeader(
                        "RAR 1.5 split packed size overflows usize",
                    ))
            })
    }

    fn fragment_reader<'a>(
        &self,
        volumes: &'a [Archive],
        password: Option<&[u8]>,
    ) -> Result<Box<dyn Read + 'a>> {
        let mut readers = Vec::with_capacity(self.fragments.len());
        for &(volume_index, file_index) in &self.fragments {
            let archive = volumes
                .get(volume_index)
                .ok_or(Error::InvalidHeader("RAR 1.5 split volume is missing"))?;
            let file = archive
                .files()
                .nth(file_index)
                .ok_or(Error::InvalidHeader("RAR 1.5 split entry is missing"))?;
            readers.push(archive.range_reader(file.packed_range.clone())?);
        }
        let reader = ChainedReader::new(readers);
        if !self.encrypted {
            return Ok(Box::new(reader));
        }

        let Some(password) = password else {
            return Err(Error::NeedPassword);
        };
        Ok(Box::new(DecryptingReader::new(
            reader,
            self.unp_ver,
            password,
            self.salt,
        )?))
    }
}

enum SplitCipher {
    Rar15(Rar15Cipher),
    Rar20(Box<Rar20Cipher>),
    Rar30(Box<Rar30Cipher>),
}

impl SplitCipher {
    fn new(unp_ver: u8, password: &[u8], salt: Option<[u8; 8]>) -> Result<Self> {
        if unp_ver == 15 {
            return Ok(Self::Rar15(Rar15Cipher::new(password)));
        }
        if unp_ver == 20 || unp_ver == 26 {
            return Ok(Self::Rar20(Box::new(Rar20Cipher::new(password))));
        }
        if unp_ver >= 29 {
            return Ok(Self::Rar30(Box::new(Rar30Cipher::new(password, salt))));
        }
        Err(Error::UnsupportedEncryption {
            family: "RAR 1.5-4.x split volume",
            unpack_version: unp_ver,
        })
    }
}

struct DecryptingReader<R> {
    inner: R,
    cipher: SplitCipher,
    encrypted_block: Vec<u8>,
    decrypted: Vec<u8>,
    eof: bool,
}

impl<R: Read> DecryptingReader<R> {
    fn new(inner: R, unp_ver: u8, password: &[u8], salt: Option<[u8; 8]>) -> Result<Self> {
        Ok(Self {
            inner,
            cipher: SplitCipher::new(unp_ver, password, salt)?,
            encrypted_block: Vec::new(),
            decrypted: Vec::new(),
            eof: false,
        })
    }

    fn fill_decrypted(&mut self) -> std::io::Result<()> {
        if !self.decrypted.is_empty() || self.eof {
            return Ok(());
        }

        match &mut self.cipher {
            SplitCipher::Rar15(cipher) => {
                let mut buf = vec![0u8; 64 * 1024];
                let count = self.inner.read(&mut buf)?;
                if count == 0 {
                    self.eof = true;
                    return Ok(());
                }
                buf.truncate(count);
                cipher.crypt_in_place(&mut buf);
                self.decrypted = buf;
            }
            SplitCipher::Rar20(_) | SplitCipher::Rar30(_) => self.fill_block_decrypted()?,
        }
        Ok(())
    }

    fn fill_block_decrypted(&mut self) -> std::io::Result<()> {
        while self.encrypted_block.len() < 16 && !self.eof {
            let mut buf = [0u8; 64 * 1024];
            let count = self.inner.read(&mut buf)?;
            if count == 0 {
                self.eof = true;
                break;
            }
            self.encrypted_block.extend_from_slice(&buf[..count]);
        }

        let full_len = (self.encrypted_block.len() / 16) * 16;
        if full_len != 0 {
            let mut data: Vec<u8> = self.encrypted_block.drain(..full_len).collect();
            match &mut self.cipher {
                SplitCipher::Rar15(_) => unreachable!("RAR 1.5 is byte-stream decrypted"),
                SplitCipher::Rar20(cipher) => {
                    for block in data.chunks_exact_mut(16) {
                        cipher.decrypt_in_place(block);
                    }
                }
                SplitCipher::Rar30(cipher) => {
                    for block in data.chunks_exact_mut(16) {
                        cipher.decrypt_in_place(block);
                    }
                }
            }
            self.decrypted = data;
        } else if self.eof && !self.encrypted_block.is_empty() {
            self.decrypted = std::mem::take(&mut self.encrypted_block);
        }
        Ok(())
    }
}

impl<R: Read> Read for DecryptingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        self.fill_decrypted()?;
        if self.decrypted.is_empty() {
            return Ok(0);
        }
        let count = out.len().min(self.decrypted.len());
        out[..count].copy_from_slice(&self.decrypted[..count]);
        self.decrypted.drain(..count);
        Ok(count)
    }
}

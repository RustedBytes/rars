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
                    let mut packed = file
                        .packed_reader_for_decode(archive, password)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))?;
                    let mut out = Vec::new();
                    decoder
                        .decode_member_from_reader(
                            &mut packed,
                            usize::try_from(file.unp_size).map_err(|_| {
                                Error::InvalidHeader("RAR 1.5 unpacked size overflows usize")
                            })?,
                            solid,
                            &mut out,
                        )
                        .map(|_| out)
                        .map_err(Into::into)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))
                } else {
                    file.unpacked_data_with_unpack15(archive, decoder, solid)
                }
            }
            Self::Unpack20(decoder) => file.unpacked_data_with_unpack20(archive, decoder, password),
            Self::Unpack29(decoder) => {
                if file.is_encrypted() {
                    let mut packed = file
                        .packed_reader_for_decode(archive, password)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))?;
                    let mut out = Vec::new();
                    decoder
                        .decode_member_from_reader(
                            &mut packed,
                            usize::try_from(file.unp_size).map_err(|_| {
                                Error::InvalidHeader("RAR 2.9 unpacked size overflows usize")
                            })?,
                            &mut out,
                        )
                        .map(|_| out)
                        .map_err(Into::into)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))
                } else {
                    file.unpacked_data_with_rar29(archive, decoder, solid)
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
                    let mut packed = file
                        .packed_reader_for_decode(archive, password)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))?;
                    let target = usize::try_from(file.unp_size).map_err(|_| {
                        Error::InvalidHeader("RAR 1.5 unpacked size overflows usize")
                    })?;
                    if solid {
                        decoder.decode_member_from_reader(&mut packed, target, &mut crc_writer)
                    } else {
                        decoder.decode_non_solid_member_from_reader(
                            &mut packed,
                            target,
                            &mut crc_writer,
                        )
                    }
                    .map_err(Error::from)
                    .map_err(|error| file.map_encrypted_payload_error(password, error))?;
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
            Self::Unpack29(decoder) => if solid {
                decoder.decode_member_from_reader(input, target, &mut crc_writer)
            } else {
                decoder.decode_non_solid_member_from_reader(input, target, &mut crc_writer)
            }
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
pub fn extract_volumes_to<F>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    if volumes.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.5 volume set is empty"));
    }

    let password = options.password;
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
            return Ok(Self::Rar30(Box::new(
                Rar30Cipher::new(password, salt).map_err(super::map_rar30_crypto_error)?,
            )));
        }
        Err(Error::UnsupportedEncryption {
            family: "RAR 1.5-4.x split volume",
            unpack_version: unp_ver,
        })
    }
}

pub(super) struct DecryptingReader<R> {
    inner: R,
    cipher: SplitCipher,
    encrypted_block: Vec<u8>,
    decrypted: Vec<u8>,
    decrypted_pos: usize,
    eof: bool,
}

impl<R: Read> DecryptingReader<R> {
    pub(super) fn new(
        inner: R,
        unp_ver: u8,
        password: &[u8],
        salt: Option<[u8; 8]>,
    ) -> Result<Self> {
        Ok(Self {
            inner,
            cipher: SplitCipher::new(unp_ver, password, salt)?,
            encrypted_block: Vec::new(),
            decrypted: Vec::new(),
            decrypted_pos: 0,
            eof: false,
        })
    }

    fn fill_decrypted(&mut self) -> std::io::Result<()> {
        if self.decrypted_pos < self.decrypted.len() || self.eof {
            return Ok(());
        }
        self.decrypted.clear();
        self.decrypted_pos = 0;

        match &mut self.cipher {
            SplitCipher::Rar15(cipher) => {
                self.decrypted.resize(64 * 1024, 0);
                let count = self.inner.read(&mut self.decrypted)?;
                if count == 0 {
                    self.eof = true;
                    self.decrypted.clear();
                    return Ok(());
                }
                self.decrypted.truncate(count);
                cipher.crypt_in_place(&mut self.decrypted);
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
            let tail = self.encrypted_block.split_off(full_len);
            let mut data = std::mem::replace(&mut self.encrypted_block, tail);
            match &mut self.cipher {
                SplitCipher::Rar15(_) => unreachable!("RAR 1.5 is byte-stream decrypted"),
                SplitCipher::Rar20(cipher) => cipher
                    .decrypt_in_place(&mut data)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?,
                SplitCipher::Rar30(cipher) => cipher
                    .decrypt_in_place(&mut data)
                    .map_err(super::map_rar30_crypto_error)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?,
            }
            self.decrypted = data;
            self.decrypted_pos = 0;
        } else if self.eof && !self.encrypted_block.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "RAR encrypted payload is not block aligned",
            ));
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
        if self.decrypted_pos == self.decrypted.len() {
            return Ok(0);
        }
        let count = out.len().min(self.decrypted.len() - self.decrypted_pos);
        out[..count]
            .copy_from_slice(&self.decrypted[self.decrypted_pos..self.decrypted_pos + count]);
        self.decrypted_pos += count;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        ArchiveSource, Block, BlockHeader, MainHeader, FHD_DIRECTORY_MASK, FHD_PASSWORD,
        FHD_SPLIT_AFTER, FHD_SPLIT_BEFORE,
    };
    use super::*;
    use std::io::Cursor;
    use std::sync::Arc;

    fn block(flags: u16) -> BlockHeader {
        BlockHeader {
            head_crc: 0,
            head_type: 0x74,
            flags,
            head_size: 0,
            add_size: Some(0),
            offset: 0,
        }
    }

    fn file(name: &[u8], flags: u16) -> FileHeader {
        FileHeader {
            block: block(flags),
            pack_size: 0,
            unp_size: 0,
            host_os: 2,
            file_crc: 0,
            file_time: 0,
            unp_ver: 29,
            method: 0x30,
            name: name.to_vec(),
            attr: 0x20,
            salt: None,
            file_comment: Vec::new(),
            ext_time: Vec::new(),
            packed_range: 0..0,
        }
    }

    struct ChunkedReader<R> {
        inner: R,
        chunk: usize,
    }

    impl<R: Read> ChunkedReader<R> {
        fn new(inner: R, chunk: usize) -> Self {
            Self { inner, chunk }
        }
    }

    impl<R: Read> Read for ChunkedReader<R> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let take = out.len().min(self.chunk);
            self.inner.read(&mut out[..take])
        }
    }

    fn read_in_small_chunks(mut reader: impl Read) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 7];
        loop {
            let count = reader.read(&mut buf).unwrap();
            if count == 0 {
                break;
            }
            out.extend_from_slice(&buf[..count]);
        }
        out
    }

    #[test]
    fn decrypting_reader_streams_rar15_payload() {
        let plain = b"RAR 1.5 encrypted payload read in pieces";
        let mut encrypted = plain.to_vec();
        Rar15Cipher::new(b"pw").crypt_in_place(&mut encrypted);
        let mut reader = DecryptingReader::new(Cursor::new(encrypted), 15, b"pw", None).unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 3];

        loop {
            let count = reader.read(&mut buf).unwrap();
            if count == 0 {
                break;
            }
            out.extend_from_slice(&buf[..count]);
        }

        assert_eq!(out, plain);
    }

    #[test]
    fn decrypting_reader_streams_rar20_blocks_from_short_inner_reads() {
        let plain = *b"0123456789abcdefRAR2 block two!!";
        let mut encrypted = plain;
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let reader = DecryptingReader::new(
            ChunkedReader::new(Cursor::new(encrypted), 5),
            20,
            b"pw",
            None,
        )
        .unwrap();
        let out = read_in_small_chunks(reader);

        assert_eq!(out, plain);
    }

    #[test]
    fn decrypting_reader_streams_rar30_blocks_from_short_inner_reads() {
        let salt = Some([7u8; 8]);
        let plain = *b"0123456789abcdefRAR3 block two!!";
        let mut encrypted = plain;
        Rar30Cipher::new(b"pw", salt)
            .unwrap()
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let reader = DecryptingReader::new(
            ChunkedReader::new(Cursor::new(encrypted), 5),
            29,
            b"pw",
            salt,
        )
        .unwrap();
        let out = read_in_small_chunks(reader);

        assert_eq!(out, plain);
    }

    #[test]
    fn validate_split_fragment_rejects_directories_and_demands_password_for_encrypted() {
        let dir = file(b"d", FHD_DIRECTORY_MASK | FHD_SPLIT_AFTER);
        assert!(matches!(
            validate_split_fragment(&dir, None),
            Err(Error::InvalidHeader(_))
        ));

        let encrypted = file(b"a", FHD_PASSWORD | FHD_SPLIT_AFTER);
        assert!(matches!(
            validate_split_fragment(&encrypted, None),
            Err(Error::NeedPassword)
        ));
        validate_split_fragment(&encrypted, Some(b"pw")).unwrap();

        let plain = file(b"a", FHD_SPLIT_AFTER);
        validate_split_fragment(&plain, None).unwrap();
    }

    #[test]
    fn validate_split_continuation_refs_rejects_property_drift_between_fragments() {
        let first = file(b"a.txt", FHD_SPLIT_AFTER);
        let pending = PendingSplitRefs::new(&first, 0, 0);

        let renamed = file(b"b.txt", FHD_SPLIT_BEFORE);
        assert!(matches!(
            validate_split_continuation_refs(&pending, &renamed, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut new_method = file(b"a.txt", FHD_SPLIT_BEFORE);
        new_method.method = 0x35;
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_method, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut new_version = file(b"a.txt", FHD_SPLIT_BEFORE);
        new_version.unp_ver = 20;
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_version, None),
            Err(Error::InvalidHeader(_))
        ));

        let new_encryption = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_encryption, Some(b"pw")),
            Err(Error::InvalidHeader(_))
        ));

        let same = file(b"a.txt", FHD_SPLIT_BEFORE);
        validate_split_continuation_refs(&pending, &same, None).unwrap();
    }

    #[test]
    fn validate_split_continuation_refs_rejects_salt_drift_for_rar3_encrypted_entries() {
        let mut first = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_AFTER);
        first.salt = Some([1u8; 8]);
        let pending = PendingSplitRefs::new(&first, 0, 0);

        let mut other_salt = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        other_salt.salt = Some([2u8; 8]);
        assert!(matches!(
            validate_split_continuation_refs(&pending, &other_salt, Some(b"pw")),
            Err(Error::InvalidHeader(_))
        ));

        let mut same_salt = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        same_salt.salt = Some([1u8; 8]);
        validate_split_continuation_refs(&pending, &same_salt, Some(b"pw")).unwrap();
    }

    fn empty_archive() -> Archive {
        Archive {
            sfx_offset: 0,
            main: MainHeader {
                head_crc: 0,
                flags: 0,
                head_size: 0,
                reserved1: 0,
                reserved2: 0,
                encrypt_version: None,
            },
            blocks: Vec::new(),
            source: ArchiveSource::Memory(Arc::from(Vec::new().into_boxed_slice())),
        }
    }

    fn archive_with(blocks: Vec<Block>) -> Archive {
        let mut archive = empty_archive();
        archive.blocks = blocks;
        archive
    }

    fn archive_with_source(blocks: Vec<Block>, source: Vec<u8>) -> Archive {
        Archive {
            sfx_offset: 0,
            main: MainHeader {
                head_crc: 0,
                flags: 0,
                head_size: 0,
                reserved1: 0,
                reserved2: 0,
                encrypt_version: None,
            },
            blocks,
            source: ArchiveSource::Memory(Arc::from(source.into_boxed_slice())),
        }
    }

    #[test]
    fn encrypted_split_fragment_reader_decrypts_after_chaining_fragments() {
        let plain = *b"0123456789abcdefRAR2 block two!!";
        let mut encrypted = plain;
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let split = 7;

        let mut first = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_AFTER);
        first.unp_ver = 20;
        first.pack_size = split as u64;
        first.packed_range = 0..split;

        let mut second = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        second.unp_ver = 20;
        second.pack_size = (encrypted.len() - split) as u64;
        second.packed_range = 0..(encrypted.len() - split);

        let mut pending = PendingSplitRefs::new(&first, 0, 0);
        pending.append(&second, 1, 0);
        let volumes = vec![
            archive_with_source(vec![Block::File(first)], encrypted[..split].to_vec()),
            archive_with_source(vec![Block::File(second)], encrypted[split..].to_vec()),
        ];

        let reader = pending.fragment_reader(&volumes, Some(b"pw")).unwrap();
        let out = read_in_small_chunks(reader);

        assert_eq!(out, plain);
    }

    fn never_open(_meta: &ExtractedEntryMeta) -> Result<Box<dyn Write>> {
        panic!("open should not be invoked for this test");
    }

    #[test]
    fn extract_volumes_to_rejects_split_state_violations() {
        let empty: Vec<Archive> = Vec::new();
        assert!(matches!(
            extract_volumes_to(&empty, crate::ArchiveReadOptions::default(), never_open),
            Err(Error::InvalidHeader(_))
        ));

        let only_continuation = vec![archive_with(vec![Block::File(file(
            b"a.txt",
            FHD_SPLIT_BEFORE,
        ))])];
        assert!(matches!(
            extract_volumes_to(
                &only_continuation,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));

        let interrupted = vec![archive_with(vec![
            Block::File(file(b"a.txt", FHD_SPLIT_AFTER)),
            Block::File(file(b"unrelated", 0)),
        ])];
        assert!(matches!(
            extract_volumes_to(
                &interrupted,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));

        let incomplete = vec![archive_with(vec![Block::File(file(
            b"a.txt",
            FHD_SPLIT_AFTER,
        ))])];
        assert!(matches!(
            extract_volumes_to(
                &incomplete,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));
    }
}

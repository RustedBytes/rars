use super::{blake2sp, Archive, ExtractedEntry, ExtractedEntryMeta, FileHeader};
use crate::error::{Error, Result};
use crate::volume_extract::{ChainedReader, SplitVolumeState, SplitVolumeStep};
use rars_codec::rar50::{DecodeMode, Unpack50Decoder};
use rars_crypto::rar50::{Rar50Cipher, Rar50Keys};
use std::io::{Read, Write};

impl FileHeader {
    fn crypto_with_password(&self, password: Option<&[u8]>) -> Result<Option<Rar50Keys>> {
        if !self.encrypted {
            return Ok(None);
        }
        if let Some(crypto) = &self.crypto {
            return Ok(Some(crypto.keys.clone()));
        }
        let password = password.ok_or(Error::NeedPassword)?;
        let encryption = self.encryption.as_ref().ok_or(Error::InvalidHeader(
            "RAR 5 encrypted file is missing encryption record",
        ))?;
        if encryption.version != 0 {
            return Err(Error::UnsupportedFeature {
                version: crate::version::ArchiveVersion::Rar50,
                feature: "RAR 5 unknown file encryption version",
            });
        }
        let keys = Rar50Keys::derive(password, encryption.salt, encryption.kdf_count)
            .map_err(map_rar50_crypto_error)?;
        if let Some(check_value) = encryption.check_value {
            keys.check_password(&check_value)
                .map_err(map_rar50_crypto_error)?;
        }
        Ok(Some(keys))
    }

    fn encryption_iv(&self) -> Result<[u8; 16]> {
        if let Some(crypto) = &self.crypto {
            return Ok(crypto.iv);
        }
        self.encryption
            .as_ref()
            .map(|encryption| encryption.iv)
            .ok_or(Error::InvalidHeader(
                "RAR 5 encrypted file is missing encryption record",
            ))
    }

    fn packed_data_with_password(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Option<Rar50Keys>)> {
        let mut packed = self.packed_data(archive)?;
        if !self.encrypted {
            return Ok((packed, None));
        }
        if packed.len() % 16 != 0 {
            return Err(Error::InvalidHeader(
                "RAR 5 encrypted file payload is not block aligned",
            ));
        }

        let keys = self
            .crypto_with_password(password)?
            .expect("encrypted file has keys");
        Rar50Cipher::new(keys.key, self.encryption_iv()?).decrypt_in_place(&mut packed);
        Ok((packed, Some(keys)))
    }

    fn verify_integrity_with_keys(&self, data: &[u8], keys: Option<&Rar50Keys>) -> Result<()> {
        if let Some(expected) = self.data_crc32 {
            let actual = crate::rar15_40::crc32(data);
            let actual = if self.uses_hash_mac() {
                let keys = keys.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted hash MAC needs encryption keys",
                ))?;
                keys.mac_crc32(actual)
            } else {
                actual
            };
            if actual != expected {
                return Err(Error::Crc32Mismatch { expected, actual });
            }
        }

        let Some(hash) = &self.hash else {
            return Ok(());
        };
        match hash.hash_type {
            0 if hash.data.len() == 32 => {
                let actual = blake2sp::hash(data);
                let actual = if self.uses_hash_mac() {
                    let keys = keys.ok_or(Error::InvalidHeader(
                        "RAR 5 encrypted hash MAC needs encryption keys",
                    ))?;
                    keys.mac_hash32(actual)
                } else {
                    actual
                };
                if hash.data == actual {
                    Ok(())
                } else {
                    Err(Error::HashMismatch { hash_type: 0 })
                }
            }
            0 => Err(Error::InvalidHeader(
                "RAR 5 BLAKE2sp hash record has invalid length",
            )),
            _ => Err(Error::UnsupportedFeature {
                version: crate::version::ArchiveVersion::Rar50,
                feature: "RAR 5 unknown file hash type",
            }),
        }
    }

    fn uses_hash_mac(&self) -> bool {
        self.encryption
            .as_ref()
            .is_some_and(|encryption| encryption.flags & 0x0002 != 0)
    }

    pub fn metadata(&self) -> ExtractedEntryMeta {
        ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.mtime.unwrap_or(0),
            attr: self.attributes,
            host_os: self.host_os,
            is_directory: self.is_directory(),
        }
    }

    pub fn extract(&self, archive: &Archive) -> Result<ExtractedEntry> {
        self.extract_with_password(archive, None)
    }

    pub fn extract_with_password(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<ExtractedEntry> {
        let mut session = DecoderSession::new_with_password(password);
        session.extract_file(archive, self)
    }

    fn extract_with_decoder(
        &self,
        archive: &Archive,
        decoder: &mut Unpack50Decoder,
        password: Option<&[u8]>,
    ) -> Result<ExtractedEntry> {
        if self.is_directory() {
            return Ok(ExtractedEntry {
                name: self.name.clone(),
                data: Vec::new(),
                file_time: self.mtime.unwrap_or(0),
                attr: self.attributes,
                host_os: self.host_os,
                is_directory: true,
            });
        }
        let decoded = self
            .decoded_data_with_decoder(archive, decoder, password)
            .map_err(|error| self.entry_error("decoding", error))?;
        self.verify_integrity_with_keys(&decoded.data, decoded.keys.as_ref())
            .map_err(|error| self.entry_error("verifying", error))?;
        Ok(ExtractedEntry {
            name: self.name.clone(),
            data: decoded.data,
            file_time: self.mtime.unwrap_or(0),
            attr: self.attributes,
            host_os: self.host_os,
            is_directory: false,
        })
    }

    fn decoded_data_with_decoder(
        &self,
        archive: &Archive,
        decoder: &mut Unpack50Decoder,
        password: Option<&[u8]>,
    ) -> Result<DecodedData> {
        let (packed, keys) = self.packed_data_with_password(archive, password)?;
        let data = self.decode_packed_with_decoder(&packed, decoder)?;
        Ok(DecodedData { data, keys })
    }

    fn decode_packed_with_decoder(
        &self,
        packed: &[u8],
        decoder: &mut Unpack50Decoder,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            if self.encrypted {
                let unpacked_size = usize::try_from(self.unpacked_size).map_err(|_| {
                    Error::InvalidHeader("RAR 5 unpacked size overflows host address size")
                })?;
                if packed.len() < unpacked_size {
                    return Err(Error::InvalidHeader(
                        "RAR 5 encrypted stored file is shorter than unpacked size",
                    ));
                }
                return Ok(packed[..unpacked_size].to_vec());
            }
            if packed.len() as u64 != self.unpacked_size {
                return Err(Error::InvalidHeader(
                    "RAR 5 stored file has mismatched packed and unpacked sizes",
                ));
            }
            return Ok(packed.to_vec());
        }

        let info = self.decoded_compression_info()?;
        let dictionary_size = usize::try_from(info.dictionary_size).map_err(|_| {
            Error::InvalidHeader("RAR 5 dictionary size overflows host address size")
        })?;
        decoder
            .decode_member_with_dictionary(
                packed,
                info.algorithm_version,
                self.unpacked_size as usize,
                dictionary_size,
                info.solid,
                DecodeMode::Lz,
            )
            .map_err(Error::from)
    }

    fn entry_error(&self, operation: &'static str, error: Error) -> Error {
        error.at_entry(self.name.clone(), operation)
    }
}

fn map_rar50_crypto_error(error: rars_crypto::rar50::Error) -> Error {
    match error {
        rars_crypto::rar50::Error::KdfCountTooLarge => Error::UnsupportedFeature {
            version: crate::version::ArchiveVersion::Rar50,
            feature: "RAR 5 KDF count",
        },
        rars_crypto::rar50::Error::BadPassword => Error::WrongPasswordOrCorruptData,
    }
}

impl Archive {
    pub fn extract(&self) -> Result<Vec<ExtractedEntry>> {
        self.extract_with_password(None)
    }

    pub fn extract_with_password(&self, password: Option<&[u8]>) -> Result<Vec<ExtractedEntry>> {
        let mut out = Vec::new();
        let mut session = DecoderSession::new_with_password(password);
        for file in self.files() {
            if file.is_split_before() || file.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry requires multivolume extraction",
                ));
            }
            out.push(session.extract_file(self, file)?);
        }
        Ok(out)
    }

    pub fn extract_to<F>(&self, open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        self.extract_to_with_password(None, open)
    }

    pub fn extract_to_with_password<F>(&self, password: Option<&[u8]>, mut open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let mut session = DecoderSession::new_with_password(password);
        for file in self.files() {
            if file.is_split_before() || file.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry requires multivolume extraction",
                ));
            }
            let meta = file.metadata();
            let mut writer = open(&meta)?;
            if !meta.is_directory {
                session.write_file_to(self, file, &mut writer)?;
            }
        }
        Ok(())
    }
}

struct DecodedData {
    data: Vec<u8>,
    keys: Option<Rar50Keys>,
}

struct DecoderSession<'a> {
    decoder: Unpack50Decoder,
    password: Option<&'a [u8]>,
}

impl<'a> DecoderSession<'a> {
    fn new_with_password(password: Option<&'a [u8]>) -> Self {
        Self {
            decoder: Unpack50Decoder::new(),
            password,
        }
    }

    fn extract_file(&mut self, archive: &Archive, file: &FileHeader) -> Result<ExtractedEntry> {
        file.extract_with_decoder(archive, &mut self.decoder, self.password)
    }

    fn write_file_to(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let decoded = self
            .decoded_file_data(archive, file)
            .map_err(|error| file.entry_error("decoding", error))?;
        file.verify_integrity_with_keys(&decoded.data, decoded.keys.as_ref())
            .map_err(|error| file.entry_error("verifying", error))?;
        writer
            .write_all(&decoded.data)
            .map_err(Error::from)
            .map_err(|error| file.entry_error("writing", error))
    }

    fn decoded_file_data(&mut self, archive: &Archive, file: &FileHeader) -> Result<DecodedData> {
        file.decoded_data_with_decoder(archive, &mut self.decoder, self.password)
    }

    fn split_decryptor(
        &self,
        split: &PendingSplitRefs,
        volumes: &[Archive],
    ) -> Result<Option<SplitDecryptor>> {
        split.split_decryptor(volumes, self.password)
    }

    fn decode_split(
        &mut self,
        volumes: &[Archive],
        split: &PendingSplitRefs,
        final_file: &FileHeader,
        decryptor: Option<&SplitDecryptor>,
    ) -> Result<Vec<u8>> {
        final_file.decode_split_with_decoder(volumes, split, &mut self.decoder, decryptor)
    }
}

/// Convenience multivolume extraction API that buffers each extracted entry in
/// memory. Prefer [`extract_volumes_to`] for large archives.
pub fn extract_volumes(volumes: &[Archive]) -> Result<Vec<ExtractedEntry>> {
    extract_volumes_with_options(volumes, crate::ArchiveReadOptions::default())
}

pub fn extract_volumes_with_options(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
) -> Result<Vec<ExtractedEntry>> {
    extract_volumes_with_password(volumes, options.password)
}

pub fn extract_volumes_with_password(
    volumes: &[Archive],
    password: Option<&[u8]>,
) -> Result<Vec<ExtractedEntry>> {
    use std::cell::RefCell;
    use std::rc::Rc;

    struct SharedWriter(Rc<RefCell<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut captured: Vec<(ExtractedEntryMeta, Rc<RefCell<Vec<u8>>>)> = Vec::new();
    extract_volumes_to_with_password(volumes, password, |meta| {
        let data = Rc::new(RefCell::new(Vec::new()));
        captured.push((meta.clone(), data.clone()));
        Ok(Box::new(SharedWriter(data)))
    })?;

    Ok(captured
        .into_iter()
        .map(|(meta, data)| ExtractedEntry {
            name: meta.name,
            data: data.borrow().clone(),
            file_time: meta.file_time,
            attr: meta.attr,
            host_os: meta.host_os,
            is_directory: meta.is_directory,
        })
        .collect())
}

/// Streams a RAR 5 multivolume archive set to caller-provided writers.
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
        return Err(Error::InvalidHeader("RAR 5 volume set is empty"));
    }

    let mut split = SplitVolumeState::new();
    let mut session = DecoderSession::new_with_password(password);

    for (volume_index, archive) in volumes.iter().enumerate() {
        for (file_index, file) in archive.files().enumerate() {
            match split.advance(file.is_split_before(), file.is_split_after()) {
                SplitVolumeStep::Regular => {
                    let meta = file.metadata();
                    let mut writer = open(&meta)?;
                    if !meta.is_directory {
                        session.write_file_to(archive, file, &mut writer)?;
                    }
                }
                SplitVolumeStep::Start => {
                    validate_split_fragment(file, password)?;
                    split.begin(PendingSplitRefs::new(file, volume_index, file_index));
                }
                SplitVolumeStep::Continue(current) => {
                    validate_split_continuation_refs(current, file, password)?;
                    current.append(volume_index, file_index);
                }
                SplitVolumeStep::Finish(mut completed) => {
                    validate_split_continuation_refs(&completed, file, password)?;
                    completed.append(volume_index, file_index);
                    completed.write_to(volumes, file, &mut session, &mut open)?;
                }
                SplitVolumeStep::MissingFirst => {
                    return Err(Error::InvalidHeader(
                        "RAR 5 split entry is missing its first part",
                    ));
                }
                SplitVolumeStep::Interrupted => {
                    return Err(Error::InvalidHeader(
                        "RAR 5 split entry is interrupted by a regular entry",
                    ));
                }
            }
        }
    }

    if split.is_pending() {
        return Err(Error::InvalidHeader("RAR 5 split entry is incomplete"));
    }

    Ok(())
}

fn validate_split_fragment(file: &FileHeader, password: Option<&[u8]>) -> Result<()> {
    if file.is_directory() {
        return Err(Error::InvalidHeader(
            "RAR 5 split directory entry is invalid",
        ));
    }
    if file.encrypted && password.is_none() && file.crypto.is_none() {
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
        return Err(Error::InvalidHeader("RAR 5 split entry name changed"));
    }
    if file.compression_info != pending.compression_info {
        return Err(Error::InvalidHeader(
            "RAR 5 split entry compression info changed",
        ));
    }
    if file.encrypted != pending.encrypted {
        return Err(Error::InvalidHeader(
            "RAR 5 split entry encryption flag changed",
        ));
    }
    Ok(())
}

struct PendingSplitRefs {
    name: Vec<u8>,
    fragments: Vec<(usize, usize)>,
    file_time: u32,
    attr: u64,
    host_os: u64,
    compression_info: u64,
    encrypted: bool,
}

impl PendingSplitRefs {
    fn new(file: &FileHeader, volume_index: usize, file_index: usize) -> Self {
        Self {
            name: file.name.clone(),
            fragments: vec![(volume_index, file_index)],
            file_time: file.mtime.unwrap_or(0),
            attr: file.attributes,
            host_os: file.host_os,
            compression_info: file.compression_info,
            encrypted: file.encrypted,
        }
    }

    fn append(&mut self, volume_index: usize, file_index: usize) {
        self.fragments.push((volume_index, file_index));
    }

    fn write_to<F>(
        self,
        volumes: &[Archive],
        final_file: &FileHeader,
        session: &mut DecoderSession<'_>,
        open: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let decryptor = session.split_decryptor(&self, volumes)?;
        let meta = ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.file_time,
            attr: self.attr,
            host_os: self.host_os,
            is_directory: false,
        };
        let mut writer = open(&meta)?;
        if final_file.is_stored() {
            return self
                .write_stored_to(volumes, final_file, decryptor.as_ref(), &mut writer)
                .map_err(|error| final_file.entry_error("extracting", error));
        }

        let data = session
            .decode_split(volumes, &self, final_file, decryptor.as_ref())
            .map_err(|error| final_file.entry_error("decoding", error))?;
        final_file
            .verify_integrity_with_keys(&data, decryptor.as_ref().map(|decryptor| &decryptor.keys))
            .map_err(|error| final_file.entry_error("verifying", error))?;
        writer
            .write_all(&data)
            .map_err(Error::from)
            .map_err(|error| final_file.entry_error("writing", error))?;
        Ok(())
    }

    fn write_stored_to(
        &self,
        volumes: &[Archive],
        final_file: &FileHeader,
        decryptor: Option<&SplitDecryptor>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let mut reader = self.fragment_reader(volumes, decryptor)?;
        let mut crc = StreamingCrc32::new();
        let mut hash = streaming_hash_verifier(final_file)?;
        let mut written = 0u64;
        let mut buf = [0u8; 64 * 1024];

        loop {
            let count = reader.read(&mut buf)?;
            if count == 0 {
                break;
            }
            let chunk = if final_file.encrypted {
                let remaining = final_file.unpacked_size.saturating_sub(written) as usize;
                &buf[..count.min(remaining)]
            } else {
                &buf[..count]
            };
            written = written
                .checked_add(chunk.len() as u64)
                .ok_or(Error::InvalidHeader("RAR 5 stored split size overflows"))?;
            crc.update(chunk);
            if let Some((_, hasher)) = &mut hash {
                hasher.update(chunk);
            }
            writer.write_all(chunk)?;
        }

        if written != final_file.unpacked_size {
            return Err(Error::InvalidHeader(
                "RAR 5 stored split file has mismatched packed and unpacked sizes",
            ));
        }
        if let Some(expected) = final_file.data_crc32 {
            let actual = if final_file.encrypted {
                let decryptor = decryptor.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted split CRC needs encryption keys",
                ))?;
                decryptor.keys.mac_crc32(crc.finish())
            } else {
                crc.finish()
            };
            if actual != expected {
                return Err(Error::Crc32Mismatch { expected, actual });
            }
        }
        if let Some((expected, hasher)) = hash {
            let actual = if final_file.encrypted {
                let decryptor = decryptor.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted split hash needs encryption keys",
                ))?;
                decryptor.keys.mac_hash32(hasher.finalize())
            } else {
                hasher.finalize()
            };
            if expected != actual {
                return Err(Error::HashMismatch { hash_type: 0 });
            }
        }
        Ok(())
    }

    fn split_decryptor(
        &self,
        volumes: &[Archive],
        password: Option<&[u8]>,
    ) -> Result<Option<SplitDecryptor>> {
        if !self.encrypted {
            return Ok(None);
        }
        let (volume_index, file_index) = self.fragments[0];
        let archive = volumes
            .get(volume_index)
            .ok_or(Error::InvalidHeader("RAR 5 split volume is missing"))?;
        let file = archive
            .files()
            .nth(file_index)
            .ok_or(Error::InvalidHeader("RAR 5 split entry is missing"))?;
        let keys = file
            .crypto_with_password(password)?
            .expect("encrypted split file has keys");
        Ok(Some(SplitDecryptor {
            keys,
            iv: file.encryption_iv()?,
        }))
    }

    fn fragment_reader<'a>(
        &self,
        volumes: &'a [Archive],
        decryptor: Option<&SplitDecryptor>,
    ) -> Result<Box<dyn Read + 'a>> {
        let mut readers = Vec::with_capacity(self.fragments.len());
        for &(volume_index, file_index) in &self.fragments {
            let archive = volumes
                .get(volume_index)
                .ok_or(Error::InvalidHeader("RAR 5 split volume is missing"))?;
            let file = archive
                .files()
                .nth(file_index)
                .ok_or(Error::InvalidHeader("RAR 5 split entry is missing"))?;
            readers.push(archive.range_reader(file.block.data_range.clone())?);
        }
        let chained = ChainedReader::new(readers);
        if let Some(decryptor) = decryptor {
            Ok(Box::new(Rar50DecryptingReader::new(
                chained,
                decryptor.keys.key,
                decryptor.iv,
            )))
        } else {
            Ok(Box::new(chained))
        }
    }
}

struct SplitDecryptor {
    keys: Rar50Keys,
    iv: [u8; 16],
}

fn streaming_hash_verifier(file: &FileHeader) -> Result<Option<([u8; 32], blake2sp::Hasher)>> {
    let Some(hash) = &file.hash else {
        return Ok(None);
    };
    match hash.hash_type {
        0 if hash.data.len() == 32 => {
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&hash.data);
            Ok(Some((expected, blake2sp::Hasher::new())))
        }
        0 => Err(Error::InvalidHeader(
            "RAR 5 BLAKE2sp hash record has invalid length",
        )),
        _ => Err(Error::UnsupportedFeature {
            version: crate::version::ArchiveVersion::Rar50,
            feature: "RAR 5 unknown file hash type",
        }),
    }
}

impl FileHeader {
    fn decode_split_with_decoder(
        &self,
        volumes: &[Archive],
        split: &PendingSplitRefs,
        decoder: &mut Unpack50Decoder,
        decryptor: Option<&SplitDecryptor>,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            let mut data = Vec::new();
            let mut reader = split.fragment_reader(volumes, decryptor)?;
            reader.read_to_end(&mut data)?;
            if data.len() as u64 != self.unpacked_size {
                return Err(Error::InvalidHeader(
                    "RAR 5 stored split file has mismatched packed and unpacked sizes",
                ));
            }
            return Ok(data);
        }

        let info = self.decoded_compression_info()?;
        let dictionary_size = usize::try_from(info.dictionary_size).map_err(|_| {
            Error::InvalidHeader("RAR 5 dictionary size overflows host address size")
        })?;
        let mut reader = split.fragment_reader(volumes, decryptor)?;
        decoder
            .decode_member_from_reader_with_dictionary(
                &mut reader,
                info.algorithm_version,
                self.unpacked_size as usize,
                dictionary_size,
                info.solid,
                DecodeMode::Lz,
            )
            .map_err(Error::from)
    }
}

struct Rar50DecryptingReader<R> {
    inner: R,
    cipher: Rar50Cipher,
    buffer: [u8; 16],
    pos: usize,
    len: usize,
}

impl<R: Read> Rar50DecryptingReader<R> {
    fn new(inner: R, key: [u8; 32], iv: [u8; 16]) -> Self {
        Self {
            inner,
            cipher: Rar50Cipher::new(key, iv),
            buffer: [0; 16],
            pos: 0,
            len: 0,
        }
    }

    fn fill_buffer(&mut self) -> std::io::Result<bool> {
        let mut encrypted = [0; 16];
        let mut read = 0;
        while read < encrypted.len() {
            let count = self.inner.read(&mut encrypted[read..])?;
            if count == 0 {
                if read == 0 {
                    return Ok(false);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated RAR 5 encrypted stream",
                ));
            }
            read += count;
        }
        self.buffer = encrypted;
        self.cipher.decrypt_in_place(&mut self.buffer);
        self.pos = 0;
        self.len = self.buffer.len();
        Ok(true)
    }
}

impl<R: Read> Read for Rar50DecryptingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos == self.len && !self.fill_buffer()? {
            return Ok(0);
        }
        let count = out.len().min(self.len - self.pos);
        out[..count].copy_from_slice(&self.buffer[self.pos..self.pos + count]);
        self.pos += count;
        Ok(count)
    }
}

struct StreamingCrc32 {
    value: u32,
}

impl StreamingCrc32 {
    fn new() -> Self {
        Self { value: 0xffff_ffff }
    }

    fn update(&mut self, input: &[u8]) {
        for &byte in input {
            self.value ^= byte as u32;
            for _ in 0..8 {
                let mask = 0u32.wrapping_sub(self.value & 1);
                self.value = (self.value >> 1) ^ (0xedb8_8320 & mask);
            }
        }
    }

    fn finish(self) -> u32 {
        !self.value
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        ArchiveSource, Block, BlockHeader, FileHash, MainHeader, HEAD_FILE, HFL_SPLIT_AFTER,
        HFL_SPLIT_BEFORE,
    };
    use super::*;
    use crate::rar15_40::crc32;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    #[test]
    fn stored_split_entries_stream_fragments_to_writer() {
        struct SharedWriter(Rc<RefCell<Vec<u8>>>);

        impl Write for SharedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let first = b"stored ";
        let second = b"split payload";
        let full = [first.as_slice(), second.as_slice()].concat();
        let expected_crc = crc32(&full);
        let volumes = vec![
            stored_split_archive(first, &full, expected_crc, HFL_SPLIT_AFTER),
            stored_split_archive(second, &full, expected_crc, HFL_SPLIT_BEFORE),
        ];
        let captured = Rc::new(RefCell::new(Vec::new()));
        let sink = captured.clone();

        extract_volumes_to(&volumes, move |_meta| {
            Ok(Box::new(SharedWriter(sink.clone())))
        })
        .unwrap();

        assert_eq!(&*captured.borrow(), &full);
    }

    fn stored_split_archive(data: &[u8], full: &[u8], crc: u32, flags: u64) -> Archive {
        let source: Arc<[u8]> = Arc::from(data.to_vec().into_boxed_slice());
        Archive {
            sfx_offset: 0,
            main: MainHeader {
                block: empty_block(1, 0, 0..0),
                archive_flags: 0,
                volume_number: None,
                extras: Vec::new(),
            },
            blocks: vec![Block::File(FileHeader {
                block: empty_block(HEAD_FILE, flags, 0..data.len()),
                file_flags: 0,
                unpacked_size: full.len() as u64,
                attributes: 0x20,
                mtime: None,
                data_crc32: Some(crc),
                compression_info: 0,
                host_os: 2,
                name: b"split.txt".to_vec(),
                hash: Some(FileHash {
                    hash_type: 0,
                    data: blake2sp::hash(full).to_vec(),
                }),
                service_data: None,
                encrypted: false,
                encryption: None,
                crypto: None,
            })],
            source: ArchiveSource::Memory(source),
        }
    }

    fn empty_block(
        header_type: u64,
        flags: u64,
        data_range: std::ops::Range<usize>,
    ) -> BlockHeader {
        BlockHeader {
            header_crc: 0,
            header_size: 0,
            header_type,
            flags,
            extra_area_size: None,
            data_size: Some(data_range.len() as u64),
            offset: 0,
            header_range: 0..0,
            data_range,
        }
    }
}

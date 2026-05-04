use super::{blake2sp, Archive, ExtractedEntry, ExtractedEntryMeta, FileHeader};
use crate::error::{Error, Result};
use rars_codec::rar50::{DecodeMode, Unpack50Decoder};
use std::io::{Read, Write};

impl FileHeader {
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
        let mut decoder = Unpack50Decoder::new();
        self.extract_with_decoder(archive, &mut decoder)
    }

    fn extract_with_decoder(
        &self,
        archive: &Archive,
        decoder: &mut Unpack50Decoder,
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
        let data = self
            .decoded_data_with_decoder(archive, decoder)
            .map_err(|error| self.entry_error("decoding", error))?;
        self.verify_integrity(&data)
            .map_err(|error| self.entry_error("verifying", error))?;
        Ok(ExtractedEntry {
            name: self.name.clone(),
            data,
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
    ) -> Result<Vec<u8>> {
        if self.encrypted {
            return Err(Error::NeedPassword);
        }
        let packed = self.packed_data(archive)?;
        self.decode_packed_with_decoder(&packed, decoder)
    }

    fn decode_packed_with_decoder(
        &self,
        packed: &[u8],
        decoder: &mut Unpack50Decoder,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
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

impl Archive {
    pub fn extract(&self) -> Result<Vec<ExtractedEntry>> {
        let mut out = Vec::new();
        let mut decoder = Unpack50Decoder::new();
        for file in self.files() {
            if file.is_split_before() || file.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry requires multivolume extraction",
                ));
            }
            out.push(file.extract_with_decoder(self, &mut decoder)?);
        }
        Ok(out)
    }

    pub fn extract_to<F>(&self, mut open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let mut decoder = Unpack50Decoder::new();
        for file in self.files() {
            if file.is_split_before() || file.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry requires multivolume extraction",
                ));
            }
            let meta = file.metadata();
            let mut writer = open(&meta)?;
            if !meta.is_directory {
                let data = file
                    .decoded_data_with_decoder(self, &mut decoder)
                    .map_err(|error| file.entry_error("decoding", error))?;
                file.verify_integrity(&data)
                    .map_err(|error| file.entry_error("verifying", error))?;
                writer
                    .write_all(&data)
                    .map_err(Error::from)
                    .map_err(|error| file.entry_error("writing", error))?;
            }
        }
        Ok(())
    }
}

/// Convenience multivolume extraction API that buffers each extracted entry in
/// memory. Prefer [`extract_volumes_to`] for large archives.
pub fn extract_volumes(volumes: &[Archive]) -> Result<Vec<ExtractedEntry>> {
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
    extract_volumes_to(volumes, |meta| {
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
pub fn extract_volumes_to<F>(volumes: &[Archive], mut open: F) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    if volumes.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 volume set is empty"));
    }

    let mut pending: Option<PendingSplitRefs> = None;
    let mut decoder = Unpack50Decoder::new();

    for (volume_index, archive) in volumes.iter().enumerate() {
        for (file_index, file) in archive.files().enumerate() {
            match (
                pending.is_some(),
                file.is_split_before(),
                file.is_split_after(),
            ) {
                (false, false, false) => {
                    let meta = file.metadata();
                    let mut writer = open(&meta)?;
                    if !meta.is_directory {
                        let data = file.decoded_data_with_decoder(archive, &mut decoder)?;
                        file.verify_integrity(&data)?;
                        writer.write_all(&data)?;
                    }
                }
                (false, false, true) => {
                    validate_split_fragment(file)?;
                    pending = Some(PendingSplitRefs::new(file, volume_index, file_index));
                }
                (true, true, true) => {
                    let current = pending.as_mut().expect("pending split");
                    validate_split_continuation_refs(current, file)?;
                    current.append(volume_index, file_index);
                }
                (true, true, false) => {
                    let mut completed = pending.take().expect("pending split");
                    validate_split_continuation_refs(&completed, file)?;
                    completed.append(volume_index, file_index);
                    completed.write_to(volumes, file, &mut decoder, &mut open)?;
                }
                (false, true, _) => {
                    return Err(Error::InvalidHeader(
                        "RAR 5 split entry is missing its first part",
                    ));
                }
                (true, false, _) => {
                    return Err(Error::InvalidHeader(
                        "RAR 5 split entry is interrupted by a regular entry",
                    ));
                }
            }
        }
    }

    if pending.is_some() {
        return Err(Error::InvalidHeader("RAR 5 split entry is incomplete"));
    }

    Ok(())
}

fn validate_split_fragment(file: &FileHeader) -> Result<()> {
    if file.is_directory() {
        return Err(Error::InvalidHeader(
            "RAR 5 split directory entry is invalid",
        ));
    }
    if file.encrypted {
        return Err(Error::NeedPassword);
    }
    Ok(())
}

fn validate_split_continuation_refs(pending: &PendingSplitRefs, file: &FileHeader) -> Result<()> {
    validate_split_fragment(file)?;
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
        decoder: &mut Unpack50Decoder,
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
        if final_file.is_stored() {
            return self
                .write_stored_to(volumes, final_file, &mut writer)
                .map_err(|error| final_file.entry_error("extracting", error));
        }

        let data = final_file
            .decode_split_with_decoder(volumes, &self, decoder)
            .map_err(|error| final_file.entry_error("decoding", error))?;
        final_file
            .verify_integrity(&data)
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
        writer: &mut dyn Write,
    ) -> Result<()> {
        let mut reader = self.fragment_reader(volumes)?;
        let mut crc = StreamingCrc32::new();
        let mut hash = streaming_hash_verifier(final_file)?;
        let mut written = 0u64;
        let mut buf = [0u8; 64 * 1024];

        loop {
            let count = reader.read(&mut buf)?;
            if count == 0 {
                break;
            }
            let chunk = &buf[..count];
            written = written
                .checked_add(count as u64)
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
            let actual = crc.finish();
            if actual != expected {
                return Err(Error::Crc32Mismatch { expected, actual });
            }
        }
        if let Some((expected, hasher)) = hash {
            let actual = hasher.finalize();
            if expected != actual {
                return Err(Error::HashMismatch { hash_type: 0 });
            }
        }
        Ok(())
    }

    fn fragment_reader<'a>(&self, volumes: &'a [Archive]) -> Result<ChainedReader<'a>> {
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
        Ok(ChainedReader { readers, index: 0 })
    }
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
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            let mut data = Vec::new();
            let mut reader = split.fragment_reader(volumes)?;
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
        let mut reader = split.fragment_reader(volumes)?;
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

struct ChainedReader<'a> {
    readers: Vec<Box<dyn Read + 'a>>,
    index: usize,
}

impl Read for ChainedReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while let Some(reader) = self.readers.get_mut(self.index) {
            let read = reader.read(out)?;
            if read != 0 {
                return Ok(read);
            }
            self.index += 1;
        }
        Ok(0)
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
                encrypted: false,
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

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::compress::{Method, copy_region, decompress_stream};
use crate::entry::Entry;
use crate::error::{Error, Result};
use crate::io_ext::{le_u32, read_exact_at, read_exact_now, to_u64};
use crate::{pe, table};

/// Magic at the start of the overlay: `wwgT`, little-endian.
pub const MAGIC: u32 = 0x5467_7777;

/// Marker that terminates the metadata section.
pub const END_MARKER: u32 = 0x0000_7F7F;

/// Read-ahead buffer used while streaming file blobs.
const COPY_BUFFER: usize = 64 * 1024;

/// Layout information gathered while opening an archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveInfo {
    /// Size of the whole executable.
    pub file_size: u64,
    /// Offset of the archive overlay inside the executable.
    pub overlay_offset: u64,
    /// Offset of the end marker.
    pub marker_offset: u64,
    /// Offset of the first byte of the data stream.
    pub data_offset: u64,
    /// Length of the data stream in bytes.
    pub data_size: u64,
    /// Number of metadata blocks, including the file table.
    pub block_count: usize,
}

/// An opened Clickteam Install Creator 2 archive.
///
/// The reader is kept alive so file data can be streamed on demand.  Any
/// [`Read`] + [`Seek`] source works, which makes it possible to unpack from a
/// file, an in-memory buffer or a decompressing wrapper.
///
/// Only the metadata blocks (installer resources and the file table, a few
/// hundred kilobytes in total) are kept in memory.  File blobs are never
/// buffered as a whole: they are decoded chunk by chunk straight into the
/// caller's [`Write`] sink.
pub struct Installer<R> {
    reader: R,
    info: ArchiveInfo,
    blocks: Vec<Vec<u8>>,
    entries: Vec<Entry>,
}

impl Installer<File> {
    /// Opens an installer executable from disk.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or is not a supported
    /// Install Creator archive.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::new(File::open(path)?)
    }
}

impl<R: Read + Seek> Installer<R> {
    /// Reads the archive structure from an arbitrary reader.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is not a PE file, the overlay is
    /// malformed, a metadata block cannot be decompressed or the file table
    /// cannot be parsed.
    pub fn new(mut reader: R) -> Result<Self> {
        let file_size = reader.seek(SeekFrom::End(0))?;
        let overlay_offset = pe::overlay_offset(&mut reader, file_size)?;

        reader.seek(SeekFrom::Start(overlay_offset))?;
        let mut prefix = [0_u8; 10];
        read_exact_now(&mut reader, &mut prefix)?;

        let magic = le_u32(&prefix, 0).ok_or(Error::UnexpectedEof(overlay_offset))?;
        if magic != MAGIC {
            return Err(Error::BadMagic {
                found: magic,
                offset: overlay_offset,
            });
        }
        let version = u16::from_le_bytes([prefix[8], prefix[9]]);
        if version != 1 {
            return Err(Error::UnsupportedVersion(version));
        }

        let mut blocks = Vec::new();

        // The first block has no identifier in front of its header.
        let mut header = [0_u8; 9];
        read_exact_now(&mut reader, &mut header)?;
        let position = reader.stream_position()?;
        let start = position
            .checked_sub(9)
            .ok_or(Error::UnexpectedEof(position))?;
        blocks.push(read_payload(
            &mut reader,
            file_size,
            start,
            le_u32(&header, 0).ok_or(Error::UnexpectedEof(start))?,
            le_u32(&header, 4).ok_or(Error::UnexpectedEof(start))?,
            Method::from_byte(header[8])?,
        )?);

        let (marker_offset, data_offset, data_size) = loop {
            let mut header = [0_u8; 13];
            read_exact_now(&mut reader, &mut header)?;
            let position = reader.stream_position()?;
            let start = position
                .checked_sub(13)
                .ok_or(Error::UnexpectedEof(position))?;
            let id = le_u32(&header, 0).ok_or(Error::UnexpectedEof(start))?;

            if id == END_MARKER {
                let data_size = u64::from(le_u32(&header, 4).ok_or(Error::UnexpectedEof(start))?);
                let data_offset = start.checked_add(12).ok_or(Error::UnexpectedEof(start))?;
                break (start, data_offset, data_size);
            }

            blocks.push(read_payload(
                &mut reader,
                file_size,
                start,
                le_u32(&header, 4).ok_or(Error::UnexpectedEof(start))?,
                le_u32(&header, 8).ok_or(Error::UnexpectedEof(start))?,
                Method::from_byte(header[12])?,
            )?);
        };

        let expected_base = file_size
            .checked_sub(data_size)
            .ok_or(Error::InconsistentStream {
                base: data_offset,
                expected: 0,
            })?;
        if expected_base != data_offset {
            return Err(Error::InconsistentStream {
                base: data_offset,
                expected: expected_base,
            });
        }
        if data_offset.checked_add(data_size) != Some(file_size) {
            return Err(Error::StreamNotAtEof);
        }

        let table_blob = blocks.last().ok_or(Error::TableNotFound)?;
        let entries = table::parse(table_blob, data_size);
        if entries.is_empty() {
            return Err(Error::TableNotFound);
        }

        let info = ArchiveInfo {
            file_size,
            overlay_offset,
            marker_offset,
            data_offset,
            data_size,
            block_count: blocks.len(),
        };

        Ok(Self {
            reader,
            info,
            blocks,
            entries,
        })
    }

    /// Layout information of the opened archive.
    #[must_use]
    pub const fn info(&self) -> &ArchiveInfo {
        &self.info
    }

    /// File-table entries in archive order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Number of metadata blocks.
    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Decompressed content of a metadata block.
    #[must_use]
    pub fn block(&self, index: usize) -> Option<&[u8]> {
        self.blocks.get(index).map(Vec::as_slice)
    }

    /// Copies a decompressed metadata block into `writer`.
    ///
    /// # Errors
    ///
    /// Returns an error when the index is out of range or writing fails.
    pub fn copy_block<W: Write>(&self, index: usize, writer: &mut W) -> Result<u64> {
        let data = self.blocks.get(index).ok_or(Error::BlockIndex(index))?;
        writer.write_all(data)?;
        Ok(to_u64(data.len()))
    }

    /// Streams a raw range of the data stream into `writer`.
    ///
    /// The range is decompressed chunk by chunk without buffering the blob.
    ///
    /// # Errors
    ///
    /// Returns an error when the range leaves the data stream, the compressed
    /// data is corrupt, or writing fails.
    pub fn copy_blob<W: Write>(&mut self, offset: u64, length: u64, writer: &mut W) -> Result<u64> {
        let end = offset
            .checked_add(length)
            .ok_or(Error::BlobOutOfRange { offset, length })?;
        if end > self.info.data_size {
            return Err(Error::BlobOutOfRange { offset, length });
        }
        if length == 0 {
            return Ok(0);
        }

        let position = self
            .info
            .data_offset
            .checked_add(offset)
            .ok_or(Error::BlobOutOfRange { offset, length })?;
        self.reader.seek(SeekFrom::Start(position))?;

        let limited = (&mut self.reader).take(length);
        let mut buffered = BufReader::with_capacity(COPY_BUFFER, limited);
        copy_region(&mut buffered, writer)
    }

    /// Decompresses a raw range of the data stream into memory.
    ///
    /// Prefer [`Self::copy_blob`] for large files.
    ///
    /// # Errors
    ///
    /// Returns an error when the range leaves the data stream or the data is
    /// corrupt.
    pub fn blob_bytes(&mut self, offset: u64, length: u64) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        self.copy_blob(offset, length, &mut data)?;
        Ok(data)
    }

    /// Streams the decompressed content of one entry into `writer`.
    ///
    /// # Errors
    ///
    /// Returns an error when the entry points outside the data stream, the
    /// payload size does not match the table, or writing fails.
    pub fn copy_entry<W: Write>(&mut self, entry: &Entry, writer: &mut W) -> Result<u64> {
        if entry.size == 0 {
            return Ok(0);
        }

        let written =
            self.copy_blob(u64::from(entry.offset), u64::from(entry.compressed), writer)?;
        if written != u64::from(entry.size) {
            return Err(Error::EntrySize {
                name: entry.name.clone(),
                got: written,
                expected: u64::from(entry.size),
            });
        }
        Ok(written)
    }

    /// Decompresses the content of one entry into memory.
    ///
    /// Prefer [`Self::copy_entry`] for large files.
    ///
    /// # Errors
    ///
    /// Returns an error when the entry points outside the data stream, the
    /// payload size does not match the table, or reading fails.
    pub fn entry_bytes(&mut self, entry: &Entry) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        self.copy_entry(entry, &mut data)?;
        Ok(data)
    }

    /// Reads the chunk method byte at the start of a blob.
    ///
    /// Returns `None` when `offset` lies outside the data stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying reader fails.
    pub fn blob_method_byte(&mut self, offset: u64) -> Result<Option<u8>> {
        if offset >= self.info.data_size {
            return Ok(None);
        }
        let position = self
            .info
            .data_offset
            .checked_add(offset)
            .ok_or(Error::BlobOutOfRange { offset, length: 1 })?;
        let mut byte = [0_u8; 1];
        read_exact_at(&mut self.reader, &mut byte, position)?;
        Ok(Some(byte[0]))
    }
}

/// Suggested file name for a metadata block.
///
/// The first block contains installer fonts and bitmaps, the last one is the
/// file table; the middle blocks are numbered `resource0`, `resource1`, ...
#[must_use]
pub fn record_file_name(index: usize, block_count: usize) -> String {
    if index == 0 {
        "fonts.bin".to_owned()
    } else if index.checked_add(1) == Some(block_count) {
        "file_table.bin".to_owned()
    } else {
        format!("resource{}.bin", index.saturating_sub(1))
    }
}

fn read_payload<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
    start: u64,
    packed: u32,
    unpacked: u32,
    method: Method,
) -> Result<Vec<u8>> {
    let payload = packed.checked_sub(5).ok_or(Error::BadBlockLength {
        offset: start,
        length: packed,
    })?;

    // Reject a declared length that cannot fit in the file before allocating
    // it: a four-byte field must not be able to request a multi-gigabyte
    // buffer.
    let payload_start = reader.stream_position()?;
    let payload_end =
        payload_start
            .checked_add(u64::from(payload))
            .ok_or(Error::BadBlockLength {
                offset: start,
                length: packed,
            })?;
    if payload_end > file_size {
        return Err(Error::UnexpectedEof(payload_end));
    }

    let size = usize::try_from(payload).map_err(|_| Error::BadBlockLength {
        offset: start,
        length: packed,
    })?;
    let mut raw = vec![0_u8; size];
    read_exact_now(reader, &mut raw)?;

    let data = decompress_stream(&raw, method)?;
    if to_u64(data.len()) != u64::from(unpacked) {
        return Err(Error::BlockSize {
            offset: start,
            got: to_u64(data.len()),
            expected: u64::from(unpacked),
        });
    }
    Ok(data)
}

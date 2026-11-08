use std::io::{self, Read, Seek, SeekFrom};

use crate::error::{Error, Result};

/// Reads exactly `buf.len()` bytes starting at absolute `offset`.
pub fn read_exact_at<R>(reader: &mut R, buf: &mut [u8], offset: u64) -> Result<()>
where
    R: Read + Seek,
{
    reader.seek(SeekFrom::Start(offset))?;
    read_exact_now(reader, buf)
}

/// Reads exactly `buf.len()` bytes from the current position.
pub fn read_exact_now<R>(reader: &mut R, buf: &mut [u8]) -> Result<()>
where
    R: Read + Seek,
{
    let offset = reader.stream_position()?;
    match reader.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(Error::UnexpectedEof(offset)),
        Err(err) => Err(Error::Io(err)),
    }
}

/// Widens a slice length to `u64` without a lossy cast.
pub fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Reads a little-endian `u16` at `offset` inside `buf`.
#[must_use]
pub fn le_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes: [u8; 2] = buf.get(offset..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

/// Reads a little-endian `u32` at `offset` inside `buf`.
#[must_use]
pub fn le_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = buf.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Reads a little-endian `u64` at `offset` inside `buf`.
#[must_use]
pub fn le_u64(buf: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let bytes: [u8; 8] = buf.get(offset..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

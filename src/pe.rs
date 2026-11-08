use std::io::{Read, Seek};

use crate::error::{Error, Result};
use crate::io_ext::{le_u16, le_u32, read_exact_at};

/// Offset of the first byte after the last PE section, i.e. the overlay.
pub fn overlay_offset<R>(reader: &mut R, file_len: u64) -> Result<u64>
where
    R: Read + Seek,
{
    let mut dos = [0_u8; 0x40];
    if read_exact_at(reader, &mut dos, 0).is_err() || !dos.starts_with(b"MZ") {
        return Err(Error::NotMz);
    }

    let pe_offset = u64::from(le_u32(&dos, 0x3C).ok_or(Error::UnexpectedEof(0))?);
    let header_end = pe_offset
        .checked_add(0x18)
        .ok_or(Error::UnexpectedEof(pe_offset))?;
    if header_end > file_len {
        return Err(Error::NotPe);
    }

    let mut pe = [0_u8; 0x18];
    read_exact_at(reader, &mut pe, pe_offset)?;
    if !pe.starts_with(b"PE\0\0") {
        return Err(Error::NotPe);
    }

    let section_count = le_u16(&pe, 6).ok_or(Error::UnexpectedEof(pe_offset))?;
    let optional_size = le_u16(&pe, 20).ok_or(Error::UnexpectedEof(pe_offset))?;
    let mut cursor = pe_offset
        .checked_add(24)
        .and_then(|value| value.checked_add(u64::from(optional_size)))
        .ok_or(Error::UnexpectedEof(pe_offset))?;

    let mut end = 0_u64;
    for _ in 0..section_count {
        let mut section = [0_u8; 40];
        read_exact_at(reader, &mut section, cursor)?;
        let raw_size = u64::from(le_u32(&section, 16).ok_or(Error::UnexpectedEof(cursor))?);
        let raw_pointer = u64::from(le_u32(&section, 20).ok_or(Error::UnexpectedEof(cursor))?);
        cursor = cursor.checked_add(40).ok_or(Error::UnexpectedEof(cursor))?;
        end = end.max(raw_pointer.saturating_add(raw_size));
    }

    if end > file_len {
        return Err(Error::UnexpectedEof(end));
    }

    Ok(end)
}

use crate::entry::{Entry, FileTimes};
use crate::io_ext::{le_u32, le_u64};

/// Length of the fixed part of a file-table record.
const STRUCT_LEN: usize = 78;
/// Length of the file-table header before the uninstaller strings.
const TABLE_HEADER_LEN: usize = 0x32;
/// How far the parser may scan for the next record.
const SEARCH_WINDOW: usize = 600;
/// Maximum accepted length of a stored name.
const MAX_NAME_LEN: usize = 260;

/// Attribute values that only appear in valid records.
const KNOWN_ATTRIBUTES: [u32; 2] = [0x00CF_E408, 0x00CF_E008];

struct RawEntry {
    checksum: u32,
    attributes: u32,
    size: u32,
    offset: u32,
    compressed: u32,
    blob_id: u32,
    times: FileTimes,
}

/// Parses the decompressed file-table block.
pub fn parse(blob: &[u8], total_data: u64) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut cursor = find_struct(blob, TABLE_HEADER_LEN, total_data);

    while let Some(position) = cursor {
        let Some(raw) = read_struct(blob, position, total_data) else {
            break;
        };
        let Some(name_start) = position.checked_add(STRUCT_LEN) else {
            break;
        };
        let Some(tail) = blob.get(name_start..) else {
            break;
        };
        let Some(length) = tail.iter().position(|&byte| byte == 0) else {
            break;
        };
        let Some(raw_name) = tail.get(..length) else {
            break;
        };
        if !valid_name(raw_name) {
            break;
        }

        entries.push(Entry {
            name: decode_name(raw_name),
            size: raw.size,
            offset: raw.offset,
            compressed: raw.compressed,
            checksum: raw.checksum,
            attributes: raw.attributes,
            blob_id: raw.blob_id,
            times: raw.times,
        });

        cursor = name_start
            .checked_add(length)
            .and_then(|next| next.checked_add(1))
            .and_then(|next| find_struct(blob, next, total_data));
    }

    entries
}

fn read_struct(blob: &[u8], position: usize, total_data: u64) -> Option<RawEntry> {
    let end = position.checked_add(STRUCT_LEN)?;
    if end > blob.len() {
        return None;
    }

    let attributes = le_u32(blob, position.checked_add(0x10)?)?;
    if !KNOWN_ATTRIBUTES.contains(&attributes) {
        return None;
    }

    let size = le_u32(blob, position.checked_add(0x20)?)?;
    let offset = u64::from(le_u32(blob, position.checked_add(0x24)?)?);
    let compressed = le_u32(blob, position.checked_add(0x28)?)?;
    if compressed == 0 || u64::from(compressed) > total_data {
        return None;
    }
    if offset.checked_add(u64::from(compressed))? > total_data {
        return None;
    }

    Some(RawEntry {
        checksum: le_u32(blob, position.checked_add(0x1C)?)?,
        attributes,
        size,
        offset: u32::try_from(offset).ok()?,
        compressed,
        blob_id: le_u32(blob, position.checked_add(0x30)?)?,
        times: FileTimes {
            created: le_u64(blob, position.checked_add(0x36)?)?,
            modified: le_u64(blob, position.checked_add(0x3E)?)?,
            accessed: le_u64(blob, position.checked_add(0x46)?)?,
        },
    })
}

/// Finds the next record structure at or after `start`.
///
/// A record is followed by the name it describes, so a candidate is only
/// accepted when that name looks valid.
fn find_struct(blob: &[u8], start: usize, total_data: u64) -> Option<usize> {
    let last = blob.len().checked_sub(STRUCT_LEN)?;
    let limit = start.saturating_add(SEARCH_WINDOW).min(last);

    (start..=limit).find(|&position| {
        if read_struct(blob, position, total_data).is_none() {
            return false;
        }
        let Some(name_start) = position.checked_add(STRUCT_LEN) else {
            return false;
        };
        let Some(tail) = blob.get(name_start..) else {
            return false;
        };
        let Some(length) = tail.iter().position(|&byte| byte == 0) else {
            return false;
        };
        length <= MAX_NAME_LEN && tail.get(..length).is_some_and(valid_name)
    })
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.iter().all(|&byte| byte >= 0x20 && byte != 0x7F)
}

/// The installer stores ANSI (Windows-1251) names.
fn decode_name(raw: &[u8]) -> String {
    let (text, _, _) = encoding_rs::WINDOWS_1251.decode(raw);
    text.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOTAL_DATA: u64 = 4096;

    fn push_entry(table: &mut Vec<u8>, name: &[u8], offset: u32, compressed: u32, extra: &[u8]) {
        let mut record = [0_u8; STRUCT_LEN];
        record[0x10..0x14].copy_from_slice(&0x00CF_E408_u32.to_le_bytes());
        record[0x1C..0x20].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        record[0x20..0x24].copy_from_slice(&9999_u32.to_le_bytes());
        record[0x24..0x28].copy_from_slice(&offset.to_le_bytes());
        record[0x28..0x2C].copy_from_slice(&compressed.to_le_bytes());
        record[0x30..0x34].copy_from_slice(&7_u32.to_le_bytes());
        table.extend_from_slice(&record);
        table.extend_from_slice(name);
        table.push(0);
        table.extend_from_slice(extra);
    }

    fn build_table() -> Vec<u8> {
        let mut table = vec![0_u8; TABLE_HEADER_LEN];
        table.extend_from_slice(b"Uninstal.exe\0");
        table.extend_from_slice(b"Counter-Strike 1.6\0");
        table.extend_from_slice(b"Uninstall Counter-Strike 1.6.lnk\0");
        push_entry(&mut table, b"a.txt", 0, 64, b"");
        push_entry(&mut table, br"cstrike\b.bin", 64, 128, b"shortcut-name\0");
        push_entry(&mut table, br"cstrike\empty.cfg", 192, 32, b"");
        table
    }

    #[test]
    fn parses_records_and_names() {
        let table = build_table();
        let entries = parse(&table, TOTAL_DATA);

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[0].offset, 0);
        assert_eq!(entries[0].compressed, 64);
        assert_eq!(entries[0].checksum, 0xDEAD_BEEF);
        assert_eq!(entries[0].blob_id, 7);
        assert_eq!(entries[1].name, r"cstrike\b.bin");
        assert_eq!(entries[1].offset, 64);
        assert_eq!(entries[2].name, r"cstrike\empty.cfg");
    }

    #[test]
    fn rejects_out_of_range_blob() {
        let mut table = vec![0_u8; TABLE_HEADER_LEN];
        push_entry(&mut table, b"bad.bin", 0, u32::MAX, b"");
        assert_eq!(parse(&table, TOTAL_DATA).len(), 0);
    }

    #[test]
    fn stops_at_dangling_name() {
        let mut table = build_table();
        table.extend_from_slice(b"last-name-without-struct");
        assert_eq!(parse(&table, TOTAL_DATA).len(), 3);
    }

    #[test]
    fn decodes_cp1251_names() {
        let mut table = vec![0_u8; TABLE_HEADER_LEN];
        push_entry(&mut table, b"\xcf\xf0\xe8\xe2\xe5\xf2.txt", 0, 16, b"");
        let entries = parse(&table, TOTAL_DATA);
        assert_eq!(entries[0].name, "Привет.txt");
    }
}

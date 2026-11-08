#![no_main]

use std::io::{self, Cursor, Write};

use libfuzzer_sys::fuzz_target;
use uu_archive_clickteam_install_creator_v2::{Entry, FileTimes, Installer};

const STRUCT_LEN: usize = 78;
const TABLE_HEADER_LEN: usize = 0x32;
const OUTPUT_BUDGET: u64 = 4 * 1024 * 1024;

struct Budget {
    left: u64,
}

impl Write for Budget {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = u64::try_from(buf.len()).map_err(|_| io::Error::other("buffer too large"))?;
        if len > self.left {
            return Err(io::Error::other("output budget exhausted"));
        }
        self.left -= len;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn le32(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// Minimal PE header whose single section ends at `0x400`.
fn pe_stub() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x400];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&le32(0x80));
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0_u16.to_le_bytes());

    let section = 0x98;
    bytes[section + 16..section + 20].copy_from_slice(&le32(0x200));
    bytes[section + 20..section + 24].copy_from_slice(&le32(0x200));
    bytes
}

/// Appends a metadata block with a raw (stored) payload.
fn push_block(out: &mut Vec<u8>, id: Option<u32>, payload: &[u8]) {
    let packed = u32::try_from(payload.len().saturating_add(5)).unwrap_or(u32::MAX);
    let unpacked = u32::try_from(payload.len()).unwrap_or(u32::MAX);

    if let Some(id) = id {
        out.extend_from_slice(&le32(id));
    }
    out.extend_from_slice(&le32(packed));
    out.extend_from_slice(&le32(unpacked));
    out.push(0);
    out.extend_from_slice(payload);
}

/// Builds an archive whose only blob is `blob`, referenced by one entry.
fn build_archive(blob: &[u8], size: u32) -> Option<Vec<u8>> {
    let compressed = u32::try_from(blob.len()).ok()?;
    if compressed == 0 {
        return None;
    }

    let mut table = vec![0_u8; TABLE_HEADER_LEN];
    let mut record = [0_u8; STRUCT_LEN];
    record[0x10..0x14].copy_from_slice(&le32(0x00CF_E408));
    record[0x20..0x24].copy_from_slice(&le32(size));
    // offset stays 0, compressed covers the whole blob
    record[0x28..0x2C].copy_from_slice(&le32(compressed));
    record[0x30..0x34].copy_from_slice(&le32(1));
    table.extend_from_slice(&record);
    table.extend_from_slice(b"blob.bin\0");

    let mut exe = pe_stub();
    exe.extend_from_slice(&le32(0x5467_7777));
    exe.extend_from_slice(&le32(0));
    exe.extend_from_slice(&1_u16.to_le_bytes());
    // First block has no id in front of its header.
    push_block(&mut exe, None, &[]);
    push_block(&mut exe, Some(1), &table);

    exe.extend_from_slice(&le32(0x0000_7F7F));
    exe.extend_from_slice(&le32(compressed));
    exe.extend_from_slice(&le32(compressed));
    exe.extend_from_slice(blob);
    Some(exe)
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let size = data
        .get(..4)
        .and_then(|head| <[u8; 4]>::try_from(head).ok())
        .map_or_else(
            || u32::try_from(data.len()).unwrap_or(u32::MAX),
            u32::from_le_bytes,
        );

    let Some(archive) = build_archive(data, size) else {
        return;
    };
    let Ok(mut installer) = Installer::new(Cursor::new(archive)) else {
        return;
    };

    let entry = installer
        .entries()
        .first()
        .cloned()
        .unwrap_or_else(|| Entry {
            name: "blob.bin".to_owned(),
            size,
            offset: 0,
            compressed: u32::try_from(data.len()).unwrap_or(u32::MAX),
            checksum: 0,
            attributes: 0,
            blob_id: 1,
            times: FileTimes::default(),
        });

    let mut sink = Budget {
        left: OUTPUT_BUDGET,
    };
    let _ = installer.copy_entry(&entry, &mut sink);

    let mut sink = Budget {
        left: OUTPUT_BUDGET,
    };
    let _ = installer.copy_blob(0, u64::from(entry.compressed), &mut sink);
    let _ = installer.entry_bytes(&entry);
});

#![no_main]

use std::io::{self, Cursor, Write};

use libfuzzer_sys::fuzz_target;
use uu_archive_clickteam_install_creator_v2::Installer;

/// Bytes a single entry may produce before the sink refuses more output.
const ENTRY_BUDGET: u64 = 256 * 1024;
/// Bytes all calls together may produce, to keep one input from running for
/// minutes or exhausting memory through a decompression bomb.
const TOTAL_BUDGET: u64 = 4 * 1024 * 1024;
/// Metadata blocks may be large, but a fuzz input only needs a few.
const MAX_BLOCKS: usize = 8;
/// Entries are processed in archive order; enough to cover every path.
const MAX_ENTRIES: usize = 64;

struct Budget {
    entry: u64,
    total: u64,
}

impl Budget {
    const fn new() -> Self {
        Self {
            entry: ENTRY_BUDGET,
            total: TOTAL_BUDGET,
        }
    }
}

impl Write for Budget {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = u64::try_from(buf.len()).map_err(|_| io::Error::other("buffer too large"))?;
        if len > self.entry || len > self.total {
            return Err(io::Error::other("output budget exhausted"));
        }
        self.entry -= len;
        self.total -= len;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(mut installer) = Installer::new(Cursor::new(data)) else {
        return;
    };

    let info = installer.info();
    std::hint::black_box((
        info.file_size,
        info.overlay_offset,
        info.marker_offset,
        info.data_offset,
        info.data_size,
    ));

    for index in 0..installer.block_count().min(MAX_BLOCKS) {
        if let Some(block) = installer.block(index) {
            std::hint::black_box(block.len());
        }
        let mut sink = Budget::new();
        let _ = installer.copy_block(index, &mut sink);
    }

    let entries = installer
        .entries()
        .iter()
        .take(MAX_ENTRIES)
        .cloned()
        .collect::<Vec<_>>();

    for entry in &entries {
        std::hint::black_box(entry.times.newest_stamp());
        std::hint::black_box(entry.relative_path());
        let mut sink = Budget::new();
        let _ = installer.copy_entry(entry, &mut sink);
    }

    if let Some(first) = entries.first() {
        let mut sink = Budget::new();
        let _ = installer.copy_blob(
            u64::from(first.offset),
            u64::from(first.compressed),
            &mut sink,
        );
        let _ = installer.blob_method_byte(u64::from(first.offset));
    }
});

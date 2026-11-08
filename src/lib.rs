//! Reader and unpacker for the archive format used by
//! **Clickteam Install Creator 2** self-extracting installers.
//!
//! The installer is a regular PE executable with an overlay appended after
//! the last section.  The overlay is a small archive: a few metadata blocks
//! (installer resources and the file table) followed by one compressed data
//! stream that holds every packed file.
//!
//! ```text
//! +0x00  u32   magic             "wwgT" (0x5467_7777)
//! +0x04  u32   unknown           (checksum or build id)
//! +0x08  u16   version           1
//!
//!        block   (fonts / bitmaps, no id)
//!        block   (id + header + payload) ...
//!
//! u32 0x0000_7F7F                end of the metadata section
//! u32 uncompressed total         (repeated)
//! u32 uncompressed total
//! u8  method                     first byte of the data stream
//! ...                            data stream, runs to end of file
//! ```
//!
//! Every block and every file blob is split into chunks.  A chunk starts with
//! a one-byte method (`0` = stored, `1` = zlib, `2` = bzip2) immediately
//! followed by the compressed payload.  Stored chunks run to the end of the
//! blob, compressed chunks end where their zlib/bzip2 stream ends, which lets
//! several chunks share one blob.
//!
//! The file table itself is the last metadata block.  It starts with a
//! `0x32`-byte header and three NUL-terminated uninstaller strings, then
//! repeats `78-byte struct` followed by the NUL-terminated file name (and
//! optional shortcut metadata for entries that create shortcuts).
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//!
//! use uu_archive_clickteam_install_creator_v2::{ExtractOptions, Installer};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut installer = Installer::open("setup.exe")?;
//!
//! for entry in installer.entries() {
//!     println!("{} ({} bytes)", entry.name, entry.size);
//! }
//!
//! installer.extract(Path::new("out"), &ExtractOptions::default(), |_| {})?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod compress;
mod entry;
mod error;
mod extract;
mod installer;
mod io_ext;
mod pe;
mod table;

pub use entry::{Entry, FileTimes, safe_relative_path};
pub use error::{Error, Result};
pub use extract::{
    ExtractEvent, ExtractOptions, ExtractOutcome, Failure, compile_filter, filter_matches,
};
pub use installer::{ArchiveInfo, END_MARKER, Installer, MAGIC, record_file_name};

use std::io;

/// Result type used by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced while reading or unpacking an installer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// The file does not start with the DOS `MZ` signature.
    #[error("not an MZ executable")]
    NotMz,

    /// The DOS header does not point at a valid PE header.
    #[error("not a PE executable")]
    NotPe,

    /// The input ended in the middle of a structure.
    #[error("unexpected end of file at offset {0:#x}")]
    UnexpectedEof(u64),

    /// The overlay does not start with the expected magic value.
    #[error("bad overlay magic {found:#010x} at offset {offset:#x} (expected 0x5477_7777)")]
    BadMagic {
        /// Value read from the file.
        found: u32,
        /// Where the overlay was expected to start.
        offset: u64,
    },

    /// The archive version is not supported.
    #[error("unsupported archive version {0}")]
    UnsupportedVersion(u16),

    /// A block declares an impossible packed length.
    #[error("block at {offset:#x} has invalid packed length {length}")]
    BadBlockLength {
        /// Offset of the block header.
        offset: u64,
        /// Packed length read from the header.
        length: u32,
    },

    /// A decompressed block does not match its declared size.
    #[error("block at {offset:#x} decompressed to {got} bytes, expected {expected}")]
    BlockSize {
        /// Offset of the block header.
        offset: u64,
        /// Number of bytes produced by the decoder.
        got: u64,
        /// Number of bytes declared in the header.
        expected: u64,
    },

    /// A chunk uses an unknown compression method.
    #[error("unknown compression method {0}")]
    UnknownMethod(u8),

    /// A compressed stream ended before its end marker.
    #[error("truncated compressed stream")]
    TruncatedStream,

    /// The zlib or bzip2 decoder rejected the data.
    #[error("corrupt compressed stream: {0}")]
    CorruptStream(String),

    /// The end marker and the file size disagree about the data stream.
    #[error("inconsistent data stream: marker says {base:#x}, file size says {expected:#x}")]
    InconsistentStream {
        /// Data stream offset derived from the end marker.
        base: u64,
        /// Data stream offset derived from the file size.
        expected: u64,
    },

    /// The data stream does not reach the end of the file.
    #[error("data stream does not end at end of file")]
    StreamNotAtEof,

    /// The file table could not be located or parsed.
    #[error("could not locate the file table")]
    TableNotFound,

    /// The requested metadata block does not exist.
    #[error("block index {0} is out of range")]
    BlockIndex(usize),

    /// A blob points outside the data stream.
    #[error("blob at {offset:#x} with length {length:#x} lies outside the data stream")]
    BlobOutOfRange {
        /// Offset inside the data stream.
        offset: u64,
        /// Length of the blob.
        length: u64,
    },

    /// An extracted entry has an unexpected size.
    #[error("{name}: decompressed to {got} bytes, expected {expected}")]
    EntrySize {
        /// Name of the entry.
        name: String,
        /// Number of bytes produced by the decoder.
        got: u64,
        /// Number of bytes declared in the file table.
        expected: u64,
    },

    /// The glob pattern is invalid.
    #[error("invalid glob pattern: {0}")]
    Glob(#[from] globset::Error),
}

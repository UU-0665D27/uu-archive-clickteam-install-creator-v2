use std::io::{self, BufRead, Read, Write};

use flate2::{Decompress as ZlibDecompress, FlushDecompress, Status as ZlibStatus};

use crate::error::{Error, Result};

/// Size of a single output reservation while inflating in memory.
const OUTPUT_STEP: usize = 256 * 1024;

/// Compression method stored in front of every chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Bytes are stored as-is and run to the end of the blob.
    Raw,
    /// A zlib (deflate) stream.
    Zlib,
    /// A bzip2 stream.
    Bzip2,
}

impl Method {
    pub const fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(Self::Raw),
            1 => Ok(Self::Zlib),
            2 => Ok(Self::Bzip2),
            other => Err(Error::UnknownMethod(other)),
        }
    }
}

/// Decompresses one self-contained stream (a metadata block).
pub fn decompress_stream(data: &[u8], method: Method) -> Result<Vec<u8>> {
    match method {
        Method::Raw => Ok(data.to_vec()),
        Method::Zlib => inflate(data).map(|(output, _consumed)| output),
        Method::Bzip2 => bunzip2(data).map(|(output, _consumed)| output),
    }
}

/// Streams a blob made of one or more chunks into `writer`.
///
/// `reader` must be positioned at the first method byte and limited to the
/// blob, for example with [`Read::take`].  Only one chunk is decoded at a
/// time, so neither the compressed nor the decompressed blob is buffered as a
/// whole.
pub fn copy_region<R, W>(reader: &mut R, writer: &mut W) -> Result<u64>
where
    R: BufRead,
    W: Write,
{
    let mut written = 0_u64;

    loop {
        let mut tag = [0_u8; 1];
        match reader.read_exact(&mut tag) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(written),
            Err(err) => return Err(Error::Io(err)),
        }

        match Method::from_byte(tag[0])? {
            Method::Raw => {
                written = written.saturating_add(copy_bytes(reader, writer)?);
                return Ok(written);
            }
            Method::Zlib => {
                let mut decoder = flate2::bufread::ZlibDecoder::new(&mut *reader);
                written = written.saturating_add(copy_bytes(&mut decoder, writer)?);
                let _ = decoder.into_inner();
            }
            Method::Bzip2 => {
                let mut decoder = bzip2::bufread::BzDecoder::new(&mut *reader);
                written = written.saturating_add(copy_bytes(&mut decoder, writer)?);
                let _ = decoder.into_inner();
            }
        }
    }
}

fn copy_bytes<R, W>(reader: &mut R, writer: &mut W) -> Result<u64>
where
    R: Read,
    W: Write,
{
    io::copy(reader, writer).map_err(|err| {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            Error::TruncatedStream
        } else {
            Error::Io(err)
        }
    })
}

fn inflate(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut decoder = ZlibDecompress::new(true);
    let mut output = Vec::new();
    let mut consumed = 0_usize;

    loop {
        if output.len() == output.capacity() {
            output.reserve(OUTPUT_STEP);
        }

        let rest = data.get(consumed..).ok_or(Error::TruncatedStream)?;
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder
            .decompress_vec(rest, &mut output, FlushDecompress::None)
            .map_err(|err| Error::CorruptStream(err.to_string()))?;
        consumed = usize::try_from(decoder.total_in())
            .map_err(|_| Error::CorruptStream("zlib stream is too large".to_owned()))?;

        match status {
            ZlibStatus::StreamEnd => return Ok((output, consumed)),
            ZlibStatus::Ok | ZlibStatus::BufError => {
                if decoder.total_in() == before_in && decoder.total_out() == before_out {
                    return Err(Error::TruncatedStream);
                }
            }
        }
    }
}

fn bunzip2(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut decoder = bzip2::Decompress::new(false);
    let mut output = Vec::new();
    let mut consumed = 0_usize;

    loop {
        if output.len() == output.capacity() {
            output.reserve(OUTPUT_STEP);
        }

        let rest = data.get(consumed..).ok_or(Error::TruncatedStream)?;
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder
            .decompress_vec(rest, &mut output)
            .map_err(|err| Error::CorruptStream(err.to_string()))?;
        consumed = usize::try_from(decoder.total_in())
            .map_err(|_| Error::CorruptStream("bzip2 stream is too large".to_owned()))?;

        match status {
            bzip2::Status::StreamEnd => return Ok((output, consumed)),
            bzip2::Status::Ok => {
                if decoder.total_in() == before_in && decoder.total_out() == before_out {
                    return Err(Error::TruncatedStream);
                }
            }
            bzip2::Status::MemNeeded => {
                return Err(Error::CorruptStream("out of memory".to_owned()));
            }
            other => {
                return Err(Error::CorruptStream(format!(
                    "unexpected bzip2 status {other:?}"
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn bz2(data: &[u8]) -> Vec<u8> {
        let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn region(data: &[u8]) -> Result<Vec<u8>> {
        let mut input = Cursor::new(data);
        let mut output = Vec::new();
        copy_region(&mut input, &mut output)?;
        Ok(output)
    }

    #[test]
    fn raw_stream_is_copied() {
        let data = b"stored bytes";
        assert_eq!(decompress_stream(data, Method::Raw).unwrap(), data);
    }

    #[test]
    fn zlib_stream_roundtrips() {
        let data = b"hello zlib".repeat(1000);
        assert_eq!(decompress_stream(&zlib(&data), Method::Zlib).unwrap(), data);
    }

    #[test]
    fn bzip2_stream_roundtrips() {
        let data = b"hello bzip2".repeat(1000);
        assert_eq!(decompress_stream(&bz2(&data), Method::Bzip2).unwrap(), data);
    }

    #[test]
    fn region_concatenates_chunks() {
        let mut data = vec![1_u8];
        data.extend_from_slice(&zlib(b"first "));
        data.push(2);
        data.extend_from_slice(&bz2(b"second "));
        data.push(1);
        data.extend_from_slice(&zlib(b"third"));

        assert_eq!(region(&data).unwrap(), b"first second third");
    }

    #[test]
    fn region_stops_at_raw_chunk() {
        let mut data = vec![1_u8];
        data.extend_from_slice(&zlib(b"compressed "));
        data.push(0);
        data.extend_from_slice(b"raw tail");

        assert_eq!(region(&data).unwrap(), b"compressed raw tail");
    }

    #[test]
    fn truncated_region_is_rejected() {
        let mut data = vec![1_u8];
        let compressed = zlib(b"payload that will be cut in half");
        data.extend_from_slice(compressed.get(..compressed.len() / 2).unwrap_or(&[]));

        assert!(matches!(
            region(&data),
            Err(Error::TruncatedStream | Error::CorruptStream(_))
        ));
    }

    #[test]
    fn unknown_method_is_rejected() {
        assert!(matches!(
            region(&[9, 1, 2, 3]),
            Err(Error::UnknownMethod(9))
        ));
    }
}

use std::fs;
use std::io::{Cursor, Write as _};

use uu_archive_clickteam_install_creator_v2::{
    Entry, ExtractOptions, FileTimes, Installer, compile_filter, filter_matches, safe_relative_path,
};

const STRUCT_LEN: usize = 78;

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn bz2(data: &[u8]) -> Vec<u8> {
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn le32(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

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

fn push_block(out: &mut Vec<u8>, id: Option<u32>, payload: &[u8], method: u8) {
    let packed = match method {
        1 => zlib(payload),
        2 => bz2(payload),
        _ => payload.to_vec(),
    };
    let packed_len = u32::try_from(packed.len() + 5).unwrap();
    let unpacked_len = u32::try_from(payload.len()).unwrap();

    if let Some(id) = id {
        out.extend_from_slice(&le32(id));
    }
    out.extend_from_slice(&le32(packed_len));
    out.extend_from_slice(&le32(unpacked_len));
    out.push(method);
    out.extend_from_slice(&packed);
}

fn push_entry(table: &mut Vec<u8>, name: &str, size: u32, offset: u32, compressed: u32) {
    let mut record = [0_u8; STRUCT_LEN];
    record[0x10..0x14].copy_from_slice(&le32(0x00CF_E408));
    record[0x20..0x24].copy_from_slice(&le32(size));
    record[0x24..0x28].copy_from_slice(&le32(offset));
    record[0x28..0x2C].copy_from_slice(&le32(compressed));
    record[0x30..0x34].copy_from_slice(&le32(7));

    table.extend_from_slice(&record);
    table.extend_from_slice(name.as_bytes());
    table.push(0);
}

struct Fixture {
    exe: Vec<u8>,
    stream_len: u64,
}

fn build_fixture() -> Fixture {
    let mut stream = vec![0_u8];
    stream
        .extend_from_slice(b"Uninstal.exe\0Counter-Strike 1.6\0Uninstall Counter-Strike 1.6.lnk\0");

    let readme_offset = u32::try_from(stream.len()).unwrap();
    let compressed = zlib(b"hello world\n");
    stream.push(1);
    stream.extend_from_slice(&compressed);
    let compressed_len = u32::try_from(compressed.len() + 1).unwrap();

    let mut table = vec![0_u8; 0x32];
    table
        .extend_from_slice(b"Uninstal.exe\0Counter-Strike 1.6\0Uninstall Counter-Strike 1.6.lnk\0");
    push_entry(&mut table, "readme.txt", 12, readme_offset, compressed_len);
    push_entry(
        &mut table,
        "docs\\copy.txt",
        12,
        readme_offset,
        compressed_len,
    );
    push_entry(
        &mut table,
        "cstrike\\empty.cfg",
        0,
        readme_offset,
        compressed_len,
    );

    let mut exe = pe_stub();
    exe.extend_from_slice(&0x5467_7777_u32.to_le_bytes());
    exe.extend_from_slice(&le32(0));
    exe.extend_from_slice(&1_u16.to_le_bytes());
    push_block(&mut exe, None, b"font data", 1);
    push_block(&mut exe, Some(1), b"installer resource", 2);
    push_block(&mut exe, Some(2), &table, 1);

    let stream_len = u64::try_from(stream.len()).unwrap();
    let stream_len32 = u32::try_from(stream.len()).unwrap();
    exe.extend_from_slice(&le32(0x0000_7F7F));
    exe.extend_from_slice(&le32(stream_len32));
    exe.extend_from_slice(&le32(stream_len32));
    exe.extend_from_slice(&stream);

    Fixture { exe, stream_len }
}

#[test]
fn opens_archive_and_reports_layout() {
    let fixture = build_fixture();
    let installer = Installer::new(Cursor::new(fixture.exe)).unwrap();
    let info = installer.info();

    assert_eq!(info.overlay_offset, 0x400);
    assert_eq!(info.data_size, fixture.stream_len);
    assert_eq!(info.data_offset + info.data_size, info.file_size);
    assert_eq!(installer.block_count(), 3);
    assert_eq!(installer.entries().len(), 3);
    assert_eq!(installer.block(0).unwrap(), b"font data");
    assert_eq!(installer.block(1).unwrap(), b"installer resource");
    assert_eq!(installer.entries()[1].name, "docs\\copy.txt");
}

#[test]
fn extracts_files_and_empty_entries() {
    let fixture = build_fixture();
    let mut installer = Installer::new(Cursor::new(fixture.exe)).unwrap();
    let directory = tempfile::tempdir().unwrap();

    let outcome = installer
        .extract(directory.path(), &ExtractOptions::default(), |_| {})
        .unwrap();

    assert_eq!(outcome.extracted, 3);
    assert_eq!(outcome.failed, 0);
    assert_eq!(outcome.bytes, 24);
    assert_eq!(
        fs::read(directory.path().join("readme.txt")).unwrap(),
        b"hello world\n"
    );
    assert_eq!(
        fs::read(directory.path().join("docs/copy.txt")).unwrap(),
        b"hello world\n"
    );
    assert_eq!(
        fs::read(directory.path().join("cstrike/empty.cfg")).unwrap(),
        b""
    );
}

#[test]
fn filtered_extraction_only_writes_matches() {
    let fixture = build_fixture();
    let mut installer = Installer::new(Cursor::new(fixture.exe)).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let filter = compile_filter("cstrike/*").unwrap();
    let options = ExtractOptions {
        filter: Some(&filter),
        ..ExtractOptions::default()
    };

    let outcome = installer
        .extract(directory.path(), &options, |_| {})
        .unwrap();

    assert_eq!(outcome.extracted, 1);
    assert!(directory.path().join("cstrike/empty.cfg").exists());
    assert!(!directory.path().join("readme.txt").exists());
}

#[test]
fn streams_entries_through_write() {
    let fixture = build_fixture();
    let mut installer = Installer::new(Cursor::new(fixture.exe)).unwrap();
    let entry = installer.entries()[0].clone();

    assert!(matches!(
        installer.blob_method_byte(u64::from(entry.offset)),
        Ok(Some(1))
    ));

    let mut output = Vec::new();
    let written = installer.copy_entry(&entry, &mut output).unwrap();
    assert_eq!(written, 12);
    assert_eq!(output, b"hello world\n");
}

#[test]
fn dangerous_names_stay_relative() {
    assert_eq!(
        safe_relative_path("..\\..\\windows\\system32\\evil.dll"),
        std::path::PathBuf::from("__dotdot__/__dotdot__/windows/system32/evil.dll")
    );
}

fn bare_entry(name: &str) -> Entry {
    Entry {
        name: name.to_owned(),
        size: 1,
        offset: 0,
        compressed: 1,
        checksum: 0,
        attributes: 0,
        blob_id: 0,
        times: FileTimes::default(),
    }
}

#[test]
fn star_stays_in_one_directory_and_double_star_is_recursive() {
    let entry = bare_entry("cstrike/maps/de_dust2.bsp");

    let direct = compile_filter("cstrike/maps/*").unwrap();
    assert!(filter_matches(&direct, &entry));

    let shallow = compile_filter("cstrike/*").unwrap();
    assert!(!filter_matches(&shallow, &entry));

    let recursive = compile_filter("cstrike/**").unwrap();
    assert!(filter_matches(&recursive, &entry));

    let recursive_extension = compile_filter("cstrike/**/*.bsp").unwrap();
    assert!(filter_matches(&recursive_extension, &entry));
}

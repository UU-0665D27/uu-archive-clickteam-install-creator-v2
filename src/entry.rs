use std::path::PathBuf;

/// One entry of the installer's file table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// File name as stored in the archive (`\` is used as a separator).
    pub name: String,
    /// Uncompressed size in bytes.
    pub size: u32,
    /// Offset of the blob inside the data stream.
    pub offset: u32,
    /// Compressed size of the blob in the data stream.
    pub compressed: u32,
    /// Installer-specific checksum (not CRC-32).
    pub checksum: u32,
    /// Installer-specific attribute bit field.
    pub attributes: u32,
    /// Identifier shared by deduplicated files.
    pub blob_id: u32,
    /// Timestamps stored for the file.
    pub times: FileTimes,
}

impl Entry {
    /// Relative, sanitized output path for this entry.
    #[must_use]
    pub fn relative_path(&self) -> PathBuf {
        safe_relative_path(&self.name)
    }

    /// Returns `true` when the entry stores no data.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }
}

/// The three `FILETIME` values stored for every entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileTimes {
    /// Creation time (`+0x36`).
    pub created: u64,
    /// Last write time (`+0x3e`).
    pub modified: u64,
    /// Last access time (`+0x46`).
    pub accessed: u64,
}

impl FileTimes {
    /// Newest plausible timestamp converted to Unix seconds.
    ///
    /// Values before 1980 or after 2100 are treated as bogus and ignored.
    #[must_use]
    pub fn newest_unix(&self) -> Option<i64> {
        self.newest_stamp().map(|(seconds, _nanos)| seconds)
    }

    /// Newest plausible timestamp as Unix seconds and nanoseconds.
    ///
    /// `FILETIME` has 100 ns resolution, so the nanosecond part is always a
    /// multiple of 100.
    #[must_use]
    pub fn newest_stamp(&self) -> Option<(i64, u32)> {
        [self.created, self.modified, self.accessed]
            .into_iter()
            .filter_map(filetime_to_stamp)
            .max_by_key(|&(seconds, nanos)| (seconds, nanos))
    }
}

/// Converts a Windows `FILETIME` into Unix seconds and nanoseconds.
fn filetime_to_stamp(filetime: u64) -> Option<(i64, u32)> {
    /// Difference between 1601-01-01 and 1970-01-01 in 100 ns ticks.
    const EPOCH_DIFFERENCE: u64 = 116_444_736_000_000_000;
    /// 1980-01-01.
    const MIN_TIMESTAMP: i64 = 315_532_800;
    /// 2100-01-01.
    const MAX_TIMESTAMP: i64 = 4_102_444_800;

    if filetime < EPOCH_DIFFERENCE {
        return None;
    }
    let ticks = filetime - EPOCH_DIFFERENCE;
    let seconds = i64::try_from(ticks / 10_000_000).ok()?;
    let nanos = u32::try_from((ticks % 10_000_000) * 100).ok()?;
    (MIN_TIMESTAMP..=MAX_TIMESTAMP)
        .contains(&seconds)
        .then_some((seconds, nanos))
}

/// Turns an archive name into a safe relative path.
///
/// Both `/` and `\` are treated as separators, empty components and `.` are
/// dropped, `..` is replaced by `__dotdot__`, and characters that are illegal
/// on Windows are replaced by `_`.  The result is always relative and never
/// contains a parent-directory component.
#[must_use]
pub fn safe_relative_path(name: &str) -> PathBuf {
    let mut path = PathBuf::new();

    for part in name.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => path.push("__dotdot__"),
            other => path.push(sanitize_component(other)),
        }
    }

    if path.as_os_str().is_empty() {
        path.push("_unnamed_");
    }
    path
}

fn sanitize_component(part: &str) -> String {
    part.chars()
        .map(|ch| {
            if ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
                '_'
            } else {
                ch
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separators_are_normalized() {
        assert_eq!(
            safe_relative_path(r"cstrike\maps\de_dust2.bsp"),
            PathBuf::from("cstrike/maps/de_dust2.bsp")
        );
        assert_eq!(
            safe_relative_path("cstrike/maps/de_dust2.bsp"),
            PathBuf::from("cstrike/maps/de_dust2.bsp")
        );
    }

    #[test]
    fn parent_components_are_neutralized() {
        let path = safe_relative_path("../../etc/passwd");
        assert_eq!(path, PathBuf::from("__dotdot__/__dotdot__/etc/passwd"));
        assert!(!path.is_absolute());
    }

    #[test]
    fn empty_name_gets_a_placeholder() {
        assert_eq!(safe_relative_path(""), PathBuf::from("_unnamed_"));
        assert_eq!(safe_relative_path("///"), PathBuf::from("_unnamed_"));
    }

    #[test]
    fn illegal_characters_are_replaced() {
        assert_eq!(
            safe_relative_path("C:/dir/file?.txt"),
            PathBuf::from("C_/dir/file_.txt")
        );
    }

    #[test]
    fn filetime_conversion_works() {
        // 2000-01-01T00:00:00Z
        let filetime = 125_911_584_000_000_000;
        assert_eq!(filetime_to_stamp(filetime), Some((946_684_800, 0)));
        assert_eq!(filetime_to_stamp(0), None);
        assert_eq!(
            FileTimes {
                created: 0,
                modified: filetime,
                accessed: 0,
            }
            .newest_unix(),
            Some(946_684_800)
        );
    }
}

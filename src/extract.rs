use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use filetime::FileTime;
use globset::{GlobBuilder, GlobMatcher};

use crate::entry::{Entry, FileTimes};
use crate::error::{Error, Result};
use crate::installer::Installer;

/// Compiles a glob pattern for [`ExtractOptions::filter`].
///
/// `*` matches within a single path component, while `**` also crosses
/// directory separators: `cstrike/maps/*` selects files directly inside
/// `cstrike/maps`, `cstrike/maps/**` selects the whole subtree.
///
/// # Errors
///
/// Returns an error when the pattern is not a valid glob.
pub fn compile_filter(pattern: &str) -> Result<GlobMatcher> {
    Ok(GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()?
        .compile_matcher())
}

/// Checks whether an entry matches a compiled filter.
///
/// Both the sanitized relative path and the raw archive name are tried, so
/// patterns written with `/` or `\` separators both work.
#[must_use]
pub fn filter_matches(filter: &GlobMatcher, entry: &Entry) -> bool {
    filter.is_match(entry.relative_path()) || filter.is_match(entry.name.replace('\\', "/"))
}

/// Options controlling [`Installer::extract`].
#[derive(Debug, Clone)]
pub struct ExtractOptions<'a> {
    /// Extract only entries whose path matches this filter.
    pub filter: Option<&'a GlobMatcher>,
    /// Restore modification and access times from the file table.
    pub restore_times: bool,
    /// Copy deduplicated entries instead of decompressing the same blob again.
    pub deduplicate: bool,
}

impl Default for ExtractOptions<'_> {
    fn default() -> Self {
        Self {
            filter: None,
            restore_times: true,
            deduplicate: true,
        }
    }
}

/// Result of an extraction run.
#[derive(Debug, Default)]
pub struct ExtractOutcome {
    /// Number of entries written successfully.
    pub extracted: usize,
    /// Number of entries that failed.
    pub failed: usize,
    /// Total number of bytes written.
    pub bytes: u64,
    /// Details about the failed entries.
    pub failures: Vec<Failure>,
}

/// One entry that could not be written.
#[derive(Debug)]
pub struct Failure {
    /// Destination path that was being written.
    pub path: PathBuf,
    /// Underlying error.
    pub error: Error,
}

/// Progress callback delivered to [`Installer::extract`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ExtractEvent<'a> {
    /// An entry was written successfully.
    Entry {
        /// 1-based position among the selected entries.
        index: usize,
        /// Number of selected entries.
        total: usize,
        /// Destination path.
        path: &'a Path,
    },
    /// An entry could not be written.
    Failed {
        /// 1-based position among the selected entries.
        index: usize,
        /// Number of selected entries.
        total: usize,
        /// Destination path.
        path: &'a Path,
        /// Underlying error.
        error: &'a Error,
    },
}

impl<R: Read + Seek> Installer<R> {
    /// Extracts entries into `destination`.
    ///
    /// Individual failures are reported through `observer` and collected in
    /// [`ExtractOutcome`]; the run itself only returns an error when the
    /// destination cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error when `destination` cannot be created.
    pub fn extract<F>(
        &mut self,
        destination: &Path,
        options: &ExtractOptions<'_>,
        mut observer: F,
    ) -> Result<ExtractOutcome>
    where
        F: for<'a> FnMut(ExtractEvent<'a>),
    {
        fs::create_dir_all(destination)?;

        let selected: Vec<usize> = self
            .entries()
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                options
                    .filter
                    .is_none_or(|filter| filter_matches(filter, entry))
            })
            .map(|(index, _)| index)
            .collect();

        let total = selected.len();
        let mut outcome = ExtractOutcome::default();
        let mut used = HashSet::new();
        let mut cache: HashMap<(u32, u32), PathBuf> = HashMap::new();

        for (position, index) in selected.into_iter().enumerate() {
            let number = position.saturating_add(1);
            let Some(entry) = self.entries().get(index).cloned() else {
                continue;
            };
            let path = unique_path(destination.join(entry.relative_path()), &used);
            used.insert(path.clone());

            match write_entry(self, &entry, &path, options, &mut cache) {
                Ok(written) => {
                    outcome.extracted = outcome.extracted.saturating_add(1);
                    outcome.bytes = outcome.bytes.saturating_add(written);
                    observer(ExtractEvent::Entry {
                        index: number,
                        total,
                        path: &path,
                    });
                }
                Err(error) => {
                    outcome.failed = outcome.failed.saturating_add(1);
                    observer(ExtractEvent::Failed {
                        index: number,
                        total,
                        path: &path,
                        error: &error,
                    });
                    outcome.failures.push(Failure { path, error });
                }
            }
        }

        Ok(outcome)
    }

    /// Extracts entries without a progress callback.
    ///
    /// # Errors
    ///
    /// Returns an error when `destination` cannot be created.
    pub fn extract_silent(
        &mut self,
        destination: &Path,
        options: &ExtractOptions<'_>,
    ) -> Result<ExtractOutcome> {
        self.extract(destination, options, |_| {})
    }
}

fn write_entry<R: Read + Seek>(
    installer: &mut Installer<R>,
    entry: &Entry,
    path: &Path,
    options: &ExtractOptions<'_>,
    cache: &mut HashMap<(u32, u32), PathBuf>,
) -> Result<u64> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let key = (entry.offset, entry.compressed);
    let written = if entry.is_empty() {
        // Empty entries may share a blob id with a real file; never deduplicate them.
        write_file(installer, entry, path)?
    } else if options.deduplicate {
        if let Some(source) = cache.get(&key) {
            fs::copy(source, path)?;
            u64::from(entry.size)
        } else {
            let written = write_file(installer, entry, path)?;
            cache.insert(key, path.to_path_buf());
            written
        }
    } else {
        write_file(installer, entry, path)?
    };

    if options.restore_times {
        apply_times(path, &entry.times);
    }

    Ok(written)
}

fn write_file<R: Read + Seek>(
    installer: &mut Installer<R>,
    entry: &Entry,
    path: &Path,
) -> Result<u64> {
    let mut file = fs::File::create(path)?;
    match installer.copy_entry(entry, &mut file) {
        Ok(written) => Ok(written),
        Err(error) => {
            drop(file);
            let _ = fs::remove_file(path);
            Err(error)
        }
    }
}

fn apply_times(path: &Path, times: &FileTimes) {
    let Some((seconds, nanos)) = times.newest_stamp() else {
        return;
    };
    let stamp = FileTime::from_unix_time(seconds, nanos);
    let _ = filetime::set_file_mtime(path, stamp);
    let _ = filetime::set_file_atime(path, stamp);
}

fn unique_path(path: PathBuf, used: &HashSet<PathBuf>) -> PathBuf {
    if !used.contains(&path) {
        return path;
    }

    let parent = path.parent().map_or_else(PathBuf::new, Path::to_path_buf);
    let stem = path.file_stem().map_or_else(
        || "file".to_owned(),
        |stem| stem.to_string_lossy().into_owned(),
    );
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().into_owned());

    let mut counter = 1_u32;
    loop {
        let name = extension.as_ref().map_or_else(
            || format!("{stem}_{counter}"),
            |extension| format!("{stem}_{counter}.{extension}"),
        );
        let candidate = parent.join(name);
        if !used.contains(&candidate) {
            return candidate;
        }
        counter = counter.saturating_add(1);
    }
}

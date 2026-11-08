use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::Parser;

use uu_archive_clickteam_install_creator_v2::{
    Error, ExtractEvent, ExtractOptions, Installer, compile_filter, filter_matches,
    record_file_name,
};

/// Unpack Clickteam Install Creator 2 self-extracting installers.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Installer executable to unpack.
    #[arg(value_name = "INSTALLER")]
    input: PathBuf,

    /// Directory for extracted files.
    #[arg(short, long, value_name = "DIR", default_value = "unpacked")]
    output: PathBuf,

    /// Extract only paths matching this glob (for example `cstrike/maps/*`).
    #[arg(long, value_name = "GLOB")]
    filter: Option<String>,

    #[command(flatten)]
    actions: Actions,

    #[command(flatten)]
    behaviour: Behaviour,
}

/// Switches that change what the program does.
#[derive(Debug, clap::Args)]
struct Actions {
    /// List the archive contents instead of extracting.
    #[arg(long)]
    list: bool,

    /// Also dump the installer's internal blocks.
    #[arg(long)]
    resources: bool,
}

/// Switches that only affect extraction details.
#[derive(Debug, clap::Args)]
struct Behaviour {
    /// Do not restore modification times.
    #[arg(long)]
    no_times: bool,

    /// Do not print every extracted file.
    #[arg(long)]
    quiet: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<ExitCode, Error> {
    let started = Instant::now();
    let mut installer = Installer::open(&cli.input)?;
    let info = *installer.info();
    let entries = installer.entries();

    let mut unique_sizes: HashMap<(u32, u32), u32> = HashMap::new();
    for entry in entries {
        unique_sizes
            .entry((entry.offset, entry.compressed))
            .or_insert(entry.size);
    }
    let unique_bytes: u64 = unique_sizes.values().map(|&size| u64::from(size)).sum();
    let total_bytes: u64 = entries.iter().map(|entry| u64::from(entry.size)).sum();

    println!("archive:        {}", cli.input.display());
    println!("file size:      {}", human(info.file_size));
    println!("overlay:        {:#x}", info.overlay_offset);
    println!(
        "data stream:    {:#x}..{:#x} ({})",
        info.data_offset,
        info.data_offset.saturating_add(info.data_size),
        human(info.data_size)
    );
    println!("blocks:         {}", info.block_count);
    println!(
        "entries:        {} ({} unique blobs)",
        entries.len(),
        unique_sizes.len()
    );
    println!(
        "uncompressed:   {} (unique), {} (with duplicates)",
        human(unique_bytes),
        human(total_bytes)
    );

    let filter = cli.filter.as_deref().map(compile_filter).transpose()?;

    if cli.actions.list {
        list(&mut installer, filter.as_ref())?;
        return Ok(ExitCode::SUCCESS);
    }

    if cli.actions.resources {
        let directory = cli.output.join("_installer");
        dump_resources(&mut installer, &directory)?;
        println!("resources:      {}", directory.display());
    }

    let options = ExtractOptions {
        filter: filter.as_ref(),
        restore_times: !cli.behaviour.no_times,
        deduplicate: true,
    };
    let verbose = !cli.behaviour.quiet;
    let outcome = installer.extract(&cli.output, &options, |event| match event {
        ExtractEvent::Entry { index, total, path } => {
            if verbose && (index == 1 || index % 100 == 0 || index == total) {
                println!("[{index}/{total}] {}", path.display());
            }
        }
        ExtractEvent::Failed {
            index,
            total,
            path,
            error,
        } => {
            eprintln!("[{index}/{total}] ERROR {}: {error}", path.display());
        }
        _ => {}
    })?;

    if !outcome.failures.is_empty() {
        eprintln!("\n{} file(s) failed:", outcome.failed);
        for failure in outcome.failures.iter().take(20) {
            eprintln!("  {}: {}", failure.path.display(), failure.error);
        }
    }

    println!(
        "\nextracted {} file(s), {} error(s), {} in {:.1}s",
        outcome.extracted,
        outcome.failed,
        human(outcome.bytes),
        started.elapsed().as_secs_f64()
    );
    println!("output:         {}", absolute(&cli.output).display());

    Ok(if outcome.failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn list<R: Read + Seek>(
    installer: &mut Installer<R>,
    filter: Option<&globset::GlobMatcher>,
) -> Result<(), Error> {
    let entries = installer.entries().to_vec();

    for entry in &entries {
        if filter.is_some_and(|filter| !filter_matches(filter, entry)) {
            continue;
        }

        let method = if entry.size == 0 {
            "-".to_owned()
        } else {
            installer
                .blob_method_byte(u64::from(entry.offset))?
                .map_or_else(|| "?".to_owned(), |byte| byte.to_string())
        };
        println!(
            "{method}\t{:>10}\t{:>10}\t{:>10}\t{}",
            entry.size,
            entry.compressed,
            entry.offset,
            entry.relative_path().display()
        );
    }
    Ok(())
}

fn dump_resources<R: Read + Seek>(
    installer: &mut Installer<R>,
    directory: &Path,
) -> Result<(), Error> {
    fs::create_dir_all(directory)?;

    let count = installer.block_count();
    for index in 0..count {
        let path = directory.join(record_file_name(index, count));
        let mut file = fs::File::create(path)?;
        installer.copy_block(index, &mut file)?;
    }

    let first = installer
        .entries()
        .iter()
        .map(|entry| u64::from(entry.offset))
        .min()
        .unwrap_or(0);
    if first > 0 {
        let mut file = fs::File::create(directory.join("uninstaller_strings.bin"))?;
        installer.copy_blob(0, first, &mut file)?;
    }

    Ok(())
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];

    if bytes < 1024 {
        return format!("{bytes} B");
    }

    let mut divisor = 1024_u64;
    let mut unit = 1_usize;
    while unit.saturating_add(1) < UNITS.len() && bytes / divisor >= 1024 {
        let Some(next) = divisor.checked_mul(1024) else {
            break;
        };
        divisor = next;
        unit = unit.saturating_add(1);
    }

    let whole = bytes / divisor;
    let tenths = (bytes % divisor).saturating_mul(10) / divisor;
    UNITS.get(unit).map_or_else(
        || format!("{bytes} B"),
        |name| format!("{whole}.{tenths} {name}"),
    )
}

#[cfg(test)]
mod tests {
    use super::human;

    #[test]
    fn formats_sizes() {
        assert_eq!(human(0), "0 B");
        assert_eq!(human(1023), "1023 B");
        assert_eq!(human(1024), "1.0 KiB");
        assert_eq!(human(1536), "1.5 KiB");
        assert_eq!(human(1024 * 1024), "1.0 MiB");
        assert_eq!(human(392_645_792), "374.4 MiB");
    }
}

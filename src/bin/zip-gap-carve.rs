use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use indicatif::{ProgressBar, ProgressStyle};
use zip_carver::zip_recovery::{self as recovery, CarveOptions};

struct Args {
    image: PathBuf,
    headers: PathBuf,
    map: PathBuf,
    output: PathBuf,
    filtered: Option<PathBuf>,
    from: u32,
    to: u32,
    cluster_size: u64,
    partition: u64,
    file_size: Option<u64>,
    max_stream: u64,
    max_trials: u64,
    assume_contiguous: bool,
}

fn number(value: &std::ffi::OsStr) -> Result<u64, String> {
    let s = value.to_str().ok_or("invalid number")?;
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse()
    }
    .map_err(|_| format!("invalid number: {s}"))
}

fn args() -> Result<Option<Args>, Box<dyn std::error::Error>> {
    let mut values = env::args_os().skip(1);
    let mut positional = Vec::new();
    let (mut from, mut to, mut filtered, mut file_size) = (None, None, None, None);
    let (mut cluster_size, mut partition, mut max_stream, mut max_trials) =
        (4096, 0, 256 * 1024 * 1024, 4096);
    let mut assume_contiguous = false;
    while let Some(value) = values.next() {
        match value.to_str() {
            Some("--help" | "-h") => return Ok(None),
            Some("--assume-contiguous") => assume_contiguous = true,
            Some("--filtered-output") => {
                filtered = Some(PathBuf::from(
                    values.next().ok_or("missing filtered output path")?,
                ))
            }
            Some("--from" | "--to") => {
                let date = values.next().ok_or("missing datetime")?;
                let date = recovery::dos_datetime(date.to_str().ok_or("invalid datetime")?)?;
                if value == "--from" {
                    from = Some(date);
                } else {
                    to = Some(date);
                }
            }
            Some(
                "--cluster-size" | "--partition-offset" | "--file-size" | "--max-stream-bytes"
                | "--max-trials",
            ) => {
                let n = number(&values.next().ok_or("missing numeric value")?)?;
                match value.to_str().unwrap() {
                    "--cluster-size" => cluster_size = n,
                    "--partition-offset" => partition = n,
                    "--file-size" => file_size = Some(n),
                    "--max-stream-bytes" => max_stream = n,
                    _ => max_trials = n,
                }
            }
            Some("--") => {
                positional.extend(values);
                break;
            }
            Some(s) if s.starts_with('-') => return Err(format!("unknown option: {s}").into()),
            _ => positional.push(value),
        }
    }
    if positional.len() != 4 {
        return Err("usage: zip-gap-carve --from DATETIME --to DATETIME [OPTIONS] DISK_IMAGE HEADERS.txt INPUT_MAP.txt OUTPUT_MAP.txt".into());
    }
    if !(512..=2 * 1024 * 1024).contains(&cluster_size) || !cluster_size.is_power_of_two() {
        return Err("cluster size must be a power of two from 512 to 2097152".into());
    }
    if max_stream == 0 || max_trials == 0 {
        return Err("resource limits must be positive".into());
    }
    let (from, to) = (
        from.ok_or("--from is required")?,
        to.ok_or("--to is required")?,
    );
    if from > to {
        return Err("--from must not be later than --to".into());
    }
    Ok(Some(Args {
        image: positional[0].clone().into(),
        headers: positional[1].clone().into(),
        map: positional[2].clone().into(),
        output: positional[3].clone().into(),
        filtered,
        from,
        to,
        cluster_size,
        partition,
        file_size,
        max_stream,
        max_trials,
        assume_contiguous,
    }))
}

fn help() {
    println!("zip-gap-carve --from DATETIME --to DATETIME [OPTIONS] DISK_IMAGE HEADERS.txt INPUT_MAP.txt OUTPUT_MAP.txt

Fill unknown VCNs using ZIP headers from zip-header-scan.exe and raw DEFLATE/CRC checks.
HEADERS.txt is the existing scanner output, including its checkpoint first line.
Maps use the ntfs-file-map/prototype format: hex VCN, tab, optional hex LCN.

  --from DATETIME          Inclusive DOS-local timestamp, YYYY-MM-DDTHH:MM:SS
  --to DATETIME            Inclusive end; seconds are rounded down to even seconds
  --filtered-output PATH  Also save filtered FILE/CDFH and matching DATA headers
  --cluster-size N        NTFS bytes per cluster [4096]
  --partition-offset N    Volume start in image, in bytes [0]
  --file-size N           Exact ZIP length [map cluster count * cluster size]
  --max-stream-bytes N    Maximum compressed bytes buffered per stream [268435456]
  --max-trials N          Maximum split candidates per gap [4096]
  --assume-contiguous     Allow prototype's unverified physically continuous fill

Scanner offsets must be absolute bytes in DISK_IMAGE; map LCNs are volume-relative.
Numbers accept decimal or 0x-prefixed hex. ZIP local extras and CDFH/EOCD comments
are accounted for; no next-header search is performed inside comment fields.
Known mappings are preserved. Unsupported, ambiguous and unvalidated gaps remain
blank. ZIP64, encrypted and multi-disk entries are skipped; methods 0 and 8 work.
Only a single unknown gap entirely inside one stream is tested, using forward/
backward contiguous candidates. Leading/trailing gaps need header anchors.
Outputs must be new paths. Ctrl+C during carving saves the current map (exit 130).");
}

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let Some(args) = args()? else {
        help();
        return Ok(false);
    };
    if args.output.exists() || args.filtered.as_ref().is_some_and(|p| p.exists()) {
        return Err("output exists; choose new output paths".into());
    }
    if args.filtered.as_ref() == Some(&args.output) {
        return Err("map and filtered outputs must differ".into());
    }
    let mut image = File::open(&args.image)?;
    let image_size = image.metadata()?.len();
    if args.partition > image_size {
        return Err("partition offset exceeds image size".into());
    }
    let mut scanner = File::open(&args.headers)?;
    let mut map = recovery::read_map(BufReader::new(File::open(&args.map)?))?;
    let capacity = (map.len() as u64)
        .checked_mul(args.cluster_size)
        .ok_or("map size overflow")?;
    let file_size = args.file_size.unwrap_or(capacity);
    if file_size == 0 || file_size.div_ceil(args.cluster_size) != map.len() as u64 {
        return Err("--file-size must agree with the input map's cluster count".into());
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancel);
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))?;
    let progress = ProgressBar::new(scanner.metadata()?.len().saturating_mul(2));
    progress.set_style(ProgressStyle::with_template(
        "Filtering ZIP headers {bar:30} {bytes}/{total_bytes} {eta}",
    )?);
    let filtered = recovery::filter_headers(&mut scanner, args.from, args.to, &cancel, |n| {
        progress.set_position(n)
    });
    progress.finish_and_clear();
    let filtered = match filtered {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::Interrupted => {
            eprintln!("Interrupted during filtering; no output written");
            return Ok(true);
        }
        Err(e) => return Err(e.into()),
    };
    let matched = recovery::match_entries(&filtered, file_size)?;
    eprintln!(
        "{} filtered headers; {} usable ZIP entries, {} missing/ambiguous/unsupported entries skipped",
        filtered.len(),
        matched.entries.len(),
        matched.skipped
    );
    if let Some(path) = &args.filtered {
        let mut writer =
            BufWriter::new(OpenOptions::new().write(true).create_new(true).open(path)?);
        for f in &filtered {
            recovery::write_finding(&mut writer, f)?;
        }
        writer.flush()?;
    }
    let options = CarveOptions {
        cluster_size: args.cluster_size,
        partition_offset: args.partition,
        file_size,
        max_stream_bytes: args.max_stream,
        max_trials: args.max_trials,
        assume_contiguous: args.assume_contiguous,
    };
    let stats = recovery::carve(
        &mut image,
        image_size,
        &mut map,
        &matched.entries,
        &options,
        &cancel,
        |msg| eprintln!("{msg}"),
    )?;
    let mut writer = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args.output)?,
    );
    recovery::write_map(&map, &mut writer)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    eprintln!(
        "{}: {} anchors, {} CRC-validated clusters, {} assumed clusters, {} trials, {} unknown; wrote {}",
        if stats.interrupted {
            "Interrupted"
        } else {
            "Finished"
        },
        stats.anchors,
        stats.validated,
        stats.assumed,
        stats.trials,
        stats.unresolved,
        args.output.display()
    );
    Ok(stats.interrupted)
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::from(130),
        Ok(false) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

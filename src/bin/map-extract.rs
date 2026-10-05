use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use indicatif::{ProgressBar, ProgressStyle};
use zip_carver::zip_recovery::read_map;

struct Args {
    image: PathBuf,
    map: PathBuf,
    output: PathBuf,
    cluster_size: u64,
    partition_offset: u64,
    file_size: Option<u64>,
    fill: u8,
}

fn number(value: &std::ffi::OsStr) -> Result<u64, String> {
    let text = value.to_str().ok_or("invalid number")?;
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse()
    }
    .map_err(|_| format!("invalid number: {text}"))
}

fn args() -> Result<Option<Args>, Box<dyn std::error::Error>> {
    let mut values = env::args_os().skip(1);
    let mut positional = Vec::new();
    let (mut cluster_size, mut partition_offset, mut file_size, mut fill) = (4096, 0, None, 0xff);
    while let Some(value) = values.next() {
        match value.to_str() {
            Some("--help" | "-h") => return Ok(None),
            Some("--cluster-size" | "--partition-offset" | "--file-size" | "--fill-byte") => {
                let n = number(&values.next().ok_or("missing numeric value")?)?;
                match value.to_str().unwrap() {
                    "--cluster-size" => cluster_size = n,
                    "--partition-offset" => partition_offset = n,
                    "--file-size" => file_size = Some(n),
                    _ => fill = u8::try_from(n).map_err(|_| "fill byte must be 0..255")?,
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
    if positional.len() != 3 {
        return Err("usage: map-extract [OPTIONS] DISK_IMAGE MAP.txt OUTFILE".into());
    }
    if !(512..=2 * 1024 * 1024).contains(&cluster_size) || !cluster_size.is_power_of_two() {
        return Err("cluster size must be a power of two from 512 to 2097152".into());
    }
    Ok(Some(Args {
        image: positional[0].clone().into(),
        map: positional[1].clone().into(),
        output: positional[2].clone().into(),
        cluster_size,
        partition_offset,
        file_size,
        fill,
    }))
}

fn physical(lcn: u64, args: &Args) -> io::Result<u64> {
    lcn.checked_mul(args.cluster_size)
        .and_then(|n| n.checked_add(args.partition_offset))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "physical offset overflow"))
}

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let Some(args) = args()? else {
        println!(
            "map-extract [OPTIONS] DISK_IMAGE MAP.txt OUTFILE

Construct a file from a VCN-to-LCN map (prototype/zip_map.py).
Map rows: hexadecimal VCN, tab, hexadecimal LCN or blank for unknown.
VCNs must be consecutive starting at zero. LCN zero is a valid location.

  --cluster-size N        Bytes per cluster [4096]
  --partition-offset N    NTFS volume start within the disk image [0]
  --file-size N           Exact output bytes [map cluster count * cluster size]
  --fill-byte N           Byte for unknown clusters [0xff]; use 0 for zero fill

Numbers accept decimal or 0x-prefixed hex. An exact size must agree with the
map's cluster count. Known cluster ranges are checked before output creation.
Existing outputs are never overwritten. Ctrl+C flushes the completed prefix
and exits 130; I/O errors retain a partial file. No automatic resume is performed."
        );
        return Ok(false);
    };
    if args.output.exists() {
        return Err("output exists; choose a new path".into());
    }
    let map = read_map(BufReader::new(File::open(&args.map)?))?;
    let mut image = File::open(&args.image)?;
    let image_size = image.metadata()?.len();
    if args.partition_offset > image_size {
        return Err("partition offset exceeds image size".into());
    }
    let capacity = (map.len() as u64)
        .checked_mul(args.cluster_size)
        .ok_or("map size overflow")?;
    let size = args.file_size.unwrap_or(capacity);
    if size == 0 || size.div_ceil(args.cluster_size) != map.len() as u64 {
        return Err("--file-size must agree with the map's cluster count".into());
    }
    let mut unknown_bytes = 0;
    for (vcn, lcn) in map.iter().enumerate() {
        let length = args.cluster_size.min(size - vcn as u64 * args.cluster_size);
        if let Some(lcn) = lcn {
            if physical(*lcn, &args)?
                .checked_add(length)
                .is_none_or(|end| end > image_size)
            {
                return Err(format!("VCN {vcn:08x}, LCN {lcn:08x} exceeds image length").into());
            }
        } else {
            unknown_bytes += length;
        }
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancel);
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    let mut output = BufWriter::with_capacity(1024 * 1024, file);
    let progress = ProgressBar::new(size);
    progress.set_style(ProgressStyle::with_template(
        "Constructing {bar:30} {bytes}/{total_bytes} {bytes_per_sec} {eta}",
    )?);
    let mut buffer = vec![args.fill; args.cluster_size as usize];
    let mut written = 0;
    let mut last_flush = std::time::Instant::now();
    let copy_result = (|| -> io::Result<()> {
        for lcn in &map {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let length = args.cluster_size.min(size - written) as usize;
            if let Some(lcn) = lcn {
                let offset = physical(*lcn, &args)?;
                if image.stream_position()? != offset {
                    image.seek(SeekFrom::Start(offset))?;
                }
                image.read_exact(&mut buffer[..length])?;
            } else {
                buffer[..length].fill(args.fill);
            }
            output.write_all(&buffer[..length])?;
            written += length as u64;
            progress.set_position(written);
            if last_flush.elapsed().as_secs() >= 5 {
                output.flush()?;
                last_flush = std::time::Instant::now();
            }
        }
        Ok(())
    })();
    let flush_result = output.flush().and_then(|()| output.get_ref().sync_all());
    progress.finish_and_clear();
    if let Err(error) = copy_result.and(flush_result) {
        return Err(format!(
            "construction failed; partial output retained at {}: {error}",
            args.output.display()
        )
        .into());
    }
    let interrupted = written != size;
    if interrupted {
        eprintln!(
            "Interrupted: saved {written}/{size} bytes to {}",
            args.output.display()
        );
    } else {
        eprintln!(
            "Wrote {size} bytes to {}; {unknown_bytes} unknown bytes filled with 0x{:02x}",
            args.output.display(),
            args.fill
        );
    }
    Ok(interrupted)
}

fn main() -> ExitCode {
    match run() {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(130),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

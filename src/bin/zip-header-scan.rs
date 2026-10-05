use std::cell::RefCell;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use indicatif::{ProgressBar, ProgressStyle};
use zip_carver::{Finding, ScanOptions, ScanProgress, scan_with_control};

const FLUSH_INTERVAL: Duration = Duration::from_secs(60);
const FLUSH_RECORDS: usize = 1024;
const CHECKPOINT_LINE_LENGTH: u64 = 21;

#[derive(Debug)]
struct Args {
    input: PathBuf,
    output: PathBuf,
    start_offset: u64,
    end_offset: Option<u64>,
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

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let args = parse_args(env::args().skip(1))?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal_flag = Arc::clone(&cancelled);
    ctrlc::set_handler(move || signal_flag.store(true, Ordering::Relaxed))?;

    let mut input = File::open(&args.input).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot open input '{}': {error}", args.input.display()),
        )
    })?;
    let input_len = input.metadata()?.len();
    let checkpoint = read_checkpoint(&args.output)?;
    let start_offset = checkpoint
        .map(|(offset, _)| offset)
        .unwrap_or(args.start_offset);
    if input_len != 0 && start_offset > input_len {
        return Err(format!("checkpoint {start_offset} exceeds input length {input_len}").into());
    }
    if args.end_offset.is_some_and(|end| end < start_offset) {
        return Err("--end-offset must not be smaller than the resume offset".into());
    }
    input.seek(SeekFrom::Start(start_offset))?;

    if checkpoint.is_some() {
        eprintln!(
            "Resuming {} from offset {} using {}",
            args.input.display(),
            start_offset,
            args.output.display()
        );
    }
    let output = RefCell::new(open_output(&args.output, checkpoint, start_offset)?);

    let total_size = (input_len != 0).then_some(input_len);
    let progress = create_progress_bar(total_size, start_offset, &args.input.display().to_string());

    let options = ScanOptions::default();
    let stats = match args.end_offset {
        Some(end) => scan_with_control(
            input.take(end - start_offset),
            start_offset,
            options,
            |finding| output.borrow_mut().write_finding(&finding),
            |state| {
                update_progress(&progress, start_offset, state);
                output
                    .borrow_mut()
                    .update_checkpoint(start_offset + state.bytes_scanned)
            },
            || cancelled.load(Ordering::Relaxed),
        )?,
        None => scan_with_control(
            input,
            start_offset,
            options,
            |finding| output.borrow_mut().write_finding(&finding),
            |state| {
                update_progress(&progress, start_offset, state);
                output
                    .borrow_mut()
                    .update_checkpoint(start_offset + state.bytes_scanned)
            },
            || cancelled.load(Ordering::Relaxed),
        )?,
    };
    progress.finish_and_clear();
    let mut output = output.into_inner();
    output.checkpoint = stats.resume_offset;
    output.flush()?;
    drop(output);
    replace_offset_placeholder(&args.output, stats.resume_offset)?;

    if stats.interrupted {
        eprintln!(
            "Interrupted at offset {}; saved {} ZIP records to {}",
            stats.resume_offset,
            stats.records_found,
            args.output.display()
        );
    } else {
        eprintln!(
            "Scanned {} bytes; found {} ZIP records; wrote {}",
            stats.bytes_scanned,
            stats.records_found,
            args.output.display()
        );
    }
    Ok(stats.interrupted)
}

struct PeriodicOutput {
    writer: BufWriter<File>,
    last_flush: Instant,
    records_since_flush: usize,
    checkpoint: u64,
}

impl PeriodicOutput {
    fn new(mut file: File, checkpoint: u64, write_header: bool) -> io::Result<Self> {
        if write_header {
            writeln!(file, "{checkpoint:020}")?;
        } else {
            file.seek(SeekFrom::End(0))?;
        }
        let mut writer = BufWriter::new(file);
        writer.flush()?;
        Ok(Self {
            writer,
            last_flush: Instant::now(),
            records_since_flush: 0,
            checkpoint,
        })
    }

    fn write_finding(&mut self, finding: &Finding) -> io::Result<()> {
        write_finding(&mut self.writer, finding)?;
        self.checkpoint = finding.offset.saturating_add(1);
        self.records_since_flush += 1;
        if self.records_since_flush >= FLUSH_RECORDS || self.last_flush.elapsed() >= FLUSH_INTERVAL
        {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()?;
        let file = self.writer.get_mut();
        file.seek(SeekFrom::Start(0))?;
        write!(file, "{:020}", self.checkpoint)?;
        file.seek(SeekFrom::End(0))?;
        file.flush()?;
        self.last_flush = Instant::now();
        self.records_since_flush = 0;
        Ok(())
    }

    fn update_checkpoint(&mut self, checkpoint: u64) -> io::Result<()> {
        self.checkpoint = checkpoint;
        if self.last_flush.elapsed() >= FLUSH_INTERVAL {
            self.flush()?;
        }
        Ok(())
    }
}

fn create_progress_bar(total: Option<u64>, start_offset: u64, input: &str) -> ProgressBar {
    let progress = match total {
        Some(total) => {
            let progress = ProgressBar::new(total);
            progress.set_style(
                ProgressStyle::with_template(
                    "{spinner:.green} {prefix} [{bar:40.cyan/blue}] {bytes}/{total_bytes} \
                     ({bytes_per_sec}, {eta}) {msg}",
                )
                .expect("valid progress template")
                .progress_chars("=>-"),
            );
            progress
        }
        None => {
            let progress = ProgressBar::new_spinner();
            progress.set_style(
                ProgressStyle::with_template(
                    "{spinner:.green} {prefix} {bytes} ({bytes_per_sec}) {msg}",
                )
                .expect("valid spinner template"),
            );
            progress
        }
    };
    progress.set_prefix(format!("Scanning {input}"));
    progress.set_message("0 headers");
    progress.set_draw_target(indicatif::ProgressDrawTarget::stderr());
    progress.set_position(start_offset.min(total.unwrap_or(start_offset)));
    progress.enable_steady_tick(Duration::from_millis(100));
    progress
}

fn update_progress(progress: &ProgressBar, start_offset: u64, state: ScanProgress) {
    progress.set_position(start_offset.saturating_add(state.bytes_scanned));
    progress.set_message(format!("{} headers", state.records_found));
}

fn read_checkpoint(path: &Path) -> io::Result<Option<(u64, u64)>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() == 0 {
        return Ok(None);
    }

    let mut line = Vec::new();
    BufReader::new(file).read_until(b'\n', &mut line)?;
    if !line.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "output '{}' has an incomplete checkpoint line",
                path.display()
            ),
        ));
    }
    let text = std::str::from_utf8(&line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "checkpoint is not UTF-8"))?;
    let offset = text.trim().parse::<u64>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("output '{}' has an invalid checkpoint", path.display()),
        )
    })?;
    Ok(Some((offset, line.len() as u64)))
}

fn open_output(
    path: &Path,
    checkpoint: Option<(u64, u64)>,
    start_offset: u64,
) -> io::Result<PeriodicOutput> {
    if let Some((offset, prefix_length)) = checkpoint {
        let fixed_checkpoint = format!("{offset:020}\n");
        replace_file_prefix(path, prefix_length, fixed_checkpoint.as_bytes())?;
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        PeriodicOutput::new(file, offset, false)
    } else {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        PeriodicOutput::new(file, start_offset, true)
    }
}

fn replace_offset_placeholder(path: &Path, ending_offset: u64) -> io::Result<()> {
    let offset_line = format!("{ending_offset}\n");
    replace_file_prefix(path, CHECKPOINT_LINE_LENGTH, offset_line.as_bytes())
}

fn replace_file_prefix(path: &Path, old_prefix_length: u64, new_prefix: &[u8]) -> io::Result<()> {
    let new_prefix_length = new_prefix.len() as u64;
    let original_len = fs::metadata(path)?.len();
    if old_prefix_length > original_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint line exceeds output length",
        ));
    }

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let mut buffer = vec![0_u8; 1024 * 1024];

    if new_prefix_length <= old_prefix_length {
        let mut read_at = old_prefix_length;
        let mut write_at = new_prefix_length;
        while read_at < original_len {
            file.seek(SeekFrom::Start(read_at))?;
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            file.seek(SeekFrom::Start(write_at))?;
            file.write_all(&buffer[..count])?;
            read_at += count as u64;
            write_at += count as u64;
        }
        file.set_len(original_len - (old_prefix_length - new_prefix_length))?;
    } else {
        let shift = new_prefix_length - old_prefix_length;
        file.set_len(original_len + shift)?;
        let mut read_end = original_len;
        while read_end > old_prefix_length {
            let count = (read_end - old_prefix_length).min(buffer.len() as u64) as usize;
            let read_at = read_end - count as u64;
            file.seek(SeekFrom::Start(read_at))?;
            file.read_exact(&mut buffer[..count])?;
            file.seek(SeekFrom::Start(read_at + shift))?;
            file.write_all(&buffer[..count])?;
            read_end = read_at;
        }
    }

    file.seek(SeekFrom::Start(0))?;
    file.write_all(new_prefix)?;
    file.flush()
}

fn write_finding(writer: &mut impl Write, finding: &Finding) -> io::Result<()> {
    write!(writer, "{} {:012x} b'", finding.kind, finding.offset)?;
    write_python_bytes(writer, &finding.raw_header)?;
    writeln!(writer, "'")
}

fn write_python_bytes(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    for &byte in bytes {
        match byte {
            b'\\' => writer.write_all(b"\\\\")?,
            b'\'' => writer.write_all(b"\\'")?,
            b'\t' => writer.write_all(b"\\t")?,
            b'\r' => writer.write_all(b"\\r")?,
            b'\n' => writer.write_all(b"\\n")?,
            0x20..=0x7e => writer.write_all(&[byte])?,
            _ => write!(writer, "\\x{byte:02x}")?,
        }
    }
    Ok(())
}

fn parse_args(mut values: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut positional = Vec::new();
    let mut start_offset = 0;
    let mut end_offset = None;

    while let Some(value) = values.next() {
        match value.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--start-offset" => start_offset = parse_number(next_value(&mut values, &value)?)?,
            "--end-offset" => end_offset = Some(parse_number(next_value(&mut values, &value)?)?),
            _ if value.starts_with('-') => return Err(format!("unknown option: {value}")),
            _ => positional.push(value),
        }
    }

    if positional.len() != 2 {
        return Err(
            "usage: zip-header-scan [OPTIONS] <INPUT> <OUTPUT.txt> (use --help for details)".into(),
        );
    }

    Ok(Args {
        input: PathBuf::from(&positional[0]),
        output: PathBuf::from(&positional[1]),
        start_offset,
        end_offset,
    })
}

fn next_value(values: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    values
        .next()
        .ok_or_else(|| format!("missing value for {option}"))
}

fn parse_number(value: String) -> Result<u64, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|_| format!("invalid hexadecimal number: {value}"))
    } else {
        value
            .parse()
            .map_err(|_| format!("invalid decimal number: {value}"))
    }
}

fn print_help() {
    println!(
        "zip-header-scan - locate ZIP structures in a disk image or raw device\n\n\
Usage:\n  zip-header-scan [OPTIONS] <INPUT> <OUTPUT.txt>\n\n\
Arguments:\n  <INPUT>       Disk image, volume, or raw-device path\n  <OUTPUT.txt>  Raw ZIP headers in the Python prototype format\n\n\
Options:\n  --start-offset <BYTES>  Start at a decimal or 0x-prefixed byte offset [default: 0]\n  --end-offset <BYTES>    Stop at this exclusive byte offset\n  -h, --help              Print help\n\n\
An existing output file is resumed from its first-line checkpoint. --start-offset\n\
is used only when creating a new output file.\n\n\
Windows raw-device examples (run an elevated shell):\n  zip-header-scan \\\\.\\PhysicalDrive1 findings.txt\n  zip-header-scan \\\\.\\C: findings.txt"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_output_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("zip-carver-{name}-{}.txt", std::process::id()))
    }

    #[test]
    fn accepts_decimal_and_hex_offsets() {
        assert_eq!(parse_number("4096".into()).unwrap(), 4096);
        assert_eq!(parse_number("0x1000".into()).unwrap(), 4096);
    }

    #[test]
    fn parses_scan_range() {
        let args = parse_args(
            [
                "--start-offset",
                "0x1000",
                "--end-offset",
                "8192",
                "disk.img",
                "hits.tsv",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(args.start_offset, 4096);
        assert_eq!(args.end_offset, Some(8192));
    }

    #[test]
    fn formats_raw_header_like_python_bytes() {
        let finding = Finding {
            kind: zip_carver::RecordKind::DataDescriptor,
            offset: 0x2a,
            raw_header: vec![b'P', b'K', 0, b'\'', b'\\', b'\n'],
        };
        let mut output = Vec::new();
        write_finding(&mut output, &finding).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "DATA 00000000002a b'PK\\x00\\'\\\\\\n'\n"
        );
    }

    #[test]
    fn resumes_output_without_losing_existing_findings() {
        let path = test_output_path("resume");
        fs::write(&path, b"42\nFILE old\n").unwrap();

        let checkpoint = read_checkpoint(&path).unwrap();
        assert_eq!(checkpoint, Some((42, 3)));
        let mut output = open_output(&path, checkpoint, 0).unwrap();
        output.writer.write_all(b"DATA new\n").unwrap();
        output.checkpoint = 84;
        output.flush().unwrap();
        drop(output);
        replace_offset_placeholder(&path, 84).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"84\nFILE old\nDATA new\n");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_malformed_checkpoint_without_modifying_output() {
        let path = test_output_path("malformed");
        let original = b"not-an-offset\nFILE old\n";
        fs::write(&path, original).unwrap();

        assert!(read_checkpoint(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn progress_uses_full_input_size_and_absolute_offset() {
        let progress = create_progress_bar(Some(1000), 400, "disk.img");
        assert_eq!(progress.length(), Some(1000));
        assert_eq!(progress.position(), 400);

        update_progress(
            &progress,
            400,
            ScanProgress {
                bytes_scanned: 50,
                records_found: 2,
            },
        );
        assert_eq!(progress.length(), Some(1000));
        assert_eq!(progress.position(), 450);
        progress.finish_and_clear();
    }
}

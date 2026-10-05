use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use zip_carver::ntfs::{ClusterMap, ClusterRange, scan_fragment};

#[derive(Default)]
struct Args {
    inputs: Vec<PathBuf>,
    output: PathBuf,
    bitmap: Option<PathBuf>,
    clusters: Option<u64>,
    sector_size: usize,
    merge_non_allocated: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = Args {
        sector_size: 512,
        ..Args::default()
    };
    let mut values = env::args_os().skip(1);
    while let Some(value) = values.next() {
        match value.to_str() {
            Some("-h" | "--help") => return Ok(None),
            Some("--merge-non-allocated") => args.merge_non_allocated = true,
            Some("--output" | "-o") => {
                args.output = values.next().ok_or("missing output path")?.into()
            }
            Some("--bitmap") => {
                args.bitmap = Some(values.next().ok_or("missing bitmap path")?.into())
            }
            Some("--clusters" | "--sector-size") => {
                let number = values.next().ok_or("missing numeric value")?;
                let text = number.to_str().ok_or("invalid numeric value")?;
                let number = if let Some(hex) = text.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16)
                } else {
                    text.parse()
                }
                .map_err(|_| "invalid numeric value")?;
                if value == "--clusters" {
                    args.clusters = Some(number);
                } else {
                    args.sector_size =
                        usize::try_from(number).map_err(|_| "sector size too large")?;
                }
            }
            Some("--") => {
                args.inputs.extend(values.map(PathBuf::from));
                break;
            }
            Some(text) if text.starts_with('-') => return Err(format!("unknown option: {text}")),
            _ => args.inputs.push(value.into()),
        }
    }
    if args.inputs.is_empty() || args.output.as_os_str().is_empty() {
        return Err("usage: ntfs-cluster-map --output MAP.csv [OPTIONS] SOURCE...".into());
    }
    if args.bitmap.is_some() && args.clusters.is_none() {
        return Err(
            "--bitmap requires --clusters (volume cluster count, excluding bitmap padding)".into(),
        );
    }
    if args.merge_non_allocated && args.bitmap.is_some() {
        return Err("--merge-non-allocated applies to MFT-inferred maps and cannot be combined with --bitmap".into());
    }
    if args.sector_size < 512 || args.sector_size > 65536 || !args.sector_size.is_power_of_two() {
        return Err("--sector-size must be a power of two between 512 and 65536".into());
    }
    Ok(Some(args))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let Some(args) = parse_args()? else {
        println!(
            "ntfs-cluster-map --output MAP.csv [OPTIONS] SOURCE...\n\n\
Scan a disk/volume image or recovered MFT fragments from the same volume and snapshot.\n\
  --output, -o PATH     New CSV output path (existing files are never overwritten)\n\
  --sector-size BYTES   NTFS sector size for update-sequence fixups [512]\n\
  --clusters COUNT      Volume cluster count; otherwise end at last referenced LCN\n\
  --bitmap PATH         Extracted, decoded volume $Bitmap::$DATA, requires --clusters\n\
  --merge-non-allocated Merge adjacent non-allocated_inferred ranges; no --bitmap\n\n\
All output includes live_files and deleted_files from recovered $FILE_NAME attributes.\n\
Merged output omits reference counts and unions file lists across each region. The merged\n\
status is not_allocated_inferred; these clusters are not confirmed free space.\n\n\
Ranges use volume-relative LCNs and exclusive end_lcn values. Live records yield\n\
allocated_inferred; deleted records yield deleted_reference; gaps are unknown.\n\
LCNs use lowercase hexadecimal, zero-padded to at least seven digits; counts are decimal.\n\
Only --bitmap establishes allocated/unallocated status. Deleted runlists can be\n\
stale or reused. Overlapping copies are deduplicated; differing versions are kept.\n\
Incomplete records and failed fixups are counted and excluded. Fragment boundaries\n\
are independent; records split between files cannot be reconstructed automatically."
        );
        return Ok(());
    };
    if args.output.exists() {
        return Err("output already exists; choose a new output path".into());
    }
    // Check all inputs before spending time on the scan.
    for path in &args.inputs {
        File::open(path)?;
    }
    let bitmap = args.bitmap.as_ref().map(fs::read).transpose()?;
    let mut map = ClusterMap::default();
    let mut total_valid = 0;
    for path in &args.inputs {
        eprintln!("Scanning {}...", path.display());
        let stats = scan_fragment(File::open(path)?, args.sector_size, |_, record| {
            map.add(record)
        })?;
        eprintln!(
            "  {} bytes; {} FILE candidates; {} valid; {} rejected",
            stats.bytes_read, stats.candidates, stats.valid, stats.rejected
        );
        total_valid += stats.valid;
        for (reason, count) in stats.rejection_reasons {
            eprintln!("    {count} rejected: {reason}");
        }
    }
    if total_valid == 0 {
        return Err("no valid MFT records found; check the sector size and fragment format".into());
    }
    eprintln!(
        "Unique records: {} in use, {} deleted; {} duplicate records skipped",
        map.live_records, map.deleted_records, map.duplicates
    );
    let clusters = args.clusters.unwrap_or(map.max_lcn_end);
    if args.clusters.is_none() {
        eprintln!("Map ends at last referenced LCN ({clusters}); volume size is unknown.");
    }
    let mut ranges = map.ranges(clusters, bitmap.as_deref())?;
    if args.merge_non_allocated {
        ranges = merge_non_allocated(ranges);
    }
    let mut totals = BTreeMap::new();
    let mut conflicts = 0;
    let mut writer = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args.output)?,
    );
    if args.merge_non_allocated {
        writeln!(
            writer,
            "start_lcn,end_lcn,cluster_count,status,live_files,deleted_files"
        )?;
    } else {
        writeln!(
            writer,
            "start_lcn,end_lcn,cluster_count,status,live_references,deleted_references,live_files,deleted_files"
        )?;
    }
    for range in &ranges {
        let count = range.end - range.start;
        *totals.entry(range.status).or_insert(0_u64) += count;
        if range.status == "unallocated" && range.live_references != 0 {
            conflicts += count;
        }
        write!(
            writer,
            "{:07x},{:07x},{},{}",
            range.start, range.end, count, range.status,
        )?;
        if !args.merge_non_allocated {
            write!(
                writer,
                ",{},{}",
                range.live_references, range.deleted_references
            )?;
        }
        writeln!(
            writer,
            ",{},{}",
            csv_field(
                &range
                    .live_files
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            csv_field(
                &range
                    .deleted_files
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        )?;
    }
    writer.flush()?;
    for (status, count) in totals {
        eprintln!("{status}: {count} clusters");
    }
    if conflicts != 0 {
        eprintln!(
            "Bitmap/MFT conflict: {conflicts} bitmap-free clusters have live MFT references."
        );
    }
    eprintln!("Wrote {} ranges to {}", ranges.len(), args.output.display());
    Ok(())
}

fn csv_field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn merge_non_allocated(ranges: Vec<ClusterRange>) -> Vec<ClusterRange> {
    let mut merged: Vec<ClusterRange> = Vec::new();
    for mut range in ranges {
        if range.status != "allocated_inferred" {
            range.status = "not_allocated_inferred";
            // Reference multiplicities vary within the resulting range and are
            // deliberately omitted from this mode's CSV.
            range.live_references = 0;
            range.deleted_references = 0;
            if let Some(last) = merged
                .last_mut()
                .filter(|last| last.status == range.status && last.end == range.start)
            {
                last.end = range.end;
                last.live_files.extend(range.live_files);
                last.deleted_files.extend(range.deleted_files);
                continue;
            }
        }
        merged.push(range);
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_csv_names_and_unions_deleted_owners_when_merging() {
        assert_eq!(csv_field("a,\"b\"\n"), "\"a,\"\"b\"\"\n\"");
        let ranges = ["first.zip", "second.zip"]
            .into_iter()
            .enumerate()
            .map(|(i, name)| ClusterRange {
                start: i as u64,
                end: i as u64 + 1,
                status: "deleted_reference",
                live_references: 0,
                deleted_references: 1,
                live_files: Default::default(),
                deleted_files: [name.to_string()].into(),
            })
            .collect();
        let merged = merge_non_allocated(ranges);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].end, 2);
        assert_eq!(merged[0].deleted_files.len(), 2);
    }

    #[test]
    fn merges_unknown_and_deleted_ranges_but_never_crosses_allocations_or_gaps() {
        let ranges = [
            (0, 4, "unknown", 0),
            (4, 7, "deleted_reference", 1),
            (7, 9, "deleted_reference", 3),
            (9, 10, "allocated_inferred", 0),
            (10, 12, "deleted_reference", 1),
            (12, 20, "unknown", 0),
            (25, 30, "unknown", 0),
        ]
        .into_iter()
        .map(|(start, end, status, deleted_references)| ClusterRange {
            start,
            end,
            status,
            deleted_references,
            live_references: i64::from(status == "allocated_inferred"),
            live_files: Default::default(),
            deleted_files: Default::default(),
        })
        .collect();
        let actual: Vec<_> = merge_non_allocated(ranges)
            .into_iter()
            .map(|r| (r.start, r.end, r.status))
            .collect();
        assert_eq!(
            actual,
            vec![
                (0, 9, "not_allocated_inferred"),
                (9, 10, "allocated_inferred"),
                (10, 20, "not_allocated_inferred"),
                (25, 30, "not_allocated_inferred"),
            ]
        );
        assert!(merge_non_allocated(Vec::new()).is_empty());
    }
}

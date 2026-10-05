use std::collections::HashSet;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use indicatif::{ProgressBar, ProgressStyle};
use zip_carver::ntfs::{AttributeData, Record, scan_fragment_with_data};
use zip_carver::rescue::{plan_mapping, plan_orphan_stream, read_csv, select_base, write_mapping};

struct Args {
    csv: PathBuf,
    id: u32,
    output: PathBuf,
    fragments: Vec<PathBuf>,
    cluster_size: u64,
    sector_size: usize,
    sequence: Option<u16>,
    stream: Vec<u16>,
}

fn number(value: &std::ffi::OsStr) -> Result<u64, String> {
    let value = value.to_str().ok_or("invalid number")?;
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
    .map_err(|_| format!("invalid number: {value}"))
}

fn args() -> Result<Option<Args>, String> {
    let (mut positional, mut fragments) = (Vec::new(), Vec::new());
    let (mut cluster_size, mut sector_size) = (4096, 512);
    let (mut sequence, mut stream) = (None, Vec::new());
    let mut values = env::args_os().skip(1);
    while let Some(value) = values.next() {
        match value.to_str() {
            Some("-h" | "--help") => return Ok(None),
            Some("--mft-source" | "--mft-fragment") => {
                fragments.push(PathBuf::from(values.next().ok_or("missing fragment path")?))
            }
            Some("--stream") => {
                stream = values
                    .next()
                    .ok_or("missing stream name")?
                    .to_str()
                    .ok_or("invalid stream name")?
                    .encode_utf16()
                    .collect()
            }
            Some("--cluster-size" | "--sector-size" | "--sequence") => {
                let n = number(&values.next().ok_or("missing numeric value")?)?;
                match value.to_str().unwrap() {
                    "--cluster-size" => cluster_size = n,
                    "--sector-size" => {
                        sector_size = usize::try_from(n).map_err(|_| "sector size overflow")?
                    }
                    _ => sequence = Some(u16::try_from(n).map_err(|_| "sequence exceeds 65535")?),
                }
            }
            Some("--") => {
                positional.extend(values);
                break;
            }
            Some(text) if text.starts_with('-') => return Err(format!("unknown option: {text}")),
            _ => positional.push(value),
        }
    }
    if positional.len() != 3 {
        return Err(
            "usage: ntfs-file-map --mft-source PATH [OPTIONS] MFT.csv RECORD_ID OUTFILE".into(),
        );
    }
    if fragments.is_empty() {
        return Err("at least one --mft-source PATH (alias --mft-fragment) is required".into());
    }
    if !(512..=2 * 1024 * 1024).contains(&cluster_size) || !cluster_size.is_power_of_two() {
        return Err("cluster size must be a power of two between 512 and 2097152".into());
    }
    if !(512..=65536).contains(&sector_size) || !sector_size.is_power_of_two() {
        return Err("sector size must be a power of two between 512 and 65536".into());
    }
    Ok(Some(Args {
        csv: positional[0].clone().into(),
        id: u32::try_from(number(&positional[1])?).map_err(|_| "record ID exceeds 32 bits")?,
        output: positional[2].clone().into(),
        fragments,
        cluster_size,
        sector_size,
        sequence,
        stream,
    }))
}

fn collect_records(args: &Args, id: u32) -> io::Result<Vec<Record>> {
    let mut records = HashSet::new();
    for path in &args.fragments {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        eprintln!("Scanning MFT metadata in {}...", path.display());
        let bar = ProgressBar::new(size);
        bar.set_style(
            ProgressStyle::with_template("{bar:30} {bytes}/{total_bytes} {bytes_per_sec} {eta}")
                .unwrap(),
        );
        let stats = scan_fragment_with_data(bar.wrap_read(file), args.sector_size, |_, record| {
            if record.number == id
                || (record.base_reference != 0
                    && record.base_reference & 0x0000_ffff_ffff_ffff == u64::from(id))
            {
                records.insert(record);
            }
        });
        bar.finish_and_clear();
        let stats = stats?;
        eprintln!(
            "  {} valid records; {} rejected candidates",
            stats.valid, stats.rejected
        );
    }
    Ok(records.into_iter().collect())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let Some(args) = args()? else {
        println!(
            "ntfs-file-map --mft-source PATH [OPTIONS] MFT.csv RECORD_ID OUTFILE\n\n\
Write a VCN-to-LCN map. RECORD_ID is decimal or 0x-prefixed.\n\
MFT.csv is the filename-aware output of ntfs-cluster-map (normal or merged).\n\
  --mft-source PATH       Required; image or MFT fragment; repeat for multiple inputs\n\
  --mft-fragment PATH     Alias for --mft-source\n\
  --cluster-size BYTES    NTFS cluster size [4096]\n\
  --sector-size BYTES     MFT sector fixup size [512]\n\
  --sequence N            Select a record generation if the ID has been reused\n\
  --stream NAME           Map a named $DATA stream (default: unnamed file data)\n\n\
Output matches prototype/rescued_map.txt: one line per VCN, eight-digit lowercase\n\
hex VCN, tab, hex LCN (blank for sparse/unknown clusters), no header.\n\
With a lost/corrupt base, map surviving extensions through the highest known VCN.\n\
Resident attribute lists are followed; nonresident lists use recovered base links.\n\
Sources are scanned for MFT metadata only; no file data is copied. Mappings include\n\
uninitialized clusters; rows stop at the cluster containing the last file byte.\n\
Existing outputs, resident streams, compressed/EFS streams and conflicting\n\
metadata are rejected. I/O failures can leave a partial mapping file."
        );
        return Ok(());
    };
    if args.output.exists() {
        return Err("output exists; choose a new path".into());
    }
    File::open(&args.csv)?;
    let mut records = collect_records(&args, args.id)?;
    let mut id = args.id;
    if !records
        .iter()
        .any(|r| r.number == id && r.base_reference == 0)
    {
        let bases: HashSet<_> = records
            .iter()
            .filter(|r| r.number == id && r.base_reference != 0)
            .map(|r| r.base_reference)
            .collect();
        if bases.len() == 1 {
            let base_ref = *bases.iter().next().unwrap();
            id = u32::try_from(base_ref & 0x0000_ffff_ffff_ffff)?;
            eprintln!(
                "Record {} is an extension; resolving base MFT {}:{}",
                args.id,
                id,
                base_ref >> 48
            );
            records = collect_records(&args, id)?;
            records.retain(|r| {
                r.base_reference == base_ref || zip_carver::rescue::reference(r) == base_ref
            });
        }
    }
    let evidence = read_csv(File::open(&args.csv)?, id)?;
    let sequence = args.sequence.or_else(|| {
        if evidence.sequences.len() == 1 {
            evidence.sequences.first().copied()
        } else {
            None
        }
    });
    let (mut plan, sequence, in_use) = if records.iter().any(|r| {
        r.number == id && r.base_reference == 0 && sequence.is_none_or(|seq| r.sequence == seq)
    }) {
        let base = select_base(&records, id, sequence)?;
        if records
            .iter()
            .filter(|r| {
                zip_carver::rescue::reference(r) == zip_carver::rescue::reference(base)
                    || r.base_reference == zip_carver::rescue::reference(base)
            })
            .flat_map(|r| &r.attributes)
            .any(|a| a.kind == 0x20 && matches!(a.data, AttributeData::Nonresident { .. }))
        {
            eprintln!(
                "Nonresident $ATTRIBUTE_LIST unavailable: using recovered base-linked DATA segments"
            );
        }
        let plan = plan_mapping(&records, base, &args.stream, args.cluster_size)?;
        for name in &base.file_names {
            eprintln!("  name: {:?}", name.name);
        }
        (plan, base.sequence, base.in_use)
    } else {
        let recovery = plan_orphan_stream(&records, id, sequence, &args.stream, args.cluster_size)?;
        eprintln!(
            "Base MFT record unavailable: partial recovery from surviving extensions; \
             unknown VCNs have blank LCNs, inferred size {} bytes (original size unknown)",
            recovery.plan.size
        );
        (
            recovery.plan,
            (recovery.base_reference >> 48) as u16,
            recovery.in_use,
        )
    };
    if plan.resident.is_some() {
        return Err("resident stream has no VCN-to-LCN mapping".into());
    }
    // Mapping exports physical allocation, including uninitialized clusters.
    plan.initialized = plan.size;
    evidence.validate_owner(&plan, id, sequence, in_use, args.cluster_size)?;
    eprintln!(
        "Mapping MFT {}:{} ({}): {} bytes, {} runs, {} VCNs",
        id,
        sequence,
        if in_use {
            "in use"
        } else {
            "deleted; contents may have been reused"
        },
        plan.size,
        plan.runs.len(),
        plan.size.div_ceil(args.cluster_size)
    );
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    let mut output = BufWriter::new(file);
    if let Err(error) = write_mapping(&plan, &mut output, args.cluster_size)
        .and_then(|()| output.flush())
        .and_then(|()| output.get_ref().sync_all())
    {
        return Err(format!(
            "mapping failed; partial output retained at {}: {error}",
            args.output.display()
        )
        .into());
    }
    eprintln!(
        "Wrote {} VCN mappings to {}",
        plan.size.div_ceil(args.cluster_size),
        args.output.display()
    );
    Ok(())
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

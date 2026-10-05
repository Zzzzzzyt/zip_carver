//! Reconstruct NTFS streams in VCN order, never by sorting their physical LCNs.
use std::collections::{BTreeSet, HashSet};
use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::ntfs::{AttributeData, DataRun, Record, RescueAttribute};

const REFERENCE_MASK: u64 = 0x0000_ffff_ffff_ffff;
const MAX_ATTRIBUTE_LIST: u64 = 64 * 1024 * 1024;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub fn reference(record: &Record) -> u64 {
    u64::from(record.number) | (u64::from(record.sequence) << 48)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    pub kind: u32,
    pub name: Vec<u16>,
    pub first_vcn: u64,
    pub record_reference: u64,
    pub attribute_id: u16,
}

pub fn parse_attribute_list(data: &[u8]) -> io::Result<Vec<ListEntry>> {
    let mut entries = Vec::new();
    let mut at = 0;
    while at < data.len() {
        if data.len() - at < 26 {
            return Err(invalid("truncated $ATTRIBUTE_LIST entry"));
        }
        let entry = &data[at..];
        let kind = u32::from_le_bytes(entry[..4].try_into().unwrap());
        let len = usize::from(u16::from_le_bytes(entry[4..6].try_into().unwrap()));
        let name_len = usize::from(entry[6]) * 2;
        let name_at = usize::from(entry[7]);
        if kind == 0
            || len < 26
            || len > entry.len()
            || (name_len != 0 && (name_at < 26 || name_at + name_len > len))
        {
            return Err(invalid("invalid $ATTRIBUTE_LIST entry bounds"));
        }
        entries.push(ListEntry {
            kind,
            name: if name_len == 0 {
                Vec::new()
            } else {
                entry[name_at..name_at + name_len]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect()
            },
            first_vcn: u64::from_le_bytes(entry[8..16].try_into().unwrap()),
            record_reference: u64::from_le_bytes(entry[16..24].try_into().unwrap()),
            attribute_id: u16::from_le_bytes(entry[24..26].try_into().unwrap()),
        });
        at += len;
    }
    Ok(entries)
}

#[derive(Debug, Clone)]
pub struct StreamPlan {
    pub size: u64,
    pub initialized: u64,
    pub runs: Vec<DataRun>,
    pub resident: Option<Vec<u8>>,
}

fn first_vcn(attr: &RescueAttribute) -> u64 {
    match attr.data {
        AttributeData::Resident(_) => 0,
        AttributeData::Nonresident { first_vcn, .. } => first_vcn,
    }
}

fn assemble(attributes: Vec<RescueAttribute>, cluster_size: u64) -> io::Result<StreamPlan> {
    assemble_segments(attributes, cluster_size, false)
}

fn assemble_segments(
    attributes: Vec<RescueAttribute>,
    cluster_size: u64,
    infer_size: bool,
) -> io::Result<StreamPlan> {
    let mut attributes: Vec<_> = attributes
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    if attributes.is_empty() {
        return Err(invalid("requested stream has no recovered attributes"));
    }
    attributes.sort_by_key(first_vcn);
    for attr in &attributes {
        if attr.flags & 0x4001 != 0
            || matches!(
                attr.data,
                AttributeData::Nonresident {
                    compression_unit: 1..,
                    ..
                }
            )
        {
            return Err(invalid(
                "NTFS compressed or EFS-encrypted streams are not supported",
            ));
        }
    }
    if let AttributeData::Resident(bytes) = &attributes[0].data {
        if attributes.len() != 1 {
            return Err(invalid("conflicting resident stream versions"));
        }
        return Ok(StreamPlan {
            size: bytes.len() as u64,
            initialized: bytes.len() as u64,
            runs: Vec::new(),
            resident: Some(bytes.clone()),
        });
    }
    let (mut file_size, mut initialized_size) = if infer_size {
        // Extension size fields are not authoritative, even when nonzero.
        (0, 0)
    } else {
        let AttributeData::Nonresident {
            first_vcn: 0,
            file_size,
            initialized_size,
            ..
        } = attributes[0].data
        else {
            return Err(invalid("missing VCN 0 segment with stream size metadata"));
        };
        (file_size, initialized_size)
    };
    if initialized_size > file_size {
        return Err(invalid("initialized size exceeds file size"));
    }
    let mut expected = 0;
    let mut runs = Vec::new();
    for attr in attributes {
        let AttributeData::Nonresident {
            first_vcn,
            last_vcn,
            runs: segment,
            ..
        } = attr.data
        else {
            return Err(invalid("mixed resident and nonresident stream segments"));
        };
        if infer_size && first_vcn > expected {
            runs.push(DataRun {
                vcn: expected,
                clusters: first_vcn - expected,
                lcn: None,
            });
        } else if first_vcn != expected {
            return Err(invalid(format!(
                "missing or conflicting stream segment: expected VCN {expected}, found {first_vcn}"
            )));
        }
        let end = if last_vcn == u64::MAX && first_vcn == 0 && segment.is_empty() {
            0
        } else {
            last_vcn
                .checked_add(1)
                .ok_or_else(|| invalid("VCN overflow"))?
        };
        let mut run_end = first_vcn;
        for run in &segment {
            if run.vcn != run_end || run.clusters == 0 {
                return Err(invalid("inconsistent data run"));
            }
            run_end = run
                .vcn
                .checked_add(run.clusters)
                .ok_or_else(|| invalid("VCN overflow"))?;
        }
        if run_end != end {
            return Err(invalid("incomplete segment runlist"));
        }
        expected = end;
        runs.extend(segment);
    }
    if infer_size {
        file_size = multiply(expected, cluster_size)?;
        initialized_size = file_size;
    }
    if expected
        .checked_mul(cluster_size)
        .ok_or_else(|| invalid("stream allocation overflow"))?
        < file_size
    {
        return Err(invalid(
            "recovered segments do not cover the file's logical size",
        ));
    }
    Ok(StreamPlan {
        size: file_size,
        initialized: initialized_size,
        runs,
        resident: None,
    })
}

/// Select a base record by CSV generation or explicit sequence, avoiding a
/// silent choice between reused record IDs and conflicting recovered versions.
pub fn select_base(records: &[Record], id: u32, sequence: Option<u16>) -> io::Result<&Record> {
    let mut candidates = records.iter().filter(|r| {
        r.number == id && r.base_reference == 0 && sequence.is_none_or(|seq| seq == r.sequence)
    });
    let base = candidates.next().ok_or_else(|| {
        invalid("base MFT record not recovered; supply --mft-source or the base record ID")
    })?;
    let base_attrs: HashSet<_> = base.attributes.iter().collect();
    for other in candidates {
        if other.sequence != base.sequence
            || other.in_use != base.in_use
            || other.attributes.iter().collect::<HashSet<_>>() != base_attrs
        {
            return Err(invalid(
                "ambiguous base record versions; use --sequence and metadata from a single snapshot",
            ));
        }
    }
    Ok(base)
}

pub fn plan_stream(
    records: &[Record],
    base: &Record,
    stream: &[u16],
    image: &mut (impl Read + Seek),
    cluster_size: u64,
    partition_offset: u64,
) -> io::Result<StreamPlan> {
    plan_with_list(records, base, stream, cluster_size, |attrs| {
        let list_plan = assemble(attrs, cluster_size)?;
        if list_plan.size > MAX_ATTRIBUTE_LIST || list_plan.size != list_plan.initialized {
            return Err(invalid(
                "invalid or oversized $ATTRIBUTE_LIST (limit 64 MiB)",
            ));
        }
        let mut bytes = Vec::new();
        copy_stream(
            &list_plan,
            image,
            &mut bytes,
            cluster_size,
            partition_offset,
        )?;
        Ok(Some(bytes))
    })
}

/// Build a map using only recovered records. Nonresident attribute-list contents
/// require a disk image, so use base-linked DATA segments when unavailable.
pub fn plan_mapping(
    records: &[Record],
    base: &Record,
    stream: &[u16],
    cluster_size: u64,
) -> io::Result<StreamPlan> {
    plan_with_list(records, base, stream, cluster_size, |attrs| {
        if attrs
            .iter()
            .any(|a| matches!(a.data, AttributeData::Nonresident { .. }))
        {
            return Ok(None);
        }
        Ok(assemble(attrs, cluster_size)?.resident)
    })
}

fn plan_with_list(
    records: &[Record],
    base: &Record,
    stream: &[u16],
    cluster_size: u64,
    read_list: impl FnOnce(Vec<RescueAttribute>) -> io::Result<Option<Vec<u8>>>,
) -> io::Result<StreamPlan> {
    if cluster_size < 512 || !cluster_size.is_power_of_two() {
        return Err(invalid(
            "cluster size must be a power of two of at least 512",
        ));
    }
    let base_ref = reference(base);
    let belongs = |r: &&Record| {
        (reference(r) == base_ref && r.base_reference == 0 || r.base_reference == base_ref)
            && r.in_use == base.in_use
    };
    let list_attrs: Vec<_> = records
        .iter()
        .filter(belongs)
        .flat_map(|r| &r.attributes)
        .filter(|a| a.kind == 0x20 && a.name.is_empty())
        .cloned()
        .collect();
    let mut selected = Vec::new();
    let list_bytes = if list_attrs.is_empty() {
        None
    } else {
        read_list(list_attrs)?
    };
    let Some(bytes) = list_bytes else {
        selected.extend(
            records
                .iter()
                .filter(belongs)
                .flat_map(|r| &r.attributes)
                .filter(|a| a.kind == 0x80 && a.name == stream)
                .cloned(),
        );
        return assemble(selected, cluster_size);
    };
    {
        let entries = parse_attribute_list(&bytes)?;
        for entry in entries
            .iter()
            .filter(|e| e.kind == 0x80 && e.name == stream)
        {
            let mut matches = Vec::new();
            for record in records
                .iter()
                .filter(belongs)
                .filter(|r| reference(r) == entry.record_reference)
            {
                matches.extend(
                    record
                        .attributes
                        .iter()
                        .filter(|a| {
                            a.kind == entry.kind
                                && a.id == entry.attribute_id
                                && a.name == entry.name
                                && first_vcn(a) == entry.first_vcn
                        })
                        .cloned(),
                );
            }
            let mut matches: HashSet<_> = matches.into_iter().collect();
            if matches.len() != 1 {
                return Err(invalid(format!(
                    "missing or conflicting $ATTRIBUTE_LIST target MFT {}:{} attribute {} VCN {}",
                    entry.record_reference & REFERENCE_MASK,
                    entry.record_reference >> 48,
                    entry.attribute_id,
                    entry.first_vcn
                )));
            }
            selected.push(matches.drain().next().unwrap());
        }
    }
    assemble(selected, cluster_size)
}

pub struct PartialRecovery {
    pub base_reference: u64,
    pub in_use: bool,
    pub plan: StreamPlan,
}

/// Recover surviving extensions when no valid base record was recovered.
/// Base generation and allocation state must be unambiguous; missing VCNs
/// become zero runs and size is inferred from the highest segment end.
pub fn plan_orphan_stream(
    records: &[Record],
    id: u32,
    sequence: Option<u16>,
    stream: &[u16],
    cluster_size: u64,
) -> io::Result<PartialRecovery> {
    if cluster_size < 512 || !cluster_size.is_power_of_two() {
        return Err(invalid(
            "cluster size must be a power of two of at least 512",
        ));
    }
    if records.iter().any(|r| {
        r.number == id && r.base_reference == 0 && sequence.is_none_or(|seq| seq == r.sequence)
    }) {
        return Err(invalid(
            "base record is available; use normal stream recovery",
        ));
    }
    let extensions: Vec<_> = records
        .iter()
        .filter(|r| {
            r.base_reference != 0
                && r.base_reference & REFERENCE_MASK == u64::from(id)
                && sequence.is_none_or(|seq| u64::from(seq) == r.base_reference >> 48)
        })
        .collect();
    let identities: HashSet<_> = extensions
        .iter()
        .map(|r| (r.base_reference, r.in_use))
        .collect();
    if identities.len() != 1 {
        return Err(invalid(
            "missing or ambiguous extension records; use --sequence to select the base generation",
        ));
    }
    let (base_reference, in_use) = *identities.iter().next().unwrap();
    let attributes = extensions
        .iter()
        .flat_map(|r| &r.attributes)
        .filter(|a| a.kind == 0x80 && a.name == stream)
        .cloned()
        .collect();
    Ok(PartialRecovery {
        base_reference,
        in_use,
        plan: assemble_segments(attributes, cluster_size, true)?,
    })
}

fn multiply(value: u64, cluster_size: u64) -> io::Result<u64> {
    value
        .checked_mul(cluster_size)
        .ok_or_else(|| invalid("cluster byte offset overflow"))
}

fn physical_offset(lcn: u64, cluster_size: u64, partition_offset: u64) -> io::Result<u64> {
    multiply(lcn, cluster_size)?
        .checked_add(partition_offset)
        .ok_or_else(|| invalid("image offset overflow"))
}

/// Prototype format: one VCN per line, lowercase hex (minimum eight digits),
/// a tab, and an optional LCN. Sparse/unknown clusters have an empty LCN.
pub fn write_mapping(
    plan: &StreamPlan,
    output: &mut impl Write,
    cluster_size: u64,
) -> io::Result<()> {
    if cluster_size == 0 {
        return Err(invalid("cluster size must be nonzero"));
    }
    if plan.resident.is_some() {
        return Err(invalid("resident stream has no VCN-to-LCN mapping"));
    }
    let count = plan.size.div_ceil(cluster_size);
    let mut expected = 0;
    for run in &plan.runs {
        if expected >= count {
            break;
        }
        if run.vcn != expected {
            return Err(invalid("noncontiguous mapping plan"));
        }
        let length = run.clusters.min(count - expected);
        for delta in 0..length {
            let vcn = expected + delta;
            if let Some(lcn) = run.lcn {
                let lcn = lcn
                    .checked_add(delta)
                    .ok_or_else(|| invalid("LCN overflow"))?;
                writeln!(output, "{vcn:08x}\t{lcn:08x}")?;
            } else {
                writeln!(output, "{vcn:08x}\t")?;
            }
        }
        expected += length;
    }
    if expected != count {
        return Err(invalid("mapping plan does not cover file size"));
    }
    Ok(())
}

impl StreamPlan {
    /// Check every byte that will actually be read before creating the output.
    pub fn validate_image(
        &self,
        size: u64,
        cluster_size: u64,
        partition_offset: u64,
    ) -> io::Result<()> {
        for run in &self.runs {
            let start = multiply(run.vcn, cluster_size)?;
            if start >= self.initialized {
                break;
            }
            let count = multiply(run.clusters, cluster_size)?.min(self.initialized - start);
            if let Some(lcn) = run.lcn {
                let end = physical_offset(lcn, cluster_size, partition_offset)?
                    .checked_add(count)
                    .ok_or_else(|| invalid("image range overflow"))?;
                if end > size {
                    return Err(invalid(format!(
                        "data run at LCN {lcn:07x} exceeds disk image length; check geometry"
                    )));
                }
            }
        }
        Ok(())
    }
}

pub fn copy_stream(
    plan: &StreamPlan,
    image: &mut (impl Read + Seek),
    output: &mut impl Write,
    cluster_size: u64,
    partition_offset: u64,
) -> io::Result<()> {
    if let Some(bytes) = &plan.resident {
        return output.write_all(bytes);
    }
    let zeros = [0; 64 * 1024];
    let mut written = 0;
    for run in &plan.runs {
        if written >= plan.size {
            break;
        }
        let count = multiply(run.clusters, cluster_size)?.min(plan.size - written);
        let initialized = count.min(plan.initialized.saturating_sub(written));
        let mut zero_count = count;
        if let Some(lcn) = run.lcn.filter(|_| initialized != 0) {
            image.seek(SeekFrom::Start(physical_offset(
                lcn,
                cluster_size,
                partition_offset,
            )?))?;
            let copied = io::copy(&mut (&mut *image).take(initialized), output)?;
            if copied != initialized {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "disk image truncated during rescue",
                ));
            }
            zero_count -= initialized;
        }
        while zero_count != 0 {
            let count = zero_count.min(zeros.len() as u64) as usize;
            output.write_all(&zeros[..count])?;
            zero_count -= count as u64;
        }
        written += count;
    }
    if written != plan.size {
        return Err(invalid("stream plan did not cover output length"));
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct CsvEvidence {
    pub sequences: BTreeSet<u16>,
    pub ranges: Vec<(u64, u64, u16, bool)>,
}

/// Parse IDs only outside the quoted/escaped filename labels emitted by the
/// mapper, so a filename containing '; MFT 42:1' cannot impersonate an owner.
fn owners(field: &str) -> Vec<(u64, u16)> {
    let mut owners = Vec::new();
    let bytes = field.as_bytes();
    let (mut at, mut quoted) = (0, false);
    while at < bytes.len() {
        if quoted && bytes[at] == b'\\' {
            at += 2;
            continue;
        }
        if bytes[at] == b'"' {
            quoted = !quoted;
            at += 1;
            continue;
        }
        if !quoted && (at == 0 || bytes[..at].ends_with(b"; ")) && bytes[at..].starts_with(b"MFT ")
        {
            let token = field[at + 4..].split(' ').next().unwrap_or("");
            if let Some((id, seq)) = token.split_once(':')
                && let (Ok(id), Ok(seq)) = (id.parse(), seq.parse())
            {
                owners.push((id, seq));
            }
        }
        at += 1;
    }
    owners
}

pub fn read_csv(input: impl Read, id: u32) -> io::Result<CsvEvidence> {
    let mut csv = csv::Reader::from_reader(input);
    let headers = csv.headers().map_err(|e| invalid(e.to_string()))?.clone();
    let column = |name: &str| {
        headers.iter().position(|h| h == name).ok_or_else(|| {
            invalid(format!(
                "CSV requires {name} column; regenerate using ntfs-cluster-map with filename support"
            ))
        })
    };
    let (start_col, end_col, live_col, deleted_col) = (
        column("start_lcn")?,
        column("end_lcn")?,
        column("live_files")?,
        column("deleted_files")?,
    );
    let mut evidence = CsvEvidence::default();
    for row in csv.records() {
        let row = row.map_err(|e| invalid(e.to_string()))?;
        let start = u64::from_str_radix(&row[start_col], 16)
            .map_err(|_| invalid("invalid CSV start_lcn"))?;
        let end =
            u64::from_str_radix(&row[end_col], 16).map_err(|_| invalid("invalid CSV end_lcn"))?;
        if start >= end {
            return Err(invalid("invalid CSV cluster range"));
        }
        for (column, live) in [(live_col, true), (deleted_col, false)] {
            for (owner, sequence) in owners(&row[column]) {
                if owner == u64::from(id) {
                    evidence.sequences.insert(sequence);
                    evidence.ranges.push((start, end, sequence, live));
                }
            }
        }
    }
    Ok(evidence)
}

impl CsvEvidence {
    pub fn validate(&self, plan: &StreamPlan, base: &Record, cluster_size: u64) -> io::Result<()> {
        self.validate_owner(plan, base.number, base.sequence, base.in_use, cluster_size)
    }

    pub fn validate_owner(
        &self,
        plan: &StreamPlan,
        id: u32,
        sequence: u16,
        in_use: bool,
        cluster_size: u64,
    ) -> io::Result<()> {
        let mut ranges: Vec<_> = self
            .ranges
            .iter()
            .filter(|r| r.2 == sequence && r.3 == in_use)
            .map(|r| (r.0, r.1))
            .collect();
        ranges.sort_unstable();
        let mut union: Vec<(u64, u64)> = Vec::new();
        for (start, end) in ranges {
            if let Some(last) = union.last_mut().filter(|last| start <= last.1) {
                last.1 = last.1.max(end);
            } else {
                union.push((start, end));
            }
        }
        for run in &plan.runs {
            let start = multiply(run.vcn, cluster_size)?;
            if start >= plan.initialized {
                break;
            }
            if let Some(lcn) = run.lcn {
                let clusters = multiply(run.clusters, cluster_size)?
                    .min(plan.initialized - start)
                    .div_ceil(cluster_size);
                let end = lcn
                    .checked_add(clusters)
                    .ok_or_else(|| invalid("LCN overflow"))?;
                if !union
                    .iter()
                    .any(|&(first, last)| first <= lcn && last >= end)
                {
                    return Err(invalid(format!(
                        "LCN range {lcn:07x}..{end:07x} is not attributed to MFT {}:{} in the CSV",
                        id, sequence
                    )));
                }
            }
        }
        Ok(())
    }
}

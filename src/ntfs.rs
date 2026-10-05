//! Parsing of raw on-disk NTFS FILE records and nonresident mapping pairs.
//! MFT references alone cannot establish the volume's free-space bitmap.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, Read};

const MAX_RECORD: usize = 65536;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Extent {
    pub start_lcn: u64,
    pub cluster_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileName {
    pub parent_reference: u64,
    pub namespace: u8,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Record {
    pub number: u32,
    pub sequence: u16,
    pub lsn: u64,
    pub base_reference: u64,
    pub in_use: bool,
    pub extents: Vec<Extent>,
    pub file_names: Vec<FileName>,
    /// Populated only by the opt-in data-aware parser/scanner.
    pub attributes: Vec<RescueAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataRun {
    pub vcn: u64,
    pub clusters: u64,
    pub lcn: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttributeData {
    Resident(Vec<u8>),
    Nonresident {
        first_vcn: u64,
        last_vcn: u64,
        file_size: u64,
        initialized_size: u64,
        compression_unit: u16,
        runs: Vec<DataRun>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RescueAttribute {
    pub kind: u32,
    pub id: u16,
    pub name: Vec<u16>,
    pub flags: u16,
    pub data: AttributeData,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// Validate update-sequence fixups, attributes and mapping pairs. A damaged
/// record contributes no extents. All nonresident attribute types are included.
pub fn parse_record(raw: &[u8], sector_size: usize) -> io::Result<Record> {
    parse_record_inner(raw, sector_size, false)
}

pub fn parse_record_with_data(raw: &[u8], sector_size: usize) -> io::Result<Record> {
    parse_record_inner(raw, sector_size, true)
}

fn parse_record_inner(raw: &[u8], sector_size: usize, capture_data: bool) -> io::Result<Record> {
    if raw.len() < 48 || &raw[..4] != b"FILE" {
        return Err(invalid("not a FILE record"));
    }
    let size = u32_at(raw, 28) as usize;
    if !(512..=MAX_RECORD).contains(&size)
        || !size.is_power_of_two()
        || size > raw.len()
        || sector_size < 512
        || !sector_size.is_power_of_two()
        || !size.is_multiple_of(sector_size)
    {
        return Err(invalid("invalid or truncated record size"));
    }
    let used = u32_at(raw, 24) as usize;
    let attr_start = u16_at(raw, 20) as usize;
    let usa = u16_at(raw, 4) as usize;
    let usa_count = u16_at(raw, 6) as usize;
    if used > size
        || used < 48
        || attr_start < 48
        || attr_start >= used
        || !attr_start.is_multiple_of(8)
        || usa < 42
        || !usa.is_multiple_of(2)
        || usa_count != size / sector_size + 1
        || usa + usa_count * 2 > attr_start
        || usa + usa_count * 2 > sector_size - 2
    {
        return Err(invalid("invalid record header or update sequence array"));
    }
    let mut data = raw[..size].to_vec();
    for sector in 1..usa_count {
        let trailer = sector * sector_size - 2;
        if data[trailer..trailer + 2] != raw[usa..usa + 2] {
            return Err(invalid("sector update-sequence mismatch (torn record)"));
        }
        data[trailer..trailer + 2].copy_from_slice(&raw[usa + sector * 2..usa + sector * 2 + 2]);
    }
    let mut record = Record {
        number: if usa >= 48 { u32_at(&data, 44) } else { 0 },
        sequence: u16_at(&data, 16),
        lsn: u64_at(&data, 8),
        base_reference: u64_at(&data, 32),
        in_use: u16_at(&data, 22) & 1 != 0,
        extents: Vec::new(),
        file_names: Vec::new(),
        attributes: Vec::new(),
    };
    let mut at = attr_start;
    while at + 4 <= used {
        let kind = u32_at(&data, at);
        if kind == u32::MAX {
            return Ok(record);
        }
        if kind == 0 || at + 16 > used {
            return Err(invalid("invalid attribute header"));
        }
        let len = u32_at(&data, at + 4) as usize;
        if len < 24 || !len.is_multiple_of(8) || len > used - at {
            return Err(invalid("invalid attribute length"));
        }
        let attr = &data[at..at + len];
        let nonresident = attr[8];
        let minimum = match nonresident {
            0 => 24,
            1 => 64,
            _ => return Err(invalid("invalid nonresident flag")),
        };
        if len < minimum {
            return Err(invalid("truncated attribute"));
        }
        let name_len = usize::from(attr[9]) * 2;
        let name_at = u16_at(attr, 10) as usize;
        if name_len != 0 && (name_at < minimum || name_at + name_len > len) {
            return Err(invalid("invalid attribute name bounds"));
        }
        let capture = capture_data && matches!(kind, 0x20 | 0x80);
        let name = if capture && name_len != 0 {
            attr[name_at..name_at + name_len]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect()
        } else {
            Vec::new()
        };
        if nonresident == 0 {
            let value_len = u32_at(attr, 16) as usize;
            let value_at = u16_at(attr, 20) as usize;
            if value_at < minimum || value_at > len || value_len > len - value_at {
                return Err(invalid("invalid resident value bounds"));
            }
            if kind == 0x30 {
                record
                    .file_names
                    .push(parse_file_name(&attr[value_at..value_at + value_len])?);
            }
            if capture {
                record.attributes.push(RescueAttribute {
                    kind,
                    id: u16_at(attr, 14),
                    name,
                    flags: u16_at(attr, 12),
                    data: AttributeData::Resident(attr[value_at..value_at + value_len].to_vec()),
                });
            }
        } else {
            let run_at = u16_at(attr, 32) as usize;
            if run_at < minimum || run_at >= len || (name_len != 0 && run_at < name_at + name_len) {
                return Err(invalid("invalid mapping-pairs offset"));
            }
            let runs = parse_data_runs(&attr[run_at..], u64_at(attr, 16), u64_at(attr, 24))?;
            record.extents.extend(runs.iter().filter_map(|run| {
                run.lcn.map(|lcn| Extent {
                    start_lcn: lcn,
                    cluster_count: run.clusters,
                })
            }));
            if capture {
                record.attributes.push(RescueAttribute {
                    kind,
                    id: u16_at(attr, 14),
                    name,
                    flags: u16_at(attr, 12),
                    data: AttributeData::Nonresident {
                        first_vcn: u64_at(attr, 16),
                        last_vcn: u64_at(attr, 24),
                        file_size: u64_at(attr, 48),
                        initialized_size: u64_at(attr, 56),
                        compression_unit: u16_at(attr, 34),
                        runs,
                    },
                });
            }
        }
        at += len;
    }
    Err(invalid("missing attribute terminator"))
}

fn parse_file_name(value: &[u8]) -> io::Result<FileName> {
    if value.len() < 66 {
        return Err(invalid("truncated $FILE_NAME value"));
    }
    let name_end = 66 + usize::from(value[64]) * 2;
    if name_end > value.len() || value[65] > 3 {
        return Err(invalid("invalid $FILE_NAME length or namespace"));
    }
    let units: Vec<_> = value[66..name_end]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Ok(FileName {
        parent_reference: u64_at(value, 0),
        namespace: value[65],
        name: String::from_utf16_lossy(&units),
    })
}

/// Mapping pairs use unsigned run lengths and signed, relative LCN deltas.
/// Sparse runs advance the VCN but neither allocate space nor change the LCN.
#[cfg(test)]
fn parse_runs(bytes: &[u8], first_vcn: u64, last_vcn: u64) -> io::Result<Vec<Extent>> {
    Ok(parse_data_runs(bytes, first_vcn, last_vcn)?
        .into_iter()
        .filter_map(|run| {
            run.lcn.map(|lcn| Extent {
                start_lcn: lcn,
                cluster_count: run.clusters,
            })
        })
        .collect())
}

fn parse_data_runs(bytes: &[u8], first_vcn: u64, last_vcn: u64) -> io::Result<Vec<DataRun>> {
    let mut at = 0;
    let mut vcn = first_vcn;
    let mut lcn = 0_i128;
    let mut extents = Vec::new();
    while at < bytes.len() {
        let header = bytes[at];
        at += 1;
        if header == 0 {
            let expected = if last_vcn == u64::MAX && first_vcn == 0 {
                0
            } else {
                last_vcn
                    .checked_add(1)
                    .ok_or_else(|| invalid("VCN overflow"))?
            };
            if vcn != expected {
                return Err(invalid("runlist does not cover its declared VCN range"));
            }
            return Ok(extents);
        }
        let length_bytes = usize::from(header & 15);
        let offset_bytes = usize::from(header >> 4);
        if length_bytes == 0
            || length_bytes > 8
            || offset_bytes > 8
            || at + length_bytes + offset_bytes > bytes.len()
        {
            return Err(invalid("invalid mapping-pair field lengths"));
        }
        let mut length_buf = [0; 8];
        length_buf[..length_bytes].copy_from_slice(&bytes[at..at + length_bytes]);
        let count = u64::from_le_bytes(length_buf);
        if count == 0 {
            return Err(invalid("zero-length run"));
        }
        at += length_bytes;
        let run_vcn = vcn;
        vcn = vcn
            .checked_add(count)
            .ok_or_else(|| invalid("VCN overflow"))?;
        if offset_bytes != 0 {
            let sign = if bytes[at + offset_bytes - 1] & 0x80 != 0 {
                0xff
            } else {
                0
            };
            let mut delta = [sign; 8];
            delta[..offset_bytes].copy_from_slice(&bytes[at..at + offset_bytes]);
            lcn += i128::from(i64::from_le_bytes(delta));
            if lcn < 0 || lcn > i128::from(i64::MAX) {
                return Err(invalid("invalid physical cluster number"));
            }
            let start_lcn = lcn as u64;
            start_lcn
                .checked_add(count)
                .ok_or_else(|| invalid("LCN range overflow"))?;
            extents.push(DataRun {
                vcn: run_vcn,
                lcn: Some(start_lcn),
                clusters: count,
            });
        } else {
            extents.push(DataRun {
                vcn: run_vcn,
                lcn: None,
                clusters: count,
            });
        }
        at += offset_bytes;
    }
    Err(invalid("unterminated mapping pairs"))
}

#[derive(Debug, Default)]
pub struct ScanStats {
    pub bytes_read: u64,
    pub candidates: u64,
    pub valid: u64,
    pub rejected: u64,
    pub rejection_reasons: BTreeMap<String, u64>,
}

/// Find records at arbitrary offsets, including records crossing read boundaries.
pub fn scan_fragment(
    input: impl Read,
    sector_size: usize,
    record: impl FnMut(u64, Record),
) -> io::Result<ScanStats> {
    scan_fragment_inner(input, sector_size, false, record)
}

pub fn scan_fragment_with_data(
    input: impl Read,
    sector_size: usize,
    record: impl FnMut(u64, Record),
) -> io::Result<ScanStats> {
    scan_fragment_inner(input, sector_size, true, record)
}

fn scan_fragment_inner(
    mut input: impl Read,
    sector_size: usize,
    capture_data: bool,
    mut record: impl FnMut(u64, Record),
) -> io::Result<ScanStats> {
    let mut stats = ScanStats::default();
    let mut buffer = Vec::new();
    let mut chunk = vec![0; 4 * 1024 * 1024];
    let mut base = 0_u64;
    loop {
        let n = input.read(&mut chunk)?;
        stats.bytes_read += n as u64;
        buffer.extend_from_slice(&chunk[..n]);
        let limit = if n == 0 {
            buffer.len()
        } else {
            buffer.len().saturating_sub(MAX_RECORD)
        };
        let mut at = 0;
        while at < limit && at + 4 <= buffer.len() {
            if &buffer[at..at + 4] != b"FILE" {
                at += 1;
                continue;
            }
            stats.candidates += 1;
            match parse_record_inner(&buffer[at..], sector_size, capture_data) {
                Ok(parsed) => {
                    let size = u32_at(&buffer, at + 28) as usize;
                    record(base + at as u64, parsed);
                    stats.valid += 1;
                    at += size;
                }
                Err(error) => {
                    stats.rejected += 1;
                    *stats
                        .rejection_reasons
                        .entry(error.to_string())
                        .or_default() += 1;
                    at += 1;
                }
            }
        }
        if n == 0 {
            break;
        }
        buffer.drain(..at);
        base += at as u64;
    }
    Ok(stats)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterRange {
    pub start: u64,
    pub end: u64,
    pub status: &'static str,
    pub live_references: i64,
    pub deleted_references: i64,
    pub live_files: BTreeSet<String>,
    pub deleted_files: BTreeSet<String>,
}

#[derive(Default)]
pub struct ClusterMap {
    records: HashSet<Record>,
    events: BTreeMap<u64, (i64, i64, i64)>,
    pub duplicates: u64,
    pub live_records: u64,
    pub deleted_records: u64,
    pub max_lcn_end: u64,
}

impl ClusterMap {
    pub fn add(&mut self, record: Record) {
        if !self.records.insert(record.clone()) {
            self.duplicates += 1;
            return;
        }
        if record.in_use {
            self.live_records += 1;
        } else {
            self.deleted_records += 1;
        }
        for extent in record.extents {
            let end = extent.start_lcn + extent.cluster_count;
            self.max_lcn_end = self.max_lcn_end.max(end);
            for (at, delta) in [(extent.start_lcn, 1), (end, -1)] {
                let event = self.events.entry(at).or_default();
                if record.in_use {
                    event.0 += delta;
                } else {
                    event.1 += delta;
                }
            }
        }
    }

    /// An optional extracted volume $Bitmap provides authoritative allocation
    /// bits (LSB first). Its padding is excluded by the volume cluster count.
    pub fn ranges(mut self, clusters: u64, bitmap: Option<&[u8]>) -> io::Result<Vec<ClusterRange>> {
        if self.max_lcn_end > clusters {
            return Err(invalid(
                "MFT extent exceeds --clusters; check volume identity or damaged records",
            ));
        }
        if let Some(bitmap) = bitmap {
            if clusters > bitmap.len() as u64 * 8 {
                return Err(invalid("bitmap is shorter than --clusters"));
            }
            let mut previous = 0_i64;
            for lcn in 0..clusters {
                let allocated = i64::from((bitmap[(lcn / 8) as usize] >> (lcn % 8)) & 1);
                if allocated != previous {
                    self.events.entry(lcn).or_default().2 += allocated - previous;
                    previous = allocated;
                }
            }
        }
        self.events.entry(0).or_default();
        self.events.entry(clusters).or_default();
        // Resolve names after all fragments have been scanned. Sequence numbers
        // and in-use status keep reused/deleted base records from lending names
        // to unrelated extension records. Retain all recovered aliases.
        let owner_key = |record: &Record| {
            let reference = if record.base_reference != 0 {
                record.base_reference
            } else {
                u64::from(record.number) | (u64::from(record.sequence) << 48)
            };
            (reference, record.in_use)
        };
        let mut names: BTreeMap<(u64, bool), BTreeSet<String>> = BTreeMap::new();
        for record in &self.records {
            for name in &record.file_names {
                names
                    .entry(owner_key(record))
                    .or_default()
                    .insert(format!("{:?}", name.name));
            }
        }
        let mut owner_events: BTreeMap<u64, Vec<(bool, String, i64)>> = BTreeMap::new();
        for record in &self.records {
            let key = owner_key(record);
            let aliases = names
                .get(&key)
                .map(|names| names.iter().cloned().collect::<Vec<_>>().join(" | "))
                .unwrap_or_else(|| "[name unavailable]".to_string());
            let label = format!(
                "MFT {}:{} {}",
                key.0 & 0x0000_ffff_ffff_ffff,
                key.0 >> 48,
                aliases
            );
            for extent in &record.extents {
                for (at, delta) in [
                    (extent.start_lcn, 1),
                    (extent.start_lcn + extent.cluster_count, -1),
                ] {
                    owner_events
                        .entry(at)
                        .or_default()
                        .push((record.in_use, label.clone(), delta));
                }
            }
        }
        let mut live_files: BTreeMap<String, i64> = BTreeMap::new();
        let mut deleted_files: BTreeMap<String, i64> = BTreeMap::new();
        let mut ranges: Vec<ClusterRange> = Vec::new();
        let mut counts = (0, 0, 0);
        let mut start = 0;
        for (end, delta) in self.events {
            if end > start {
                let status = if bitmap.is_some() {
                    if counts.2 != 0 {
                        "allocated"
                    } else {
                        "unallocated"
                    }
                } else if counts.0 > 0 {
                    "allocated_inferred"
                } else if counts.1 > 0 {
                    "deleted_reference"
                } else {
                    "unknown"
                };
                let next = ClusterRange {
                    start,
                    end,
                    status,
                    live_references: counts.0,
                    deleted_references: counts.1,
                    live_files: live_files.keys().cloned().collect(),
                    deleted_files: deleted_files.keys().cloned().collect(),
                };
                if let Some(last) = ranges.last_mut().filter(|last| {
                    last.status == status
                        && last.live_references == counts.0
                        && last.deleted_references == counts.1
                        && last.live_files == next.live_files
                        && last.deleted_files == next.deleted_files
                }) {
                    last.end = end;
                } else {
                    ranges.push(next);
                }
            }
            counts.0 += delta.0;
            counts.1 += delta.1;
            counts.2 += delta.2;
            for (live, name, change) in owner_events.remove(&end).unwrap_or_default() {
                let owners = if live {
                    &mut live_files
                } else {
                    &mut deleted_files
                };
                let count = owners.entry(name.clone()).or_default();
                *count += change;
                if *count == 0 {
                    owners.remove(&name);
                }
            }
            start = end;
        }
        Ok(ranges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_record(in_use: bool) -> Vec<u8> {
        let mut data = vec![0; 1024];
        data[..4].copy_from_slice(b"FILE");
        data[4..6].copy_from_slice(&48_u16.to_le_bytes());
        data[6..8].copy_from_slice(&3_u16.to_le_bytes());
        data[16..18].copy_from_slice(&1_u16.to_le_bytes());
        data[20..22].copy_from_slice(&56_u16.to_le_bytes());
        data[22..24].copy_from_slice(&u16::from(in_use).to_le_bytes());
        data[24..28].copy_from_slice(&136_u32.to_le_bytes());
        data[28..32].copy_from_slice(&1024_u32.to_le_bytes());
        data[44..48].copy_from_slice(&42_u32.to_le_bytes());
        data[48..50].copy_from_slice(&0xabcd_u16.to_le_bytes());
        data[510..512].copy_from_slice(&0xabcd_u16.to_le_bytes());
        data[1022..1024].copy_from_slice(&0xabcd_u16.to_le_bytes());
        let attr = &mut data[56..128];
        attr[..4].copy_from_slice(&0x80_u32.to_le_bytes());
        attr[4..8].copy_from_slice(&72_u32.to_le_bytes());
        attr[8] = 1;
        attr[24..32].copy_from_slice(&2_u64.to_le_bytes());
        attr[32..34].copy_from_slice(&64_u16.to_le_bytes());
        attr[64..68].copy_from_slice(&[0x11, 3, 10, 0]);
        data[128..132].copy_from_slice(&u32::MAX.to_le_bytes());
        data
    }

    #[test]
    fn validates_fixups_and_nonresident_runs() {
        let mut raw = file_record(true);
        let parsed = parse_record(&raw, 512).unwrap();
        assert_eq!(parsed.number, 42);
        assert!(parsed.in_use);
        assert_eq!(
            parsed.extents,
            vec![Extent {
                start_lcn: 10,
                cluster_count: 3
            }]
        );
        raw[510] ^= 1;
        assert!(parse_record(&raw, 512).is_err());
    }

    #[test]
    fn parses_resident_unicode_file_name_and_rejects_truncation() {
        let mut raw = file_record(true);
        let name = "资料,\"😀.zip";
        let units: Vec<_> = name.encode_utf16().collect();
        let value_len = 66 + units.len() * 2;
        let attr_len = (24 + value_len).next_multiple_of(8);
        let end = 128 + attr_len;
        raw[128..end + 8].fill(0);
        raw[24..28].copy_from_slice(&((end + 8) as u32).to_le_bytes());
        let attr = &mut raw[128..end];
        attr[..4].copy_from_slice(&0x30_u32.to_le_bytes());
        attr[4..8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        attr[16..20].copy_from_slice(&(value_len as u32).to_le_bytes());
        attr[20..22].copy_from_slice(&24_u16.to_le_bytes());
        attr[24..32].copy_from_slice(&(5_u64 | (7_u64 << 48)).to_le_bytes());
        attr[24 + 64] = units.len() as u8;
        attr[24 + 65] = 1;
        for (index, unit) in units.iter().enumerate() {
            attr[90 + index * 2..92 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        raw[end..end + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let record = parse_record(&raw, 512).unwrap();
        assert_eq!(
            record.file_names[0],
            FileName {
                name: name.to_string(),
                namespace: 1,
                parent_reference: 5 | (7 << 48),
            }
        );
        assert_eq!(record.extents.len(), 1);
        raw[128 + 24 + 64] = 255;
        assert!(parse_record(&raw, 512).is_err());
    }

    fn with_name(mut record: Record, name: &str) -> Record {
        record.file_names.push(FileName {
            name: name.into(),
            namespace: 1,
            parent_reference: 5,
        });
        record
    }

    #[test]
    fn owner_changes_split_ranges_even_with_equal_reference_counts() {
        let mut map = ClusterMap::default();
        map.add(with_name(record_at(true, 0, 3), "first.zip"));
        let mut second = with_name(record_at(true, 3, 2), "second.zip");
        second.number = 43;
        map.add(second);
        map.add(with_name(record_at(false, 1, 3), "deleted.zip"));
        let ranges = map.ranges(5, None).unwrap();
        let left = ranges.iter().find(|r| r.start == 1).unwrap();
        let right = ranges.iter().find(|r| r.start == 3).unwrap();
        assert!(left.live_files.iter().any(|s| s.contains("first.zip")));
        assert!(right.live_files.iter().any(|s| s.contains("second.zip")));
        assert!(
            right
                .deleted_files
                .iter()
                .any(|s| s.contains("deleted.zip"))
        );
        assert_eq!(left.live_references, right.live_references);
        assert_eq!(left.deleted_references, right.deleted_references);
    }

    #[test]
    fn resolves_extension_names_across_fragments_with_sequence_validation() {
        let mut base = with_name(record_at(true, 0, 1), "long-name.zip");
        base = with_name(base, "LONGNA~1.ZIP");
        let mut extension = record_at(true, 5, 2);
        extension.number = 99;
        extension.base_reference = 42 | (1 << 48);
        let mut stale = extension.clone();
        stale.number = 100;
        stale.base_reference = 42 | (2 << 48);
        stale.extents[0].start_lcn = 8;
        let mut map = ClusterMap::default();
        map.add(extension);
        map.add(stale);
        map.add(base);
        let ranges = map.ranges(10, None).unwrap();
        let linked = ranges.iter().find(|r| r.start == 5).unwrap();
        let label = linked.live_files.first().unwrap();
        assert!(label.contains("MFT 42:1"));
        assert!(label.contains("long-name.zip"));
        assert!(label.contains("LONGNA~1.ZIP"));
        let stale = ranges.iter().find(|r| r.start == 8).unwrap();
        assert!(
            stale
                .live_files
                .first()
                .unwrap()
                .contains("[name unavailable]")
        );
    }

    #[test]
    fn handles_negative_lcn_deltas_sparse_runs_and_extension_vcns() {
        let runs = parse_runs(&[0x11, 3, 100, 0x01, 2, 0x11, 4, 0xfb, 0], 8, 16).unwrap();
        assert_eq!(
            runs,
            vec![
                Extent {
                    start_lcn: 100,
                    cluster_count: 3
                },
                Extent {
                    start_lcn: 95,
                    cluster_count: 4
                }
            ]
        );
        assert!(parse_runs(&[0x11, 1, 0xff, 0], 0, 0).is_err());
        assert!(parse_runs(&[0x91, 1, 0], 0, 0).is_err());
        assert!(parse_runs(&[0x11, 0, 2, 0], 0, 0).is_err());
        assert!(parse_runs(&[0x11, 3, 2, 0], 0, 5).is_err());
    }

    #[test]
    fn rejects_bad_attributes_without_retaining_partial_extents() {
        let mut raw = file_record(true);
        raw[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_record(&raw, 512).is_err());
        let mut raw = file_record(true);
        raw[128..132].fill(0);
        assert!(parse_record(&raw, 512).is_err());
        assert!(parse_record(&file_record(true)[..900], 512).is_err());
    }

    #[test]
    fn scans_unaligned_records_across_chunk_boundaries() {
        let mut fragment = vec![0; 4 * 1024 * 1024 - 17];
        let offset = fragment.len() as u64;
        fragment.extend(file_record(true));
        fragment.extend(file_record(false));
        fragment.extend_from_slice(b"FILE truncated");
        let mut found = Vec::new();
        let stats = scan_fragment(&fragment[..], 512, |at, rec| found.push((at, rec))).unwrap();
        assert_eq!(stats.valid, 2);
        assert_eq!(stats.rejected, 1);
        assert_eq!(found[0].0, offset);
        assert!(!found[1].1.in_use);
    }

    fn record_at(in_use: bool, start: u64, count: u64) -> Record {
        let mut record = parse_record(&file_record(in_use), 512).unwrap();
        record.extents = vec![Extent {
            start_lcn: start,
            cluster_count: count,
        }];
        record
    }

    #[test]
    fn merges_fragments_without_calling_missing_records_free() {
        let mut map = ClusterMap::default();
        let live = record_at(true, 4, 4);
        map.add(live.clone());
        map.add(live);
        map.add(record_at(false, 6, 4));
        assert_eq!(map.duplicates, 1);
        let ranges = map.ranges(12, None).unwrap();
        let actual: Vec<_> = ranges.iter().map(|r| (r.start, r.end, r.status)).collect();
        assert_eq!(
            actual,
            vec![
                (0, 4, "unknown"),
                (4, 6, "allocated_inferred"),
                (6, 8, "allocated_inferred"),
                (8, 10, "deleted_reference"),
                (10, 12, "unknown")
            ]
        );
        assert_eq!(ranges[2].live_references, 1);
        assert_eq!(ranges[2].deleted_references, 1);
    }

    #[test]
    fn bitmap_controls_allocation_even_when_mft_disagrees() {
        let mut map = ClusterMap::default();
        map.add(record_at(true, 0, 2));
        let ranges = map.ranges(8, Some(&[0b0000_0010])).unwrap();
        assert_eq!(ranges[0].status, "unallocated");
        assert_eq!(ranges[0].live_references, 1);
        assert_eq!(ranges[1].status, "allocated");
        assert_eq!(ranges.last().unwrap().end, 8);
        assert!(ClusterMap::default().ranges(9, Some(&[0])).is_err());
    }
}

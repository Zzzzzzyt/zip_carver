//! ZIP-assisted cluster-map recovery. Scanner offsets are absolute image bytes;
//! map LCNs are relative to the NTFS volume, VCNs to the recovered ZIP file.
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use flate2::{Decompress, FlushDecompress, Status};

use crate::{Finding, RecordKind};

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("byte offset overflow"))
}

fn u16le(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(b[p..p + 2].try_into().unwrap())
}

fn u32le(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}

fn check_cancel(cancel: &AtomicBool) -> io::Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"))
    } else {
        Ok(())
    }
}

/// DOS timestamps have no timezone and a two-second resolution.
pub fn dos_datetime(text: &str) -> io::Result<u32> {
    let b = text.as_bytes();
    if b.len() != 19
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(invalid(
            "datetime must be YYYY-MM-DDTHH:MM:SS (ZIP local time)",
        ));
    }
    let number = |a: usize, z: usize| -> io::Result<u32> {
        if !b[a..z].iter().all(u8::is_ascii_digit) {
            return Err(invalid("invalid datetime digits"));
        }
        Ok(b[a..z].iter().fold(0, |v, c| v * 10 + u32::from(c - b'0')))
    };
    let (y, m, d, h, min, s) = (
        number(0, 4)?,
        number(5, 7)?,
        number(8, 10)?,
        number(11, 13)?,
        number(14, 16)?,
        number(17, 19)?,
    );
    let leap = y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let days = match m {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    if !(1980..=2107).contains(&y) || d == 0 || d > days || h > 23 || min > 59 || s > 59 {
        return Err(invalid("invalid DOS datetime"));
    }
    Ok((((y - 1980) << 9 | m << 5 | d) << 16) | (h << 11 | min << 5 | (s / 2)))
}

fn valid_stamp(stamp: u32) -> bool {
    let date = stamp >> 16;
    let time = stamp & 0xffff;
    dos_datetime(&format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        1980 + (date >> 9),
        (date >> 5) & 15,
        date & 31,
        time >> 11,
        (time >> 5) & 63,
        (time & 31) * 2
    ))
    .is_ok()
}

/// Parse Python's bytes repr without evaluating Python expressions.
pub fn parse_python_bytes(text: &str) -> io::Result<Vec<u8>> {
    let b = text.as_bytes();
    if b.len() < 3 || b[0] != b'b' || !matches!(b[1], b'\'' | b'"') || b.last() != Some(&b[1]) {
        return Err(invalid("expected Python bytes literal"));
    }
    let mut result = Vec::new();
    let mut i = 2;
    let end = b.len() - 1;
    while i < end {
        let c = b[i];
        i += 1;
        if c == b'\\' {
            if i >= end {
                return Err(invalid("truncated bytes escape"));
            }
            let c = b[i];
            i += 1;
            result.push(match c {
                b'\\' | b'\'' | b'"' => c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'a' => 7,
                b'b' => 8,
                b'f' => 12,
                b'v' => 11,
                b'x' => {
                    if i + 2 > end {
                        return Err(invalid("truncated hex escape"));
                    }
                    let digits = std::str::from_utf8(&b[i..i + 2])
                        .map_err(|_| invalid("invalid hex escape"))?;
                    let value = u8::from_str_radix(digits, 16)
                        .map_err(|_| invalid("invalid hex escape"))?;
                    i += 2;
                    value
                }
                _ => return Err(invalid("unsupported bytes escape")),
            });
        } else {
            if c == b[1] || !(0x20..=0x7e).contains(&c) {
                return Err(invalid("unescaped byte in literal"));
            }
            result.push(c);
        }
    }
    Ok(result)
}

/// Total record size, including fields omitted by the first-pass scanner.
/// ZIP entry comments belong to CDFH; archive comments belong to EOCD.
pub fn header_length(f: &Finding) -> io::Result<u64> {
    let b = &f.raw_header;
    let (signature, fixed) = match f.kind {
        RecordKind::LocalFileHeader => (b"PK\x03\x04", 30),
        RecordKind::CentralDirectoryHeader => (b"PK\x01\x02", 46),
        RecordKind::DataDescriptor => (b"PK\x07\x08", 16),
        RecordKind::EndOfCentralDirectory => (b"PK\x05\x06", 22),
    };
    if b.len() < fixed || &b[..4] != signature {
        return Err(invalid("invalid scanner header"));
    }
    let (name, extra, comment) = match f.kind {
        RecordKind::LocalFileHeader => (u16le(b, 26), u16le(b, 28), 0),
        RecordKind::CentralDirectoryHeader => (u16le(b, 28), u16le(b, 30), u16le(b, 32)),
        RecordKind::EndOfCentralDirectory => (0, 0, u16le(b, 20)),
        RecordKind::DataDescriptor => (0, 0, 0),
    };
    let total = fixed + usize::from(name) + usize::from(extra) + usize::from(comment);
    if b.len() < fixed + usize::from(name) || b.len() > total {
        return Err(invalid("invalid scanner header length"));
    }
    Ok(total as u64)
}

pub fn parse_finding(line: &str) -> io::Result<Finding> {
    let mut parts = line.trim_end().splitn(3, ' ');
    let kind = match parts.next() {
        Some("FILE") => RecordKind::LocalFileHeader,
        Some("CDFH") => RecordKind::CentralDirectoryHeader,
        Some("DATA") => RecordKind::DataDescriptor,
        Some("EOCD") => RecordKind::EndOfCentralDirectory,
        _ => return Err(invalid("unknown scanner record type")),
    };
    let offset = u64::from_str_radix(parts.next().ok_or_else(|| invalid("missing offset"))?, 16)
        .map_err(|_| invalid("invalid scanner offset"))?;
    let raw_header = parse_python_bytes(parts.next().ok_or_else(|| invalid("missing header"))?)?;
    let f = Finding {
        kind,
        offset,
        raw_header,
    };
    header_length(&f)?;
    Ok(f)
}

pub fn write_finding(out: &mut impl Write, f: &Finding) -> io::Result<()> {
    write!(out, "{} {:012x} b'", f.kind, f.offset)?;
    for &b in &f.raw_header {
        match b {
            b'\\' => write!(out, "\\\\")?,
            b'\'' => write!(out, "\\'")?,
            b'\n' => write!(out, "\\n")?,
            b'\r' => write!(out, "\\r")?,
            b'\t' => write!(out, "\\t")?,
            0x20..=0x7e => out.write_all(&[b])?,
            _ => write!(out, "\\x{b:02x}")?,
        }
    }
    writeln!(out, "'")
}

type Sizes = (u32, u32, u32);
fn sizes(b: &[u8], start: usize) -> Sizes {
    (u32le(b, start), u32le(b, start + 4), u32le(b, start + 8))
}

/// Two passes avoid retaining every DATA descriptor from a whole-disk scan.
pub fn filter_headers(
    input: &mut (impl Read + Seek),
    from: u32,
    to: u32,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> io::Result<Vec<Finding>> {
    if from > to {
        return Err(invalid("--from must not be later than --to"));
    }
    let mut filtered = Vec::new();
    let mut tuples = HashSet::new();
    let mut bytes = 0;
    for pass in 0..2 {
        input.seek(SeekFrom::Start(0))?;
        let mut reader = BufReader::new(&mut *input);
        let mut line = String::new();
        let mut line_no = 0;
        loop {
            check_cancel(cancel)?;
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            bytes += n as u64;
            line_no += 1;
            if line_no % 4096 == 0 {
                progress(bytes);
            }
            let text = line.trim_end();
            if line_no == 1 && !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            if text.is_empty() {
                continue;
            }
            if pass == 1 && !text.starts_with("DATA ") {
                continue;
            }
            let f =
                parse_finding(text).map_err(|e| invalid(format!("scanner line {line_no}: {e}")))?;
            if pass == 0 {
                let stamp = match f.kind {
                    RecordKind::LocalFileHeader => u32le(&f.raw_header, 10),
                    RecordKind::CentralDirectoryHeader => u32le(&f.raw_header, 12),
                    _ => continue,
                };
                if (from..=to).contains(&stamp) && valid_stamp(stamp) {
                    if f.kind == RecordKind::CentralDirectoryHeader {
                        tuples.insert(sizes(&f.raw_header, 16));
                    }
                    filtered.push(f);
                }
            } else if tuples.contains(&sizes(&f.raw_header, 4)) {
                filtered.push(f);
            }
        }
    }
    progress(bytes);
    filtered.sort_by_key(|f| f.offset);
    filtered.dedup();
    Ok(filtered)
}

pub fn read_map(input: impl BufRead) -> io::Result<Vec<Option<u64>>> {
    let mut map = Vec::new();
    for (i, line) in input.lines().enumerate() {
        let line = line?;
        let (vcn, lcn) = line
            .split_once('\t')
            .ok_or_else(|| invalid(format!("map line {} lacks tab", i + 1)))?;
        let vcn = u64::from_str_radix(vcn.trim(), 16).map_err(|_| invalid("invalid map VCN"))?;
        if vcn != map.len() as u64 {
            return Err(invalid("map VCNs must be consecutive, starting at zero"));
        }
        let lcn = if lcn.trim().is_empty() {
            None
        } else {
            Some(u64::from_str_radix(lcn.trim(), 16).map_err(|_| invalid("invalid map LCN"))?)
        };
        map.push(lcn);
    }
    if map.is_empty() {
        return Err(invalid("empty cluster map"));
    }
    Ok(map)
}

pub fn write_map(map: &[Option<u64>], out: &mut impl Write) -> io::Result<()> {
    for (vcn, lcn) in map.iter().enumerate() {
        match lcn {
            Some(lcn) => writeln!(out, "{vcn:08x}\t{lcn:08x}")?,
            None => writeln!(out, "{vcn:08x}\t")?,
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: Vec<u8>,
    pub stream_start: u64,
    pub physical_header: u64,
    pub logical_header: u64,
    pub local: Finding,
    pub compressed: u64,
    pub uncompressed: u64,
    pub crc: u32,
    pub method: u16,
}

pub struct Entries {
    pub entries: Vec<Entry>,
    pub skipped: usize,
}

/// Duplicate names/physical copies are deliberately not resolved by guessing.
pub fn match_entries(headers: &[Finding], file_size: u64) -> io::Result<Entries> {
    let mut locals: HashMap<Vec<u8>, Vec<&Finding>> = HashMap::new();
    let mut centrals: HashMap<Vec<u8>, Vec<&Finding>> = HashMap::new();
    for f in headers {
        header_length(f)?;
        let b = &f.raw_header;
        match f.kind {
            RecordKind::LocalFileHeader => locals
                .entry(b[30..30 + usize::from(u16le(b, 26))].to_vec())
                .or_default()
                .push(f),
            RecordKind::CentralDirectoryHeader => centrals
                .entry(b[46..46 + usize::from(u16le(b, 28))].to_vec())
                .or_default()
                .push(f),
            _ => {}
        }
    }
    let mut result = Entries {
        entries: Vec::new(),
        skipped: 0,
    };
    for (name, cs) in centrals {
        let Some(ls) = locals.get(&name) else {
            result.skipped += 1;
            continue;
        };
        if cs.len() != 1 || ls.len() != 1 {
            result.skipped += 1;
            continue;
        }
        let (c, l) = (cs[0], ls[0]);
        let (cb, lb) = (&c.raw_header, &l.raw_header);
        let (crc, compressed, uncompressed) = sizes(cb, 16);
        let flags = u16le(cb, 8);
        let method = u16le(cb, 10);
        let logical_header = u64::from(u32le(cb, 42));
        let stream_start = add(logical_header, header_length(l)?)?;
        if flags & 0x2041 != 0
            || !matches!(method, 0 | 8)
            || u16le(cb, 34) != 0
            || [compressed, uncompressed, u32le(cb, 42)].contains(&u32::MAX)
            || method != u16le(lb, 8)
            || flags != u16le(lb, 6)
            || cb[12..16] != lb[10..14]
            || (flags & 8 == 0 && sizes(lb, 14) != (crc, compressed, uncompressed))
            || add(stream_start, u64::from(compressed))? > file_size
        {
            result.skipped += 1;
            continue;
        }
        result.entries.push(Entry {
            name,
            stream_start,
            physical_header: l.offset,
            logical_header,
            local: l.clone(),
            compressed: u64::from(compressed),
            uncompressed: u64::from(uncompressed),
            crc,
            method,
        });
    }
    result.entries.sort_by_key(|e| e.logical_header);
    // Two unrelated entries cannot own overlapping archive ranges.
    let mut overlaps = HashSet::new();
    for (i, e) in result.entries.iter().enumerate() {
        for (j, next) in result.entries.iter().enumerate().skip(i + 1) {
            if next.logical_header >= e.stream_start + e.compressed {
                break;
            }
            overlaps.insert(i);
            overlaps.insert(j);
        }
    }
    result.skipped += overlaps.len();
    result.entries = result
        .entries
        .into_iter()
        .enumerate()
        .filter_map(|(i, e)| (!overlaps.contains(&i)).then_some(e))
        .collect();
    Ok(result)
}

#[derive(Debug, Clone)]
pub struct CarveOptions {
    pub cluster_size: u64,
    pub partition_offset: u64,
    pub file_size: u64,
    pub max_stream_bytes: u64,
    pub max_trials: u64,
    pub assume_contiguous: bool,
}

#[derive(Debug, Default)]
pub struct CarveStats {
    pub anchors: u64,
    pub validated: u64,
    pub assumed: u64,
    pub trials: u64,
    pub interrupted: bool,
    pub unresolved: u64,
}

fn disk_offset(lcn: u64, cluster_size: u64, partition: u64) -> io::Result<u64> {
    add(
        lcn.checked_mul(cluster_size)
            .ok_or_else(|| invalid("LCN overflow"))?,
        partition,
    )
}

fn prediction(left: (usize, u64), right: (usize, u64), vcn: usize, front: bool) -> Option<u64> {
    if front {
        left.1.checked_add((vcn - left.0) as u64)
    } else {
        right.1.checked_sub((right.0 - vcn) as u64)
    }
}

fn verify_header(image: &mut (impl Read + Seek), image_size: u64, f: &Finding) -> io::Result<bool> {
    if add(f.offset, header_length(f)?)? > image_size {
        return Ok(false);
    }
    image.seek(SeekFrom::Start(f.offset))?;
    let mut bytes = vec![0; f.raw_header.len()];
    image.read_exact(&mut bytes)?;
    Ok(bytes == f.raw_header)
}

fn seed_anchors(
    image: &mut (impl Read + Seek),
    image_size: u64,
    entries: &[Entry],
    map: &mut [Option<u64>],
    options: &CarveOptions,
    cancel: &AtomicBool,
) -> io::Result<u64> {
    // Collect all proposals before applying any: collisions between archives
    // must not be resolved by whichever header was encountered first.
    let mut proposals: BTreeMap<usize, HashSet<u64>> = BTreeMap::new();
    for e in entries {
        check_cancel(cancel)?;
        let Some(relative) = e.physical_header.checked_sub(options.partition_offset) else {
            continue;
        };
        if relative % options.cluster_size != e.logical_header % options.cluster_size
            || !verify_header(image, image_size, &e.local)?
        {
            continue;
        }
        // Only bytes actually captured by the scanner establish contiguous anchors.
        // The omitted extra field may straddle an NTFS fragmentation boundary.
        let first = (e.logical_header / options.cluster_size) as usize;
        let last = ((e.logical_header + e.local.raw_header.len() as u64 - 1) / options.cluster_size)
            as usize;
        if (first..=last).any(|vcn| {
            map.get(vcn)
                .copied()
                .flatten()
                .is_some_and(|lcn| lcn != relative / options.cluster_size + (vcn - first) as u64)
        }) {
            continue;
        }
        for vcn in first..=last {
            let lcn = relative / options.cluster_size + (vcn - first) as u64;
            if vcn < map.len() {
                proposals.entry(vcn).or_default().insert(lcn);
            }
        }
    }
    let mut added = 0;
    for (vcn, lcns) in proposals {
        if map[vcn].is_none() && lcns.len() == 1 {
            map[vcn] = lcns.into_iter().next();
            added += 1;
        }
    }
    Ok(added)
}

struct CandidateBuffers {
    front: Vec<u8>,
    back: Vec<u8>,
    bad_front: Vec<usize>,
    bad_back: Vec<usize>,
}

fn candidate_buffers(
    image: &mut (impl Read + Seek),
    image_size: u64,
    map: &[Option<u64>],
    entry: &Entry,
    gap: (usize, usize),
    options: &CarveOptions,
    cancel: &AtomicBool,
) -> io::Result<CandidateBuffers> {
    let len = usize::try_from(entry.compressed).map_err(|_| invalid("stream too large"))?;
    let mut buffers = CandidateBuffers {
        front: vec![0; len],
        back: vec![0; len],
        bad_front: Vec::new(),
        bad_back: Vec::new(),
    };
    let cs = options.cluster_size;
    let end = entry.stream_start + entry.compressed;
    let left = (gap.0, map[gap.0].unwrap());
    let right = (gap.1, map[gap.1].unwrap());
    let mut position = entry.stream_start;
    while position < end {
        check_cancel(cancel)?;
        let vcn = (position / cs) as usize;
        let start = (position - entry.stream_start) as usize;
        let length = (cs - position % cs).min(end - position) as usize;
        for front in [true, false] {
            let lcn = map[vcn].or_else(|| prediction(left, right, vcn, front));
            let offset = lcn
                .and_then(|lcn| disk_offset(lcn, cs, options.partition_offset).ok())
                .and_then(|offset| offset.checked_add(position % cs));
            let valid = offset
                .and_then(|offset| offset.checked_add(length as u64))
                .is_some_and(|last| last <= image_size);
            if !valid {
                if front {
                    buffers.bad_front.push(vcn);
                } else {
                    buffers.bad_back.push(vcn);
                }
                continue;
            }
            let target = if front {
                &mut buffers.front
            } else {
                &mut buffers.back
            };
            image.seek(SeekFrom::Start(offset.unwrap()))?;
            image.read_exact(&mut target[start..start + length])?;
        }
        position += length as u64;
    }
    Ok(buffers)
}

/// Streaming raw DEFLATE, bounded output memory, exact compressed length and CRC.
fn validate_stream(entry: &Entry, parts: [&[u8]; 2], cancel: &AtomicBool) -> io::Result<bool> {
    let mut crc = crc32fast::Hasher::new();
    if entry.method == 0 {
        if entry.compressed != entry.uncompressed {
            return Ok(false);
        }
        for part in parts {
            for chunk in part.chunks(65536) {
                check_cancel(cancel)?;
                crc.update(chunk);
            }
        }
        return Ok(crc.finalize() == entry.crc);
    }
    let mut decoder = Decompress::new(false);
    let mut output = [0; 65536];
    for part in parts {
        let mut at = 0;
        loop {
            check_cancel(cancel)?;
            let before_in = decoder.total_in();
            let before_out = decoder.total_out();
            let status = match decoder.decompress(&part[at..], &mut output, FlushDecompress::None) {
                Ok(status) => status,
                Err(_) => return Ok(false),
            };
            let consumed = (decoder.total_in() - before_in) as usize;
            let produced = (decoder.total_out() - before_out) as usize;
            at += consumed;
            if decoder.total_out() > entry.uncompressed {
                return Ok(false);
            }
            crc.update(&output[..produced]);
            if status == Status::StreamEnd {
                return Ok(decoder.total_in() == entry.compressed
                    && decoder.total_out() == entry.uncompressed
                    && crc.finalize() == entry.crc);
            }
            if consumed == 0 && produced == 0 {
                if at != part.len() {
                    return Ok(false);
                }
                break;
            }
            if at == part.len() && produced < output.len() {
                break;
            }
        }
    }
    // Drain a possible final buffered end-of-block without accepting truncation.
    loop {
        check_cancel(cancel)?;
        let before = decoder.total_out();
        let status = match decoder.decompress(&[], &mut output, FlushDecompress::Finish) {
            Ok(status) => status,
            Err(_) => return Ok(false),
        };
        let produced = (decoder.total_out() - before) as usize;
        if decoder.total_out() > entry.uncompressed {
            return Ok(false);
        }
        crc.update(&output[..produced]);
        if status == Status::StreamEnd {
            return Ok(decoder.total_in() == entry.compressed
                && decoder.total_out() == entry.uncompressed
                && crc.finalize() == entry.crc);
        }
        if produced == 0 {
            return Ok(false);
        }
    }
}

pub fn carve(
    image: &mut (impl Read + Seek),
    image_size: u64,
    map: &mut [Option<u64>],
    entries: &[Entry],
    options: &CarveOptions,
    cancel: &AtomicBool,
    mut report: impl FnMut(&str),
) -> io::Result<CarveStats> {
    if options.cluster_size < 512
        || !options.cluster_size.is_power_of_two()
        || options.file_size.div_ceil(options.cluster_size) != map.len() as u64
    {
        return Err(invalid("invalid cluster size or map/file-size mismatch"));
    }
    for (vcn, lcn) in map.iter().enumerate() {
        if let Some(lcn) = lcn {
            let bytes = options
                .cluster_size
                .min(options.file_size - vcn as u64 * options.cluster_size);
            if add(
                disk_offset(*lcn, options.cluster_size, options.partition_offset)?,
                bytes,
            )? > image_size
            {
                return Err(invalid(format!(
                    "known mapping VCN {vcn:x} exceeds disk image"
                )));
            }
        }
    }
    let mut stats = CarveStats::default();
    let work = (|| -> io::Result<()> {
        stats.anchors = seed_anchors(image, image_size, entries, map, options, cancel)?;
        report(&format!("Seeded {} header anchor clusters", stats.anchors));
        let mut left = 0;
        while left < map.len() {
            check_cancel(cancel)?;
            let Some(left_lcn) = map[left] else {
                left += 1;
                continue;
            };
            let Some(right) = (left + 1..map.len()).find(|&v| map[v].is_some()) else {
                break;
            };
            if right == left + 1 {
                left = right;
                continue;
            }
            let right_lcn = map[right].unwrap();
            let gap = right - left - 1;
            let contiguous = left_lcn.checked_add((right - left) as u64) == Some(right_lcn);
            report(&format!(
                "Gap VCN {:08x}..{:08x}: {gap} clusters",
                left + 1,
                right
            ));
            if contiguous && options.assume_contiguous {
                for (vcn, value) in map.iter_mut().enumerate().take(right).skip(left + 1) {
                    *value = Some(left_lcn + (vcn - left) as u64);
                }
                stats.assumed += gap as u64;
                report("  Filled by unverified continuous-mapping assumption");
                left = right;
                continue;
            }
            let start_byte = (left as u64 + 1) * options.cluster_size;
            let end_byte = right as u64 * options.cluster_size;
            let entry = entries.iter().find(|e| {
                e.stream_start <= start_byte && e.stream_start + e.compressed >= end_byte
            });
            let Some(entry) = entry else {
                report("  Unresolved: no ZIP stream covers this entire gap");
                left = right;
                continue;
            };
            if entry.compressed > options.max_stream_bytes {
                report("  Unresolved: stream exceeds --max-stream-bytes");
                left = right;
                continue;
            }
            let first = (entry.stream_start / options.cluster_size) as usize;
            let last =
                ((entry.stream_start + entry.compressed - 1) / options.cluster_size) as usize;
            if (first..=last).any(|v| map[v].is_none() && !(left < v && v < right)) {
                report("  Unresolved: stream contains another unknown gap");
                left = right;
                continue;
            }
            let trials = if contiguous { 1 } else { gap as u64 + 1 };
            if trials > options.max_trials {
                report("  Unresolved: split count exceeds --max-trials");
                left = right;
                continue;
            }
            let buffers = candidate_buffers(
                image,
                image_size,
                map,
                entry,
                (left, right),
                options,
                cancel,
            )?;
            let mut winner = None;
            let mut ambiguous = false;
            let mut last_report = std::time::Instant::now();
            for front_count in 0..trials {
                check_cancel(cancel)?;
                if last_report.elapsed().as_secs() >= 5 {
                    report(&format!("  Testing split {}/{trials}", front_count + 1));
                    last_report = std::time::Instant::now();
                }
                // First backward-mapped VCN; includes both all-back and all-front.
                let split = left + 1 + front_count as usize;
                if buffers.bad_front.iter().any(|&v| v < split)
                    || buffers.bad_back.iter().any(|&v| v >= split)
                {
                    continue;
                }
                let split_byte = (split as u64 * options.cluster_size)
                    .saturating_sub(entry.stream_start)
                    .min(entry.compressed) as usize;
                stats.trials += 1;
                if validate_stream(
                    entry,
                    [&buffers.front[..split_byte], &buffers.back[split_byte..]],
                    cancel,
                )? {
                    if winner.is_some() {
                        ambiguous = true;
                        break;
                    }
                    winner = Some(split);
                }
            }
            if let Some(split) = winner.filter(|_| !ambiguous) {
                for (vcn, value) in map.iter_mut().enumerate().take(right).skip(left + 1) {
                    *value = prediction((left, left_lcn), (right, right_lcn), vcn, vcn < split);
                }
                stats.validated += gap as u64;
                report(&format!(
                    "  CRC/size validated: {:?}, split VCN {split:08x}",
                    String::from_utf8_lossy(&entry.name)
                ));
            } else {
                report(if ambiguous {
                    "  Unresolved: multiple valid mappings"
                } else {
                    "  Unresolved: no split passes stream/size/CRC checks"
                });
            }
            left = right;
        }
        Ok(())
    })();
    if let Err(error) = work {
        if error.kind() == io::ErrorKind::Interrupted {
            stats.interrupted = true;
        } else {
            return Err(error);
        }
    }
    stats.unresolved = map.iter().filter(|v| v.is_none()).count() as u64;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::DeflateEncoder};

    #[test]
    fn streaming_deflate_checks_end_length_crc_and_large_output() {
        let payload = b"many repetitions and a little changing context\n".repeat(8000);
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut entry = Entry {
            name: Vec::new(),
            stream_start: 0,
            physical_header: 0,
            logical_header: 0,
            local: Finding {
                kind: RecordKind::LocalFileHeader,
                offset: 0,
                raw_header: Vec::new(),
            },
            compressed: compressed.len() as u64,
            uncompressed: payload.len() as u64,
            crc: crc32fast::hash(&payload),
            method: 8,
        };
        let cancel = AtomicBool::new(false);
        for split in [0, 1, compressed.len() / 2, compressed.len()] {
            assert!(
                validate_stream(
                    &entry,
                    [&compressed[..split], &compressed[split..]],
                    &cancel
                )
                .unwrap()
            );
        }
        entry.uncompressed -= 1;
        assert!(!validate_stream(&entry, [&compressed, &[]], &cancel).unwrap());
        entry.uncompressed += 1;
        entry.crc ^= 1;
        assert!(!validate_stream(&entry, [&compressed, &[]], &cancel).unwrap());
        entry.crc ^= 1;
        entry.compressed -= 1;
        assert!(
            !validate_stream(&entry, [&compressed[..compressed.len() - 1], &[]], &cancel).unwrap()
        );
        let mut trailing = compressed.clone();
        trailing.push(0);
        entry.compressed = trailing.len() as u64;
        assert!(!validate_stream(&entry, [&trailing, &[]], &cancel).unwrap());
        entry.method = 0;
        entry.compressed = payload.len() as u64;
        assert!(validate_stream(&entry, [&payload[..100], &payload[100..]], &cancel).unwrap());
    }
}

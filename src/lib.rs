use std::fmt;
use std::io::{self, Read};

pub mod ntfs;
pub mod rescue;
pub mod zip_recovery;

const LOCAL_FILE_HEADER: &[u8; 4] = b"PK\x03\x04";
const DATA_DESCRIPTOR: &[u8; 4] = b"PK\x07\x08";
const CENTRAL_DIRECTORY_HEADER: &[u8; 4] = b"PK\x01\x02";
const END_OF_CENTRAL_DIRECTORY: &[u8; 4] = b"PK\x05\x06";
const MAX_NAME_LENGTH: usize = 4096;
const OVERLAP: usize = 8192;

#[derive(Debug, Clone, Copy)]
pub struct ScanOptions {
    pub chunk_size: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            chunk_size: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordKind {
    LocalFileHeader,
    DataDescriptor,
    CentralDirectoryHeader,
    EndOfCentralDirectory,
}

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::LocalFileHeader => "FILE",
            Self::DataDescriptor => "DATA",
            Self::CentralDirectoryHeader => "CDFH",
            Self::EndOfCentralDirectory => "EOCD",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: RecordKind,
    pub offset: u64,
    pub raw_header: Vec<u8>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScanStats {
    pub bytes_scanned: u64,
    pub records_found: u64,
    pub resume_offset: u64,
    pub interrupted: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScanProgress {
    pub bytes_scanned: u64,
    pub records_found: u64,
}

pub fn scan<R, F>(
    reader: R,
    base_offset: u64,
    options: ScanOptions,
    on_finding: F,
) -> io::Result<ScanStats>
where
    R: Read,
    F: FnMut(Finding) -> io::Result<()>,
{
    scan_with_control(
        reader,
        base_offset,
        options,
        on_finding,
        |_| Ok(()),
        || false,
    )
}

pub fn scan_with_progress<R, F, P>(
    reader: R,
    base_offset: u64,
    options: ScanOptions,
    on_finding: F,
    on_progress: P,
) -> io::Result<ScanStats>
where
    R: Read,
    F: FnMut(Finding) -> io::Result<()>,
    P: FnMut(ScanProgress) -> io::Result<()>,
{
    scan_with_control(
        reader,
        base_offset,
        options,
        on_finding,
        on_progress,
        || false,
    )
}

pub fn scan_with_control<R, F, P, C>(
    mut reader: R,
    base_offset: u64,
    options: ScanOptions,
    mut on_finding: F,
    mut on_progress: P,
    mut should_cancel: C,
) -> io::Result<ScanStats>
where
    R: Read,
    F: FnMut(Finding) -> io::Result<()>,
    P: FnMut(ScanProgress) -> io::Result<()>,
    C: FnMut() -> bool,
{
    if options.chunk_size < 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "chunk size must be at least 64 bytes",
        ));
    }

    let mut buffer = Vec::with_capacity(options.chunk_size + OVERLAP);
    let mut scratch = vec![0_u8; options.chunk_size];
    let mut buffer_offset = base_offset;
    let mut next_unscanned = base_offset;
    let mut records_found = 0_u64;
    let mut interrupted = false;

    'scan: loop {
        if should_cancel() {
            interrupted = true;
            break;
        }

        let read = reader.read(&mut scratch)?;
        if read != 0 {
            buffer.extend_from_slice(&scratch[..read]);
        }

        let final_chunk = read == 0;
        let safe_len = if final_chunk {
            buffer.len()
        } else {
            buffer.len().saturating_sub(OVERLAP)
        };
        let start = next_unscanned.saturating_sub(buffer_offset) as usize;

        for index in start..safe_len {
            if (index - start).is_multiple_of(64 * 1024) && should_cancel() {
                next_unscanned = buffer_offset + index as u64;
                interrupted = true;
                on_progress(ScanProgress {
                    bytes_scanned: next_unscanned - base_offset,
                    records_found,
                })?;
                break 'scan;
            }

            let Some(finding) = parse_record(&buffer[index..], buffer_offset + index as u64) else {
                continue;
            };
            on_finding(finding)?;
            records_found += 1;
        }

        next_unscanned = buffer_offset + safe_len as u64;
        on_progress(ScanProgress {
            bytes_scanned: next_unscanned - base_offset,
            records_found,
        })?;
        if final_chunk {
            break;
        }

        if safe_len > 0 {
            buffer.drain(..safe_len);
            buffer_offset += safe_len as u64;
        }
    }

    Ok(ScanStats {
        bytes_scanned: next_unscanned - base_offset,
        records_found,
        resume_offset: next_unscanned,
        interrupted,
    })
}

fn parse_record(data: &[u8], offset: u64) -> Option<Finding> {
    let signature = data.get(..4)?;

    if signature == LOCAL_FILE_HEADER {
        if data.len() < 30 {
            return None;
        }
        let name_len = le_u16(data, 26)? as usize;
        if name_len > MAX_NAME_LENGTH || data.len() < 30 + name_len {
            return None;
        }
        return Some(Finding {
            kind: RecordKind::LocalFileHeader,
            offset,
            raw_header: data[..30 + name_len].to_vec(),
        });
    }

    if signature == DATA_DESCRIPTOR {
        if data.len() < 16 {
            return None;
        }
        return Some(Finding {
            kind: RecordKind::DataDescriptor,
            offset,
            raw_header: data[..16].to_vec(),
        });
    }

    if signature == CENTRAL_DIRECTORY_HEADER {
        if data.len() < 46 {
            return None;
        }
        let name_len = le_u16(data, 28)? as usize;
        if name_len > MAX_NAME_LENGTH || data.len() < 46 + name_len {
            return None;
        }
        return Some(Finding {
            kind: RecordKind::CentralDirectoryHeader,
            offset,
            raw_header: data[..46 + name_len].to_vec(),
        });
    }

    if signature == END_OF_CENTRAL_DIRECTORY {
        if data.len() < 22 {
            return None;
        }
        return Some(Finding {
            kind: RecordKind::EndOfCentralDirectory,
            offset,
            raw_header: data[..22].to_vec(),
        });
    }

    None
}

fn le_u16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn local_header(name: &[u8]) -> Vec<u8> {
        let mut header = vec![0_u8; 30];
        header[..4].copy_from_slice(LOCAL_FILE_HEADER);
        header[4..6].copy_from_slice(&20_u16.to_le_bytes());
        header[8..10].copy_from_slice(&8_u16.to_le_bytes());
        header[18..22].copy_from_slice(&123_u32.to_le_bytes());
        header[22..26].copy_from_slice(&456_u32.to_le_bytes());
        header[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
        header.extend_from_slice(name);
        header
    }

    #[test]
    fn finds_local_header_and_reports_absolute_location() {
        let mut disk = vec![0xaa; 17];
        disk.extend(local_header(b"evidence/report.txt"));
        let mut findings = Vec::new();

        let stats = scan(Cursor::new(disk), 8192, ScanOptions::default(), |finding| {
            findings.push(finding);
            Ok(())
        })
        .unwrap();

        assert_eq!(stats.records_found, 1);
        assert_eq!(findings[0].offset, 8209);
        assert_eq!(findings[0].raw_header, local_header(b"evidence/report.txt"));
    }

    #[test]
    fn finds_header_split_across_chunks_once() {
        let mut disk = vec![0_u8; 70];
        disk.extend(local_header(b"split.zip"));
        let options = ScanOptions { chunk_size: 64 };
        let mut offsets = Vec::new();

        scan(Cursor::new(disk), 0, options, |finding| {
            offsets.push(finding.offset);
            Ok(())
        })
        .unwrap();

        assert_eq!(offsets, vec![70]);
    }

    #[test]
    fn ignores_truncated_and_implausibly_long_headers() {
        let mut disk = local_header(b"ok");
        disk.extend_from_slice(LOCAL_FILE_HEADER);
        disk.extend_from_slice(&[0_u8; 22]);
        disk.extend_from_slice(&5000_u16.to_le_bytes());
        disk.extend_from_slice(&0_u16.to_le_bytes());
        let mut count = 0;

        scan(Cursor::new(disk), 0, ScanOptions::default(), |_| {
            count += 1;
            Ok(())
        })
        .unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn preserves_complete_eocd_header() {
        let mut eocd = vec![0_u8; 22];
        eocd[..4].copy_from_slice(END_OF_CENTRAL_DIRECTORY);
        let mut findings = Vec::new();

        scan(Cursor::new(&eocd), 0, ScanOptions::default(), |finding| {
            findings.push(finding);
            Ok(())
        })
        .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].raw_header, eocd);
    }

    #[test]
    fn cancellation_reports_first_unscanned_offset() {
        let disk = vec![0_u8; 100_000];
        let mut checks = 0;
        let stats = scan_with_control(
            Cursor::new(disk),
            4096,
            ScanOptions {
                chunk_size: 100_000,
            },
            |_| Ok(()),
            |_| Ok(()),
            || {
                checks += 1;
                checks >= 3
            },
        )
        .unwrap();

        assert!(stats.interrupted);
        assert_eq!(stats.bytes_scanned, 65_536);
        assert_eq!(stats.resume_offset, 69_632);
    }
}

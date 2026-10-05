use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use flate2::Compression;
use flate2::write::DeflateEncoder;
use zip_carver::zip_recovery::*;
use zip_carver::{Finding, RecordKind, ScanOptions, scan};

const CS: u64 = 512;
const PARTITION: u64 = 1024;
static NEXT: AtomicU64 = AtomicU64::new(0);

fn set16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn set32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}

struct Fixture {
    disk: Vec<u8>,
    archive: Vec<u8>,
    headers: Vec<Finding>,
    expected: Vec<Option<u64>>,
    map: Vec<Option<u64>>,
}

impl Fixture {
    fn new(front_count: usize, contiguous: bool) -> Self {
        let payload: Vec<_> = (0..2500).map(|i| ((i * 73 + i / 7) % 256) as u8).collect();
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::none());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let crc = crc32fast::hash(&payload);
        let stamp = dos_datetime("2026-09-18T14:35:30").unwrap();
        let name = b"quote'\\\xff.dat";
        let extra = b"extra metadata field";
        let comment = vec![b'C'; 600];
        let archive_comment = vec![b'A'; 700];
        let mut local = vec![0; 30];
        local[..4].copy_from_slice(b"PK\x03\x04");
        set16(&mut local, 4, 20);
        set16(&mut local, 6, 8);
        set16(&mut local, 8, 8);
        set32(&mut local, 10, stamp);
        set16(&mut local, 26, name.len() as u16);
        set16(&mut local, 28, extra.len() as u16);
        local.extend_from_slice(name);
        local.extend_from_slice(extra);
        let mut archive = local;
        archive.extend_from_slice(&compressed);
        archive.extend_from_slice(b"PK\x07\x08");
        archive.extend_from_slice(&crc.to_le_bytes());
        archive.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        let cd_start = archive.len();
        let mut central = vec![0; 46];
        central[..4].copy_from_slice(b"PK\x01\x02");
        set16(&mut central, 4, 20);
        set16(&mut central, 6, 20);
        set16(&mut central, 8, 8);
        set16(&mut central, 10, 8);
        set32(&mut central, 12, stamp);
        set32(&mut central, 16, crc);
        set32(&mut central, 20, compressed.len() as u32);
        set32(&mut central, 24, payload.len() as u32);
        set16(&mut central, 28, name.len() as u16);
        set16(&mut central, 30, extra.len() as u16);
        set16(&mut central, 32, comment.len() as u16);
        central.extend_from_slice(name);
        central.extend_from_slice(extra);
        central.extend_from_slice(&comment);
        archive.extend_from_slice(&central);
        let mut eocd = vec![0; 22];
        eocd[..4].copy_from_slice(b"PK\x05\x06");
        set16(&mut eocd, 8, 1);
        set16(&mut eocd, 10, 1);
        set32(&mut eocd, 12, central.len() as u32);
        set32(&mut eocd, 16, cd_start as u32);
        set16(&mut eocd, 20, archive_comment.len() as u16);
        eocd.extend_from_slice(&archive_comment);
        archive.extend_from_slice(&eocd);
        let count = (archive.len() as u64).div_ceil(CS) as usize;
        let right = if contiguous { 15 } else { 40 };
        let expected: Vec<_> = (0..count)
            .map(|v| {
                Some(if v == 0 {
                    10
                } else if v < 5 && v <= front_count {
                    10 + v as u64
                } else {
                    right + v as u64 - 5
                })
            })
            .collect();
        let mut disk = vec![0xa5; PARTITION as usize + 80 * CS as usize];
        for (v, chunk) in archive.chunks(CS as usize).enumerate() {
            let offset = (PARTITION + expected[v].unwrap() * CS) as usize;
            disk[offset..offset + chunk.len()].copy_from_slice(chunk);
        }
        let mut headers = Vec::new();
        scan(Cursor::new(&disk), 0, ScanOptions::default(), |f| {
            headers.push(f);
            Ok(())
        })
        .unwrap();
        let mut map = expected.clone();
        map[..5].fill(None);
        Self {
            disk,
            archive,
            headers,
            expected,
            map,
        }
    }
    fn options(&self) -> CarveOptions {
        CarveOptions {
            cluster_size: CS,
            partition_offset: PARTITION,
            file_size: self.archive.len() as u64,
            max_stream_bytes: 1024 * 1024,
            max_trials: 64,
            assume_contiguous: false,
        }
    }
    fn filtered(&self) -> Vec<Finding> {
        let mut text = b"00000000000000099999\n".to_vec();
        for f in &self.headers {
            write_finding(&mut text, f).unwrap();
        }
        let stamp = dos_datetime("2026-09-18T14:35:30").unwrap();
        filter_headers(
            &mut Cursor::new(text),
            stamp,
            stamp,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap()
    }
}

#[test]
fn all_forward_backward_splits_with_extra_fields_and_both_zip_comments() {
    for front_count in 0..=4 {
        let fixture = Fixture::new(front_count, false);
        let filtered = fixture.filtered();
        assert_eq!(filtered.len(), 3); // FILE, CDFH, matching DATA; EOCD not timestamp-filtered.
        let entries = match_entries(&filtered, fixture.archive.len() as u64).unwrap();
        assert_eq!(entries.entries.len(), 1);
        let central = fixture
            .headers
            .iter()
            .find(|h| h.kind == RecordKind::CentralDirectoryHeader)
            .unwrap();
        assert_eq!(header_length(central).unwrap(), 46 + 12 + 20 + 600);
        let eocd = fixture
            .headers
            .iter()
            .find(|h| h.kind == RecordKind::EndOfCentralDirectory)
            .unwrap();
        assert_eq!(header_length(eocd).unwrap(), 22 + 700);
        let mut map = fixture.map.clone();
        let stats = carve(
            &mut Cursor::new(&fixture.disk),
            fixture.disk.len() as u64,
            &mut map,
            &entries.entries,
            &fixture.options(),
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        assert_eq!(stats.validated, 4, "front count {front_count}");
        assert_eq!(stats.anchors, 1);
        assert_eq!(map, fixture.expected, "front count {front_count}");
    }
}

#[test]
fn crc_failure_keeps_holes_continuity_requires_explicit_opt_in() {
    let fixture = Fixture::new(4, true);
    let mut entries = match_entries(&fixture.filtered(), fixture.archive.len() as u64)
        .unwrap()
        .entries;
    entries[0].crc ^= 1;
    for assume in [false, true] {
        let mut options = fixture.options();
        options.assume_contiguous = assume;
        let mut map = fixture.map.clone();
        let stats = carve(
            &mut Cursor::new(&fixture.disk),
            fixture.disk.len() as u64,
            &mut map,
            &entries,
            &options,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        if assume {
            assert_eq!(map, fixture.expected);
            assert_eq!(stats.assumed, 4);
        } else {
            assert!(map[1..5].iter().all(Option::is_none));
            assert_eq!(stats.validated, 0);
        }
        assert_eq!(&map[5..], &fixture.expected[5..]);
    }
}

#[test]
fn filters_dates_and_descriptor_tuples_and_rejects_python_code() {
    let fixture = Fixture::new(2, false);
    let mut text = Vec::new();
    for f in &fixture.headers {
        write_finding(&mut text, f).unwrap();
    }
    let later = dos_datetime("2026-09-19T00:00:00").unwrap();
    assert!(
        filter_headers(
            &mut Cursor::new(&text),
            later,
            later,
            &AtomicBool::new(false),
            |_| {}
        )
        .unwrap()
        .is_empty()
    );
    assert!(parse_python_bytes("__import__('os')").is_err());
    assert_eq!(
        parse_python_bytes("b\"a'\\x00\\\\\\n\"").unwrap(),
        b"a'\0\\\n"
    );
    assert!(dos_datetime("2026-02-29T00:00:00").is_err());
    assert_eq!(
        dos_datetime("2026-09-18T14:35:31").unwrap(),
        dos_datetime("2026-09-18T14:35:30").unwrap()
    );
}

#[test]
fn duplicate_entries_limits_and_cancel_never_guess() {
    let fixture = Fixture::new(2, false);
    let mut filtered = fixture.filtered();
    let mut duplicate = filtered
        .iter()
        .find(|f| f.kind == RecordKind::LocalFileHeader)
        .unwrap()
        .clone();
    duplicate.offset += 512;
    filtered.push(duplicate);
    assert!(
        match_entries(&filtered, fixture.archive.len() as u64)
            .unwrap()
            .entries
            .is_empty()
    );
    let entries = match_entries(&fixture.filtered(), fixture.archive.len() as u64)
        .unwrap()
        .entries;
    let mut options = fixture.options();
    options.max_trials = 1;
    let mut map = fixture.map.clone();
    let stats = carve(
        &mut Cursor::new(&fixture.disk),
        fixture.disk.len() as u64,
        &mut map,
        &entries,
        &options,
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(stats.trials, 0);
    assert_eq!(stats.unresolved, 4);
    let mut map = fixture.map.clone();
    let stats = carve(
        &mut Cursor::new(&fixture.disk),
        fixture.disk.len() as u64,
        &mut map,
        &entries,
        &options,
        &AtomicBool::new(true),
        |_| {},
    )
    .unwrap();
    assert!(stats.interrupted);
    assert_eq!(map, fixture.map);
}

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn cli_consumes_scanner_output_writes_both_outputs_and_preserves_inputs() {
    let fixture = Fixture::new(2, false);
    let dir = Temp(std::env::temp_dir().join(format!(
        "zip-fill-map-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    fs::create_dir(&dir.0).unwrap();
    fs::write(dir.0.join("disk.dd"), &fixture.disk).unwrap();
    let scan_result = Command::new(env!("CARGO_BIN_EXE_zip-header-scan"))
        .arg(dir.0.join("disk.dd"))
        .arg(dir.0.join("headers.txt"))
        .output()
        .unwrap();
    assert!(
        scan_result.status.success(),
        "{}",
        String::from_utf8_lossy(&scan_result.stderr)
    );
    let mut map_text = Vec::new();
    write_map(&fixture.map, &mut map_text).unwrap();
    fs::write(dir.0.join("input.txt"), &map_text).unwrap();
    let command = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_zip-gap-carve"));
        c.args([
            "--from",
            "2026-09-18T14:34:30",
            "--to",
            "2026-09-18T14:36:29",
            "--cluster-size",
            "512",
            "--partition-offset",
            "1024",
        ])
        .arg("--file-size")
        .arg(fixture.archive.len().to_string())
        .arg("--filtered-output")
        .arg(dir.0.join("filtered.txt"))
        .arg(dir.0.join("disk.dd"))
        .arg(dir.0.join("headers.txt"))
        .arg(dir.0.join("input.txt"))
        .arg(dir.0.join("output.txt"));
        c
    };
    let result = command().output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let actual = read_map(Cursor::new(fs::read(dir.0.join("output.txt")).unwrap())).unwrap();
    assert_eq!(actual, fixture.expected);
    assert_eq!(fs::read(dir.0.join("input.txt")).unwrap(), map_text);
    assert_eq!(
        fs::read_to_string(dir.0.join("filtered.txt"))
            .unwrap()
            .lines()
            .count(),
        3
    );
    assert!(!command().output().unwrap().status.success());
}

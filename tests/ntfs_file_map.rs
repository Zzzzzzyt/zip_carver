use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use zip_carver::ntfs::{AttributeData, parse_record_with_data};
use zip_carver::rescue::{plan_orphan_stream, plan_stream, read_csv, select_base};

const BASE: u64 = 42 | (3 << 48);
const EXT: u64 = 99 | (7 << 48);
const PARTITION: usize = 512;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    dir: PathBuf,
    image: Vec<u8>,
    base: Vec<u8>,
    extension: Vec<u8>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn nonresident(
    kind: u32,
    id: u16,
    vcn: u64,
    last: u64,
    size: u64,
    initialized: u64,
    pairs: &[u8],
) -> Vec<u8> {
    let mut attr = vec![0; (64 + pairs.len()).next_multiple_of(8)];
    let len = attr.len() as u32;
    attr[..4].copy_from_slice(&kind.to_le_bytes());
    attr[4..8].copy_from_slice(&len.to_le_bytes());
    attr[8] = 1;
    attr[14..16].copy_from_slice(&id.to_le_bytes());
    attr[16..24].copy_from_slice(&vcn.to_le_bytes());
    attr[24..32].copy_from_slice(&last.to_le_bytes());
    attr[32..34].copy_from_slice(&64_u16.to_le_bytes());
    attr[40..48].copy_from_slice(&1536_u64.to_le_bytes());
    attr[48..56].copy_from_slice(&size.to_le_bytes());
    attr[56..64].copy_from_slice(&initialized.to_le_bytes());
    attr[64..64 + pairs.len()].copy_from_slice(pairs);
    attr
}

fn resident(kind: u32, bytes: &[u8], name: &str) -> Vec<u8> {
    let name: Vec<_> = name.encode_utf16().collect();
    let value_at = (24 + name.len() * 2).next_multiple_of(8);
    let mut attr = vec![0; (value_at + bytes.len()).next_multiple_of(8)];
    let len = attr.len() as u32;
    attr[..4].copy_from_slice(&kind.to_le_bytes());
    attr[4..8].copy_from_slice(&len.to_le_bytes());
    attr[9] = name.len() as u8;
    attr[10..12].copy_from_slice(&24_u16.to_le_bytes());
    attr[16..20].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    attr[20..22].copy_from_slice(&(value_at as u16).to_le_bytes());
    for (i, unit) in name.iter().enumerate() {
        attr[24 + i * 2..26 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }
    attr[value_at..value_at + bytes.len()].copy_from_slice(bytes);
    attr
}

fn list() -> Vec<u8> {
    let mut list = vec![0; 64];
    for (at, record_ref, vcn, id) in [(0, BASE, 0_u64, 1_u16), (32, EXT, 1, 2)] {
        list[at..at + 4].copy_from_slice(&0x80_u32.to_le_bytes());
        list[at + 4..at + 6].copy_from_slice(&32_u16.to_le_bytes());
        list[at + 8..at + 16].copy_from_slice(&vcn.to_le_bytes());
        list[at + 16..at + 24].copy_from_slice(&record_ref.to_le_bytes());
        list[at + 24..at + 26].copy_from_slice(&id.to_le_bytes());
    }
    list
}

fn record(reference: u64, base: u64, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = vec![0; 1024];
    raw[..4].copy_from_slice(b"FILE");
    raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
    raw[16..18].copy_from_slice(&((reference >> 48) as u16).to_le_bytes());
    raw[20..22].copy_from_slice(&56_u16.to_le_bytes());
    raw[22..24].copy_from_slice(&1_u16.to_le_bytes());
    raw[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    raw[32..40].copy_from_slice(&base.to_le_bytes());
    raw[44..48].copy_from_slice(&(reference as u32).to_le_bytes());
    let mut at = 56;
    for attr in attrs {
        raw[at..at + attr.len()].copy_from_slice(attr);
        at += attr.len();
    }
    raw[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    raw[24..28].copy_from_slice(&((at + 8) as u32).to_le_bytes());
    raw[48..50].copy_from_slice(&0xbeef_u16.to_le_bytes());
    for (trailer, usa) in [(510, 50), (1022, 52)] {
        let old = [raw[trailer], raw[trailer + 1]];
        raw[usa..usa + 2].copy_from_slice(&old);
        raw[trailer..trailer + 2].copy_from_slice(&0xbeef_u16.to_le_bytes());
    }
    raw
}

impl Fixture {
    fn new(nonresident_list: bool) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "mft-rescue-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let list_attr = if nonresident_list {
            nonresident(0x20, 3, 0, 0, 64, 64, &[0x11, 1, 24, 0])
        } else {
            resident(0x20, &list(), "")
        };
        let base = record(
            BASE,
            0,
            &[
                nonresident(0x80, 1, 0, 0, 1200, 1100, &[0x11, 1, 20, 0]),
                list_attr,
            ],
        );
        let extension = record(
            EXT,
            BASE,
            &[nonresident(0x80, 2, 1, 2, 0, 0, &[0x11, 1, 5, 0x01, 1, 0])],
        );
        let mut image = vec![0xcc; PARTITION + 32 * 512];
        image[PARTITION + 4096..PARTITION + 5120].copy_from_slice(&base);
        image[PARTITION + 5120..PARTITION + 6144].copy_from_slice(&extension);
        image[PARTITION + 20 * 512..PARTITION + 21 * 512].fill(b'A');
        image[PARTITION + 5 * 512..PARTITION + 6 * 512].fill(b'B');
        image[PARTITION + 24 * 512..PARTITION + 24 * 512 + 64].copy_from_slice(&list());
        fs::write(dir.join("base.dd"), &base).unwrap();
        fs::write(dir.join("extension.dd"), &extension).unwrap();
        fs::write(
            dir.join("map.csv"),
            concat!(
                "start_lcn,end_lcn,cluster_count,status,live_files,deleted_files\n",
                "0000005,0000006,1,allocated_inferred,\"MFT 42:3 \"\"report,资料.zip\"\"\",\"\"\n",
                "0000014,0000015,1,allocated_inferred,\"MFT 42:3 \"\"report,资料.zip\"\"\",\"\"\n"
            ),
        )
        .unwrap();
        Self {
            dir,
            image,
            base,
            extension,
        }
    }

    fn command(&self, id: &str, outfile: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ntfs-file-map"));
        cmd.arg("--cluster-size")
            .arg("512")
            .arg(self.dir.join("map.csv"))
            .arg(id)
            .arg(self.dir.join(outfile));
        cmd
    }

    fn full_command(&self, id: &str, outfile: &str) -> Command {
        let mut cmd = self.command(id, outfile);
        cmd.arg("--mft-source")
            .arg(self.dir.join("base.dd"))
            .arg("--mft-fragment")
            .arg(self.dir.join("extension.dd"));
        cmd
    }

    fn expected(&self) -> &[u8] {
        b"00000000\t00000014\n00000001\t00000005\n00000002\t\n"
    }
}

#[test]
fn image_to_csv_to_file_map_uses_new_cli_names() {
    let fixture = Fixture::new(false);
    let image = fixture.dir.join("volume.dd");
    let csv = fixture.dir.join("MFT.csv");
    let output = fixture.dir.join("stage1-map.txt");
    fs::write(&image, &fixture.image).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_ntfs-cluster-map"))
        .arg("--output")
        .arg(&csv)
        .arg(&image)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(env!("CARGO_BIN_EXE_ntfs-file-map"))
        .arg("--mft-source")
        .arg(&image)
        .args(["--cluster-size", "512"])
        .arg(&csv)
        .arg("42")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(output).unwrap(), fixture.expected());
}

#[test]
fn cli_maps_fragmented_sparse_stream_without_disk_and_never_overwrites() {
    let fixture = Fixture::new(false);
    let result = fixture.full_command("42", "rescued.bin").output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(fixture.dir.join("rescued.bin")).unwrap(),
        fixture.expected()
    );
    assert!(
        !fixture
            .full_command("42", "rescued.bin")
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::read(fixture.dir.join("rescued.bin")).unwrap(),
        fixture.expected()
    );
}

#[test]
fn cli_uses_base_links_for_nonresident_list_and_extension_id() {
    let fixture = Fixture::new(true);
    let result = fixture
        .command("99", "rescued.bin")
        .arg("--mft-fragment")
        .arg(fixture.dir.join("extension.dd"))
        .arg("--mft-fragment")
        .arg(fixture.dir.join("base.dd"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(fixture.dir.join("rescued.bin")).unwrap(),
        fixture.expected()
    );
}

#[test]
fn missing_list_target_and_wrong_csv_refuse_output() {
    let fixture = Fixture::new(false);
    let result = fixture
        .command("42", "missing.bin")
        .arg("--mft-fragment")
        .arg(fixture.dir.join("base.dd"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("$ATTRIBUTE_LIST target"));
    assert!(!fixture.dir.join("missing.bin").exists());
    fs::write(
        fixture.dir.join("map.csv"),
        "start_lcn,end_lcn,live_files,deleted_files\n0000000,0000001,MFT 42:3,\n",
    )
    .unwrap();
    let result = fixture.full_command("42", "wrong.bin").output().unwrap();
    assert!(!result.status.success());
    assert!(!fixture.dir.join("wrong.bin").exists());
}

#[test]
fn copies_resident_named_stream_and_zeroes_uninitialized_physical_data() {
    let fixture = Fixture::new(false);
    let mut base = parse_record_with_data(
        &record(BASE, 0, &[resident(0x80, b"named data", "meta")]),
        512,
    )
    .unwrap();
    let mut image = std::io::Cursor::new(fixture.image.clone());
    let stream: Vec<_> = "meta".encode_utf16().collect();
    let plan = plan_stream(
        std::slice::from_ref(&base),
        &base,
        &stream,
        &mut image,
        512,
        512,
    )
    .unwrap();
    let mut output = Vec::new();
    zip_carver::rescue::copy_stream(&plan, &mut image, &mut output, 512, 512).unwrap();
    assert_eq!(output, b"named data");
    base = parse_record_with_data(
        &record(
            BASE,
            0,
            &[nonresident(0x80, 1, 0, 0, 100, 10, &[0x11, 1, 20, 0])],
        ),
        512,
    )
    .unwrap();
    let plan = plan_stream(
        std::slice::from_ref(&base),
        &base,
        &[],
        &mut image,
        512,
        512,
    )
    .unwrap();
    output.clear();
    zip_carver::rescue::copy_stream(&plan, &mut image, &mut output, 512, 512).unwrap();
    assert_eq!(&output[..10], &[b'A'; 10]);
    assert_eq!(&output[10..], &[0; 90]);
    assert!(plan.validate_image(100, 512, 512).is_err());
}

#[test]
fn rejects_reused_records_conflicts_and_unsupported_compression() {
    let fixture = Fixture::new(false);
    let base = parse_record_with_data(&fixture.base, 512).unwrap();
    let ext = parse_record_with_data(&fixture.extension, 512).unwrap();
    let mut other = base.clone();
    other.sequence += 1;
    assert!(select_base(&[base.clone(), other], 42, None).is_err());
    let mut other = base.clone();
    other.attributes[0].flags = 1;
    let mut image = std::io::Cursor::new(fixture.image.clone());
    assert!(
        plan_stream(
            &[other.clone(), ext.clone()],
            &other,
            &[],
            &mut image,
            512,
            512
        )
        .is_err()
    );
    let mut bad_extension = ext.clone();
    bad_extension.sequence += 1;
    assert!(
        plan_stream(
            &[base.clone(), bad_extension],
            &base,
            &[],
            &mut image,
            512,
            512
        )
        .is_err()
    );
    let mut conflicting = ext.clone();
    if let AttributeData::Nonresident { runs, .. } = &mut conflicting.attributes[0].data {
        runs[0].lcn = Some(6);
    }
    assert!(
        plan_stream(
            &[base.clone(), ext, conflicting],
            &base,
            &[],
            &mut image,
            512,
            512
        )
        .is_err()
    );
}

#[test]
fn filename_text_cannot_impersonate_csv_owner() {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record(["start_lcn", "end_lcn", "live_files", "deleted_files"])
        .unwrap();
    writer
        .write_record([
            "0000000",
            "0000001",
            "MFT 99:1 \"fake; MFT 42:3 text\"; MFT 8:2 \"real\"",
            "",
        ])
        .unwrap();
    let bytes = writer.into_inner().unwrap();
    assert!(read_csv(&bytes[..], 42).unwrap().sequences.is_empty());
    assert!(read_csv(&bytes[..], 8).unwrap().sequences.contains(&2));
}

#[test]
fn no_list_requires_complete_vcn_coverage_and_accepts_negative_lcn_deltas() {
    let fixture = Fixture::new(false);
    let raw = record(
        BASE,
        0,
        &[nonresident(
            0x80,
            1,
            0,
            1,
            1024,
            1024,
            &[0x11, 1, 20, 0x11, 1, 0xf1, 0],
        )],
    );
    let base = parse_record_with_data(&raw, 512).unwrap();
    let mut image = std::io::Cursor::new(fixture.image.clone());
    let plan = plan_stream(
        std::slice::from_ref(&base),
        &base,
        &[],
        &mut image,
        512,
        512,
    )
    .unwrap();
    let mut output = Vec::new();
    zip_carver::rescue::copy_stream(&plan, &mut image, &mut output, 512, 512).unwrap();
    assert_eq!(&output[..512], &[b'A'; 512]);
    assert_eq!(&output[512..], &[b'B'; 512]);
    let raw = record(
        BASE,
        0,
        &[nonresident(0x80, 1, 0, 0, 1024, 1024, &[0x11, 1, 20, 0])],
    );
    let missing = parse_record_with_data(&raw, 512).unwrap();
    assert!(
        plan_stream(
            std::slice::from_ref(&missing),
            &missing,
            &[],
            &mut image,
            512,
            512
        )
        .is_err()
    );
}

#[test]
fn cli_recovers_orphans_with_leading_and_internal_holes() {
    let fixture = Fixture::new(false);
    // Deliberately bogus extension size fields must not truncate the recovery.
    let later = record(
        100 | (8 << 48),
        BASE,
        &[nonresident(0x80, 4, 5, 5, 1, 0, &[0x11, 1, 20, 0])],
    );
    fs::write(fixture.dir.join("later.dd"), later).unwrap();
    for id in ["42", "99"] {
        let outfile = format!("partial-{id}.bin");
        let result = fixture
            .command(id, &outfile)
            .arg("--mft-fragment")
            .arg(fixture.dir.join("extension.dd"))
            .arg("--mft-fragment")
            .arg(fixture.dir.join("later.dd"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stderr).contains("original size unknown"));
        let expected = b"00000000\t\n00000001\t00000005\n00000002\t\n00000003\t\n00000004\t\n00000005\t00000014\n";
        assert_eq!(fs::read(fixture.dir.join(outfile)).unwrap(), expected);
    }
}

#[test]
fn cli_falls_back_when_base_record_fixup_is_corrupt() {
    let mut fixture = Fixture::new(false);
    fixture.base[510] ^= 1;
    fs::write(fixture.dir.join("base.dd"), &fixture.base).unwrap();
    let result = fixture.full_command("42", "partial.bin").output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let expected = b"00000000\t\n00000001\t00000005\n00000002\t\n";
    assert_eq!(fs::read(fixture.dir.join("partial.bin")).unwrap(), expected);
    // CSV ownership is still required for every surviving physical run.
    let csv = fs::read_to_string(fixture.dir.join("map.csv")).unwrap();
    fs::write(fixture.dir.join("map.csv"), csv.replace("42:3", "43:3")).unwrap();
    let result = fixture
        .full_command("42", "wrong-owner.bin")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!fixture.dir.join("wrong-owner.bin").exists());
}

#[test]
fn orphan_recovery_rejects_ambiguity_overlap_and_unsupported_streams() {
    let fixture = Fixture::new(false);
    let ext = parse_record_with_data(&fixture.extension, 512).unwrap();
    let mut reused = ext.clone();
    reused.base_reference += 1 << 48;
    let records = [ext.clone(), reused];
    assert!(plan_orphan_stream(&records, 42, None, &[], 512).is_err());
    let recovery = plan_orphan_stream(&records, 42, Some(3), &[], 512).unwrap();
    assert_eq!(recovery.plan.size, 1536);
    assert_eq!(recovery.base_reference, BASE);
    assert!(plan_orphan_stream(&records, 42, Some(5), &[], 512).is_err());
    let mut conflicting = ext.clone();
    if let AttributeData::Nonresident { runs, .. } = &mut conflicting.attributes[0].data {
        runs[0].lcn = Some(6);
    }
    assert!(plan_orphan_stream(&[ext.clone(), conflicting], 42, None, &[], 512).is_err());
    assert_eq!(
        plan_orphan_stream(&[ext.clone(), ext.clone()], 42, None, &[], 512)
            .unwrap()
            .plan
            .size,
        1536
    );
    let mut compressed = ext.clone();
    compressed.attributes[0].flags = 1;
    assert!(plan_orphan_stream(&[compressed], 42, None, &[], 512).is_err());
    assert!(plan_orphan_stream(&[ext], 42, None, &[b'x' as u16], 512).is_err());
}

#[test]
fn mapping_expands_runs_preserves_lcn_zero_and_ignores_initialized_length() {
    use zip_carver::ntfs::DataRun;
    use zip_carver::rescue::{StreamPlan, write_mapping};
    let plan = StreamPlan {
        size: 3 * 512 + 1,
        initialized: 0,
        resident: None,
        runs: vec![
            DataRun {
                vcn: 0,
                clusters: 2,
                lcn: Some(0),
            },
            DataRun {
                vcn: 2,
                clusters: 1,
                lcn: None,
            },
            DataRun {
                vcn: 3,
                clusters: 2,
                lcn: Some(0xabcdef),
            },
        ],
    };
    let mut output = Vec::new();
    write_mapping(&plan, &mut output, 512).unwrap();
    assert_eq!(
        output,
        b"00000000\t00000000\n00000001\t00000001\n00000002\t\n00000003\t00abcdef\n"
    );
}

#[test]
fn cli_requires_fragments_and_rejects_resident_stream_before_output() {
    let fixture = Fixture::new(false);
    let result = fixture.command("42", "missing.txt").output().unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--mft-fragment"));
    assert!(!fixture.dir.join("missing.txt").exists());
    fs::write(
        fixture.dir.join("resident.dd"),
        record(BASE, 0, &[resident(0x80, b"hello", "meta")]),
    )
    .unwrap();
    let result = fixture
        .command("42", "resident.txt")
        .arg("--mft-fragment")
        .arg(fixture.dir.join("resident.dd"))
        .arg("--stream")
        .arg("meta")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("resident stream has no VCN-to-LCN mapping")
    );
    assert!(!fixture.dir.join("resident.txt").exists());
}

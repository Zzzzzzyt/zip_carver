use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "zip-map-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let mut disk = vec![0xcc; 512];
        disk.extend([b'A'; 512]);
        disk.extend([b'B'; 512]);
        disk.extend([b'C'; 512]);
        fs::write(path.join("disk.dd"), disk).unwrap();
        fs::write(
            path.join("map.txt"),
            b"00000000\t00000002\n00000001\t\n00000002\t00000000\n",
        )
        .unwrap();
        Self(path)
    }
    fn command(&self, output: &str) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_map-extract"));
        c.args(["--cluster-size", "512", "--partition-offset", "512"])
            .arg(self.0.join("disk.dd"))
            .arg(self.0.join("map.txt"))
            .arg(self.0.join(output));
        c
    }
}

#[test]
fn reconstructs_fragmented_map_lcn_zero_unknowns_and_partial_last_cluster() {
    let f = Fixture::new();
    let result = f
        .command("out.zip")
        .args(["--file-size", "0x465"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut expected = vec![b'C'; 512];
    expected.extend([0xff; 512]);
    expected.extend([b'A'; 101]);
    assert_eq!(fs::read(f.0.join("out.zip")).unwrap(), expected);
    assert!(!f.command("out.zip").output().unwrap().status.success());
    assert_eq!(fs::read(f.0.join("out.zip")).unwrap(), expected);
    let result = f
        .command("zero.zip")
        .args(["--fill-byte", "0"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let mut expected = vec![b'C'; 512];
    expected.extend([0; 512]);
    expected.extend([b'A'; 512]);
    assert_eq!(fs::read(f.0.join("zero.zip")).unwrap(), expected);
}

#[test]
fn invalid_maps_geometry_and_bounds_fail_before_creating_output() {
    let f = Fixture::new();
    for (index, map) in [
        "00000000\tffffffffffffffff\n",
        "00000001\t0\n",
        "00000000\tx\n",
        "00000000\t3\n",
    ]
    .iter()
    .enumerate()
    {
        fs::write(f.0.join("map.txt"), map).unwrap();
        let name = format!("bad-{index}");
        assert!(!f.command(&name).output().unwrap().status.success());
        assert!(!f.0.join(&name).exists());
    }
    fs::write(f.0.join("map.txt"), "00000000\t0\n").unwrap();
    for (i, flags) in [
        ["--file-size", "513"],
        ["--cluster-size", "513"],
        ["--fill-byte", "256"],
    ]
    .iter()
    .enumerate()
    {
        let name = format!("arg-{i}");
        assert!(
            !f.command(&name)
                .args(flags)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(!f.0.join(&name).exists());
    }
}

#[test]
fn only_required_bytes_of_final_physical_cluster_must_exist() {
    let f = Fixture::new();
    fs::write(f.0.join("map.txt"), "00000000\t0\n").unwrap();
    fs::write(f.0.join("disk.dd"), vec![0x42; 512 + 17]).unwrap();
    let result = f
        .command("tail")
        .args(["--file-size", "17"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(f.0.join("tail")).unwrap(), [0x42; 17]);
}

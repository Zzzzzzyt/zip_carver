# ZIP file carving from NTFS images

Tools for inventorying NTFS metadata, mapping a fragmented ZIP file, filling
missing mappings from ZIP signature, and constructing the recovered file.

**DISCLAIMER: This is a personal research prototype with mostly LLM-generated code. It is not guaranteed to recover any particular file. Use at your own risk. The author is not responsible for any data loss or damage.**

## Build

```powershell
cargo build --release --bins
cargo test --all-targets
```

Executables are in `target\release`. Each supports `--help`.

| Executable | Purpose | Previous name |
| --- | --- | --- |
| `ntfs-cluster-map` | Export MFT cluster ownership CSV | `mft-cluster-map` |
| `ntfs-file-map` | Export one file's VCN-to-LCN map | `mft-rescue` |
| `zip-header-scan` | Scan raw ZIP headers | `zip-carver` |
| `zip-gap-carve` | Filter ZIP evidence and fill map gaps | `zip-fill-map` |
| `map-extract` | Construct a file from a cluster map | `zip-map` |

## Complete recovery example

These five steps use a **single NTFS volume image**, `disk.img`, with 4096-byte
clusters and 512-byte sectors. Replace the sample record ID, datetime range, and
exact file size with the target file's values. Run from the repository directory.
Use new output paths, except when resuming the ZIP signature scan.

### 1. Extract MFT.csv from the disk image

```powershell
.\target\release\ntfs-cluster-map.exe --sector-size 512 --output MFT.csv disk.img
```

The tool scans raw `FILE` records and exports cluster ownership, filenames, and
MFT identities. `MFT.csv` is a derived inventory, not a raw MFT dump. Find the
target filename in `live_files` or `deleted_files`: `MFT 12345:3` means record ID
`12345`, sequence `3`.

Recovered fragments can replace the full image to save scanning time:

```powershell
.\target\release\ntfs-cluster-map.exe --output MFT.csv MFT1.dd MFT2.dd
```

All sources must belong to the same NTFS volume and snapshot; records from
different partitions are not separated automatically.

### 2. Get the first-stage map using the MFT record ID

```powershell
.\target\release\ntfs-file-map.exe --mft-source disk.img --cluster-size 4096 --sector-size 512 MFT.csv 12345 stage1-map.txt
```

This scans the source for MFT metadata only and writes a VCN-to-LCN map. The CSV
lacks logical run order, so raw records are still required. For recovered
fragments, repeat `--mft-source MFT1.dd --mft-source MFT2.dd`. The old
`--mft-fragment` option remains an alias.

Supply a base record ID or an extension ID. Use `--sequence 3` to select a reused
base generation, or `--stream NAME` for a named `$DATA` stream. If the base record
is lost or corrupt, surviving extensions are mapped through the highest known
VCN, leaving unknown regions blank. The inferred size is
`(highest VCN + 1) * cluster_size`, not the original byte length.

### 3. Scan the disk image for ZIP signatures

```powershell
.\target\release\zip-header-scan.exe disk.img zip-headers.txt
```

This records local headers (`FILE`), signed data descriptors (`DATA`), central
directory headers (`CDFH`), and end-of-central-directory records (`EOCD`). It scans
allocated and unallocated bytes and does not extract files.

Output starts with a decimal resume offset, followed by record type, hexadecimal
image offset, and Python-style raw bytes. Repeating the command resumes the
existing output. Ctrl+C flushes completed records and saves the checkpoint before
exit 130. Periodic flushes occur after 60 seconds or 1024 records. The progress bar
uses the full input size, including when resuming.

### 4. Use the carving algorithm to fill gaps

```powershell
.\target\release\zip-gap-carve.exe --from 2026-09-18T14:34:30 --to 2026-09-18T14:36:29 --cluster-size 4096 --file-size 0x2108AC98 --filtered-output filtered-headers.txt disk.img zip-headers.txt stage1-map.txt stage2-map.txt
```

The range is inclusive ZIP local time, with seconds rounded down to DOS's
two-second resolution and no timezone conversion. FILE/CDFH timestamps are
filtered, then DATA descriptors are retained when CRC and both sizes match a
retained CDFH. EOCD has no timestamp and is excluded. Saving the filtered headers
with `--filtered-output` is optional.

Matched local headers seed missing cluster anchors. For each eligible gap, the
algorithm tests every forward/backward split between physical continuations of
the left and right known clusters. Candidates must finish raw DEFLATE at the
recorded compressed length, produce the recorded uncompressed length, and match
CRC32. Stored entries (ZIP method 0) also work. Known map entries are preserved;
unresolved or ambiguous clusters stay blank. Header anchors, CRC-validated
clusters, and assumed clusters are counted separately.

Local extra-field lengths, per-entry central-directory comments, and EOCD archive
comments are accounted for. Comments are not treated as compressed data, and
record boundaries are not inferred by finding signatures inside comments.

Even a physically continuous gap requires validation by default. Add
`--assume-contiguous` to allow the prototype's unverified continuity assumption.

### 5. Generate the final file from the second-stage map

```powershell
.\target\release\map-extract.exe --cluster-size 4096 --file-size 0x2108AC98 disk.img stage2-map.txt recovered.zip
```

Known clusters are copied in VCN order. Unknown clusters are filled with `0xFF`; use `--fill-byte 0` for zero fill. The last cluster
is trimmed to `--file-size`. The summary reports how many unknown bytes were
filled. Inspect this count and validate the resulting archive: successful output
construction does not mean every cluster was recovered.

## Geometry and file size

VCN is the cluster index within the file; LCN is the cluster index within the
NTFS volume. Physical reads use `partition_offset + LCN * cluster_size`.
Cluster size defaults to 4096 and MFT sector size to 512; neither is detected
automatically. Numeric options accept decimal or `0x`-prefixed hexadecimal.

For a whole-disk image whose volume starts at `0x100000`, add
`--partition-offset 0x100000` to **both** `zip-gap-carve` and `map-extract`.
Run `zip-header-scan` against the same whole-disk image so offsets remain absolute.
Its `--start-offset` and exclusive `--end-offset` can restrict the scan;
`--start-offset` only applies to new outputs. If the disk contains multiple
volumes, use MFT fragments or a volume image from the target partition for steps
1 and 2. Source byte positions do not change the records' volume-relative LCNs.

`--file-size` in steps 4 and 5 must agree with the map's rounded-up cluster count.
Without it, both tools use `map cluster count * cluster_size`, possibly retaining
padding at the end. Keep geometry and file size consistent across stages.

## Formats and MFT behavior

The normal CSV columns are `start_lcn,end_lcn,cluster_count,status,live_references,
deleted_references,live_files,deleted_files`. Ranges have exclusive ends. LCNs use
lowercase hex padded to at least seven digits; counts are decimal. Filename fields
contain escaped basenames and record/sequence IDs, not full paths.

Without the volume bitmap, statuses are `allocated_inferred`, `deleted_reference`,
and `unknown`; missing records do not prove free space. `--merge-non-allocated`
combines adjacent non-allocated-inferred regions for length analysis, omits
reference counts, and unions owner labels. For confirmed allocation status, use
the extracted, decoded **volume `$Bitmap::$DATA`** with
`--bitmap volume-bitmap.bin --clusters VOLUME_CLUSTER_COUNT`; this cannot be
combined with `--merge-non-allocated`. Without `--clusters`, the inventory ends
at the highest referenced LCN.

MFT parsing checks sector fixups and attribute bounds, decodes signed run deltas,
and links extension records to base references. Invalid records are excluded.
Records split across separate input files are not reassembled.

`ntfs-file-map` follows resident `$ATTRIBUTE_LIST` entries with sequence,
attribute-ID, stream-name, and VCN checks. Nonresident list contents require disk
data, so this metadata-only tool uses recovered base-linked segments instead.
With a valid base, missing/conflicting coverage is rejected. Without a base,
known extension runs are exported with holes. Every physical run is checked
against CSV owner/generation/status evidence. Resident, NTFS-compressed, and
EFS streams are not supported.

## Limits and interruption

Carving tests one unknown gap fully covered by one member stream. Other unknown
gaps in that stream, gaps crossing metadata, and leading/trailing gaps without
anchors remain unresolved. Duplicate filenames or candidate archive copies are
skipped. ZIP64, encrypted/multi-disk ZIPs, and methods other than 0/8 are unsupported.
Self-extracting prefix adjustments are not inferred.

Carving defaults to `--max-stream-bytes 268435456` (256 MiB compressed) and
`--max-trials 4096` per gap. Larger searches remain unresolved unless limits are
raised. Two compressed candidate buffers use up to twice the stream limit, plus
headers/map memory; decompressed output is checked in bounded chunks.

All outputs except scanner checkpoints require new paths. Ctrl+C during carving
saves the current map and exits 130; during filtering it exits without a map.
Continue with the saved map as input and a new output path. `map-extract` flushes
periodically; Ctrl+C saves the completed prefix and exits 130, without automatic
resume. Write errors may leave partial outputs.

Deleted-file runs may point to overwritten data. A completed command can still
leave gaps; summaries distinguish recovered, assumed, and unknown data.

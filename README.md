# Early Detection of Crypto-Ransomware on SMB File Shares

Honours thesis, University of New Brunswick, 2026. Supervised by Dr. Saqib Hakak.
[Full thesis (PDF)](Nguyen_Phu_Honours_Thesis_2026.pdf)

Detects ransomware encrypting a network file share by fusing endpoint API telemetry with
off-path SMB packet capture, and measures what each channel contributes on its own.

**100% detection at 0.5% false positives, 6 seconds after process launch**, across 109
ransomware executions from 10 families and 187 benign workloads.

---

## What this is

Most ransomware detection work watches the endpoint. That works until the endpoint is one
you don't control, and the files worth ransoming usually live on a file server, not a
laptop. This project asks whether traffic to that server carries enough signal on its own,
and whether it tells you anything the endpoint doesn't.

To answer that, every execution is recorded twice: the full API trace from inside the
guest, and a packet capture from outside it, on a common timebase. That lets the two
channels be compared on identical events rather than on separate experiments.

## Results

| | Detection | False positives |
|---|---|---|
| Host telemetry only | 100% | 2.1% |
| Network telemetry only | 100% | 2.1% |
| **Both** | **100%** | **0.5%** |

Fusing the channels cuts false alarms fourfold. Feature importance splits 52.6% network to
47.4% host, so neither dominates.

**Damage at the alarm:** 62 of 109 executions lose no files on the share at all. The
distribution is bimodal. Families that prepare before encrypting are stopped clean;
families that start destroying inside the first second are not.

**Under SMB3 encryption:** 14 of 24 network features become uncomputable when the protocol
hides the command layer. The remaining 10 still detect every execution, at 4.3% false
positives instead of 2.1%.

## Secondary result: packet-length signatures on a second implementation

A 2026 paper proposes identifying SMB operations by frame length alone, claiming the
lengths hold regardless of environment. Those constants were measured against Windows
Server; this work tested them against Samba across 10.4 million frames.

Five of seven reproduce at 99.97% purity or better. Two do not, and which ones fail follows
from the protocol specification rather than from measurement: a frame is fixed when its
message body carries no variable-length content, and the two that fail append a buffer
whose size the server chooses.

Under encryption all five surviving signatures shift by exactly 52 bytes, the size of the
transform header, with frequencies preserved to within 1.4%. Recalibration is a constant
offset, not a new feature set.

---

## Method

**Testbed.** Bare-metal Ubuntu, CAPE Sandbox over KVM. Windows 10 guest as the infected
workstation; Samba as the file server, mounted as `Z:`. 800 distinct corpus files on each
side so local and remote encryption are never ambiguous. Guest reverted to a clean
snapshot and the share restored and verified between every detonation.

**Corpus.** 286 detonations across 26 families, retained only where a disk snapshot
confirms encryption, leaving 109 executions across 10 families. 187 benign runs built from
signed Windows utilities, each chosen to reproduce part of the ransomware signature:
AES-256 archiving over the source, in-place rewrites, NTFS compression, mass renames and
moves on the share, tree-wide hashing, concurrent workloads. 25 are hard negatives that
encrypt and then destroy the original.

**Features.** 42 in total, 18 host and 24 network, computed per window and organised by the
stages of an execution. Notable ones:

- `w_rbo_rate` counts read-before-overwrite. It fires when a file that was read is then
  destroyed. A copy reads one file and writes another, so it never triggers. It is the only
  feature that catches all three destruction strategies in the corpus: overwrite-in-place,
  delete, and create-under-a-new-name.
- `w_write_buf_entropy` is measured on the I/O buffer rather than the resulting file, so it
  survives intermittent encryption.
- `w_mmap_rate` catches families that map a file, transform it in memory, and unmap it,
  issuing no write call at all.
- `w_smb_byte_ratio` is bytes out over bytes in. Encryption returns to the server roughly
  what it received, so the ratio sits near one; readers sit below, writers above. It is
  scale-free, which is why it transfers across families of very different throughput.

**Evaluation.** LightGBM, 10 leave-one-family-out folds. Benign executions assigned whole
and never split across the train/test boundary. Decision threshold swept on training folds
only. Results reported per execution, not per window.

**Validation.** Label shuffling across three seeds collapses the model to 77–91% false
positives. Keeping only the 16 strongest single features triples the false-positive rate,
so the signal is in the combination, not in a few columns.

---

## Repository

```
Nguyen_Phu_Honours_Thesis_2026.pdf    the full thesis
code/
  extract_all_features.py    feature library: API groups, path classification,
                             process-tree selection, pcap parsing, clock alignment
  extract_sliding.py         the 42 features, per window, for one execution
  train_sliding.py           leave-one-family-out training and evaluation
  feature_importance.py      importance at the window where the alarm fires
  rq123.py                   the three research-question tables
  robustness.py              label shuffle, learning curve, single-feature AUC, ablation
data/
  sliding_MAIN.csv           the dataset the thesis reports on
  ransomware_hashes.csv      SHA-256 of the 109 retained executions
```

Malware samples are **not** included and will not be provided. The hash list allows the
corpus to be reconstructed from MalwareBazaar, tria.ge, or the MLRan dataset.

---

## Known limitations

Stated plainly because they bound what the numbers mean.

**The benign corpus is scripted.** No hours-long backup jobs, no antivirus scans, no
interactive applications. Every false-positive figure is measured against a constructed
adversary; the rate against organic office traffic is unmeasured and would be higher.

**One client, one share.** A production file server carries dozens of clients at once, and
the probe would have to separate ransomware from that background.

**The host monitor is user-mode.** It must be injected before a process runs and only
follows what that process spawns. One family in the corpus defeats it: REvil relaunches
itself elevated and the monitor never attaches to the copy, so the host recorded zero
writes to the share across all 13 executions while the capture recorded 748 MB.

**Cumulative host features read zero at the alarm.** They are evaluated at the window's
start, which for the first ten seconds is process launch. The decision rests on the
per-window features.

**Latency is optimistic.** The file server is co-located with the analysis host, so network
latency is far below production and files move faster here than they would in a real
deployment.

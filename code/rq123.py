#!/usr/bin/env python3
"""Compute RQ1, RQ2 and RQ3 from a single sliding-window dataset.

The three questions share one model, one fold assignment and one decision rule; they
differ only in which columns the model is given and which quantity is reported. Running
them from one script keeps that shared configuration in one place, so a change to the
window length or the confirmation threshold cannot silently apply to one question and
not another.

RQ1 and RQ3 need only the supplied dataset. RQ2 additionally needs the packet captures
and a reference copy of the share, neither of which is distributed with this code.

Usage:
    python3 rq123.py                          # all three
    python3 rq123.py --only rq1               # one at a time
    python3 rq123.py --csv ~/data/other.csv
"""

import argparse
import bisect
import collections
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"

CSV = DATA / "sliding_MAIN.csv"
RESULTS = DATA / "results_MAIN.csv"
BACKUP = Path.home() / "fileshare_clean_backup"    # RQ2 only, not distributed
ANALYSES = Path("/opt/CAPEv2/storage/analyses")    # RQ2 only, not distributed

K_MAIN = 2            # confirmation windows used for RQ2 and RQ3
K_SWEEP = (1, 2, 3, 5)
MIN_FOLD = 5


# ─────────────────────────────────────────────────────────────────────────────
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    argv, sys.argv = sys.argv, [str(path)]      # train_sliding parses argv at import
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = argv
    return mod


def train(csv_path, k, out=None):
    """Run train_sliding and return its three '%  FPR' lines: host, network, combined."""
    cmd = ["python3", str(HERE / "train_sliding.py"), str(csv_path),
           "--min-fold", str(MIN_FOLD), "--k", str(k)]
    if out:
        cmd += ["--out", str(out)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return [l.strip() for l in r.stdout.splitlines() if "%  FPR" in l]


def subset(df, keep, path, dummy):
    """Write a dataset holding only `keep`, plus a constant column on the other side.

    train_sliding fits a host model and a network model separately; handing it a frame
    with nothing on one side raises inside LightGBM. The constant column keeps that
    path alive without contributing information."""
    META = ["task_id", "family", "label", "t_start", "t_end", "y", "onset_s"]
    s = df[META + keep].copy()
    s[dummy] = 0.0
    s.to_csv(path, index=False)
    return len(keep)


def net_groups(df):
    bd = [c for c in df.columns
          if "bytes_out" in c or "bytes_in" in c or "byte_ratio" in c]
    coi = [c for c in df.columns if "coi_" in c]
    cmd = [c for c in df.columns
           if ("smb" in c or "coi_" in c) and c not in bd and c not in coi]
    return cmd, coi, bd


# ─────────────────────────────────────────────────────────────────────────────
def rq1(df):
    """Detection and false alarms for each channel, swept over the confirmation rule.

    The sweep is reported rather than a single k because the ordering between channels
    is not stable across it -- a table at one k alone would present as a finding what
    is an artefact of that choice."""
    print("=" * 74)
    print("RQ1  Does the network channel add anything?".center(74))
    print("=" * 74)
    print(f"{df[df.y == 1].task_id.nunique()} ransomware, "
          f"{df[df.y == 0].task_id.nunique()} benign, "
          f"{len([c for c in df.columns if c not in ('task_id','family','label','t_start','t_end','y','onset_s')])} features\n")

    print(f"{'k':>3}{'latency':>9}{'host-only':>22}{'network-only':>22}{'combined':>22}")
    print("-" * 78)
    for k in K_SWEEP:
        rows = train(CSV, k)
        if len(rows) < 3:
            print(f"{k:>3}   (train failed)")
            continue
        cells = [r.replace("%  FPR", "% / FPR") for r in rows]
        print(f"{k:>3}{k + 4:>8}s" + "".join(f"{c:>22}" for c in cells))
    print()
    print("Each cell reads detection / false-positive rate. With 187 benign runs one")
    print("alarm is worth 0.53 points, so differences of one or two samples appear")
    print("here as differences of 0.5 to 1.1 percentage points.\n")


# ─────────────────────────────────────────────────────────────────────────────
def rq2(df):
    """Damage already done when the alarm fires.

    Counted from the capture. For each execution the SMB2 CREATE requests carry the
    filename; a name is charged to the corpus if it starts with one of the 800 original
    basenames, which catches both `file.pdf` and `file.pdf.akira`. Each distinct file is
    charged once, at the first frame that names it, and its original size is taken from
    the reference copy of the share. The alarm instant is t_end of the first confirming
    window plus (k-1) seconds, which is when the second window closes and the decision
    is actually available.

    Executions whose two sensors cannot be placed on a common timeline are skipped: the
    second at which each file was first touched is undetermined for them. Nine are lost
    this way, so the totals below run over 100 executions rather than 109. They are not
    zero-loss runs -- seven are REvil executions that wrote tens of thousands of SMB
    frames."""
    print("=" * 74)
    print("RQ2  How early, and at what cost?".center(74))
    print("=" * 74)

    if not RESULTS.exists():
        print(f"[!] {RESULTS} missing -- run RQ1 with --out first")
        return
    if not BACKUP.exists():
        print(f"[!] {BACKUP} missing -- RQ2 needs the reference copy of the share")
        return

    sizes = {p.name: p.stat().st_size for p in BACKUP.rglob("*") if p.is_file()}
    prefix = collections.defaultdict(list)
    for n in sizes:
        prefix[n[:12]].append(n)

    def corpus_name(basename):
        if basename in sizes:
            return basename
        for orig in prefix.get(basename[:12], ()):
            if basename.startswith(orig):
                return orig
        return None

    ef = load("ef", HERE / "extract_all_features.py")
    res = pd.read_csv(RESULTS)
    fired = res[(res.model == "combined") & (res.y == 1) & res.detected]

    rows = []
    for i, (_, r) in enumerate(fired.iterrows(), 1):
        if i % 20 == 0:
            print(f"    {i}/{len(fired)}", flush=True)
        task = int(r.task_id)
        base = ANALYSES / str(task)
        pcap, report = base / "dump.pcap", base / "reports" / "report.json"
        if not (pcap.exists() and report.exists()):
            continue

        # The two sensors run on independent clocks; without this the loss is charged
        # against the wrong instant. See Section 3.1.1.
        try:
            calls = ef.pick_malware_process(json.load(open(report))).get("calls", [])
            offset = ef.pcap_host_offset(str(pcap), calls, ef.parse_ts)
        except Exception:
            offset = None
        if offset is None:
            continue

        out = subprocess.run(
            ["tshark", "-r", str(pcap), "-Y", "smb2.filename",
             "-T", "fields", "-e", "frame.time_epoch", "-e", "smb2.filename"],
            capture_output=True, text=True)

        seen, events = set(), []
        for line in out.stdout.splitlines():
            f = line.split("\t")
            if len(f) < 2 or not f[1].strip():
                continue
            try:
                when = float(f[0]) - offset
            except ValueError:
                continue
            for raw in f[1].split(","):
                leaf = raw.strip().replace("/", "\\").split("\\")[-1]
                name = corpus_name(leaf)
                if name and name not in seen:
                    seen.add(name)
                    events.append((when, sizes[name]))
        events.sort()

        alarm = r.t_alarm + (K_MAIN - 1)
        cut = bisect.bisect_right([w for w, _ in events], alarm)
        rows.append(dict(
            family=r.family, task=task, alarm=alarm,
            files=cut,
            mb=sum(sz for _, sz in events[:cut]) / 1e6,
            total=len(events),
            first=(events[0][0] if events else None)))

    if not rows:
        print("[!] nothing matched -- check that smb2.filename is populated")
        return

    d = pd.DataFrame(rows)
    print()
    print(d.groupby("family").agg(
        n=("task", "size"),
        total_destroyed=("total", "median"),
        files_med=("files", "median"),
        files_p90=("files", lambda x: x.quantile(.9)),
        files_max=("files", "max"),
        MB_med=("mb", "median"),
        MB_max=("mb", "max"),
        lost_none=("files", lambda x: (x == 0).sum()),
    ).round(1).to_string())

    early = d.dropna(subset=["first"])
    print()
    print(f"{len(d)} executions, alarm at second {d.alarm.median():.0f}")
    print(f"  files lost   median {d.files.median():>6.0f}   "
          f"p90 {d.files.quantile(.9):>6.0f}   max {d.files.max():>6}")
    print(f"  MB lost      median {d.mb.median():>6.1f}   "
          f"p90 {d.mb.quantile(.9):>6.1f}   max {d.mb.max():>6.1f}")
    print(f"  {(d.files == 0).sum()}/{len(d)} lost nothing on the share")
    print(f"  {(early.alarm < early.first).sum()}/{len(early)} alarmed before the "
          f"first file was touched")
    print()
    print("Comparison: CryptoDrop reports a median of 10 files, but as an outcome of a")
    print("three-indicator rule rather than a fixed latency; Berrueta et al. report 113 MB")
    print("at a thirty-second window, charging the whole file even when only part of it")
    print("was encrypted, which is the convention used here.\n")


# ─────────────────────────────────────────────────────────────────────────────
def rq3(df):
    """What protocol encryption costs the network channel.

    Fourteen of the twenty-four network features are counted from the SMB2 command
    field, which an encrypted dialect hides -- Wireshark decodes 0.013% of frames once
    the transform header is in place. Ten survive: five packet-length identifiers,
    which shift by exactly 52 bytes and keep their frequencies, and five byte-volume
    features read from frame length and direction alone. Each row below drops the
    features one condition would take away, so the difference between rows is the cost
    of that condition rather than of the model."""
    print("=" * 74)
    print("RQ3  What does protocol encryption cost?".center(74))
    print("=" * 74)

    cmd, coi, bd = net_groups(df)
    print(f"command-derived {len(cmd)}, packet-length {len(coi)}, byte-volume {len(bd)}\n")

    tmp = Path("/tmp")
    configs = [
        ("plaintext SMB2, full set", None, len(cmd) + len(coi) + len(bd)),
        ("encrypted: lengths + volume", coi + bd, len(coi) + len(bd)),
        ("encrypted: volume only", bd, len(bd)),
        ("encrypted: lengths only", coi, len(coi)),
    ]

    print(f"{'condition':<32}{'features':>9}{'detection / FPR':>26}")
    print("-" * 68)
    for label, keep, n in configs:
        if keep is None:
            path = CSV
        else:
            path = tmp / f"rq3_{n}.csv"
            subset(df, keep, path, "w_dummy_host")
        rows = train(path, K_MAIN)
        # index 1 is the network-only line: for the subsets the host side is the
        # constant column, so that row is the only informative one.
        cell = rows[1].replace("%  FPR", "% / FPR") if len(rows) > 1 else "(failed)"
        print(f"{label:<32}{n:>9}{cell:>26}")
    print()
    print("The two surviving groups are not interchangeable: packet length counts how")
    print("many operations are being issued, byte volume how much data is moving, and")
    print("ransomware is distinguished by doing both at once.\n")


# ─────────────────────────────────────────────────────────────────────────────
def main():
    global CSV
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(CSV))
    ap.add_argument("--only", choices=["rq1", "rq2", "rq3"])
    a = ap.parse_args()
    CSV = Path(a.csv)
    df = pd.read_csv(CSV, low_memory=False)

    if a.only in (None, "rq1"):
        # --out so RQ2 has alarm times to work from
        train(CSV, K_MAIN, out=RESULTS)
        rq1(df)
    if a.only in (None, "rq2"):
        rq2(df)
    if a.only in (None, "rq3"):
        rq3(df)


if __name__ == "__main__":
    main()

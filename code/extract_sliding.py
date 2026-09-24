#!/usr/bin/env python3
"""
extract_sliding.py — per-window features for one execution.

Usage:
  python3 extract_sliding.py --analysis-dir /opt/CAPEv2/storage/analyses/187 \\
      --family Nefilim --task-id 187 --label ransomware \\
      --window 10 --step 1 --csv-append ~/data/sliding.csv
"""

import argparse, csv, importlib.util, json, math, sys
from collections import Counter, defaultdict
from pathlib import Path

EXTRACTOR = Path(__file__).resolve().parent / "extract_all_features.py"


def load_extractor():
    p = EXTRACTOR if EXTRACTOR.exists() else Path(__file__).with_name("extract_all_features.py")
    if not p.exists():
        sys.exit(f"[ERROR] extract_all_features.py not found ({p})")
    spec = importlib.util.spec_from_file_location("ef", p)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


# ══════════════════════════ host ══════════════════════════════════════════════

def host_events(ef, report_path):
    """(rel_seconds, api, args) for the submitted process tree, and the end of the trace."""
    d = json.load(open(report_path))
    calls = ef.pick_malware_process(d).get("calls", [])
    t0 = None; rows = []
    for c in calls:
        t = ef.parse_ts(c.get("timestamp", ""))
        if t is None: continue
        if t0 is None: t0 = t
        rows.append((t - t0, c.get("api", ""), ef.get_args(c)))
    end = rows[-1][0] if rows else 0.0
    return rows, end


HOST_KEYS = ("write_rate", "rename_rate", "mmap_rate", "traversal_rate",
             "open_rate", "api_rate", "rbo_rate", "delete_rate", "reg_rate")


def host_window(ef, rows, rbo_events, lo, hi, w):
    """The nine window counters plus the two entropy quantities.

    Path arguments are classified by storage location and count for either drive: an
    operation issued against the mapped drive traverses the same filesystem interface
    as a local one, and eleven of the eighteen host features count calls that carry no
    path at all.
    """
    wr = rn = mm = tv = op = api_n = dl = rg = 0
    wbe = []; rbe = []
    for rel, api, args in rows:
        if rel < lo or rel >= hi: continue          # window filter
        api_n += 1                                  # -> w_api_rate

        pargs = ef.path_args(args)
        drv = [ef.path_drive(v) for v in pargs]
        touched = any(d in ("C", "Z") for d in drv)  # reaches a file on either drive
        if api in ef.NTWRITE and touched: wr += 1 # -> w_write_rate
        # NtCreateFile opens as well as creates, so it counts on both
        if api == "NtCreateFile" and touched: wr += 1; op += 1   # -> w_write_rate, w_open_rate
        if api == "NtOpenFile" and touched: op += 1 # -> w_open_rate
        if api in ef.MMAP: mm += 1                  # -> w_mmap_rate
        if api in ef.TRAVERSAL: tv += 1             # -> w_traversal_rate
        if api in ef.REG_WRITE: rg += 1             # -> w_reg_rate
        if api in ef.DELETE and touched: dl += 1    # -> w_delete_rate

        if api in ef.RENAME and any(ef.encrypted_drive(v) in ("C", "Z") for v in pargs):
            rn += 1   # -> w_rename_rate.  stricter than delete: the target must be a corpus name with a suffix appended


        # entropy on corpus files only, so ransom notes do not drag the mean down
        fn = args.get("FileName") or args.get("HandleName") or ""
        if api in ef.NTWRITE and ef._is_napier_data_path(fn):
            e = ef._buf_entropy(args.get("Buffer", ""))
            if e is not None: wbe.append(e) # -> w_write_buf_entropy
        elif api in ef.NTREAD and ef._is_napier_data_path(fn):
            e = ef._buf_entropy(args.get("Buffer", ""))
            if e is not None: rbe.append(e)   # wbe - rbe -> w_iobuf_entropy_delta
    F = {
        "write_rate": wr / w, "rename_rate": rn / w, "mmap_rate": mm / w,
        "traversal_rate": tv / w, "open_rate": op / w, "api_rate": api_n / w,
        "rbo_rate": sum(1 for t, _ in rbo_events if lo <= t < hi) / w, # filtered from the whole-trace timeline: a file read at second 3 may not be overwritten until second 8, which is a different window
        "delete_rate": dl / w, "reg_rate": rg / w,
    }
    F = {f"w_{k}": round(v, 4) for k, v in F.items()}
    # means, not rates. None when the window captured no buffer
    F["w_write_buf_entropy"]   = round(ef.mean(wbe), 4) if wbe else None
    F["w_iobuf_entropy_delta"] = round(ef.mean(wbe) - ef.mean(rbe), 4) if (wbe and rbe) else None
    return F


def rbo_timeline(ef, rows):
    """Read-before-overwrite: the moment a file that was read is written, renamed or
    deleted. A copy reads one file and writes another, so it never fires."""
    # read: files seen so far; seen: files already counted; ev: (second, key) pairs
    read = set(); seen = set(); ev = []
    for rel, api, args in rows:
        # one path per call, not all of them because this tracks individual files
        fn = args.get("FileName") or args.get("HandleName") or ""
        rk = ef._rbo_key(fn) if fn else None            # (drive, basename)
        if api in ef.NTREAD and ef._is_napier_data_path(fn):
            if rk: read.add(rk)                         # remember what was read
        # a copy reads C:\a.doc and writes Z:\a.doc -- different keys, no match.
        # seen keeps each file to a single event however many times it is written.
        elif rk and rk in read and rk not in seen and (
             api in ef.NTWRITE or api in ef.DELETE or api in ef.RENAME):
            ev.append((rel, rk)); seen.add(rk)
    return ev



CUM_KEYS = ("cum_handle_enum", "cum_thread", "cum_keygen", "cum_reg_write",
            "cum_traversal", "cum_injection", "cum_duration_s")


def cumulative(ef, rows, upto):
    """Everything observable from process start to `upto` -- no knowledge of the future."""
    inj = False
    henum = thr = kg = reg = trav = 0
    for rel, api, args in rows:
        if rel >= upto: break
        if api in ef.HANDLE_ENUM: henum += 1 # -> cum_handle_enum
        if api in ef.THREAD:      thr += 1 # -> cum_thread
        if api in ef.KEYGEN:      kg += 1 # -> cum_keygen
        if api in ef.TRAVERSAL:   trav += 1 # -> cum_traversal
        if api in ef.REG_WRITE:   reg += 1 # -> cum_reg_write
        if api in ef.INJECT or (api in ef.INJECT_RWX and ef._is_rwx_protect(args)):
            inj = True  # -> cum_injection (a flag, not a count)
    return {
        "cum_handle_enum": henum, "cum_thread": thr, "cum_keygen": kg,
        "cum_reg_write": reg, "cum_traversal": trav,
        "cum_injection": int(inj), "cum_duration_s": round(upto, 2),  # -> cum_duration_s
    }


# ══════════════════════════ network ═══════════════════════════════════════════



COI_LEN = {"read": 171, "write": 138, "close": 146, "querydir": 260, "setinfo": 124}


COI_PASSES = (("smb2",          ["read", "write", "close"]),
              ("tcp.port==445", ["querydir", "setinfo"]))

NET_KEYS = ("smb_write_bps", "smb_read_bps", "smb_shortcmd_rate", "smb_rename_rate",
            "smb_delete_rate", "smb_destructive_rate", "smb_querydir_rate",
            "smb_create_rate",
            "coi_read_rate", "coi_write_rate", "coi_close_rate",
            "coi_querydir_rate", "coi_setinfo_rate",
            "smb_bytes_out_bps", "smb_bytes_in_bps", "smb_byte_ratio")


def coi_persecond(ef, pcap, t0_abs=None):

    out = {k: defaultdict(int) for k in COI_LEN}
    for filt, names in COI_PASSES:
        rows = ef.tshark(pcap, ["frame.time_epoch", "frame.len"], filt)
        t0 = t0_abs
        for r in rows:
            ep = ef.sf(r[0]) # time frame 
            if ep == 0.0: continue
            if t0 is None: t0 = ep
            ln = ef.si(r[1]) # frame size in bytes
            for name in names:
                if ln == COI_LEN[name]:
                    out[name][int(ep - t0)] += 1
    return out


def net_window(M, lo, hi, w):
    # The right edge is rounded up so that a window of [0,1] includes bin 0.
    span = range(int(lo), max(int(lo) + 1, math.ceil(hi))) #  e.g window [0, 6]   ->  span = [0, 1, 2, 3, 4, 5]

    tot = lambda d: sum(d.get(s, 0) for s in span)  #   e.g: M["w"] = {0: 12000, 1: 340000, 2: 511000, 3: 498000, 7: 200000}
                                                    #        span   = [0, 1, 2, 3, 4, 5]
                                                    #        tot(M["w"]) = 12000 + 340000 + 511000 + 498000 + 0 + 0 = 1,361,000

    nren, ndel = tot(M["ren"]), tot(M["del"]) #   nren, ndel: nums of rename, delete
    bo = sum(M["bout"].get(s, 0) for s in span) # bo = bytes out
    bi = sum(M["bin"].get(s, 0) for s in span)  # bi = bytes in
    F = {
        "smb_write_bps": tot(M["w"]) / w,           # -> w_smb_write_bps
        "smb_read_bps": tot(M["r"]) / w,            # -> w_smb_read_bps
        "smb_shortcmd_rate": tot(M["c"]) / w,       # -> w_smb_shortcmd_rate
        "smb_rename_rate": nren / w,                # -> w_smb_rename_rate
        "smb_delete_rate": ndel / w,                # -> w_smb_delete_rate
        "smb_destructive_rate": (nren + ndel) / w,  # -> w_smb_destructive_rate
        "smb_querydir_rate": tot(M["qdir"]) / w,    # -> w_smb_querydir_rate
        "smb_create_rate": tot(M["crea"]) / w,      # -> w_smb_create_rate

        "smb_bytes_out_bps": bo / max(int(hi) - int(lo), 1),   # -> w_smb_bytes_out_bps
        "smb_bytes_in_bps": bi / max(int(hi) - int(lo), 1),    # -> w_smb_bytes_in_bps
        # Offset by one on both sides so the ratio stays defined in an empty window.
        "smb_byte_ratio": (bo + 1) / (bi + 1),                 # -> w_smb_byte_ratio
    }
    F = {f"w_{k}": round(v, 4) for k, v in F.items()} # add prefix and round
    C = M.get("coi", {}) #  e.g {"read": {0:12, 1:340, 2:511}, ...}
    # -> w_coi_read_rate, w_coi_write_rate, w_coi_close_rate,
    #    w_coi_querydir_rate, w_coi_setinfo_rate
    for name in COI_LEN:
        F[f"w_coi_{name}_rate"] = round(sum(C.get(name, {}).get(s, 0) for s in span) / w, 4)
    return F


def smb_conn_opens(ef, pcap, t0_abs=None):
    """Seconds at which the client opened a TCP connection to the file server.
    """
    rows = ef.tshark(pcap, ["frame.time_epoch"],
                     "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==445")
    ts = sorted(ef.sf(r[0]) for r in rows if ef.sf(r[0]) != 0.0)
    if not ts:
        return []
    base = t0_abs if t0_abs is not None else ts[0]
    return [t - base for t in ts]


CUM_NET_KEYS = ("cum_smb_write_bytes", "cum_smb_read_bytes", "cum_smb_shortcmd",
                "cum_smb_querydir", "cum_smb_create", "cum_smb_destructive",
                "cum_smb_bytes_out", "cum_smb_bytes_in")


def net_cumulative(M, upto, hi, conn_opens=None):
    # Origin is the most recent connection opened at or before the window start.
    since = 0.0
    if conn_opens:
        prior = [t for t in conn_opens if t <= upto]     # connections already open
        since = prior[-1] if prior else conn_opens[0]    # the latest one; list is sorted
    lo = int(since)                                      # often negative: Z: is mounted at boot
    # count from the connection up to `upto`, which is the window's START
    tot = lambda d: sum(v for s, v in d.items() if lo <= s < upto)
    F = {"cum_smb_write_bytes": tot(M["w"]),             # -> cum_smb_write_bytes
         "cum_smb_read_bytes": tot(M["r"]),              # -> cum_smb_read_bytes
         "cum_smb_shortcmd": tot(M["c"]),                # -> cum_smb_shortcmd
         "cum_smb_querydir": tot(M["qdir"]),             # -> cum_smb_querydir
         "cum_smb_create": tot(M["crea"]),               # -> cum_smb_create
         "cum_smb_destructive": tot(M["ren"]) + tot(M["del"])}   # -> cum_smb_destructive

    F["cum_smb_bytes_out"] = sum(v for s, v in M["bout"].items() if s < hi)   # -> cum_smb_bytes_out
    F["cum_smb_bytes_in"]  = sum(v for s, v in M["bin"].items() if s < hi)    # -> cum_smb_bytes_in
    return F


def column_order():
    # onset_s is kept as an empty metadata column so the header matches the dataset;
    # nothing in the pipeline reads it.
    return (["task_id", "family", "label", "t_start", "t_end", "y", "onset_s"]
            + [f"w_{k}" for k in HOST_KEYS]
            + ["w_write_buf_entropy", "w_iobuf_entropy_delta"]
            + [f"w_{k}" for k in NET_KEYS]
            + list(CUM_KEYS) + list(CUM_NET_KEYS))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis-dir", required=True)
    ap.add_argument("--family", required=True)
    ap.add_argument("--task-id", required=True)
    ap.add_argument("--label", required=True, choices=["ransomware", "benign"])
    ap.add_argument("--window", type=float, default=10.0)
    ap.add_argument("--step", type=float, default=1.0)
    ap.add_argument("--csv-append", required=True)
    a = ap.parse_args()

    ef = load_extractor()

    ad = Path(a.analysis_dir)
    report = ad / "reports" / "report.json"
    if not report.exists(): report = ad / "report.json"
    pcap = ad / "dump.pcap"
    if not report.exists():
        sys.exit(f"[ERROR] no report: {report}")

    rows, end = host_events(ef, str(report))
    rbo_ev = rbo_timeline(ef, rows)
    conn_opens = []
    if pcap.exists():
        # Align the capture clock to the host trace before binning anything. Without it
        # each sensor starts its own second zero -- the host at its first API call, the
        # capture at its first SMB2 frame -- and a row labelled [0,10] carries host
        # activity from one interval and network activity from another, up to half a
        # minute apart.
        d_rep = json.load(open(str(report)))
        calls = ef.pick_malware_process(d_rep).get("calls", [])
        t0_abs = ef.pcap_host_offset(str(pcap), calls, ef.parse_ts)
        if t0_abs is None:
            print(f"[WARN] task {a.task_id}: clocks could not be aligned, "
                  f"falling back to the first SMB frame", file=sys.stderr)
        M = ef._net_persecond(str(pcap), t0_abs=t0_abs)
        M["coi"] = coi_persecond(ef, str(pcap), t0_abs)
        M["bout"], M["bin"] = ef.bytedir_persecond(str(pcap), t0_abs)
        conn_opens = smb_conn_opens(ef, str(pcap), t0_abs)
    else:
        M = {k: defaultdict(int) for k in ("w", "r", "c", "ren", "del", "qdir", "crea")}
        M["coi"] = {k: defaultdict(int) for k in COI_LEN}
        M["bout"] = {}; M["bin"] = {}

    # Horizon = the last second either sensor saw anything. Past that is capture padding.
    net_end = max([k for d in (M["w"], M["r"], M["c"], M["ren"], M["del"],
                               M["qdir"], M["crea"]) for k in d], default=0)
    horizon = max(end, float(net_end)) # end: last host end, net_end: last network end
    if horizon < a.window: # skip trace < window
        print(f"[SKIP] task {a.task_id}: trace {horizon:.1f}s is shorter than "
              f"the {a.window}s window", file=sys.stderr)
        return

    cols = column_order()
    out = Path(a.csv_append)
    new = not out.exists()
    n_pos = n_neg = 0
    with open(out, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        if new: w.writeheader()
        host_sec = Counter(int(rel) for rel, _, _ in rows) # nums of host calls: e.g: {0: 1264, 1: 890, 2: 445, 3: 12, 7: 3}

        def idle(lo, hi): #window without any activities: no smbs, no apis
            for s in range(int(lo), int(hi)):
                if host_sec.get(s) or M["w"].get(s) or M["r"].get(s) or M["c"].get(s):
                    return False
            return True

        hi = float(a.step); n_idle = 0
        while hi <= horizon:
            lo = max(0.0, hi - a.window)
            span = hi - lo

            # skip idle windows
            if idle(lo, hi):
                hi += a.step; n_idle += 1; continue


            y = 1 if a.label == "ransomware" else 0
            r = {"task_id": a.task_id, "family": a.family, "label": a.label,
                 "t_start": round(lo, 2), "t_end": round(hi, 2), "y": y,
                 "onset_s": ""}
            r.update(host_window(ef, rows, rbo_ev, lo, hi, span))
            r.update(net_window(M, lo, hi, span))
            r.update(cumulative(ef, rows, lo))
            r.update(net_cumulative(M, lo, hi, conn_opens))
            w.writerow({k: r.get(k) for k in cols})
            n_pos += y; n_neg += (1 - y)
            hi += a.step
    print(f"task {a.task_id} ({a.family[:24]}): {n_pos+n_neg} windows "
          f"[+{n_pos}/-{n_neg}]  {n_idle} idle dropped  "
          f"horizon={horizon:.0f}s  conn={len(conn_opens)}", file=sys.stderr)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
train_sliding.py — LOFO on sliding windows, reporting per-sample detection and latency.

Usage:
  python3 train_sliding.py ~/data/sliding_w10.csv --min-fold 5 --k 3
"""

import argparse, sys, warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
try:
    import lightgbm as lgb
except ImportError:
    sys.exit("[ERROR] pip install lightgbm --break-system-packages")
from sklearn.metrics import roc_auc_score, f1_score

META = ["task_id", "family", "label", "t_start", "t_end", "y", "onset_s"]

PARAMS = dict(objective="binary", n_estimators=300, learning_rate=0.05,
              num_leaves=15, max_depth=4, min_child_samples=50,
              feature_fraction=0.7, bagging_fraction=0.8, bagging_freq=1,
              reg_lambda=1.0, verbose=-1, n_jobs=2)


def feature_columns(df):
    cols = [c for c in df.columns if c not in META]
    
    NET_MARK = ("smb", "coi_")
    net  = [c for c in cols if any(m in c for m in NET_MARK)]
    host = [c for c in cols if c not in net]
    return cols, host, net


def assign_benign_folds(df, fams):
    """Whole benign executions to folds, round-robin, never split."""
    tasks = sorted(df[df.label == "benign"].task_id.unique())
    return {t: fams[i % len(fams)] for i, t in enumerate(tasks)}


def fit(Xtr, ytr):
    pos, neg = int(ytr.sum()), int(len(ytr) - ytr.sum())
    m = lgb.LGBMClassifier(**PARAMS, scale_pos_weight=(neg / pos if pos else 1.0),
                           random_state=42)
    m.fit(Xtr, ytr)
    return m


def pick_threshold(m, Xtr, ytr):
    p = m.predict_proba(Xtr)[:, 1]
    best_t, best = 0.5, -1.0
    for t in np.arange(0.05, 0.96, 0.05):
        s = f1_score(ytr, (p >= t).astype(int), zero_division=0)
        if s > best: best, best_t = s, t
    return float(best_t)


def first_alarm(times, fired, k):
    """Start time of the first run of k consecutive firing windows, else None."""
    run = 0
    for t, f in zip(times, fired):
        run = run + 1 if f else 0
        if run >= k:
            return times[list(times).index(t) - k + 1]
    return None


def evaluate(te, prob, thr, k):
    """Per-execution outcome: detected or not, and when."""
    te = te.copy(); te["prob"] = prob
    out = []
    for tid, g in te.groupby("task_id"):
        g = g.sort_values("t_end")
        fired = (g.prob.values >= thr)
        t0 = first_alarm(g.t_end.values, fired, k)
        onset = pd.to_numeric(g.onset_s, errors="coerce").iloc[0]
        out.append(dict(task_id=tid, family=g.family.iloc[0], y=int(g.y.iloc[0]),
                        detected=t0 is not None, t_alarm=t0,
                        onset=onset,
                        latency=(t0 - onset) if (t0 is not None and pd.notna(onset)) else np.nan))
    return pd.DataFrame(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--min-fold", type=int, default=5)
    ap.add_argument("--k", type=int, default=3, help="consecutive windows required before an alarm")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    df = pd.read_csv(a.csv, low_memory=False)
    cols, host, net = feature_columns(df)
    rw = df[df.label == "ransomware"]; ben = df[df.label == "benign"]

    per_fam = rw.groupby("family").task_id.nunique()
    fams = sorted([f for f, n in per_fam.items() if n >= a.min_fold])
    small = sorted([f for f, n in per_fam.items() if n < a.min_fold])

    print(f"Windows : {len(df):,}  ({len(rw):,} RW, {len(ben):,} benign)")
    print(f"Samples : {rw.task_id.nunique()} RW, {ben.task_id.nunique()} benign")
    print(f"Features: {len(cols)}  (host {len(host)}, network {len(net)})")
    print(f"Folds   : {len(fams)}  -> {', '.join(fams)}")
    if small: print(f"          skipped: {', '.join(f'{f}({per_fam[f]})' for f in small)}")
    print(f"Alarm when {a.k} consecutive windows exceed the threshold\n")

    bfold = assign_benign_folds(df, fams)
    ben = ben.copy(); ben["fold"] = ben.task_id.map(bfold)
    rw = rw[rw.family.isin(fams)]

    allrows = []
    for name, feats in (("host-only", host), ("network-only", net), ("combined", cols)):
        print("=" * 78); print(f"{name.upper():^78}"); print("=" * 78)
        print(f"{'fold':<16}{'n_rw':>5}{'n_ben':>6}{'detected':>11}{'FP':>7}"
              f"{'latency med':>13}{'AUC(win)':>10}")
        print("-" * 78)
        rows = []
        for fam in fams:
            te = pd.concat([rw[rw.family == fam], ben[ben.fold == fam]])
            tr = pd.concat([rw[rw.family != fam], ben[ben.fold != fam]])
            Xtr = tr[feats].apply(pd.to_numeric, errors="coerce")
            Xte = te[feats].apply(pd.to_numeric, errors="coerce")
            m = fit(Xtr, tr.y.values)
            thr = pick_threshold(m, Xtr, tr.y.values)
            prob = m.predict_proba(Xte)[:, 1]
            try: auc = roc_auc_score(te.y.values, prob)
            except Exception: auc = np.nan

            res = evaluate(te, prob, thr, a.k)
            res["model"] = name; res["fold"] = fam
            allrows.append(res)
            r_rw = res[res.y == 1]; r_bn = res[res.y == 0]
            det = int(r_rw.detected.sum()); nrw = len(r_rw)
            fp  = int(r_bn.detected.sum()); nbn = len(r_bn)
            lat = r_rw.latency.dropna()
            lat_s = f"{lat.median():+.1f}s" if len(lat) else "-"
            rows.append((det, nrw, fp, nbn, lat.median() if len(lat) else np.nan, auc))
            print(f"{fam:<16}{nrw:>5}{nbn:>6}{det:>7}/{nrw:<3}{fp:>4}/{nbn:<2}"
                  f"{lat_s:>13}{auc:>10.3f}")
        print("-" * 78)
        D = sum(r[0] for r in rows); N = sum(r[1] for r in rows)
        F = sum(r[2] for r in rows); B = sum(r[3] for r in rows)
        lm = np.nanmedian([r[4] for r in rows])
        am = np.nanmean([r[5] for r in rows])
        print(f"{'TOTAL':<16}{N:>5}{B:>6}{D:>7}/{N:<3}{F:>4}/{B:<2}{f'{lm:+.1f}s':>13}{am:>10.3f}")
        print(f"{'':16}{'':5}{'':6}{100*D/N if N else 0:>6.1f}%  FPR {100*F/B if B else 0:>4.1f}%")

    print("\n" + "=" * 78)
    print("LATENCY: negative = detected BEFORE the first file was encrypted".center(78))
    print("=" * 78)
    A = pd.concat(allrows)
    for name in ("host-only", "network-only", "combined"):
        lat = A[(A.model == name) & (A.y == 1) & A.detected].latency.dropna()
        if not len(lat): continue
        before = int((lat < 0).sum())
        print(f"  {name:<14} n={len(lat):>3}  median={lat.median():+7.1f}s  "
              f"before onset: {before}/{len(lat)} ({100*before/len(lat):.0f}%)")

    if a.out:
        A.to_csv(a.out, index=False)
        print(f"\n[+] details -> {a.out}")


if __name__ == "__main__":
    main()

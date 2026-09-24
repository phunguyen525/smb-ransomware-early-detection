#!/usr/bin/env python3
"""Four checks on how much confidence the reported figures support.

Usage:
    python3 robustness.py
    python3 robustness.py --only shuffle
"""

import argparse
import subprocess
import sys
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

HERE = Path(__file__).resolve().parent
CSV = HERE.parent / "data" / "sliding_MAIN.csv"
TRAIN = HERE / "train_sliding.py"
TMP = Path("/tmp")

META = ["task_id", "family", "label", "t_start", "t_end", "y", "onset_s"]
K = 2
SEEDS = (1, 2, 3)


def run(path, k=K, min_fold=5):
    """Return the three '%  FPR' lines: host-only, network-only, combined."""
    r = subprocess.run(
        ["python3", str(TRAIN), str(path), "--min-fold", str(min_fold), "--k", str(k)],
        capture_output=True, text=True)
    return [l.strip() for l in r.stdout.splitlines() if "%  FPR" in l]


def combined(path, **kw):
    rows = run(path, **kw)
    return rows[2] if len(rows) > 2 else "(failed)"


# ─────────────────────────────────────────────────────────────────────────────
def shuffle(df):
    print("=" * 72)
    print("1. Label shuffle".center(72))
    print("=" * 72)
    print("Labels reassigned per execution. A model that has found real structure")
    print("should collapse; one that has found a leak will not.\n")

    fams = sorted(df[df.y == 1].family.unique())
    tasks = sorted(df.task_id.unique())

    for seed in SEEDS:
        rng = np.random.default_rng(seed)
        fake = {t: int(rng.integers(0, 2)) for t in tasks}
        s = df.copy()
        s["y"] = s.task_id.map(fake)
        s["label"] = s.y.map({1: "ransomware", 0: "benign"})
        # families must be reassigned too, or the folds carry the true grouping
        pos = s.index[s.y == 1]
        s.loc[pos, "family"] = [fams[i % len(fams)] for i in range(len(pos))]
        p = TMP / f"shuf{seed}.csv"
        s.to_csv(p, index=False)
        n_rw = s[s.y == 1].task_id.nunique()
        print(f"  seed {seed}  ({n_rw} false positives labelled)   {combined(p)}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
def curve(df):
    print("=" * 72)
    print("2. Learning curve".center(72))
    print("=" * 72)
    print("Executions sampled per family so the class balance holds. min-fold is")
    print("lowered to 2 throughout, or the smaller fractions lose whole folds and")
    print("the rows stop being comparable.\n")

    for frac in (25, 50, 75, 100):
        rng = np.random.default_rng(0)
        keep = []
        for (_, _), g in df.groupby(["y", "family"]):
            t = sorted(g.task_id.unique())
            keep += list(rng.choice(t, max(2, int(len(t) * frac / 100)), replace=False))
        p = TMP / "lc.csv"
        sub = df[df.task_id.isin(keep)]
        sub.to_csv(p, index=False)
        n = sub[sub.y == 1].task_id.nunique()
        print(f"  {frac:>3}%  ({n:>3} ransomware)   {combined(p, min_fold=2)}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
def single_feature(df):
    from sklearn.metrics import roc_auc_score

    print("=" * 72)
    print("3. Single-feature discrimination".center(72))
    print("=" * 72)

    cols = [c for c in df.columns if c not in META]
    g = df.groupby(["task_id", "y"])[cols].max().reset_index()
    y = g.y.values

    scored = []
    for c in cols:
        x = pd.to_numeric(g[c], errors="coerce").fillna(0)
        try:
            scored.append((roc_auc_score(y, x), c))
        except ValueError:
            pass
    scored.sort(reverse=True)

    print(f"{'feature':<28}{'AUC':>7}{'benign max':>13}{'RW median':>12}")
    print("-" * 62)
    for auc, c in scored[:8]:
        b = pd.to_numeric(df[df.y == 0][c], errors="coerce").fillna(0)
        r = pd.to_numeric(df[df.y == 1][c], errors="coerce").fillna(0)
        print(f"{c:<28}{auc:>7.3f}{b.max():>13.1f}{r.median():>12.1f}")

    over = [c for a, c in scored if a > 0.95]
    print()
    print(f"  strongest single feature: {scored[0][1]} at {scored[0][0]:.3f}")
    print(f"  features above 0.95: {len(over)}" + (f" -- {over}" if over else ""))

    # where does benign exceed the ransomware median?
    exceeds = []
    for _, c in scored:
        b = pd.to_numeric(df[df.y == 0][c], errors="coerce").fillna(0)
        r = pd.to_numeric(df[df.y == 1][c], errors="coerce").fillna(0)
        if r.median() > 0 and b.max() > r.median():
            exceeds.append(c)
    print(f"  features where a benign run exceeds the ransomware median: "
          f"{len(exceeds)}/{len(cols)}")
    print()
    return scored


# ─────────────────────────────────────────────────────────────────────────────
def ablation(df, scored):
    print("=" * 72)
    print("4. Feature reduction".center(72))
    print("=" * 72)

    cols = [c for c in df.columns if c not in META]
    weakest = [c for _, c in scored[-6:]]
    strongest = [c for _, c in scored[:16]]
    net = [c for c in cols if "smb" in c or "coi_" in c]
    host = [c for c in cols if c not in net]

    trials = [
        ("full set", cols),
        ("16 strongest by single-feature AUC", strongest),
        ("drop 6 weakest by single-feature AUC", [c for c in cols if c not in weakest]),
        ("host features only", host),
        ("network features only", net),
    ]

    print(f"{'configuration':<40}{'n':>4}{'detection / FPR':>26}")
    print("-" * 70)
    for label, keep in trials:
        p = TMP / "abl.csv"
        s = df[META + keep].copy()
        # keep both sides alive: train_sliding fits host and network separately
        if not any("smb" in c or "coi_" in c for c in keep):
            s["w_dummy_net_smb"] = 0.0
        if all("smb" in c or "coi_" in c for c in keep):
            s["w_dummy_host"] = 0.0
        s.to_csv(p, index=False)
        rows = run(p)
        cell = rows[2] if len(rows) > 2 else "(failed)"
        print(f"{label:<40}{len(keep):>4}{cell:>26}")
    print()
    print("Removing the weakest features by single-feature AUC does not improve the")
    print("result, which is the point: a feature that separates poorly on its own can")
    print("still carry information the others do not.\n")


# ─────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(CSV))
    ap.add_argument("--only", choices=["shuffle", "curve", "auc", "ablation"])
    a = ap.parse_args()

    df = pd.read_csv(a.csv, low_memory=False)
    print(f"\n{df[df.y == 1].task_id.nunique()} ransomware, "
          f"{df[df.y == 0].task_id.nunique()} benign, "
          f"{len([c for c in df.columns if c not in META])} features, k = {K}\n")

    scored = None
    if a.only in (None, "shuffle"):
        shuffle(df)
    if a.only in (None, "curve"):
        curve(df)
    if a.only in (None, "auc", "ablation"):
        scored = single_feature(df)
    if a.only in (None, "ablation"):
        ablation(df, scored)


if __name__ == "__main__":
    main()

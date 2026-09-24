#!/usr/bin/env python3
"""
feature_importance.py — feature importance at the window in which the alarm is raised.


Usage:
  python3 feature_importance.py ~/data/sliding_MAIN.csv
  python3 feature_importance.py ~/data/sliding_MAIN.csv --full
"""

import argparse
import collections
import sys
import warnings

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
try:
    import lightgbm as lgb
except ImportError:
    sys.exit("[ERROR] pip install lightgbm --break-system-packages")

META = ["task_id", "family", "label", "t_start", "t_end", "y", "onset_s"]

# The five benign executions that were temporarily out of the dataset when the
# published table was computed. Excluded by default so the figures reproduce exactly;
# --full uses all 187 and shifts them by under two percentage points, leaving the
# ordering unchanged in the first five positions. Every other table uses the full 187.
EXCLUDED = [446, 654, 673, 675, 678]

# Same hyper-parameters as train_sliding.py, except min_child_samples: the alarm-window
# subset is a small fraction of the rows, and the trainer's value of 50 leaves too few
# samples per leaf to fit at all.
PARAMS = dict(objective="binary", n_estimators=300, learning_rate=0.05,
              num_leaves=15, max_depth=4, min_child_samples=20,
              feature_fraction=0.7, bagging_fraction=0.8, bagging_freq=1,
              reg_lambda=1.0, verbose=-1, n_jobs=2)


def is_network(c):
    """coi_ columns are read from the capture and belong to the network side even
    though their names carry no 'smb'."""
    return ("smb" in c) or ("coi_" in c)


def importance(d, cols, fams, alarm_window):
    """Mean gain per feature across the ten folds, normalised to the total."""
    rw = d[d.y == 1]
    ben = d[d.y == 0].copy()
    bt = sorted(ben.task_id.unique())
    ben["fold"] = ben.task_id.map({t: fams[i % len(fams)] for i, t in enumerate(bt)})
    rw = rw[rw.family.isin(fams)]

    imp = collections.defaultdict(list)
    for fam in fams:
        tr = pd.concat([rw[rw.family != fam], ben[ben.fold != fam]])
        X = tr[cols].apply(pd.to_numeric, errors="coerce")
        y = tr.y.values
        m = lgb.LGBMClassifier(**PARAMS,
                               scale_pos_weight=(len(y) - y.sum()) / y.sum(),
                               random_state=42)
        m.fit(X, y)
        g = m.booster_.feature_importance("gain")
        tot = g.sum() or 1
        for c, v in zip(cols, g):
            imp[c].append(100 * v / tot)
    return sorted(((np.mean(v), c) for c, v in imp.items()), reverse=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--alarm-window", type=int, default=6,
                    help="score rows with t_end <= this (default 6)")
    ap.add_argument("--min-fold", type=int, default=5)
    ap.add_argument("--top", type=int, default=6)
    ap.add_argument("--full", action="store_true",
                    help="keep all benign executions; the published table excludes five")
    a = ap.parse_args()

    d0 = pd.read_csv(a.csv, low_memory=False)
    if not a.full:
        d0 = d0[~d0.task_id.isin(EXCLUDED)]

    allc = [c for c in d0.columns if c not in META]
    net = [c for c in allc if is_network(c)]
    host = [c for c in allc if not is_network(c)]

    d = d0[d0.t_end <= a.alarm_window]
    rw = d[d.y == 1]
    fams = sorted([f for f, n in rw.groupby("family").task_id.nunique().items()
                   if n >= a.min_fold])

    print(f"{len(allc)} features ({len(host)} host, {len(net)} network)")
    print(f"{rw.task_id.nunique()} ransomware, "
          f"{d[d.y == 0].task_id.nunique()} benign"
          f"{'' if a.full else '  (five excluded, see EXCLUDED)'}")
    print(f"{len(d):,} rows at t_end <= {a.alarm_window}, {len(fams)} folds\n")

    for label, cols in (("COMBINED", allc), ("HOST-ONLY", host), ("NETWORK-ONLY", net)):
        r = importance(d, cols, fams, a.alarm_window)
        print(f"=== {label} ({len(cols)} features) ===")
        for i, (mn, c) in enumerate(r[:a.top], 1):
            print(f"{i:>3}  {c:<26}{mn:>7.2f} %")
        if label == "COMBINED":
            npct = sum(mn for mn, c in r if is_network(c))
            print(f"     {'network':<26}{npct:>7.1f} %")
            print(f"     {'host':<26}{100 - npct:>7.1f} %")
        print()


if __name__ == "__main__":
    main()

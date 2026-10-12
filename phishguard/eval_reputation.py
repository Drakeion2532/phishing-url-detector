"""Measure what the reputation layer adds on the 20% hold-out set."""
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from .train import fit, predict, metrics
from .reputation import reputation_safe
from .features import normalise

ROOT = Path(__file__).resolve().parents[1]


def main():
    d = pd.read_csv(ROOT / "data" / "urls.csv.gz")
    d["url"] = d["url"].map(normalise)
    tr, te = train_test_split(d, test_size=0.2, stratify=d["label"], random_state=42)
    m = fit(tr["url"].tolist(), tr["label"].values)
    _, _, pe = predict(m, te["url"].tolist())
    rep = np.array([reputation_safe(u) for u in te["url"]])
    pe2 = np.where(rep, 0.0, pe)
    y = te["label"].values
    out = {"ensemble": {k: round(float(v), 4) for k, v in metrics(y, pe).items()},
           "ensemble+reputation": {k: round(float(v), 4) for k, v in metrics(y, pe2).items()},
           "holdout_urls_on_reputable_domains": int(rep.sum()),
           "of_which_labelled_malicious": int((rep & (y == 1)).sum())}
    path = ROOT / "results" / "metrics.json"
    allm = json.loads(path.read_text())
    allm["reputation_layer_holdout"] = out
    path.write_text(json.dumps(allm, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()

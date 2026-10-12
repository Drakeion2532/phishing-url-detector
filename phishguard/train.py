"""Train and evaluate PhishGuard.

Models
  A. XGBoost on 37 hand-crafted lexical features (interpretable)
  B. Logistic Regression on character 1-5-gram TF-IDF (learns obfuscation patterns)
  C. Ensemble = mean of A and B probabilities

Evaluation
  1. Stratified 80/20 split on the combined dataset
  2. Cross-source generalisation: train WITHOUT any PhishingDatabase URLs,
     then measure detection on the (recent) PhishingDatabase phishing links.
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, f1_score, precision_score, recall_score, roc_auc_score,
                             confusion_matrix)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from .features import feature_matrix, normalise

ROOT = Path(__file__).resolve().parents[1]


def metrics(y, p, thr=0.5):
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
            "recall": recall_score(y, pred), "f1": f1_score(y, pred), "roc_auc": roc_auc_score(y, p),
            "false_positive_rate": fp / max(1, fp + tn)}


def fit(urls, y):
    F = feature_matrix(urls)
    xgb = XGBClassifier(n_estimators=400, max_depth=7, learning_rate=0.1, subsample=0.9,
                        colsample_bytree=0.8, tree_method="hist", n_jobs=2, random_state=0,
                        eval_metric="logloss").fit(F, y)
    tfidf = TfidfVectorizer(analyzer="char", ngram_range=(1, 5), min_df=3, max_features=300_000,
                            sublinear_tf=True, lowercase=True)
    T = tfidf.fit_transform(urls)
    lr = LogisticRegression(max_iter=3000, C=4.0, solver="liblinear").fit(T, y)
    return {"xgb": xgb, "tfidf": tfidf, "lr": lr, "feature_names": list(F.columns)}


def predict(model, urls):
    urls = [normalise(u) for u in urls]
    pa = model["xgb"].predict_proba(feature_matrix(urls))[:, 1]
    pb = model["lr"].predict_proba(model["tfidf"].transform(urls))[:, 1]
    return pa, pb, (pa + pb) / 2


def main():
    d = pd.read_csv(ROOT / "data" / "urls.csv.gz")
    d["url"] = d["url"].map(normalise)
    out = {"dataset": d.groupby(["source", "label"]).size().rename("n").reset_index().to_dict("records")}

    tr, te = train_test_split(d, test_size=0.2, stratify=d["label"], random_state=42)
    m = fit(tr["url"].tolist(), tr["label"].values)
    pa, pb, pe = predict(m, te["url"].tolist())
    y = te["label"].values
    out["holdout_20pct"] = {name: {k: round(float(v), 4) for k, v in metrics(y, p).items()}
                            for name, p in [("XGBoost_lexical", pa), ("LogReg_char_ngrams", pb), ("Ensemble", pe)]}
    print(json.dumps(out["holdout_20pct"], indent=2), flush=True)

    # cross-source generalisation
    src_tr = d[d["source"] != "phishing_database"]
    tr2, te2 = train_test_split(src_tr, test_size=0.2, stratify=src_tr["label"], random_state=42)
    m2 = fit(tr2["url"].tolist(), tr2["label"].values)
    unseen = d[d["source"] == "phishing_database"].sample(10000, random_state=0)
    benign_hold = te2[te2["label"] == 0]
    eval_df = pd.concat([unseen, benign_hold])
    qa, qb, qe = predict(m2, eval_df["url"].tolist())
    out["cross_source_unseen_phishing_feed"] = {
        name: {k: round(float(v), 4) for k, v in metrics(eval_df["label"].values, p).items()}
        for name, p in [("XGBoost_lexical", qa), ("LogReg_char_ngrams", qb), ("Ensemble", qe)]}
    print(json.dumps(out["cross_source_unseen_phishing_feed"], indent=2), flush=True)

    imp = pd.Series(m["xgb"].feature_importances_, index=m["feature_names"]).sort_values(ascending=False)
    out["top_lexical_features"] = imp.head(12).round(4).to_dict()
    (ROOT / "results" / "metrics.json").write_text(json.dumps(out, indent=2))

    final = fit(d["url"].tolist(), d["label"].values)      # production model on all data
    joblib.dump(final, ROOT / "models" / "phishguard.joblib", compress=3)
    print("saved model")


if __name__ == "__main__":
    main()

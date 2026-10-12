"""PhishGuard API + web checker.

    uvicorn phishguard.api:app --port 8003
    GET  /                 web UI
    POST /check {"url": "..."}  -> verdict, score, reasons
"""
from __future__ import annotations

from pathlib import Path

import joblib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .features import url_features, normalise, EXPLAIN, FREE_HOSTING, SHORTENERS
from .train import predict
from .reputation import reputation_safe, registered_domain

ROOT = Path(__file__).resolve().parents[1]
model = joblib.load(ROOT / "models" / "phishguard.joblib")
app = FastAPI(title="PhishGuard")
# the browser extension calls the API from any page
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["POST", "GET"], allow_headers=["*"])

class Req(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


@app.post("/check")
def check(r: Req):
    if reputation_safe(r.url):
        return {"url": r.url, "verdict": "safe", "score": 0.0,
                "reasons": [f"{registered_domain(r.url)} is a top-10k domain with good reputation"]}
    pa, pb, pe = predict(model, [r.url])
    score = float(pe[0])
    f = url_features(r.url)
    reasons = [txt for k, txt in EXPLAIN.items() if f.get(k, 0) > (1 if k == "n_subdomains" else 0)]
    if f["url_len"] > 90:
        reasons.append("unusually long URL")
    verdict = "phishing" if score >= 0.7 else "suspicious" if score >= 0.4 else "safe"
    return {"url": r.url, "verdict": verdict, "score": round(score, 4),
            "model_scores": {"lexical_xgboost": round(float(pa[0]), 4), "char_ngram_lr": round(float(pb[0]), 4)},
            "reasons": reasons}


@app.get("/")
def ui():
    return FileResponse(ROOT / "phishguard" / "static" / "index.html")

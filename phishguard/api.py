"""PhishGuard API + web checker.

    uvicorn phishguard.api:app --port 8003
    GET  /                 web UI
    POST /check {"url": "..."}  -> verdict, score, reasons
    POST /check_message {"text": "..."}  -> every link in an SMS / WhatsApp / email + message red flags
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
from .message import check_message

ROOT = Path(__file__).resolve().parents[1]
model = joblib.load(ROOT / "models" / "phishguard.joblib")
app = FastAPI(title="PhishGuard")
# the browser extension calls the API from any page
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["POST", "GET"], allow_headers=["*"])

class Req(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class MessageReq(BaseModel):
    text: str = Field(min_length=1, max_length=5000)


def check_url(url: str) -> dict:
    if reputation_safe(url):
        return {"url": url, "verdict": "safe", "score": 0.0,
                "reasons": [f"{registered_domain(url)} is a top-10k domain with good reputation"]}
    pa, pb, pe = predict(model, [url])
    score = float(pe[0])
    f = url_features(url)
    reasons = [txt for k, txt in EXPLAIN.items() if f.get(k, 0) > (1 if k == "n_subdomains" else 0)]
    if f["url_len"] > 90:
        reasons.append("unusually long URL")
    verdict = "phishing" if score >= 0.7 else "suspicious" if score >= 0.4 else "safe"
    return {"url": url, "verdict": verdict, "score": round(score, 4),
            "model_scores": {"lexical_xgboost": round(float(pa[0]), 4), "char_ngram_lr": round(float(pb[0]), 4)},
            "reasons": reasons}


@app.post("/check")
def check(r: Req):
    return check_url(r.url)


@app.post("/check_message")
def check_whole_message(r: MessageReq):
    return check_message(r.text, check_url)


@app.get("/")
def ui():
    return FileResponse(ROOT / "phishguard" / "static" / "index.html")

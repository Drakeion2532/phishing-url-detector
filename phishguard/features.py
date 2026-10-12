"""Lexical URL features – computed from the URL string only, so a verdict
needs no network request (safe: we never visit the suspicious site)."""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit

import numpy as np
import pandas as pd

SUSPICIOUS_WORDS = ["login", "signin", "verify", "account", "update", "secure", "banking", "confirm",
                    "password", "webscr", "ebayisapi", "wallet", "suspend", "unlock", "billing",
                    "invoice", "kyc", "otp", "refund", "support", "authenticate", "recover"]
BRANDS = ["paypal", "apple", "microsoft", "office365", "outlook", "google", "amazon", "netflix",
          "facebook", "instagram", "whatsapp", "yahoo", "chase", "wellsfargo", "dhl", "fedex",
          "sbi", "hdfc", "icici", "paytm", "phonepe", "airtel", "linkedin", "dropbox", "adobe"]
SHORTENERS = {"bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc"}
FREE_HOSTING = ["000webhostapp", "weebly", "wixsite", "blogspot", "firebaseapp", "web.app",
                "herokuapp", "github.io", "netlify.app", "vercel.app", "glitch.me", "repl.co",
                "duckdns", "ngrok", "pages.dev", "workers.dev", "sites.google", "azurewebsites"]
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "mov", "click", "link", "work",
              "support", "live", "icu", "buzz", "rest", "cam", "monster", "cyou", "shop", "online", "site"}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def normalise(url: str) -> str:
    url = str(url).strip()
    url = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url)
    return re.sub(r"^www\.", "", url, flags=re.I)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def url_features(url: str) -> dict:
    u = normalise(url)
    parts = urlsplit("http://" + u)
    host = (parts.hostname or "").lower()
    path, query = parts.path or "", parts.query or ""
    labels = host.split(".") if host else []
    tld = labels[-1] if labels else ""
    sub = labels[:-2] if len(labels) > 2 else []
    low = u.lower()
    reg_domain = ".".join(labels[-2:]) if len(labels) >= 2 else host
    return {
        "url_len": len(u), "host_len": len(host), "path_len": len(path), "query_len": len(query),
        "n_dots": u.count("."), "n_hyphens": u.count("-"), "n_host_hyphens": host.count("-"),
        "n_underscore": u.count("_"), "n_slash": u.count("/"), "n_qmark": u.count("?"),
        "n_eq": u.count("="), "n_amp": u.count("&"), "n_at": u.count("@"), "n_percent": u.count("%"),
        "n_digits": sum(ch.isdigit() for ch in u), "digit_ratio": sum(ch.isdigit() for ch in u) / max(1, len(u)),
        "host_digit_ratio": sum(ch.isdigit() for ch in host) / max(1, len(host)),
        "n_subdomains": len(sub), "path_depth": path.count("/"),
        "is_ip": int(bool(IP_RE.match(host))), "has_port": int(parts.port is not None) if _safe_port(parts) else 0,
        "punycode": int("xn--" in host), "double_slash_redirect": int("//" in path),
        "entropy_url": _entropy(u), "entropy_host": _entropy(host),
        "susp_words": sum(w in low for w in SUSPICIOUS_WORDS),
        "brand_in_url": int(any(b in low for b in BRANDS)),
        "brand_not_in_domain": int(any(b in low for b in BRANDS) and not any(b in reg_domain for b in BRANDS)),
        "shortener": int(reg_domain in SHORTENERS),
        "free_hosting": int(any(h in host for h in FREE_HOSTING)),
        "risky_tld": int(tld in RISKY_TLDS), "tld_len": len(tld),
        "ends_exe_php": int(bool(re.search(r"\.(exe|php|scr|zip|apk|js)$", path.lower()))),
        "has_email_in_query": int(bool(re.search(r"[\w.]+@[\w.]+", query))),
        "longest_token": max((len(t) for t in re.split(r"[./?=&_-]", u) if t), default=0),
    }


def _safe_port(parts):
    try:
        parts.port
        return True
    except ValueError:
        return False


def feature_matrix(urls) -> pd.DataFrame:
    return pd.DataFrame([url_features(u) for u in urls])


EXPLAIN = {
    "is_ip": "uses a raw IP address instead of a domain",
    "brand_not_in_domain": "mentions a brand that is not the real domain",
    "free_hosting": "hosted on a free website builder/host often abused by phishers",
    "susp_words": "contains credential-related words (login, verify, account…)",
    "shortener": "uses a URL shortener that hides the destination",
    "risky_tld": "uses a top-level domain popular with abuse",
    "punycode": "uses punycode (possible look-alike characters)",
    "n_at": "contains '@', which can hide the real destination",
    "double_slash_redirect": "contains an embedded redirect ('//')",
    "n_subdomains": "has many sub-domains (e.g. paypal.com.security-check.xyz)",
    "n_host_hyphens": "domain has many hyphens",
    "has_email_in_query": "carries an email address in the query (targeted link)",
    "ends_exe_php": "points directly at a script or executable",
}

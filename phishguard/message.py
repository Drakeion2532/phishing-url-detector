"""Check a whole SMS / WhatsApp / email message, not just one URL.

People don't receive bare URLs: they get "Dear customer, your SBI KYC expires today, update at
sbi-kyc-update.xyz/login". This module pulls every link out of the message (including bare
domains with no http://, which is how most Indian smishing links look), scores each one with the
URL model, and adds message-level red flags, because many scams (OTP / PIN theft) contain no
link at all.

    python -m phishguard.message "Your account is blocked. Share the OTP to unblock."
    echo "...message..." | python -m phishguard.message
"""
from __future__ import annotations

import re
import sys

# links: scheme or www. form, or a bare domain ending in a TLD (optionally with a path)
_URL = re.compile(
    r"""(?ix)
    (?:https?://|www\.)[^\s<>"']+                                  # explicit links
    |
    \b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+                 # bare domains: labels...
      (?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})\b                       # ...ending in a TLD
      (?:/[^\s<>"']*)?                                             # optional path
    """)
_TRAILING = ".,;:!?)]}'\""
# common words that look like domains but aren't links in normal text
_NOT_LINKS = {"e.g", "i.e", "etc", "a.m", "p.m", "rs.", "no."}

# message-level red flags (English and common Hinglish wording)
FLAGS = {
    "asks_for_secret": (r"(?<!not )(?<!n't )(?<!never )\b(share|send|tell|give|provide|forward|confirm|enter|batao|bhejo)\b"
                        r"(?:\s+\w+){0,6}?\s+(otp|one[- ]time password|pin|cvv|password|upi pin|mpin)\b"
                        r"|\b(otp|pin|cvv|password|mpin)\b(?:\s+\w+){0,2}?\s+(batao|bhejo|bata do|bhej do|share karo|send karo)\b",
                        "asks for an OTP, PIN, CVV or password: no bank or company ever asks for these"),
    "urgency": (r"\b(urgent|immediately|within \d+ ?(hours?|hrs?|minutes?|mins?)|today only|last (day|chance)|turant|abhi)\b",
                "creates urgency to rush you"),
    "account_threat": (r"\b(blocked|suspended|deactivat\w*|disconnect\w*|expir\w*|frozen|closed|band ho)\b",
                       "threatens that an account, card or service will be blocked or expire"),
    "kyc_update": (r"\b(kyc|pan|aadhaar|aadhar)\b.{0,40}\b(update|verify|link|expir\w*)\b|\b(update|verify|link)\b.{0,40}\b(kyc|pan|aadhaar|aadhar)\b",
                   "asks you to update KYC / PAN / Aadhaar through a link"),
    "reward_bait": (r"\b(won|winner|lottery|prize|cashback|reward|refund|gift|free)\b",
                    "promises a prize, refund or reward"),
    "call_mobile_number": (r"\b(call|contact|whatsapp|message)\b.{0,40}?(\+?91[\s-]?)?\b[6-9]\d{9}\b",
                           "asks you to call or message a personal mobile number (official helplines are usually toll-free 1800 numbers)"),
    "payment_request": (r"\b(pay|payment|transfer|send money|scan (the )?qr|collect request)\b",
                        "asks you to pay, transfer money or scan a QR code"),
}


def extract_urls(text: str) -> list[str]:
    seen, urls = set(), []
    for m in _URL.finditer(text):
        u = m.group(0).rstrip(_TRAILING)
        if "@" in text[max(0, m.start() - 1):m.start()]:          # part of an e-mail address
            continue
        if u.lower() in _NOT_LINKS or len(u) < 4 or "." not in u:
            continue
        if re.fullmatch(r"[\d.]+", u) and u.count(".") != 3:      # amounts like 1.5 or 2.50, not IPs
            continue
        key = u.lower()
        if key not in seen:
            seen.add(key)
            urls.append(u)
    return urls


def message_flags(text: str) -> list[dict]:
    t = text.lower()
    return [{"flag": k, "why": why} for k, (rx, why) in FLAGS.items() if re.search(rx, t)]


def check_message(text: str, check_url) -> dict:
    """check_url(url) -> {"verdict", "score", "reasons", ...} for a single URL."""
    links = [check_url(u) for u in extract_urls(text)]
    flags = message_flags(text)
    rank = {"safe": 0, "suspicious": 1, "phishing": 2}
    worst = max((l["verdict"] for l in links), key=rank.get, default="safe")
    names = {f["flag"] for f in flags}

    verdict = worst
    if worst == "safe":
        if "asks_for_secret" in names and (names & {"urgency", "account_threat", "kyc_update", "reward_bait"}):
            verdict = "phishing"          # classic OTP / PIN scam, often with no link at all
        elif "call_mobile_number" in names and (names & {"account_threat", "reward_bait", "kyc_update"}):
            verdict = "phishing"          # "your power will be cut tonight, call officer 98xxxxxxxx"
        elif len(names) >= 2 and links:
            verdict = "suspicious"        # clean-looking link, but scam-style wording
        elif len(names) >= 3:
            verdict = "suspicious"
    if verdict == "phishing":
        advice = "Do not click any link, call back a number in the message, or share any code. Report it at sancharsaathi.gov.in (Chakshu) or call 1930."
    elif verdict == "suspicious":
        advice = "Don't act on this message. Contact the company through its official app or the number on your card instead."
    else:
        advice = "No red flags found. Still, never share OTPs or PINs with anyone."
    return {"verdict": verdict, "links": links, "message_flags": flags, "advice": advice}


def main():
    text = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else sys.stdin.read()
    from .api import check_url          # loads the model
    import json
    print(json.dumps(check_message(text, check_url), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

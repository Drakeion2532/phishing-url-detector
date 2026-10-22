from phishguard.features import url_features, normalise


def test_normalise_strips_scheme_and_www():
    assert normalise("HTTPS://www.Example.com/a") == "Example.com/a"


def test_ip_and_brand_spoof_features():
    f = url_features("http://192.168.10.5/paypal/login.php")
    assert f["is_ip"] == 1 and f["brand_not_in_domain"] == 1 and f["susp_words"] >= 1 and f["ends_exe_php"] == 1


def test_real_brand_domain_not_flagged_as_spoof():
    assert url_features("paypal.com/signin")["brand_not_in_domain"] == 0


def test_free_hosting_and_risky_tld():
    f = url_features("secure-update-account.000webhostapp.com/verify")
    assert f["free_hosting"] == 1
    assert url_features("sbi-kyc.xyz/otp")["risky_tld"] == 1


def test_api_verdicts():
    from fastapi.testclient import TestClient
    from phishguard.api import app
    c = TestClient(app)
    assert c.post("/check", json={"url": "https://github.com/explore"}).json()["verdict"] == "safe"
    r = c.post("/check", json={"url": "paypal.com.account-verify-login.tk/signin/webscr?cmd=update"}).json()
    assert r["verdict"] in ("phishing", "suspicious") and r["reasons"]


# ---------------------------------------------------------------- whole-message checks
from phishguard.message import extract_urls, message_flags


def test_extracts_bare_and_explicit_links_but_not_amounts_or_emails():
    text = ("Pay Rs.2,500.00 at sbi-kyc-update.xyz/login or https://bit.ly/3xYz12, "
            "mail support@amazon.in, see www.example.com. Ref 1.5")
    assert extract_urls(text) == ["sbi-kyc-update.xyz/login", "https://bit.ly/3xYz12", "www.example.com"]


def test_otp_flag_needs_a_request_not_a_warning():
    assert not message_flags("482910 is your OTP for login. Do not share it with anyone. -HDFC Bank")
    assert not message_flags("Never share your OTP or PIN with anyone")
    assert "asks_for_secret" in {f["flag"] for f in message_flags("Share the OTP sent to you with our executive")}
    assert "asks_for_secret" in {f["flag"] for f in message_flags("OTP batao jaldi")}


def test_message_verdicts():
    from fastapi.testclient import TestClient
    from phishguard.api import app
    c = TestClient(app)
    verdict = lambda t: c.post("/check_message", json={"text": t}).json()["verdict"]
    # genuine messages
    assert verdict("482910 is your OTP for login to HDFC Bank NetBanking. Do not share it with anyone.") == "safe"
    assert verdict("Rs.2,500.00 debited from A/c XX1234. Not you? Call 18002586161 - SBI") == "safe"
    assert verdict("Your Amazon order #405-1234567 has shipped. Track at amazon.in/your-orders") == "safe"
    assert verdict("Hi bhai, call me on 9876501234 when you reach the station") == "safe"
    # scams, including ones with no link at all
    assert verdict("Your SBI account will be blocked today. Update PAN at sbi-kyc-update.xyz/login") == "phishing"
    assert verdict("Your HDFC account will be suspended today. Share the OTP sent to you with our executive.") == "phishing"
    assert verdict("Your electricity will be disconnected tonight. Call officer 9876543210 immediately") == "phishing"
    r = c.post("/check_message", json={"text": "Pay customs fee at indiapost-redeliver.top/pay"}).json()
    assert r["verdict"] == "phishing" and r["links"][0]["url"] == "indiapost-redeliver.top/pay" and r["advice"]

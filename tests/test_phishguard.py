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

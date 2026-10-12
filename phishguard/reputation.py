"""Domain-reputation layer: the ML model judges the URL *text*, but a URL on
a top-10k registered domain (e.g. login.microsoftonline.com) is legitimate no
matter how 'phishy' its words look. Shared-hosting / shortener domains are
excluded because anyone can publish under them."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from .features import normalise, FREE_HOSTING, SHORTENERS

ROOT = Path(__file__).resolve().parents[1]
USER_CONTENT = {"blogspot.com", "weebly.com", "wixsite.com", "wix.com", "000webhostapp.com", "web.app",
                "firebaseapp.com", "github.io", "netlify.app", "vercel.app", "herokuapp.com", "glitch.me",
                "pages.dev", "workers.dev", "azurewebsites.net", "sites.google.com", "googleusercontent.com",
                "docs.google.com", "forms.gle", "drive.google.com", "dropbox.com", "ipfs.io", "duckdns.org",
                "ngrok.io", "ngrok-free.app", "wordpress.com", "tumblr.com", "jimdo.com", "yolasite.com",
                "squarespace.com", "webflow.io", "notion.site", "typeform.com", "sharepoint.com",
                "onedrive.live.com", "1drv.ms", "box.com", "mediafire.com", "r2.dev", "amazonaws.com",
                "cloudfront.net", "windows.net", "appspot.com", "translate.goog",
                # shared hosting, paste sites, ad networks and social posts: third parties publish here
                "pastebin.com", "fc2.com", "secureserver.net", "bget.ru", "esy.es", "inmotionhosting.com",
                "wapka.mobi", "dropboxusercontent.com", "googleapis.com", "sfr.fr", "free.fr", "t-online.de",
                "adnxs.com", "doubleclick.net", "twitter.com", "x.com", "facebook.com", "linkedin.com",
                "yimg.com", "bitly.com", "narod.ru", "ucoz.ru", "hostinger.com", "000space.com",
                "altervista.org", "tripod.com", "angelfire.com", "geocities.com", "webs.com", "jimdofree.com"}
MULTI_PART_SUFFIX = {"co", "gov", "ac", "org", "net", "nic", "com", "edu"}


def registered_domain(url: str) -> str:
    host = normalise(url).split("/")[0].split("?")[0].split(":")[0].split("@")[-1].lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in MULTI_PART_SUFFIX and len(parts[-1]) == 2:
        return ".".join(parts[-3:])          # e.g. irctc.co.in
    return ".".join(parts[-2:])


@lru_cache(maxsize=1)
def top_domains() -> frozenset:
    lst = (ROOT / "data" / "top_domains_10k.txt").read_text().split()
    return frozenset(d for d in lst if d not in USER_CONTENT and d not in SHORTENERS
                     and not any(h in d for h in FREE_HOSTING))


def reputation_safe(url: str) -> bool:
    host = normalise(url).split("/")[0].lower()
    dom = registered_domain(url)
    if dom in USER_CONTENT or any(host.endswith(u) for u in USER_CONTENT):
        return False
    return dom in top_domains()

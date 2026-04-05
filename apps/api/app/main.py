from __future__ import annotations

import json
import os
import re
import uuid
import traceback
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from typing import Any, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import httpx

from sqlalchemy import text as sql_text
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import Artifact, Detection, Email, OpenSafelyJob, Rewrite
from app.auth_results import parse_authentication_from_raw_headers

from dotenv import load_dotenv

load_dotenv()


# ---- HELPERS ----------------------------------------------------------------

from app.ai_engine import detect_email_with_local_ai

def _ai_enabled() -> bool:
    # Always enabled if we have the service, but we can check if the URL is set
    return bool(os.getenv("OLLAMA_BASE_URL"))


# Third-party domains that legitimately appear in emails from other senders
_KNOWN_THIRD_PARTY = {
    "mailchimp.com", "sendgrid.net", "sendgrid.com", "constantcontact.com",
    "mailgun.com", "amazonses.com", "mandrillapp.com", "hubspot.com",
    "marketo.com", "pardot.com", "salesforce.com", "exacttarget.com",
    "list-manage.com", "campaign-archive.com", "createsend.com",
    "mailjet.com", "postmarkapp.com", "sparkpostmail.com", "sendinblue.com",
    "brevo.com", "klaviyo.com", "convertkit.com", "drip.com",
    "aweber.com", "getresponse.com", "activecampaign.com",
    "customer.io", "customeriomail.com", "intercom.io", "intercom.com", "zendesk.com",
    "freshdesk.com", "helpscout.com", "drift.com",
    "cloudfront.net", "akamaihd.net", "googleapis.com", "gstatic.com",
    "cloudflare.com", "fastly.net", "edgekey.net", "azureedge.net",
    "s3.amazonaws.com", "blob.core.windows.net", "cdn.shopify.com",
    "imgix.net", "cloudinary.com", "akamai.net", "stackpathdns.com",
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "bit.ly", "goo.gl", "t.co", "ow.ly", "tinyurl.com",
    "rebrand.ly", "cutt.ly", "short.io", "lnk.to",
    "facebook.com", "twitter.com", "linkedin.com", "instagram.com",
    "youtube.com", "google.com", "apple.com", "microsoft.com",
    "pinterest.com", "reddit.com", "tiktok.com", "x.com",
    "doubleclick.net", "google-analytics.com", "demdex.net",
    "omtrdc.net", "eloqua.com", "marketo.net", "segment.io",
    "segment.com", "mixpanel.com", "amplitude.com", "hotjar.com",
    "fullstory.com", "crazyegg.com", "mouseflow.com",
    "branch.io", "appsflyer.com", "adjust.com", "kochava.com",
    "open.tracker.com", "pixel.watch", "sentry.io",
    "stripe.com", "paypal.com", "braintreegateway.com", "squareup.com",
}

_BRAND_DOMAINS = {
    "paypal": {"paypal.com", "paypal.me"},
    "chase": {"chase.com", "jpmorganchase.com"},
    "bank of america": {"bankofamerica.com", "bofa.com"},
    "wells fargo": {"wellsfargo.com", "wf.com"},
    "citibank": {"citi.com", "citibank.com"},
    "capital one": {"capitalone.com"},
    "american express": {"americanexpress.com", "amex.com"},
    "venmo": {"venmo.com"},
    "zelle": {"zellepay.com"},
    "stripe": {"stripe.com"},
    "square": {"squareup.com", "square.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com", "binance.us"},
    "kraken": {"kraken.com"},
    "crypto.com": {"crypto.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googleapis.com"},
    "microsoft": {"microsoft.com", "outlook.com", "office.com", "live.com", "hotmail.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazonaws.com"},
    "meta": {"meta.com", "facebook.com", "instagram.com"},
    "netflix": {"netflix.com"},
    "spotify": {"spotify.com"},
    "adobe": {"adobe.com"},
    "dropbox": {"dropbox.com"},
    "zoom": {"zoom.us", "zoom.com"},
    "slack": {"slack.com"},
    "ebay": {"ebay.com"},
    "walmart": {"walmart.com"},
    "target": {"target.com"},
    "best buy": {"bestbuy.com"},
    "costco": {"costco.com"},
    "shopify": {"shopify.com", "myshopify.com"},
    "twitter": {"twitter.com", "x.com"},
    "linkedin": {"linkedin.com"},
    "instagram": {"instagram.com"},
    "tiktok": {"tiktok.com"},
    "snapchat": {"snapchat.com"},
    "whatsapp": {"whatsapp.com"},
    "telegram": {"telegram.org", "t.me"},
    "discord": {"discord.com", "discord.gg"},
    "ups": {"ups.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "dhl": {"dhl.com"},
    "github": {"github.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "intuit": {"intuit.com", "turbotax.com", "quickbooks.com"},
    "att": {"att.com"},
    "verizon": {"verizon.com"},
    "t-mobile": {"t-mobile.com"},
    "comcast": {"comcast.com", "xfinity.com"},
}

_DOMAIN_SIBLINGS = {
    "google.com": {"google.dev", "youtube.com", "gmail.com", "googlesource.com",
                   "gstatic.com", "appspot.com", "googleusercontent.com",
                   "googleapis.com", "google.co.uk", "google.co.in", "withgoogle.com",
                   "chromium.org", "android.com", "googleplex.com"},
    "microsoft.com": {"office.com", "office365.com", "azure.com", "linkedin.com",
                      "live.com", "sharepoint.com", "microsoftonline.com",
                      "outlook.com", "hotmail.com", "bing.com", "skype.com",
                      "xbox.com", "github.com", "visualstudio.com", "windowsupdate.com"},
    "amazon.com": {"media-amazon.com", "amazonaws.com", "amazon.co.uk",
                   "amazon.ca", "amazon.de", "amazon.co.jp", "amazon.in",
                   "amazon.fr", "amazon.es", "amazon.it", "a2z.com",
                   "primevideo.com", "aboutamazon.com", "whole-foods.com"},
    "apple.com": {"icloud.com", "mzstatic.com", "apple.co", "itunes.com"},
    "meta.com": {"facebook.com", "instagram.com", "whatsapp.com",
                 "fbcdn.net", "fb.com", "messenger.com", "oculus.com"},
    "paypal.com": {"paypal.me", "braintreegateway.com", "venmo.com"},
    "twitter.com": {"x.com", "t.co", "twimg.com"},
}

_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".buzz", ".info", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".work", ".life", ".loan", ".racing", ".review", ".science",
    ".stream", ".download", ".win", ".bid", ".date", ".trade", ".faith",
    ".party", ".cricket", ".accountant", ".webcam", ".icu", ".monster",
    ".rest", ".hair", ".quest", ".cfd", ".sbs", ".cyou",
}

_FREE_HOSTING_DOMAINS = {
    "weebly.com", "wixsite.com", "wix.com", "wordpress.com", "blogspot.com",
    "000webhostapp.com", "netlify.app", "vercel.app", "herokuapp.com",
    "pages.dev", "web.app", "firebaseapp.com", "glitch.me",
    "replit.co", "repl.co", "surge.sh", "github.io",
    "duckdns.org", "no-ip.com", "noip.com", "freedns.afraid.org",
    "ddns.net", "hopto.org", "zapto.org", "sytes.net",
    "serveo.net", "ngrok.io", "ngrok.app", "trycloudflare.com",
    "loca.lt", "serveo.net",
}

_GENERIC_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "aol.com", "protonmail.com", "proton.me", "mail.com", "zoho.com",
    "yandex.com", "tutanota.com", "fastmail.com", "hey.com",
    "gmx.com", "gmx.net", "live.com", "msn.com",
}


def _is_third_party_domain(host: str) -> bool:
    reg = _registrable_domain(host)
    return reg in _KNOWN_THIRD_PARTY or host in _KNOWN_THIRD_PARTY


def _domain_entropy(domain: str) -> float:
    import math
    if not domain:
        return 0.0
    name = domain.split(".")[0] if "." in domain else domain
    if not name:
        return 0.0
    freq = {}
    for c in name:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(name)
        entropy -= p * math.log2(p)
    return entropy


def _has_suspicious_tld(domain: str) -> bool:
    if not domain:
        return False
    for tld in _SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True
    return False


def _is_free_hosting(host: str) -> bool:
    reg = _registrable_domain(host)
    return reg in _FREE_HOSTING_DOMAINS or host in _FREE_HOSTING_DOMAINS


def _count_subdomains(host: str) -> int:
    parts = host.strip(".").split(".")
    if len(parts) <= 2:
        return 0
    public_suffix_2 = {"co.uk", "com.au", "co.in", "co.jp", "com.br", "gov.uk", "ac.uk"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in public_suffix_2:
        return max(0, len(parts) - 3)
    return max(0, len(parts) - 2)


def _url_has_credential_path(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
        query = (urlparse(url).query or "").lower()
    except Exception:
        return False
    cred_keywords = [
        "/login", "/signin", "/sign-in", "/sign_in",
        "/verify", "/verification", "/validate",
        "/secure", "/security", "/authenticate",
        "/account/confirm", "/password", "/credential",
        "/update-billing", "/update-payment", "/billing-update",
        "/suspend", "/reactivate", "/unlock",
    ]
    combined = path + "?" + query
    return any(kw in combined for kw in cred_keywords)


def _brand_in_url_subdomain(host: str) -> str | None:
    parts = host.strip(".").split(".")
    if len(parts) <= 2:
        return None
    host_reg = _registrable_domain(host)
    subdomain_parts = host.replace("." + host_reg, "").split(".")
    for part in subdomain_parts:
        for brand, legit_domains in _BRAND_DOMAINS.items():
            brand_key = brand.replace(" ", "").replace("-", "")
            if brand_key in part.replace("-", "").replace(".", ""):
                if host_reg not in legit_domains and not any(
                    _registrable_domain(d) == host_reg for d in legit_domains
                ):
                    return brand
    return None


def _heuristic_detect_fallback(e) -> tuple[int, str, list[str]]:
    """Heuristic phishing detection. Returns (score, label, reasons)."""
    text = (e.body_text or "").lower()
    subject = (e.subject or "").lower()
    from_addr_raw = e.from_addr or ""
    urls = e.extracted_urls or []

    reasons: list[str] = []
    score = 0
    indicator_count = 0

    email_match = re.search(r"<([^>]+)>", from_addr_raw)
    sender_email = email_match.group(1).lower() if email_match else from_addr_raw.lower()
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
    sender_reg = _registrable_domain(sender_domain)
    sender_display = from_addr_raw.split("<")[0].strip().strip('"').lower() if "<" in from_addr_raw else ""

    # Sender analysis
    spoofed_brand = None
    for brand, legit_domains in _BRAND_DOMAINS.items():
        if brand in sender_display:
            if not any(sender_reg == _registrable_domain(d) for d in legit_domains):
                spoofed_brand = brand
                reasons.append(f"Display name impersonates '{brand}' but sender domain is {sender_domain}")
                score += 30
                indicator_count += 1
                break

    # Display name contains a different email than actual sender
    if re.search(r"[\w.+-]+@[\w.-]+\.\w+", sender_display):
        display_email_match = re.search(r"([\w.+-]+@[\w.-]+\.\w+)", sender_display)
        if display_email_match:
            display_email_domain = display_email_match.group(1).split("@")[-1]
            if _registrable_domain(display_email_domain) != sender_reg:
                reasons.append(f"Display name contains email '{display_email_match.group(1)}' but actual sender is {sender_domain}")
                score += 25
                indicator_count += 1

    if sender_domain and _has_suspicious_tld(sender_domain):
        reasons.append(f"Sender domain uses suspicious TLD: {sender_domain}")
        score += 10
        indicator_count += 1

    # Randomly generated sender domain
    if sender_domain and _domain_entropy(sender_domain) > 4.0:
        sender_name_part = sender_domain.split(".")[0]
        if len(sender_name_part) > 10:
            reasons.append(f"Sender domain appears randomly generated: {sender_domain}")
            score += 10
            indicator_count += 1

    # Content analysis
    combined_text = text + " " + subject

    high_conf_phrases = [
        "compensation fund", "winning notification", "inheritance claim",
        "million usd", "million dollars", "western union", "money gram",
        "next of kin", "unclaimed fund", "lottery winner", "dear beneficiary",
        "united nations compensation", "diplomatic agent", "barrister chambers",
        "federal ministry of finance", "central bank of nigeria",
        "won a lottery", "you have been selected", "beneficiary of",
        "wire the funds", "processing fee required", "advance fee",
        "claim your prize", "modalities for payment", "to claim this fund",
        "contact our fiduciary agent", "your overdue payment",
    ]
    matched_scam = [p for p in high_conf_phrases if p in combined_text]
    if matched_scam:
        reasons.append(f"High-confidence scam language: '{matched_scam[0]}'")
        score += 40
        indicator_count += 1

    cred_phrases = [
        "enter your password", "confirm your password", "verify your ssn",
        "social security number", "credit card number", "enter your pin",
        "update your billing", "confirm your credit card",
        "verify your bank account", "enter your bank details",
        "provide your login credentials", "authenticate your account",
        "your credentials have expired", "re-enter your credentials",
    ]
    matched_cred = [p for p in cred_phrases if p in combined_text]
    if matched_cred:
        reasons.append(f"Credential harvesting language: '{matched_cred[0]}'")
        score += 25
        indicator_count += 1

    financial_bait = [
        "wire transfer", "bitcoin payment", "gift card",
        "cryptocurrency wallet", "send bitcoin to",
        "itunes gift card", "google play card", "steam card",
        "pay via bitcoin", "payment in cryptocurrency",
    ]
    matched_financial = [p for p in financial_bait if p in combined_text]
    if matched_financial:
        reasons.append(f"Financial bait language: '{matched_financial[0]}'")
        score += 20
        indicator_count += 1

    attachment_bait = [
        "enable macros", "enable content", "enable editing",
        ".exe attachment", "open the attached .zip",
        "download the attachment", "run the attached",
        "password for the zip is", "password-protected attachment",
    ]
    matched_attach = [p for p in attachment_bait if p in combined_text]
    if matched_attach:
        reasons.append(f"Attachment-based social engineering: '{matched_attach[0]}'")
        score += 20
        indicator_count += 1

    urgent_phrases = [
        "account suspended", "account will be closed", "verify your identity",
        "unauthorized transaction", "suspicious activity on your account",
        "confirm your payment", "your account has been limited",
        "immediate action required", "account will be terminated",
        "failure to verify will result", "within 24 hours",
        "within 48 hours your account", "permanent suspension",
    ]
    has_urgency = any(p in combined_text for p in urgent_phrases)
    if has_urgency:
        reasons.append("Urgency/pressure language detected")
        score += 10
        indicator_count += 1

    raw_subject = (e.subject or "")
    if len(raw_subject) >= 10:
        upper_ratio = sum(1 for c in raw_subject if c.isupper()) / len(raw_subject)
        if upper_ratio > 0.6:
            reasons.append("Excessive capitalization in subject line")
            score += 5
            indicator_count += 1

    # URL analysis
    has_ip = False
    has_punycode = False
    has_suspicious_tld_url = False
    has_free_hosting = False
    has_brand_subdomain = False
    has_credential_path = False
    has_excessive_subdomains = False
    mismatch_count = 0
    total_urls = len(urls)
    has_unsubscribe = False
    url_domains_match_sender = 0
    has_data_uri = False
    has_shortener_with_brand = False

    for u in urls[:30]:
        u_lower = u.lower()

        if u_lower.startswith("data:") or u_lower.startswith("javascript:"):
            if not has_data_uri:
                reasons.append("Contains data: or javascript: URI")
                score += 30
                indicator_count += 1
                has_data_uri = True
            continue

        host = (urlparse(u).hostname or "").strip(".").lower()
        if not host:
            continue
        host_reg = _registrable_domain(host)

        if "unsubscribe" in u_lower or "opt-out" in u_lower or "optout" in u_lower:
            has_unsubscribe = True

        if sender_domain and _domain_matches(sender_domain, host):
            url_domains_match_sender += 1

        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) and not has_ip:
            reasons.append(f"Link uses raw IP address: {host}")
            score += 35
            indicator_count += 1
            has_ip = True

        if "xn--" in host and not has_punycode:
            reasons.append(f"Punycode/IDN homograph domain: {host}")
            score += 35
            indicator_count += 1
            has_punycode = True

        if _has_suspicious_tld(host) and not has_suspicious_tld_url:
            reasons.append(f"URL uses suspicious TLD: {host}")
            score += 10
            indicator_count += 1
            has_suspicious_tld_url = True

        if _is_free_hosting(host) and not has_free_hosting:
            has_free_hosting = True

        subdomain_count = _count_subdomains(host)
        if subdomain_count >= 3 and not has_excessive_subdomains:
            reasons.append(f"URL has {subdomain_count} subdomains: {host}")
            score += 15
            indicator_count += 1
            has_excessive_subdomains = True

        brand_in_sub = _brand_in_url_subdomain(host)
        # Sponsor/partner names in subdomains on the sender's own domain (e.g. amazon-nova.devpost.com)
        if brand_in_sub and sender_reg and _registrable_domain(host) == sender_reg:
            brand_in_sub = None
        if brand_in_sub and not has_brand_subdomain:
            reasons.append(f"Brand '{brand_in_sub}' used as subdomain of unrelated domain: {host}")
            score += 30
            indicator_count += 1
            has_brand_subdomain = True

        if _url_has_credential_path(u) and not _domain_matches(sender_domain or "", host):
            if not _is_third_party_domain(host) and not has_credential_path:
                has_credential_path = True

        shortener_domains = {"bit.ly", "goo.gl", "t.co", "ow.ly", "tinyurl.com",
                             "rebrand.ly", "cutt.ly", "short.io", "is.gd", "v.gd"}
        if host_reg in shortener_domains and spoofed_brand and not has_shortener_with_brand:
            reasons.append(f"URL shortener ({host}) used in context of brand impersonation")
            score += 15
            indicator_count += 1
            has_shortener_with_brand = True

        if sender_domain and sender_domain not in _GENERIC_EMAIL_DOMAINS and not _is_third_party_domain(host):
            is_safe = False
            if _domain_matches(sender_domain, host):
                is_safe = True
            if not is_safe and sender_reg in _DOMAIN_SIBLINGS:
                if any(host_reg == _registrable_domain(s) or host.endswith("." + s)
                       for s in _DOMAIN_SIBLINGS[sender_reg]):
                    is_safe = True
            if not is_safe:
                mismatch_count += 1

    if has_credential_path and mismatch_count > 0:
        reasons.append("Credential-harvesting URL path on domain unrelated to sender")
        score += 15
        indicator_count += 1

    if has_free_hosting and indicator_count >= 1:
        reasons.append("Links point to free hosting / dynamic DNS provider")
        score += 15
        indicator_count += 1

    if mismatch_count > 0 and total_urls > 0:
        non_thirdparty_count = max(mismatch_count, 1)
        mismatch_ratio = mismatch_count / min(total_urls, 30)
        if mismatch_ratio > 0.5:
            reasons.append(f"Majority of links ({mismatch_count}/{min(total_urls, 30)}) point to domains unrelated to sender ({sender_domain})")
            score += 25
            indicator_count += 1
        elif mismatch_count >= 3:
            reasons.append(f"Multiple links ({mismatch_count}) point to domains unrelated to sender")
            score += 15
            indicator_count += 1

    # Cross-correlation
    if spoofed_brand and (has_ip or has_punycode or has_brand_subdomain):
        reasons.append("Brand impersonation + deceptive URL infrastructure")
        score += 15

    if has_urgency and (matched_cred or has_credential_path) and mismatch_count > 0:
        reasons.append("Urgency + credential harvesting + mismatched URLs")
        score += 15

    if indicator_count >= 4:
        reasons.append(f"{indicator_count} independent indicators detected")
        score += 20
    elif indicator_count >= 3:
        reasons.append(f"{indicator_count} correlated indicators")
        score += 10

    # Negative signals (reduce FPs)
    if has_unsubscribe and score > 0:
        reasons.append("Has unsubscribe link")
        score = max(0, score - 15)

    if total_urls > 0 and url_domains_match_sender == total_urls:
        reasons.append("All URLs match sender domain")
        score = max(0, score - 10)
    elif total_urls > 2 and url_domains_match_sender >= total_urls * 0.7:
        score = max(0, score - 5)

    if total_urls == 0 and len(text) < 500:
        score = max(0, score - 10)

    if sender_domain in _GENERIC_EMAIL_DOMAINS:
        score = max(0, score - 5)

    score = max(0, min(100, score))
    label = "phishing" if score >= 65 else "suspicious" if score >= 30 else "benign"
    return score, label, reasons


def _strip_links(text: str) -> str:
    return re.sub(r"https?://[^\s'\"]+", "[LINK REMOVED]", text or "", flags=re.IGNORECASE)


def defang_url(u: str) -> str:
    u = u.replace("http://", "hxxp://").replace("https://", "hxxps://")
    u = u.replace(".", "[.]")
    return u


def _registrable_domain(domain: str) -> str:
    if not domain:
        return ""
    d = domain.strip(".").lower()
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    public_suffix_2 = {"co.uk", "com.au", "co.in", "co.jp", "com.br", "gov.uk", "ac.uk"}
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in public_suffix_2 and len(parts) >= 3:
        return last3
    return last2

def _domain_matches(a: str, b: str) -> bool:
    if not a or not b: return False
    a, b = a.strip(".").lower(), b.strip(".").lower()
    ra, rb = _registrable_domain(a), _registrable_domain(b)
    return ra == rb or a.endswith("." + rb) or b.endswith("." + ra)

def extract_urls(text: str) -> list[str]:
    if not text: return []
    rx = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
    return sorted(set(rx.findall(text)))


def html_to_text(html: str) -> str:
    if not html: return ""
    soup = BeautifulSoup(html, "lxml")
    return soup.get_text("\n", strip=True)


def _host_from_url(u: str) -> str | None:
    try:
        return urlparse(u).hostname
    except Exception:
        return None


def _looks_like_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))


def _artifact_dir() -> str:
    return os.getenv("ARTIFACT_DIR", os.path.abspath(os.path.join(os.getcwd(), "..", "..", "..", "artifacts")))


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---- API SETUP --------------------------------------------------------------

app = FastAPI(title="PhishNet API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---- MODELS -----------------------------------------------------------------

class EmailListItem(BaseModel):
    id: str
    source: str
    subject: str | None = None
    from_addr: str | None = None
    created_at: str


class DetectionResult(BaseModel):
    label: str
    risk_score: int
    reasons: list[str]


class RewriteResult(BaseModel):
    safe_subject: str | None = None
    safe_body: str
    used_llm: bool


class OpenSafelyRequest(BaseModel):
    link_index: int
    allow_target_origin: bool = False


# ---- ENDPOINTS --------------------------------------------------------------

@app.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(sql_text("SELECT 1"))
    return {"ok": True, "artifact_dir": _artifact_dir(), "db": "ok"}

@app.post("/ingest/upload-eml")
async def upload_eml(file: UploadFile = File(...), db: Session = Depends(get_db)):
    raw = await file.read()
    if len(raw) > 5_000_000:
        raise HTTPException(status_code=413, detail="file too large (max 5MB)")

    msg = BytesParser(policy=policy.default).parsebytes(raw)
    subject = msg.get("subject")
    from_addr = msg.get("from")
    to_addr = msg.get("to")
    date_hdr = msg.get("date")
    raw_headers = "".join([f"{k}: {v}\n" for (k, v) in msg.items()])

    html_body = ""
    text_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get_content_disposition()
            if disp == "attachment":
                continue
            if ctype == "text/html" and not html_body:
                html_body = part.get_content()
            elif ctype == "text/plain" and not text_body:
                text_body = part.get_content()
    else:
        ctype = msg.get_content_type()
        if ctype == "text/html":
            html_body = msg.get_content()
        elif ctype == "text/plain":
            text_body = msg.get_content()

    if not text_body and html_body:
        text_body = html_to_text(html_body)

    combined_for_links = "\n".join([text_body or "", html_body or ""]).strip()
    urls = extract_urls(combined_for_links)
    defanged = [defang_url(u) for u in urls]

    email = Email(
        id=str(uuid.uuid4()),
        source="upload:eml",
        subject=subject,
        from_addr=from_addr,
        to_addr=to_addr,
        date_hdr=date_hdr,
        raw_headers=raw_headers,
        body_text=text_body or "",
        body_html=html_body or "",
        extracted_urls=urls,
        defanged_urls=defanged,
        created_at=datetime.now(timezone.utc),
    )
    db.add(email)
    db.commit()
    return {"email_id": email.id}


@app.get("/emails", response_model=list[EmailListItem])
def list_emails(db: Session = Depends(get_db)):
    emails = db.query(Email).order_by(Email.created_at.desc()).limit(200).all()
    return [
        EmailListItem(
            id=e.id,
            source=e.source,
            subject=e.subject,
            from_addr=e.from_addr,
            created_at=e.created_at.isoformat(),
        )
        for e in emails
    ]


@app.delete("/emails/{email_id}")
def delete_email(email_id: str, db: Session = Depends(get_db)):
    e = db.query(Email).filter(Email.id == email_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="email not found")
    db.delete(e)
    db.commit()
    return {"ok": True, "deleted": email_id}


@app.get("/emails/{email_id}")
def get_email(email_id: str, db: Session = Depends(get_db)):
    e = db.query(Email).filter(Email.id == email_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="email not found")

    det = db.query(Detection).filter(Detection.email_id == email_id).order_by(Detection.id.desc()).first()
    rw = db.query(Rewrite).filter(Rewrite.email_id == email_id).order_by(Rewrite.id.desc()).first()

    return {
        "id": e.id,
        "source": e.source,
        "created_at": e.created_at.isoformat(),
        "headers": {
            "subject": e.subject,
            "from": e.from_addr,
            "to": e.to_addr,
            "date": e.date_hdr,
        },
        "body": {"text": e.body_text or ""},
        "links": {"defanged": e.defanged_urls or []},
        "mail_authentication": parse_authentication_from_raw_headers(e.raw_headers),
        "analysis": {
            "detection": (None if not det else {"label": det.label, "risk_score": det.risk_score, "reasons": det.reasons}),
            "rewrite": (None if not rw else {"safe_subject": rw.safe_subject, "safe_body": rw.safe_body, "used_llm": rw.used_llm}),
        },
    }


def _bert_enabled() -> bool:
    try:
        from app.bert_engine import bert_available
        return bert_available()
    except Exception:
        return False


def _run_llm_detection(subject, from_addr, body_text, urls):
    try:
        ai = detect_email_with_local_ai(subject, from_addr, body_text, urls)
        final_score = int(ai.get("score", 0))
        label = str(ai.get("label", "benign")).lower()
        ai_reasons = ai.get("reasons", []) or []

        reasons = []
        if isinstance(ai_reasons, list):
            reasons.extend([str(x) for x in ai_reasons if str(x).strip()])
        else:
            reasons.append(str(ai_reasons))

        # guardrail: bump score if obvious technical indicators present but LLM missed them
        has_ip_link = False
        has_punycode = False
        for u in urls[:25]:
            host = (urlparse(u).hostname or "").strip(".").lower()
            if not host:
                continue
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                has_ip_link = True
            if "xn--" in host:
                has_punycode = True

        if (has_ip_link or has_punycode) and final_score < 40:
            old_score = final_score
            final_score = max(final_score, 55)
            if final_score != old_score:
                reasons.append(f"Guardrail: score adjusted from {old_score}")
                label = "suspicious" if label == "benign" else label

        final_score = max(0, min(100, final_score))
        if label == "benign" and final_score > 60:
            final_score = 15
        elif label == "phishing" and final_score < 30:
            label = "suspicious"

        seen = set()
        reasons = [x for x in reasons if not (x in seen or seen.add(x))]
        return final_score, label, reasons
    except Exception as ex:
        print(f"LLM detection failed: {ex}")
        traceback.print_exc()
        return None


def _run_bert_detection(subject, from_addr, body_text, urls):
    try:
        from app.bert_engine import detect_email_with_bert
        result = detect_email_with_bert(subject, from_addr, body_text, urls)
        return int(result["score"]), result["label"], result["reasons"]
    except Exception as ex:
        print(f"BERT detection failed: {ex}")
        traceback.print_exc()
        return None


def _adjust_combined_score_for_mail_auth(
    score: int, label: str, raw_headers: str | None
) -> tuple[int, str, list[str]]:
    """
    When Authentication-Results reports SPF+DKIM+DMARC pass, reduce the combined score.
    ML models often flag legitimate marketing/ESP mail; auth is independent corroboration.
    """
    auth = parse_authentication_from_raw_headers(raw_headers or "")
    spf = (auth.get("spf") or "").lower()
    dkim = (auth.get("dkim") or "").lower()
    dmarc = (auth.get("dmarc") or "").lower()
    if auth.get("source") == "none" or spf != "pass" or dkim != "pass" or dmarc != "pass":
        return score, label, []

    before = score
    adjusted = max(0, score - 55)
    new_label = (
        "phishing" if adjusted >= 65 else "suspicious" if adjusted >= 30 else "benign"
    )
    note = (
        f"Strong mail authentication (SPF/DKIM/DMARC pass per headers): "
        f"combined score adjusted {before} → {adjusted}."
    )
    return adjusted, new_label, [note] if before > 0 else []


@app.get("/detect/methods")
def available_methods():
    return {
        "heuristic": True,
        "llm": _ai_enabled(),
        "bert": _bert_enabled(),
    }


@app.post("/emails/{email_id}/detect", response_model=DetectionResult)
async def detect(email_id: str, method: str = "heuristic", db: Session = Depends(get_db)):
    e = db.query(Email).filter(Email.id == email_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="email not found")

    db.query(Detection).filter(Detection.email_id == email_id).delete()
    db.flush()

    subject = e.subject or ""
    from_addr = e.from_addr or ""
    body_text = e.body_text or ""
    urls: list[str] = e.extracted_urls or []

    methods = {m.strip().lower() for m in method.split(",")}
    results = []

    if "llm" in methods and _ai_enabled():
        r = _run_llm_detection(subject, from_addr, body_text, urls)
        if r:
            results.append(("LLM", r))

    if "bert" in methods and _bert_enabled():
        r = _run_bert_detection(subject, from_addr, body_text, urls)
        if r:
            results.append(("BERT", r))

    if "heuristic" in methods:
        score, label, reasons = _heuristic_detect_fallback(e)
        results.append(("Heuristic", (score, label, reasons)))

    # if nothing ran (bad method name or all failed), fall back to heuristic
    if not results:
        score, label, reasons = _heuristic_detect_fallback(e)
        results.append(("Heuristic", (score, label, reasons)))

    # combine results: take max score, most severe label, union reasons
    final_score = 0
    final_label = "benign"
    all_reasons = []
    label_priority = {"benign": 0, "suspicious": 1, "phishing": 2}

    for name, (score, label, reasons) in results:
        prefix = f"[{name}] " if len(results) > 1 else ""
        all_reasons.extend([f"{prefix}{r}" for r in reasons])
        if score > final_score:
            final_score = score
        if label_priority.get(label, 0) > label_priority.get(final_label, 0):
            final_label = label

    final_score = max(0, min(100, final_score))

    adj_score, adj_label, auth_notes = _adjust_combined_score_for_mail_auth(
        final_score, final_label, e.raw_headers
    )
    if auth_notes:
        all_reasons.extend(auth_notes)
    final_score = adj_score
    final_label = adj_label

    det = Detection(
        email_id=email_id, label=final_label, risk_score=final_score,
        reasons=all_reasons, created_at=datetime.now(timezone.utc),
    )
    db.add(det)
    db.commit()

    return DetectionResult(label=final_label, risk_score=final_score, reasons=all_reasons)


@app.post("/emails/{email_id}/rewrite", response_model=RewriteResult)
async def rewrite(email_id: str, use_llm: bool = False, db: Session = Depends(get_db)):
    e = db.query(Email).filter(Email.id == email_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="email not found")

    # Delete old rewrites for this email
    db.query(Rewrite).filter(Rewrite.email_id == email_id).delete()
    db.flush()

    safe_body = _strip_links(e.body_text or "")
    used_llm_actual = False

    if use_llm and _ai_enabled():
        try:
            from app.ai_engine import _get_client
            client = _get_client()
            prompt = f"""Rewrite this email to be safe. Remove all suspicious elements:
- Replace all URLs with [LINK REMOVED]
- Remove urgency/pressure language
- Neutralize social engineering tactics
- Keep the core informational content
- Add [REWRITTEN BY PHISHNET] at the top

Original email:
{(e.body_text or '')[:3000]}"""

            response = client.chat.completions.create(
                model="llama3.2:1b",
                messages=[
                    {"role": "system", "content": "You rewrite emails to remove phishing elements. Output only the rewritten email text."},
                    {"role": "user", "content": prompt}
                ],
                extra_body={"keep_alive": "5m"},
            )
            llm_result = response.choices[0].message.content
            if llm_result and len(llm_result.strip()) > 20:
                safe_body = llm_result.strip()
                used_llm_actual = True
        except Exception as ex:
            print(f"LLM rewrite failed, using rule-based: {ex}")

    rw = Rewrite(email_id=email_id, safe_subject=e.subject, safe_body=safe_body, used_llm=used_llm_actual, created_at=datetime.now(timezone.utc))
    db.add(rw)
    db.commit()

    return RewriteResult(safe_subject=e.subject, safe_body=safe_body, used_llm=used_llm_actual)


@app.post("/emails/{email_id}/open-safely")
async def open_safely(email_id: str, req: OpenSafelyRequest, db: Session = Depends(get_db)):
    e = db.query(Email).filter(Email.id == email_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="email not found")

    urls: list[str] = e.extracted_urls or []
    if req.link_index < 0 or req.link_index >= len(urls):
        raise HTTPException(status_code=400, detail="invalid link_index")

    url = urls[req.link_index]
    job_id = str(uuid.uuid4())

    job = OpenSafelyJob(
        job_id=job_id,
        email_id=email_id,
        target_url=url,
        allow_target_origin=bool(req.allow_target_origin),
        status="queued",
        created_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()

    runner = os.getenv("RUNNER_BASE_URL", "http://runner:7070")

    job.status = "running"
    job.started_at = datetime.now(timezone.utc)
    db.commit()

    async with httpx.AsyncClient(timeout=60.0) as client:
        r = await client.post(
            f"{runner}/render",
            json={
                "url": url,
                "job": job_id,
                "outSubdir": "open-safely",
                "allowTargetOrigin": bool(req.allow_target_origin),
            },
        )

    if r.status_code != 200:
        job.status = "failed"
        job.error = r.text
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        raise HTTPException(status_code=502, detail={"runner_error": r.text, "job_id": job_id})

    job.status = "done"
    job.finished_at = datetime.now(timezone.utc)
    db.commit()

    job_dir = os.path.join(_artifact_dir(), "open-safely", job_id)
    manifest = {
        "desktop.png": "image/png",
        "mobile.png": "image/png",
        "iocs.json": "application/json",
        "text.txt": "text/plain",
        "meta.json": "application/json",
    }

    for name, mime in manifest.items():
        p = os.path.join(job_dir, name)
        if os.path.exists(p):
            size = os.path.getsize(p)
            sha = None
            db.add(Artifact(job_id=job_id, name=name, rel_path=f"open-safely/{job_id}/{name}", sha256=sha, mime=mime, size_bytes=size, created_at=datetime.now(timezone.utc)))

    db.commit()
    return {
        "job_id": job_id,
        "artifacts": {
            "desktop": f"/open-safely/download/{job_id}?name=desktop.png",
            "mobile": f"/open-safely/download/{job_id}?name=mobile.png",
            "iocs": f"/open-safely/download/{job_id}?name=iocs.json",
            "text": f"/open-safely/download/{job_id}?name=text.txt",
            "meta": f"/open-safely/download/{job_id}?name=meta.json",
        },
    }

@app.get("/open-safely/status/{job_id}")
def open_safely_status(job_id: str, db: Session = Depends(get_db)):
    job = db.query(OpenSafelyJob).filter(OpenSafelyJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return {
        "job_id": job.job_id,
        "email_id": job.email_id,
        "target_url": job.target_url,
        "allow_target_origin": job.allow_target_origin,
        "status": job.status,
        "error": job.error,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }

@app.get("/open-safely/artifacts/{job_id}")
def open_safely_artifacts(job_id: str, db: Session = Depends(get_db)):
    job = db.query(OpenSafelyJob).filter(OpenSafelyJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="job not found")

    artifacts = db.query(Artifact).filter(Artifact.job_id == job_id).order_by(Artifact.id.asc()).all()
    return {
        "job_id": job_id,
        "status": job.status,
        "artifacts": [
            {
                "name": a.name,
                "sha256": a.sha256,
                "mime": a.mime,
                "size_bytes": a.size_bytes,
                "url": f"/open-safely/download/{job_id}?name={a.name}",
            }
            for a in artifacts
        ],
    }

@app.get("/open-safely/download/{job_id}")
def open_safely_download(job_id: str, name: str, db: Session = Depends(get_db)):
    a = db.query(Artifact).filter(Artifact.job_id == job_id, Artifact.name == name).first()
    if not a:
        raise HTTPException(status_code=404, detail="not found")

    p = os.path.join(_artifact_dir(), a.rel_path)
    if not os.path.exists(p):
        raise HTTPException(status_code=404, detail="not found")

    return FileResponse(p, media_type=a.mime or None)
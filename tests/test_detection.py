"""
Run: cd apps/api && python -m pytest ../../tests/test_detection.py -v
Or:  python tests/test_detection.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.main import (
    _heuristic_detect_fallback,
    _adjust_combined_score_for_mail_auth,
    _registrable_domain,
    _is_third_party_domain,
    _domain_entropy,
    _has_suspicious_tld,
    _is_free_hosting,
    _count_subdomains,
    _url_has_credential_path,
    _brand_in_url_subdomain,
)


class FakeEmail:
    def __init__(self, subject="", from_addr="", body_text="", extracted_urls=None):
        self.subject = subject
        self.from_addr = from_addr
        self.body_text = body_text
        self.extracted_urls = extracted_urls or []


def make_email(subject="", from_addr="", body_text="", urls=None):
    return FakeEmail(subject=subject, from_addr=from_addr, body_text=body_text, extracted_urls=urls or [])


def _run(label, e):
    score, lbl, reasons = _heuristic_detect_fallback(e)
    print(f"[{label}] score={score}, label={lbl}, reasons={reasons}")
    return score, lbl, reasons


# --- phishing ---

def test_nigerian_scam():
    s, l, r = _run("Nigerian scam", make_email(
        subject="URGENT: Unclaimed Fund Notification",
        from_addr="Dr. James <drjames@random-domain.ng>",
        body_text="Dear beneficiary, you have been selected to receive a compensation fund "
                  "of 5.5 million USD from the United Nations. Contact us via Western Union.",
        urls=["http://192.168.1.100/claim"]
    ))
    assert l == "phishing", f"Expected phishing, got {l} (score={s})"
    assert s >= 65


def test_lottery_scam():
    s, l, r = _run("Lottery scam", make_email(
        subject="CONGRATULATIONS! You Won a Lottery!",
        from_addr="Lottery Board <lottery@prize-claims.xyz>",
        body_text="You have won a lottery of 2.5 million dollars. To claim your prize, "
                  "please purchase a $500 iTunes gift card and send us the code.",
        urls=["http://prize-claims.xyz/claim-now"]
    ))
    assert l == "phishing", f"Expected phishing, got {l} (score={s})"
    assert s >= 65


def test_brand_spoof_with_ip():
    s, l, r = _run("Brand spoof + IP", make_email(
        subject="Your PayPal account has been limited",
        from_addr="PayPal Security <security@random-mailer.com>",
        body_text="Your account has been limited due to suspicious activity. Verify your identity now.",
        urls=["http://45.33.32.156/verify-paypal"]
    ))
    assert s >= 65, f"Expected >=65, got {s}"


def test_brand_spoof_with_credential_harvesting():
    s, l, r = _run("Brand spoof + cred harvest", make_email(
        subject="Security Alert: Verify your account",
        from_addr="Amazon Security <security@amaz0n-alerts.com>",
        body_text="Unauthorized transaction detected. Please enter your password and verify "
                  "your bank details to confirm your identity within 24 hours.",
        urls=["https://amaz0n-alerts.com/verify", "https://amaz0n-alerts.com/login"]
    ))
    assert s >= 65, f"Expected >=65, got {s}"


def test_coinbase_spoof():
    s, l, r = _run("Coinbase spoof", make_email(
        subject="[Alert] Confirm your info is required [Case ID 153465]",
        from_addr='"support@mail.coinbase.com" <mssggeauthencti-cbspprt@medisept.com.au>',
        body_text="Your Coinbase account requires verification. Confirm your identity to avoid suspension.",
        urls=["https://medisept.com.au/coinbase-verify", "https://medisept.com.au/login"]
    ))
    assert s >= 30, f"Expected >=30 (suspicious+), got {s}"


def test_microsoft_spoof_with_brand_subdomain():
    s, l, r = _run("Microsoft brand subdomain", make_email(
        subject="Your Microsoft 365 subscription has expired",
        from_addr="Microsoft 365 <renewal@msft-billing.click>",
        body_text="Your subscription has expired. Re-enter your credentials to reactivate.",
        urls=["https://microsoft-login.secure.evil-domain.com/signin"]
    ))
    assert s >= 50, f"Expected >=50, got {s}"


def test_apple_id_phish():
    s, l, r = _run("Apple ID punycode", make_email(
        subject="Confirm your Apple ID",
        from_addr="Apple <noreply@xn--pple-43d.com>",
        body_text="Your Apple ID was used to sign in. If this wasn't you, verify immediately.",
        urls=["https://xn--pple-43d.com/verify"]
    ))
    assert s >= 35, f"Expected >=35, got {s}"


def test_netflix_spoof_with_suspicious_tld():
    s, l, r = _run("Netflix suspicious TLD", make_email(
        subject="Your Netflix payment failed",
        from_addr="Netflix <billing@netflix-update.xyz>",
        body_text="Your payment method has been declined. Update your billing information now "
                  "to avoid account suspension within 48 hours your account will be terminated.",
        urls=["https://netflix-update.xyz/billing"]
    ))
    assert s >= 40, f"Expected >=40, got {s}"


def test_credential_harvesting_explicit():
    s, l, r = _run("Credential harvest", make_email(
        subject="Security verification required",
        from_addr="Bank Alert <security@secure-banking-portal.top>",
        body_text="To protect your account, please enter your password and verify your SSN. "
                  "Failure to verify will result in account closure.",
        urls=["https://secure-banking-portal.top/verify"]
    ))
    assert s >= 50, f"Expected >=50, got {s}"


def test_gift_card_scam():
    s, l, r = _run("Gift card scam", make_email(
        subject="Urgent request from your manager",
        from_addr="CEO John <ceo@company-payroll.xyz>",
        body_text="I need you to purchase 5 Google Play cards worth $200 each. "
                  "Send me the codes immediately. This is urgent.",
        urls=["https://company-payroll.xyz/gift-card-instructions"]
    ))
    assert s >= 30, f"Expected >=30, got {s}"


def test_ip_link_only():
    s, l, r = _run("IP link", make_email(
        subject="Invoice #12345",
        from_addr="accounts@unknown-company.com",
        body_text="Please review your invoice.",
        urls=["http://185.234.72.11/invoice.pdf"]
    ))
    assert s >= 35, f"Expected >=35, got {s}"
    assert any("IP" in r_item for r_item in r)


def test_free_hosting_phish():
    s, l, r = _run("Free hosting phish", make_email(
        subject="Your Chase account needs attention",
        from_addr="Chase Bank <alert@chase-secure.weebly.com>",
        body_text="Your account has been limited. Verify your identity now.",
        urls=["https://chase-secure.weebly.com/verify-account"]
    ))
    assert s >= 30, f"Expected >=30, got {s}"


def test_data_uri_attack():
    s, l, r = _run("Data URI attack", make_email(
        subject="Document shared with you",
        from_addr="colleague@company.com",
        body_text="Please review this document.",
        urls=["data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="]
    ))
    assert s >= 30, f"Expected >=30, got {s}"


def test_excessive_subdomains():
    s, l, r = _run("Excessive subdomains", make_email(
        subject="Verify your account",
        from_addr="support@legitimate-company.com",
        body_text="Please verify your account.",
        urls=["https://secure.login.verify.account.evil-domain.com/auth"]
    ))
    assert s >= 30, f"Expected >=30, got {s}"


def test_shortener_with_brand_context():
    s, l, r = _run("Shortener + brand", make_email(
        subject="Your Amazon order has a problem",
        from_addr="Amazon <orders@amzn-delivery.com>",
        body_text="There was a problem with your order. Click below to resolve.",
        urls=["https://bit.ly/3xYzAbc"]
    ))
    assert s >= 30, f"Expected >=30, got {s}"


def test_perfect_storm_phish():
    s, l, r = _run("Perfect storm", make_email(
        subject="URGENT: Your PayPal account will be closed",
        from_addr="PayPal <security@paypa1-verify.xyz>",
        body_text="Dear beneficiary, your account has been limited due to suspicious activity. "
                  "Please enter your password and confirm your credit card number. "
                  "Failure to verify will result in permanent suspension within 24 hours.",
        urls=["http://185.234.72.11/paypal-verify/login"]
    ))
    assert l == "phishing", f"Expected phishing, got {l} (score={s})"
    assert s >= 80, f"Expected >=80 for multi-signal attack, got {s}"


# --- legitimate ---

def test_legit_newsletter():
    s, l, r = _run("Legit newsletter", make_email(
        subject="This week in tech: AI breakthroughs",
        from_addr="TechCrunch <newsletter@techcrunch.com>",
        body_text="Here are the top stories this week. Read more on our site.",
        urls=[
            "https://techcrunch.com/2024/03/15/article",
            "https://techcrunch.com/unsubscribe?id=123",
            "https://list-manage.com/track/click?u=abc"
        ]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 30


def test_legit_bank_notification():
    s, l, r = _run("Legit bank", make_email(
        subject="Your monthly statement is ready",
        from_addr="Chase <no-reply@chase.com>",
        body_text="Your January statement is now available. Log in to view your account details.",
        urls=["https://chase.com/statements", "https://chase.com/unsubscribe"]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 15


def test_legit_password_reset():
    s, l, r = _run("Legit password reset", make_email(
        subject="Password reset request",
        from_addr="GitHub <noreply@github.com>",
        body_text="We received a request to reset your password. If you didn't make this request, ignore this email.",
        urls=["https://github.com/password_reset?token=abc123"]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 20


def test_legit_ecommerce_receipt():
    s, l, r = _run("Legit ecommerce", make_email(
        subject="Your order has shipped!",
        from_addr="Amazon <shipment-tracking@amazon.com>",
        body_text="Your package is on its way. Track your delivery with the link below.",
        urls=[
            "https://amazon.com/track/123",
            "https://s3.amazonaws.com/images/logo.png",
            "https://amazon.com/unsubscribe"
        ]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 15


def test_legit_marketing_with_tracking():
    s, l, r = _run("Legit marketing", make_email(
        subject="50% off this weekend only!",
        from_addr="Nike <offers@nike.com>",
        body_text="Shop our biggest sale of the year. Limited time offer.",
        urls=[
            "https://nike.com/sale",
            "https://sendgrid.net/track/click?id=abc",
            "https://doubleclick.net/impression",
            "https://nike.com/unsubscribe",
        ]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 20


def test_legit_devpost_style_customer_io_newsletter():
    """ESP click tracking + sponsor subdomain on sender domain (false positive guard)."""
    s, l, r = _run("Devpost-style newsletter", make_email(
        subject="February is for shipping",
        from_addr="Devpost <support@devpost.com>",
        body_text="Hey Builders, new hackathons and tools this week. Follow us on Instagram!",
        urls=[
            "https://e.customeriomail.com/e/c/eyJlbWFpbF9pZCI6IjEifQ/abc123",
            "https://e.customeriomail.com/e/c/eyJlbWFpbF9pZCI6IjIifQ/def456",
            "https://amazon-nova.devpost.com/?utm_source=newsletter",
            "https://instagram.com/devposthq",
            "https://devpost.com/unsubscribe",
        ],
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 30


def test_adjust_score_when_spf_dkim_dmarc_pass():
    headers = (
        "Authentication-Results: spf=pass smtp.mailfrom=example.com; "
        "dkim=pass header.d=example.com; dmarc=pass\n"
    )
    s, lbl, notes = _adjust_combined_score_for_mail_auth(99, "phishing", headers)
    assert s == 44
    assert lbl == "suspicious"
    assert notes and "adjusted" in notes[0].lower()

    s2, lbl2, n2 = _adjust_combined_score_for_mail_auth(99, "phishing", None)
    assert s2 == 99 and lbl2 == "phishing" and n2 == []


def test_legit_plain_text_no_urls():
    s, l, r = _run("Legit plain text", make_email(
        subject="Meeting tomorrow at 3pm",
        from_addr="John Smith <john@company.com>",
        body_text="Hey, just a reminder about our meeting tomorrow. See you there.",
        urls=[]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s == 0


def test_legit_gmail_sender():
    s, l, r = _run("Legit gmail", make_email(
        subject="Check out this article",
        from_addr="friend@gmail.com",
        body_text="I found this interesting article about Python.",
        urls=["https://realpython.com/python-tips", "https://youtube.com/watch?v=abc"]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 15


def test_legit_shipping_notification():
    s, l, r = _run("Legit shipping", make_email(
        subject="Your package is on its way",
        from_addr="FedEx <tracking@fedex.com>",
        body_text="Your package has shipped. Estimated delivery: March 15.",
        urls=["https://fedex.com/tracking?id=123456789", "https://fedex.com/preferences"]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 15


def test_legit_saas_notification():
    s, l, r = _run("Legit SaaS", make_email(
        subject="New message in #general",
        from_addr="Slack <notification@slack.com>",
        body_text="You have a new message in the #general channel. Click to view.",
        urls=["https://slack.com/messages/general", "https://slack.com/account/notifications"]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 15


def test_legit_docusign():
    s, l, r = _run("Legit DocuSign", make_email(
        subject="Please sign: Employment Agreement",
        from_addr="DocuSign <dse@docusign.net>",
        body_text="John Smith sent you a document to review and sign.",
        urls=["https://docusign.net/signing/abc123", "https://docusign.com/help"]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 20


def test_legit_multi_tracking_pixels():
    s, l, r = _run("Legit tracking heavy", make_email(
        subject="Your weekly digest",
        from_addr="Company <digest@company.com>",
        body_text="Here is your weekly summary.",
        urls=[
            "https://company.com/digest/2024-03",
            "https://hubspot.com/track/abc",
            "https://mailchimp.com/track/def",
            "https://doubleclick.net/pixel",
            "https://google-analytics.com/collect",
            "https://company.com/unsubscribe",
        ]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 20


def test_legit_internal_company_email():
    s, l, r = _run("Legit internal", make_email(
        subject="Team standup notes",
        from_addr="Alice <alice@mycompany.com>",
        body_text="Here are the notes from today's standup. We discussed the Q1 roadmap.",
        urls=[]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s == 0


def test_legit_google_workspace():
    s, l, r = _run("Legit Google", make_email(
        subject="New sign-in from Chrome on Windows",
        from_addr="Google <no-reply@accounts.google.com>",
        body_text="Someone just signed in to your Google Account. If this was you, no action needed.",
        urls=[
            "https://myaccount.google.com/notifications",
            "https://accounts.google.com/signin/activity",
        ]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 15


def test_legit_microsoft_teams():
    s, l, r = _run("Legit MS Teams", make_email(
        subject="You have new messages in Teams",
        from_addr="Microsoft Teams <noreply@email.teams.microsoft.com>",
        body_text="You have 3 unread messages in Teams.",
        urls=[
            "https://teams.microsoft.com/l/message/123",
            "https://outlook.office365.com/mail",
        ]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 15


# --- edge cases ---

def test_urgency_only():
    s, l, r = _run("Urgency only", make_email(
        subject="Action required: verify your account",
        from_addr="Dropbox <no-reply@dropbox.com>",
        body_text="Please verify your identity to continue using Dropbox. Your account has been limited.",
        urls=["https://dropbox.com/verify"]
    ))
    assert s < 30, f"Expected <30 (urgency alone), got {s}"


def test_single_mismatch_link():
    s, l, r = _run("Single mismatch", make_email(
        subject="Your invoice",
        from_addr="billing@company.com",
        body_text="Please find your invoice attached.",
        urls=["https://random-cdn.com/invoice.pdf"]
    ))
    assert s < 65, f"Expected <65, got {s}"


def test_caps_subject_alone():
    s, l, r = _run("CAPS subject only", make_email(
        subject="IMPORTANT UPDATE FROM YOUR PROVIDER",
        from_addr="provider@service.com",
        body_text="We have updated our terms of service.",
        urls=["https://service.com/tos"]
    ))
    assert s < 30, f"Expected <30, got {s}"


def test_suspicious_tld_alone():
    s, l, r = _run("Suspicious TLD only", make_email(
        subject="Check out our new product",
        from_addr="sales@new-startup.xyz",
        body_text="We just launched a new product line. Take a look!",
        urls=["https://new-startup.xyz/products"]
    ))
    assert s < 65, f"Expected <65, got {s}"


def test_github_io_hosting():
    s, l, r = _run("GitHub Pages", make_email(
        subject="Check out my portfolio",
        from_addr="friend@gmail.com",
        body_text="I just published my portfolio site!",
        urls=["https://myname.github.io/portfolio"]
    ))
    assert s < 30, f"Expected <30, got {s}"


def test_mixed_legit_and_suspicious():
    s, l, r = _run("Mixed signals", make_email(
        subject="Action required: update your payment method",
        from_addr="Spotify <billing@spotify.com>",
        body_text="Your payment method has been declined. Update now to keep your subscription.",
        urls=["https://spotify.com/account/payment", "https://spotify.com/unsubscribe"]
    ))
    assert l == "benign", f"Expected benign, got {l} (score={s})"
    assert s < 20


# --- helpers ---

def test_registrable_domain():
    assert _registrable_domain("www.google.com") == "google.com"
    assert _registrable_domain("mail.google.co.uk") == "google.co.uk"
    assert _registrable_domain("example.com") == "example.com"
    assert _registrable_domain("sub.deep.example.com") == "example.com"
    assert _registrable_domain("") == ""
    assert _registrable_domain("a.b.c.amazon.co.uk") == "amazon.co.uk"


def test_third_party_detection():
    assert _is_third_party_domain("sendgrid.net") is True
    assert _is_third_party_domain("tracking.sendgrid.net") is True
    assert _is_third_party_domain("evil-phishing.com") is False
    assert _is_third_party_domain("doubleclick.net") is True
    assert _is_third_party_domain("hubspot.com") is True
    assert _is_third_party_domain("klaviyo.com") is True
    assert _is_third_party_domain("e.customeriomail.com") is True
    assert _is_third_party_domain("customeriomail.com") is True


def test_domain_entropy():
    assert _domain_entropy("google.com") < 3.5
    assert _domain_entropy("paypal.com") < 3.5
    assert _domain_entropy("xk7qm2nf9p.com") > 3.0
    assert _domain_entropy("") == 0.0


def test_suspicious_tld():
    assert _has_suspicious_tld("evil.xyz") is True
    assert _has_suspicious_tld("phishing.top") is True
    assert _has_suspicious_tld("legit.com") is False
    assert _has_suspicious_tld("company.org") is False
    assert _has_suspicious_tld("site.click") is True


def test_free_hosting():
    assert _is_free_hosting("site.weebly.com") is True
    assert _is_free_hosting("evil.herokuapp.com") is True
    assert _is_free_hosting("mysite.github.io") is True
    assert _is_free_hosting("google.com") is False
    assert _is_free_hosting("company.com") is False


def test_count_subdomains():
    assert _count_subdomains("evil.com") == 0
    assert _count_subdomains("sub.evil.com") == 1
    assert _count_subdomains("a.b.c.evil.com") == 3
    assert _count_subdomains("sub.example.co.uk") == 1
    assert _count_subdomains("example.co.uk") == 0


def test_url_has_credential_path():
    assert _url_has_credential_path("https://evil.com/login") is True
    assert _url_has_credential_path("https://evil.com/signin") is True
    assert _url_has_credential_path("https://evil.com/verify") is True
    assert _url_has_credential_path("https://evil.com/about") is False
    assert _url_has_credential_path("https://evil.com/products") is False
    assert _url_has_credential_path("https://evil.com/update-billing") is True


def test_brand_in_url_subdomain():
    assert _brand_in_url_subdomain("paypal.evil.com") is not None
    assert _brand_in_url_subdomain("secure-paypal.evil.com") is not None
    assert _brand_in_url_subdomain("evil.com") is None
    assert _brand_in_url_subdomain("paypal.com") is None


if __name__ == "__main__":
    tests = [
        test_nigerian_scam, test_lottery_scam, test_brand_spoof_with_ip,
        test_brand_spoof_with_credential_harvesting, test_coinbase_spoof,
        test_microsoft_spoof_with_brand_subdomain, test_apple_id_phish,
        test_netflix_spoof_with_suspicious_tld, test_credential_harvesting_explicit,
        test_gift_card_scam, test_ip_link_only, test_free_hosting_phish,
        test_data_uri_attack, test_excessive_subdomains, test_shortener_with_brand_context,
        test_perfect_storm_phish, test_legit_newsletter, test_legit_bank_notification,
        test_legit_password_reset, test_legit_ecommerce_receipt,
        test_legit_marketing_with_tracking, test_legit_devpost_style_customer_io_newsletter,
        test_adjust_score_when_spf_dkim_dmarc_pass, test_legit_plain_text_no_urls,
        test_legit_gmail_sender, test_legit_shipping_notification,
        test_legit_saas_notification, test_legit_docusign,
        test_legit_multi_tracking_pixels, test_legit_internal_company_email,
        test_legit_google_workspace, test_legit_microsoft_teams,
        test_urgency_only, test_single_mismatch_link, test_caps_subject_alone,
        test_suspicious_tld_alone, test_github_io_hosting,
        test_mixed_legit_and_suspicious, test_registrable_domain,
        test_third_party_detection, test_domain_entropy, test_suspicious_tld,
        test_free_hosting, test_count_subdomains, test_url_has_credential_path,
        test_brand_in_url_subdomain,
    ]

    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
            print(f"  > PASS\n")
        except AssertionError as ex:
            failed += 1
            print(f"  X FAIL: {ex}\n")
        except Exception as ex:
            failed += 1
            print(f"  X ERROR: {ex}\n")

    print(f"\nResults: {passed} passed, {failed} failed out of {passed + failed}")
    if failed == 0:
        print("All tests passed!")
    sys.exit(1 if failed else 0)

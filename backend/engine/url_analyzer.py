"""
SCAMSHIELD AI - Local URL & Domain Risk Analyzer
Deconstructs links, evaluates domain structure, inspects TLD reputation,
detects brand impersonation and obfuscation without external live blacklists.
"""

import re
from urllib.parse import urlparse, unquote
from typing import Dict, List, Any, Optional

# High-risk generic and free TLDs commonly abused in automated phishing kits
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".online", ".site", ".club", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".buzz", ".rest", ".icu", ".work", ".click", ".link",
    ".live", ".info", ".cam", ".biz", ".download", ".loan", ".racing", ".win"
}

# Known URL shortener services that mask the destination
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy",
    "ow.ly", "buff.ly", "rebrand.ly", "goo.gl", "shorturl.at", "bl.ink"
}

# Legitimate official brand domains for verification check
OFFICIAL_DOMAINS = {
    "sbi": ["onlinesbi.sbi", "sbi.co.in", "bank.sbi"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "visa": ["visa.com"],
    "mastercard": ["mastercard.com"],
    "stripe": ["stripe.com"],
    "venmo": ["venmo.com"],
    "cashapp": ["cash.app"],
    "wise": ["wise.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "google": ["google.com", "pay.google.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "kbc": ["sonyliv.com"],
    "discom": [],
    "power": []
}

# Sensitive brand names frequently impersonated in scams
BRAND_KEYWORDS = [
    "paypal", "sbi", "hdfc", "icici", "axis", "visa", "mastercard",
    "stripe", "venmo", "cashapp", "wise", "paytm", "phonepe", "gpay",
    "googlepay", "amazon", "flipkart", "power-bill", "electricity",
    "discom", "bill-pay", "kbc", "kyc-update", "aadhaar", "pan-link",
    "refund-portal", "cashback-claim"
]

def analyze_url(raw_url: Optional[str]) -> Dict[str, Any]:
    """
    Analyzes URL characteristics locally and computes risk signals.
    """
    if not raw_url or not raw_url.strip():
        return {
            "analyzed": False,
            "url": "",
            "signals": [],
            "url_risk_score": 0,
            "domain": "",
            "summary": "No URL provided."
        }

    clean_url = raw_url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url

    try:
        parsed = urlparse(clean_url)
    except Exception:
        return {
            "analyzed": True,
            "url": raw_url,
            "signals": [{
                "id": "url_malformed",
                "name": "Malformed or Obfuscated URL Syntax",
                "category": "URL Structure",
                "severity": "HIGH",
                "points": 20,
                "description": "The URL cannot be parsed into standard RFC 3986 components.",
                "evidence": raw_url
            }],
            "url_risk_score": 20,
            "domain": "",
            "summary": "Malformed URL syntax detected."
        }

    hostname = (parsed.hostname or "").lower()
    path = unquote(parsed.path).lower()
    full_url = clean_url.lower()

    detected_signals: List[Dict[str, Any]] = []
    total_points = 0

    # 1. Plain HTTP Check
    if parsed.scheme == "http":
        detected_signals.append({
            "id": "url_insecure_http",
            "name": "Unencrypted HTTP Protocol",
            "category": "Transport Security",
            "severity": "MEDIUM",
            "points": 14,
            "description": "Connection is unencrypted (HTTP instead of HTTPS). Legitimate payment and banking services mandate TLS/HTTPS.",
            "evidence": parsed.scheme
        })
        total_points += 14

    # 2. Direct IP Address Host
    is_ip = bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", hostname))
    if is_ip:
        detected_signals.append({
            "id": "url_ip_host",
            "name": "Direct IP Address Host",
            "category": "Domain Spoofing",
            "severity": "CRITICAL",
            "points": 28,
            "description": "URL connects to a raw IP address rather than a registered organizational domain, a common tactic to bypass domain reputation checks.",
            "evidence": hostname
        })
        total_points += 28

    # 3. URL Shortener Masking
    if hostname in URL_SHORTENERS:
        detected_signals.append({
            "id": "url_shortener",
            "name": "Obfuscating URL Shortener",
            "category": "Anonymization",
            "severity": "HIGH",
            "points": 18,
            "description": f"URL uses a shortener service ({hostname}) to disguise the ultimate landing destination from the user.",
            "evidence": hostname
        })
        total_points += 18

    # 4. High-Risk Suspicious TLD
    matched_tld = None
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            matched_tld = tld
            break

    if matched_tld:
        detected_signals.append({
            "id": "url_suspicious_tld",
            "name": f"High-Risk Generic TLD ({matched_tld})",
            "category": "Domain Reputation",
            "severity": "HIGH",
            "points": 20,
            "description": f"The domain uses an untrusted or inexpensive TLD ({matched_tld}) statistically associated with transient disposable phishing campaigns.",
            "evidence": matched_tld
        })
        total_points += 20

    # 5. Brand Impersonation / Deceptive Domain or Path Keywords
    brand_matches = [
        brand for brand in BRAND_KEYWORDS
        if brand in hostname or re.search(
            rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])", path
        )
    ]
    spoofed_brands = []
    for brand in brand_matches:
        is_legit = any(
            b_key in brand and any(
                hostname == valid_domain or hostname.endswith("." + valid_domain)
                for valid_domain in valid_domains
            )
            for b_key, valid_domains in OFFICIAL_DOMAINS.items()
        )
        if not is_legit:
            spoofed_brands.append(brand)

    if spoofed_brands:
        brand = spoofed_brands[0]
        detected_signals.append({
            "id": f"url_brand_spoof_{brand}",
            "name": f"Brand/Service Imitation in Unverified Domain ('{brand}')",
            "category": "Impersonation",
            "severity": "HIGH",
            "points": 24,
            "description": f"The hostname or path contains the brand keyword '{brand}' without a matching official hostname. This is a heuristic cue, not confirmation of maliciousness.",
            "evidence": hostname if brand in hostname else path
        })
        total_points += 24

    # 6. Sensitive Security and Account-Action Keywords
    sensitive_keywords = ("security", "verify", "verification", "login")
    matched_sensitive_keywords = [
        keyword for keyword in sensitive_keywords
        if re.search(rf"(?<![a-z0-9]){keyword}(?![a-z0-9])", f"{hostname}/{path}")
    ]
    has_account_keyword = bool(
        re.search(r"(?<![a-z0-9])account(?![a-z0-9])", f"{hostname}/{path}")
    )
    if matched_sensitive_keywords:
        detected_signals.append({
            "id": "url_sensitive_action_keywords",
            "name": "Security, Verification, or Login Terms in URL",
            "category": "URL Content Heuristic",
            "severity": "LOW",
            "points": 6,
            "description": "Security, verification, or login wording can occur on legitimate sites, but is worth checking when paired with an unverified domain or other suspicious cues.",
            "evidence": ", ".join(matched_sensitive_keywords)
        })
        total_points += 6

    # 7. Brand and Sensitive-Action Combinations
    combination_evidence = []
    if spoofed_brands:
        if "paypal" in spoofed_brands:
            combination_evidence.extend(
                f"paypal + {keyword}"
                for keyword in ("security", "verification")
                if keyword in matched_sensitive_keywords
            )
        if "login" in matched_sensitive_keywords:
            combination_evidence.extend(
                f"{brand} + login" for brand in spoofed_brands
            )
        if has_account_keyword and any(
            keyword in matched_sensitive_keywords for keyword in ("verify", "verification")
        ):
            combination_evidence.extend(
                f"{brand} + account + verification" for brand in spoofed_brands
            )

    if combination_evidence:
        detected_signals.append({
            "id": "url_brand_keyword_combination",
            "name": "Brand Paired with Sensitive Account Terms",
            "category": "Combined URL Heuristics",
            "severity": "HIGH",
            "points": 14,
            "description": "An unverified brand keyword appears alongside account, security, verification, or login wording. This combination raises risk but does not prove the URL is malicious.",
            "evidence": "; ".join(dict.fromkeys(combination_evidence))
        })
        total_points += 14

    # 8. Suspicious URL Path Keywords
    path_keywords = ("login", "verify", "verification", "secure", "account", "update")
    matched_path_keywords = [
        keyword for keyword in path_keywords
        if re.search(rf"(?<![a-z0-9]){keyword}(?![a-z0-9])", path)
    ]
    if matched_path_keywords:
        detected_signals.append({
            "id": "url_suspicious_path_keywords",
            "name": "Sensitive Account-Action Path",
            "category": "URL Content Heuristic",
            "severity": "MEDIUM",
            "points": 8,
            "description": "The path contains login, verification, security, account, or update wording commonly used on both legitimate pages and phishing pages.",
            "evidence": ", ".join(matched_path_keywords)
        })
        total_points += 8

    # 9. Suspicious Hyphenated Hostname Labels
    suspicious_label = next((
        label for label in hostname.split(".")
        if label.count("-") >= 2 and any(
            keyword in label for keyword in BRAND_KEYWORDS + list(sensitive_keywords)
        )
    ), None)
    if suspicious_label:
        detected_signals.append({
            "id": "url_hyphenated_hostname_keywords",
            "name": "Multiple Hyphenated Hostname Terms",
            "category": "Domain Structure Heuristic",
            "severity": "MEDIUM",
            "points": 6,
            "description": "A hostname label joins multiple brand or security-related terms with hyphens, a pattern that can make an unverified domain look official.",
            "evidence": suspicious_label
        })
        total_points += 6

    # 10. Excessive Subdomain Depth
    subdomain_parts = hostname.split(".")
    if len(subdomain_parts) > 3 and not is_ip:
        detected_signals.append({
            "id": "url_deep_subdomains",
            "name": "Excessive Subdomain Stacking",
            "category": "Domain Obfuscation",
            "severity": "MEDIUM",
            "points": 12,
            "description": f"Domain contains {len(subdomain_parts)-1} subdomain levels, often used to create deceptively realistic subdomain prefixes.",
            "evidence": hostname
        })
        total_points += 12

    # 11. Suspicious Characters (@ or Unusual Ports)
    if "@" in parsed.netloc:
        detected_signals.append({
            "id": "url_embedded_credentials",
            "name": "Deceptive Userinfo Syntax (@)",
            "category": "Domain Deception",
            "severity": "CRITICAL",
            "points": 25,
            "description": "URL includes an '@' character before the host, tricking users into misidentifying the true target domain.",
            "evidence": parsed.netloc
        })
        total_points += 25

    if parsed.port and parsed.port not in (80, 443):
        detected_signals.append({
            "id": "url_unusual_port",
            "name": f"Non-Standard Port (:{parsed.port})",
            "category": "Network Anomaly",
            "severity": "MEDIUM",
            "points": 15,
            "description": f"URL targets a non-standard port (:{parsed.port}) instead of standard secure web ports (80/443).",
            "evidence": str(parsed.port)
        })
        total_points += 15

    # 12. Excessive Length / Obfuscated Hex
    if len(clean_url) > 100 or "%" in parsed.path:
        detected_signals.append({
            "id": "url_excessive_length",
            "name": "Obfuscated / High-Entropy Path Components",
            "category": "URL Structure",
            "severity": "LOW",
            "points": 8,
            "description": "URL path contains encoded hex tokens or excessive string length to bypass signature filters.",
            "evidence": f"Length: {len(clean_url)}"
        })
        total_points += 8

    # 13. Legitimate Domain Recognition (Mitigating)
    is_standard_legit = False
    if parsed.scheme == "https" and not detected_signals:
        if hostname.endswith((".com", ".org", ".in", ".gov.in", ".edu", ".net")):
            is_standard_legit = True

    return {
        "analyzed": True,
        "url": clean_url,
        "domain": hostname,
        "scheme": parsed.scheme,
        "is_https": parsed.scheme == "https",
        "signals": detected_signals,
        "url_risk_score": total_points,
        "is_benign_indicator": is_standard_legit,
        "summary": f"Detected {len(detected_signals)} URL risk signals." if detected_signals else "URL conforms to standard web conventions."
    }

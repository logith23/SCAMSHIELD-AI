"""
SCAMSHIELD AI - Dynamic Message & Intent Pattern Analyzer
Analyzes arbitrary user-provided text for financial deception, social engineering,
and coercive psychological triggers without relying on rigid sentence matching.
"""

import re
from typing import Dict, List, Any, Optional

# Pre-compiled regex patterns for semantic detection
PATTERNS = {
    "urgency": [
        r"\b(immediately|right now|urgent(ly)?|hurry|instantly|asap)\b",
        r"\bwithin\s+\d+\s*(minutes?|mins?|hours?|hrs?|seconds?)\b",
        r"\bin\s+\d+\s*(minutes?|mins?|hours?)\b",
        r"\btonight\s+at\s+\d+(:?\d+)?\s*(pm|am)?\b",
        r"\bexpire[s|d|ing]?\s+(today|soon|now|tonight)\b",
        r"\b(last|final)\s+(chance|notice|reminder|warning)\b",
        r"\baction\s+required\s+immediately\b",
        r"\bbefore\s+(midnight|tonight|today|\d+\s*(pm|am))\b",
        r"\bdo\s+not\s+delay\b",
        r"\bact\s+(now|immediately|fast)\b",
        r"\babout\s+to\s+expire\b",
        r"\bsoon\s+to\s+avoid\b",
        r"\b(verify|act|update|complete)\s+[^.!?\n]*\bsoon\b",
        r"\b(as\s+soon\s+as\s+possible|promptly)\b",
        r"\btime\s+sensitive\b"
    ],
    "security_verification": [
        r"\b(security|identity|profile)\s+verification\b",
        r"\brequires?\s+(a\s+)?(security\s+)?verification\b",
        r"\bverify\s+(your\s+)?(details|identity|security\s+details|profile\s+details)\b",
        r"\bverification\s+instructions\b",
        r"\bsecurity\s+(check|update|review|alert)\b",
        r"\bidentity\s+confirmation\b"
    ],
    "account_restriction": [
        r"\b(to\s+)?avoid\s+(temporary\s+|permanent\s+|account\s+)?restrictions?\b",
        r"\b(temporary|permanent)\s+restrictions?\b",
        r"\baccount\s+(has\s+been\s+|will\s+be\s+)?restricted\b",
        r"\brestrictions?\s+(on|to)\s+(your\s+)?account\b",
        r"\b(service|feature|access)\s+(will\s+be\s+|is\s+)?restricted\b",
        r"\bavoid\s+(service\s+)?interruption\b",
        r"\blimited\s+(account\s+)?access\b"
    ],
    "threat": [
        r"\baccount\s+[^.!?\n]*(blocked|suspended|frozen|deactivated|closed|terminated|on\s+hold|hold|issue|problem|flagged|compromised|restricted|alert)\b",
        r"\b(bank\s+)?profile\s+[^.!?\n]*(suspended|blocked|about\s+to\s+expire|deactivated)\b",
        r"\b(issue|problem|alert)\s+with\s+(your\s+)?account\b",
        r"\b(your\s+)?account\s+has\s+an?\s+issue\b",
        r"\baccount\s+(suspension|blocking|deactivation|freeze)\b",
        r"\bpower\s+(supply\s+)?(will\s+be\s+|is\s+)?disconnected\b",
        r"\belectricity\s+(will\s+be\s+|is\s+)?(disconnected|cut(\s+off)?|stopped)\b",
        r"\bsim\s+(card\s+)?(will\s+be\s+|is\s+)?(deactivated|blocked|suspended)\b",
        r"\blegal\s+(action|notice|proceedings|consequences)\b",
        r"\bpolice\s+(complaint|arrest|case|fir|action)\b",
        r"\bcourt\s+(warrant|order|notice)\b",
        r"\b(fine|penalty)\s+(of\s+rs|will\s+be\s+imposed|charge)\b",
        r"\b(cbi|cyber\s*crime|enforcement\s*directorate)\b",
        r"\bservice\s+[^.!?\n]*(cutoff|disruption|suspension|cut|stopped|disconnected)\b",
        r"\barrest\s+warrant\b"
    ],
    "authority_impersonation": [
        r"\belectricity\s+board\b",
        r"\bdiscom(\s+officer)?\b",
        r"\bpower\s+corporation\b",
        r"\bstate\s+electricity\b",
        r"\bpolice\s+department\b",
        r"\bcyber\s*crime\s*(cell|branch|unit|officer)?\b",
        r"\bincome\s+tax\s+(department|officer)\b",
        r"\bbank\s+(manager|officer|executive|support|team|branch)\b",
        r"\b(this\s+is\s+)?customer\s+(care|support|helpdesk|service)\b",
        r"\b(reserve\s+bank\s+of\s+india|rbi)\b",
        r"\b(sbi|state\s+bank\s+of\s+india)\b",
        r"\bhdfc(\s+bank)?\b",
        r"\bicici(\s+bank)?\b",
        r"\baxis(\s+bank)?\b",
        r"\bpunjab\s+national\s+bank|pnb\b",
        r"\bkotak(\s+bank)?\b",
        r"\b(trai|telecom\s+regulatory)\b",
        r"\b(kbc|kaun\s+banega\s+crorepati)\b",
        r"\bamazon\s+(customer\s+service|support|security)\b",
        r"\bflipkart\s+(support|helpdesk)\b",
        r"\bofficer\s+[a-zA-Z]+\b"
    ],
    "credential_request": [
        r"\b(share|enter|send|verify|provide|give)\s+(?:your\s+|the\s+)?(otp|one\s+time\s+password)\b",
        r"\b(send|share|tell|provide|forward)\s+(?:me\s+)?(?:your\s+|the\s+)?(otp|code|pin|password)\b",
        r"\bsend\s+the\s+otp\b",
        r"\b(enter|give|send|share)\s+(?:your\s+|the\s+)?(upi\s+)?pin\b",
        r"\bcvv|card\s+number|card\s+expiry\b",
        r"\b(netbanking|net\s+banking)\s+(password|login|credentials)\b",
        r"\b(aadhaar|pan)\s+(card\s+)?(number|details)\b",
        r"\bbanking\s+password\b",
        r"\bsecret\s+(code|pin|password)\b"
    ],
    "pin_to_receive": [
        r"\b(enter|input|type)\s+(your\s+)?(upi\s+)?pin\s+to\s+(receive|credit|claim|get|win|accept)\b",
        r"\bpin\s+(is\s+)?required\s+to\s+(credit|receive|collect|claim)\b",
        r"\baccept\s+(the\s+)?(payment|collect|request)\s+and\s+enter\s+(your\s+)?pin\b",
        r"\benter\s+pin\s+paise\s+milenge\b",
        r"\benter\s+pin\s+to\s+receive\s+money\b"
    ],
    "link_click_pressure": [
        r"\b(click|open|tap|visit)\s+(on\s+)?(the\s+)?(link|url|website|portal|here|below)\b",
        r"\bhttps?://[^\s]+\b",
        r"\bclick\s+http\b",
        r"\bupdate\s+by\s+clicking\b",
        r"\bverify\s+(by\s+clicking|at\s+link)\b"
    ],
    "fake_reward": [
        r"\b(won|win|winner)\s+(?:a\s+)?(?:cashback\s+|cash\s+)?(prize|reward|lucky\s+draw|lottery|crorepati|bonus|cashback)\b",
        r"\b(cashback|cash\s+reward|bonus)\s+(reward|bonus|claim|pending|credited)\b",
        r"\bcashback\s+reward\b",
        r"\bcongratulations!?\b",
        r"\bcash\s+reward\s+of\s+(rs\.?|inr|₹)\b",
        r"\bkbc\s+(lucky\s+draw|lottery|winner)\b",
        r"\bscratch\s+card\s+(winner|reward)\b",
        r"\bcashback\s+(bonus|claim|pending|credited)\b",
        r"\bclaim\s+(your\s+)?(prize|reward|cashback|bonus)\b"
    ],
    "investment_scam": [
        r"\bguaranteed\s+(returns?|profits?|income)\b",
        r"\bdouble\s+your\s+money\b",
        r"\bdaily\s+returns?\s+of\b",
        r"\b100%\s+(risk[- ]free|safe\s+investment)\b",
        r"\bcrypto\s+(trading\s+bot|doubler|guaranteed)\b",
        r"\binvest\s+(rs\.?|₹|inr)\s*\d+\s+and\s+get\b",
        r"\bhigh\s+yield\s+investment\b"
    ],
    "job_task_scam": [
        r"\bpart[- ]time\s+job\b",
        r"\bwork\s+from\s+home\s+(earn|job)\b",
        r"\bearn\s+(rs\.?|₹|inr)\s*\d+[- ]\d+\s+(daily|per\s+day)\b",
        r"\blike\s+(youtube\s+videos?|posts?|reels?)\s+(and\s+earn|to\s+get)\b",
        r"\btelegram\s+(task|channel|group|work)\b",
        r"\bprepaid\s+(task|order|recharge)\b",
        r"\bhotel\s+review\s+task\b"
    ],
    "remote_app_install": [
        r"\banydesk\b",
        r"\bteamviewer\b",
        r"\brustdesk\b",
        r"\bquicksupport\b",
        r"\bairdroid\b",
        r"\bscreenshare\b",
        r"\bzoho\s+assist\b",
        r"\bdownload\s+(and\s+install\s+)?apk\b",
        r"\binstall\s+[^\s]+\.apk\b",
        r"\binstall\s+(support|verification|security|bank)\s+app\b"
    ],
    "payment_instruction": [
        r"\bpay\s+(rs\.?|₹|inr)\s*\d+\b",
        r"\btransfer\s+(rs\.?|₹|inr)\s*\d+\b",
        r"\bsend\s+(rs\.?|₹|inr)\s*\d+\b",
        r"\bverification\s+(fee|charge|amount)\s*(of\s+)?(rs\.?|₹|inr)?\b",
        r"\bnominal\s+(fee|charge|amount|payment)\b",
        r"\bverify\s+(by\s+making\s+a\s+|with\s+a\s+)?small\s+payment\b",
        r"\brecharge\s+(rs\.?|₹|inr)?\s*\d+\b",
        r"\bdeposit\s+(rs\.?|₹|inr)?\s*\d+\b",
        r"\bpay\s+[^.!?\n]*\bto\s+(receive|get|claim|unlock|win|collect|credit)\b",
        r"\bpay\s+immediately\b"
    ],
    "fake_customer_support": [
        r"\b(this\s+is|from|speaking\s+from|calling\s+from|we\s+are)\s+(the\s+)?customer\s+(support|care|service|helpdesk)\b",
        r"\bcustomer\s+(care|support|helpdesk|service)\s+(team|agent|desk|officer|executive)\b",
        r"\bcall\s+officer\s+[a-zA-Z]+\b",
        r"\bcall\s+(immediately|now)\s+(at|on)\s+\d{10}\b",
        r"\bcontact\s+(customer\s+care|support|helpline)\s+(at|on)?\s*\d{10}\b",
        r"\bhelpline\s+(number)?\s*:?\s*\d{10}\b"
    ]
}

# Signal descriptors and weightings
SIGNAL_CONFIG = {
    "pin_to_receive": {
        "name": "PIN Entry to Receive Money Deception",
        "severity": "CRITICAL",
        "points": 35,
        "category": "Credential Theft",
        "desc": "Claims that entering your UPI PIN will credit money to you. UPI PIN is exclusively used to debit/send money."
    },
    "credential_request": {
        "name": "Sensitive Credential or OTP Solicitation",
        "severity": "CRITICAL",
        "points": 28,
        "category": "Credential Theft",
        "desc": "Requests secret financial credentials (OTP, PIN, passwords, CVV). Legitimate institutions never solicit these."
    },
    "remote_app_install": {
        "name": "Remote Access Tool / Unknown APK Coercion",
        "severity": "CRITICAL",
        "points": 28,
        "category": "Malware / Screen Takeover",
        "desc": "Pressures recipient to install screen-sharing tools (e.g., AnyDesk, TeamViewer) or unverified APK files."
    },
    "threat": {
        "name": "Coercive Threats & Account Blocking Intimidation",
        "severity": "HIGH",
        "points": 22,
        "category": "Fear Manipulation",
        "desc": "Threatens service disconnection, account freezing, or legal action to induce panic."
    },
    "urgency": {
        "name": "Artificial Urgency & Deadline Pressure",
        "severity": "HIGH",
        "points": 18,
        "category": "Temporal Pressure",
        "desc": "Imposes artificial countdowns or immediate deadlines to prevent victim from calmly verifying claims."
    },
    "fake_reward": {
        "name": "Unsolicited Prize / Lottery / Cashback Trap",
        "severity": "HIGH",
        "points": 20,
        "category": "Financial Deception",
        "desc": "Lures victim with unexpected cash prizes, lotteries, or cashback to induce impulsive compliance."
    },
    "investment_scam": {
        "name": "Guaranteed High-Return Investment Promise",
        "severity": "HIGH",
        "points": 20,
        "category": "Financial Fraud",
        "desc": "Promises unrealistic or risk-free profits, typical of Ponzi schemes and crypto doubler scams."
    },
    "job_task_scam": {
        "name": "Work From Home / Daily Task Payment Trap",
        "severity": "HIGH",
        "points": 20,
        "category": "Job Fraud",
        "desc": "Offers high pay for trivial tasks (liking videos, hotel reviews) while demanding upfront prepaid deposits."
    },
    "authority_impersonation": {
        "name": "Institution or Bank Impersonation",
        "severity": "HIGH",
        "points": 16,
        "category": "Impersonation",
        "desc": "Impersonates trusted entities (SBI, HDFC, Electricity Board, Police, RBI) to exploit trust."
    },
    "payment_instruction": {
        "name": "Unsolicited Payment or 'Verification Fee' Request",
        "severity": "MEDIUM",
        "points": 16,
        "category": "Payment Coercion",
        "desc": "Instructs recipient to pay money or transfer nominal fees (e.g. ₹2) under the guise of verification."
    },
    "link_click_pressure": {
        "name": "External Link Click Call-to-Action",
        "severity": "MEDIUM",
        "points": 12,
        "category": "Phishing Vector",
        "desc": "Directs user away from official applications to an external link or portal."
    },
    "fake_customer_support": {
        "name": "Unofficial Support Contact / Mobile Helpline",
        "severity": "MEDIUM",
        "points": 14,
        "category": "Impersonation",
        "desc": "Directs user to call a personal mobile number pretending to be an official bank or utility officer."
    },
    "security_verification": {
        "name": "Security Verification Request",
        "severity": "MEDIUM",
        "points": 10,
        "category": "Verification Pressure",
        "desc": "Requests account or identity verification. This is not inherently fraudulent, but can become suspicious when combined with urgency, restrictions, payment requests, or credential requests."
    },

    "account_restriction": {
        "name": "Account Restriction Warning",
        "severity": "MEDIUM",
        "points": 10,
        "category": "Fear Manipulation",
        "desc": "Warns that account access may be restricted. This becomes more suspicious when combined with urgency, payment requests, or credential requests."
    }
}


def analyze_message(message_text: Optional[str]) -> Dict[str, Any]:
    """
    Analyzes arbitrary user text for scam signals, extracting semantic patterns,
    extracted entities (links, amounts, numbers), and risk contributions.
    """
    if not message_text or not message_text.strip():
        return {
            "analyzed": False,
            "signals": [],
            "extracted_urls": [],
            "extracted_amounts": [],
            "extracted_phones": [],
            "message_risk_score": 0,
            "summary": "No message text provided."
        }

    clean_text = message_text.strip()
    lower_text = clean_text.lower()

    detected_signals: List[Dict[str, Any]] = []
    total_points = 0

    # Test each signal category against patterns
    for signal_key, pattern_list in PATTERNS.items():
        matched = False
        matching_snippets = []

        for pat in pattern_list:
            match = re.search(pat, lower_text, re.IGNORECASE)
            if match:
                matched = True
                matching_snippets.append(match.group(0))
                # Stop after first match in category to avoid duplicate category triggers
                break

        if matched and signal_key in SIGNAL_CONFIG:
            cfg = SIGNAL_CONFIG[signal_key]
            detected_signals.append({
                "id": f"msg_{signal_key}",
                "name": cfg["name"],
                "category": cfg["category"],
                "severity": cfg["severity"],
                "points": cfg["points"],
                "description": cfg["desc"],
                "evidence": matching_snippets[0] if matching_snippets else ""
            })
            total_points += cfg["points"]

    # Extract entities for cross-modality enhancement
    extracted_urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", clean_text)
    extracted_amounts = re.findall(r"(?:rs\.?|₹|inr)\s*[\d,]+(?:\.\d+)?|\b\d+\s*(?:rupees|rs)\b", clean_text, re.IGNORECASE)
    extracted_phones = re.findall(r"\b(?:\+91[- ]?)?[6-9]\d{9}\b", clean_text)

    # Check for small verification payment heuristic (Rs 1, 2, 5, 10, etc.)
    has_small_amount = False
    for amt_str in extracted_amounts:
        num_match = re.search(r"\d+", amt_str)
        if num_match:
            val = int(num_match.group(0))
            if 1 <= val <= 20:
                has_small_amount = True
                break

    # Compound pattern: Credential solicitation combined with account threats
    has_threat = any(s["id"] == "msg_threat" for s in detected_signals)
    has_cred = any(s["id"] in ("msg_credential_request", "msg_pin_to_receive") for s in detected_signals)
    has_impersonation = any(s["id"] in ("msg_authority_impersonation", "msg_fake_customer_support") for s in detected_signals)

    if has_threat and has_cred:
        detected_signals.append({
            "id": "msg_credential_threat_coercion",
            "name": "Coercive Credential Phishing Under Threat Pretext",
            "category": "Credential Theft",
            "severity": "CRITICAL",
            "points": 18,
            "description": "Attacker demands credentials (OTP, PIN, passwords) under active threat of account suspension, a hallmark of account takeover fraud.",
            "evidence": "Account threat + Credential demand"
        })
        total_points += 18

    # Compound pattern: Impersonation combined with credential request (e.g. fake support asking for OTP)
    if has_impersonation and has_cred:
        detected_signals.append({
            "id": "msg_impersonation_credential_theft",
            "name": "Support/Authority Impersonation Credential Harvesting",
            "category": "Credential Theft",
            "severity": "CRITICAL",
            "points": 20,
            "description": "Attacker impersonates customer support or an authoritative entity while soliciting OTP, PIN, or credentials. Legitimate customer support will never request your OTP.",
            "evidence": "Authority / Support Impersonation + OTP / Credential Request"
        })
        total_points += 20

    # Compound pattern: Fake reward combined with payment instruction (Advance-fee fraud)
    has_reward = any(s["id"] == "msg_fake_reward" for s in detected_signals)
    has_payment = any(s["id"] == "msg_payment_instruction" for s in detected_signals)
    if has_reward and has_payment:
        detected_signals.append({
            "id": "msg_advance_fee_reward_trap",
            "name": "Advance Fee / Fee-to-Receive Reward Trap",
            "category": "Financial Deception",
            "severity": "HIGH",
            "points": 18,
            "description": "Demands an upfront payment or deposit to receive, claim, or unlock a prize, cashback, or reward.",
            "evidence": "Fake Reward + Payment Instruction"
        })
        total_points += 18

    if has_small_amount and any(s["id"] in ("msg_threat", "msg_urgency", "msg_authority_impersonation", "msg_fake_reward", "msg_job_task_scam") for s in detected_signals):
        # Add micro-amount verification trap signal if not already added
        if not any(s["id"] == "msg_micro_verification_trap" for s in detected_signals):
            detected_signals.append({
                "id": "msg_micro_verification_trap",
                "name": "Nominal Verification Fee Trap (₹1 - ₹20)",
                "category": "Social Engineering",
                "severity": "HIGH",
                "points": 18,
                "description": "Scammers ask for small verification payments (₹1–₹20) to disarm suspicion while capturing banking credentials or initiating auto-debit mandates.",
                "evidence": "Small payment requested under verification or reward pretext"
            })
            total_points += 18

    return {
        "analyzed": True,
        "input_length": len(clean_text),
        "signals": detected_signals,
        "extracted_urls": extracted_urls,
        "extracted_amounts": extracted_amounts,
        "extracted_phones": extracted_phones,
        "message_risk_score": total_points,
        "summary": f"Detected {len(detected_signals)} message signals." if detected_signals else "No coercive or manipulative patterns detected in message."
    }

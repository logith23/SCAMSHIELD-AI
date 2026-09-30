"""
SCAMSHIELD AI - UPI & Payment Identifier Risk Analyzer
Evaluates VPA syntax, PSP handle legitimacy, impersonation cues, and contextual payment anomalies.
Distinguishes between format validation, contextual heuristics, and external verified intelligence.
"""

import re
from typing import Dict, List, Any, Optional, Union

# Common retail PSP handles in India (consumer bank extensions)
RETAIL_PSP_HANDLES = {
    "okhdfcbank", "okaxis", "oksbi", "okicici", "paytm", "ybl",
    "ibl", "apl", "axl", "barodampay", "centralbank", "idfcbank",
    "indus", "kotak", "postbank", "sbi", "upi", "federal"
}

# Deceptive keywords commonly registered in consumer handles by scammers
SUSPICIOUS_HANDLE_KEYWORDS = [
    "discom", "electricity", "power", "refund", "cashback", "prize",
    "reward", "winner", "helpdesk", "support", "care", "customer",
    "billing", "officer", "kyc", "verify", "verification", "police",
    "kbc", "lottery", "dept", "department", "govt", "rbi"
]

def analyze_payment_metadata(
    upi_id: Optional[str] = None,
    amount: Optional[Union[float, int, str]] = None,
    payment_method: Optional[str] = None,
    payment_reason: Optional[str] = None,
    context_text: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyzes payment identifier structure and combines payment context signals.
    """
    upi_provided = bool(upi_id and upi_id.strip())
    clean_upi = upi_id.strip().lower() if upi_provided else ""

    detected_signals: List[Dict[str, Any]] = []
    total_points = 0
    vpa_info = {
        "valid_structure": False,
        "username": "",
        "handle": "",
        "is_known_psp": False
    }

    # 1. Structure and Syntax Analysis
    if upi_provided:
        # UPI VPA RFC syntax check: username@handle
        vpa_regex = r"^([a-zA-Z0-9.\-_]{2,256})@([a-zA-Z0-9]{2,64})$"
        match = re.match(vpa_regex, clean_upi)

        if match:
            username = match.group(1)
            handle = match.group(2)
            vpa_info["valid_structure"] = True
            vpa_info["username"] = username
            vpa_info["handle"] = handle
            vpa_info["is_known_psp"] = handle in RETAIL_PSP_HANDLES

            # 2. Impersonation Keyword in Retail Handle
            # Scammers use retail handles (@okaxis, @paytm) with official-sounding names (discom.verify92)
            matched_keywords = [kw for kw in SUSPICIOUS_HANDLE_KEYWORDS if kw in username]
            if matched_keywords:
                detected_signals.append({
                    "id": "upi_impersonation_handle",
                    "name": f"Institutional Keyword in Personal Handle ('{matched_keywords[0]}')",
                    "category": "Identity Spoofing",
                    "severity": "HIGH",
                    "points": 20,
                    "description": f"The VPA username '{username}' mimics an official department or utility ('{matched_keywords[0]}') on a consumer bank handle (@{handle}) rather than an authorized corporate aggregator.",
                    "evidence": clean_upi
                })
                total_points += 20

            # 3. High-Entropy / Randomized Burner Pattern
            if re.search(r"[a-z0-9]{8,}", username) and any(c.isdigit() for c in username) and any(c.isalpha() for c in username):
                detected_signals.append({
                    "id": "upi_burner_pattern",
                    "name": "High-Entropy Identifier Pattern",
                    "category": "Identifier Anomaly",
                    "severity": "LOW",
                    "points": 8,
                    "description": "The VPA username contains a randomized alphanumeric sequence consistent with disposable or temporary payment handles.",
                    "evidence": username
                })
                total_points += 8

        else:
            # Malformed syntax
            detected_signals.append({
                "id": "upi_malformed_syntax",
                "name": "Irregular UPI Identifier Syntax",
                "category": "Format Analysis",
                "severity": "LOW",
                "points": 8,
                "description": "The identifier does not conform to standard UPI VPA formatting (user@handle). Note: this indicates format non-compliance, not verified fraud.",
                "evidence": clean_upi
            })
            total_points += 8

    # 4. Context Mismatch: Claimed Institution vs VPA
    if context_text and upi_provided and vpa_info["valid_structure"]:
        context_lower = context_text.lower()
        claimed_org = None
        if "electricity" in context_lower or "power" in context_lower or "discom" in context_lower:
            claimed_org = "Electricity Board"
        elif "bank" in context_lower or "sbi" in context_lower or "hdfc" in context_lower:
            claimed_org = "Banking Institution"
        elif "kbc" in context_lower or "lottery" in context_lower:
            claimed_org = "Lottery Organization"

        # If claiming official org, but VPA is clearly personal
        if claimed_org and vpa_info["is_known_psp"]:
            # Check if username is a personal name (numbers at end, etc.)
            has_personal_indicator = bool(re.search(r"\d{2,4}$", vpa_info["username"]))
            if has_personal_indicator and not any(s["id"] == "upi_impersonation_handle" for s in detected_signals):
                detected_signals.append({
                    "id": "upi_context_mismatch",
                    "name": f"Claimed Identity Mismatch ({claimed_org})",
                    "category": "Context Mismatch",
                    "severity": "HIGH",
                    "points": 18,
                    "description": f"The communication claims to represent a {claimed_org}, but payment is directed to an individual personal handle (@{vpa_info['handle']}).",
                    "evidence": f"Context: {claimed_org} -> VPA: {clean_upi}"
                })
                total_points += 18

    # 5. Payment Amount Analysis
    parsed_amount = None
    if amount is not None:
        amt_str = str(amount).replace("₹", "").replace(",", "").replace("Rs.", "").replace("Rs", "").strip()
        try:
            parsed_amount = float(amt_str)
        except ValueError:
            parsed_amount = None

    if parsed_amount is not None:
        # Micro verification amount check (₹1 to ₹20)
        context_str = f"{context_text or ''} {payment_reason or ''}".lower()
        if 1 <= parsed_amount <= 20:
            if any(term in context_str for term in ["verify", "verification", "reactivate", "activate", "unblock", "link", "kyc"]):
                detected_signals.append({
                    "id": "payment_micro_verification_trap",
                    "name": f"Nominal ₹{parsed_amount:g} Verification Pretext",
                    "category": "Credential Extraction",
                    "severity": "HIGH",
                    "points": 20,
                    "description": f"A token payment of ₹{parsed_amount:g} is requested under the guise of account verification. This pattern is commonly used to authorize background mandates or siphon bank credentials.",
                    "evidence": f"Amount: ₹{parsed_amount:g} for verification"
                })
                total_points += 20

        # Collect Request Inversion Indicator
        if any(term in context_str for term in ["prize", "won", "winner", "reward", "lottery", "cashback", "refund"]):
            detected_signals.append({
                "id": "payment_collect_request_inversion",
                "name": "Collect Request Inversion (Outgoing Payment for Incoming Claim)",
                "category": "Payment Inversion",
                "severity": "CRITICAL",
                "points": 26,
                "description": "Context indicates the user is expecting to RECEIVE money (prize/refund), but an outgoing payment or collect request is being directed to a UPI ID. A UPI PIN is NEVER required to receive money.",
                "evidence": f"Context: Receiving funds; Mechanism: Outgoing payment to {clean_upi or 'UPI'}"
            })
            total_points += 26

    return {
        "analyzed": upi_provided or (parsed_amount is not None) or bool(payment_reason),
        "upi_id": clean_upi,
        "parsed_amount": parsed_amount,
        "payment_method": payment_method or "UPI",
        "payment_reason": payment_reason,
        "vpa_info": vpa_info,
        "signals": detected_signals,
        "payment_risk_score": total_points,
        "external_intelligence": "No live NPCI or bank database lookup performed in safe offline prototype mode.",
        "summary": f"Detected {len(detected_signals)} payment identifier signals." if detected_signals else "Identifier format is consistent."
    }

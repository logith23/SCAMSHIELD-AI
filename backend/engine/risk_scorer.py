"""
SCAMSHIELD AI - Composite Risk Scoring Engine
Synthesizes signals across text, URL, UPI, and payment context into a 0-100 score.
Ensures transparent signal contributions, multi-signal synergy, and accurate scam classification.
"""

from typing import Dict, List, Any

# Standard hackathon risk level thresholds
def get_risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL RISK"
    if score >= 60:
        return "HIGH RISK"
    if score >= 30:
        return "CAUTION"
    return "LOW RISK"

def classify_scam_type(all_signals: List[Dict[str, Any]], score: int) -> str:
    """
    Classifies the scam category based on dominant evidence signatures.
    Only assigns categories when actual evidence exists; otherwise returns 'Unknown/Other'.
    """
    if score < 30 and not all_signals:
        return "Legitimate / Low Suspicion"

    signal_ids = {s.get("id") for s in all_signals}

    # High-confidence classification rules
    if "msg_pin_to_receive" in signal_ids or "payment_collect_request_inversion" in signal_ids:
        return "QR/payment request scam"

    if "msg_credential_request" in signal_ids or "msg_remote_app_install" in signal_ids or "payment_micro_verification_trap" in signal_ids or "msg_impersonation_credential_theft" in signal_ids:
        return "Credential/OTP theft attempt"

    if "msg_fake_reward" in signal_ids or "msg_advance_fee_reward_trap" in signal_ids:
        return "Fake cashback/reward"

    if "msg_investment_scam" in signal_ids:
        return "Investment scam"

    if "msg_job_task_scam" in signal_ids:
        return "Job/task scam"

    if "msg_fake_customer_support" in signal_ids:
        return "Fake customer support"

    # Authority / Bank / Utility Impersonation
    has_impersonation = (
        "msg_authority_impersonation" in signal_ids or
        "upi_impersonation_handle" in signal_ids or
        "upi_context_mismatch" in signal_ids or
        any("brand_spoof" in sid for sid in signal_ids)
    )
    if has_impersonation:
        return "Bank/account impersonation"

    # Delivery / Refund
    if any("refund" in s.get("name", "").lower() for s in all_signals):
        return "Delivery/refund scam"

    # General suspicious payment request
    if "msg_payment_instruction" in signal_ids or "msg_threat" in signal_ids:
        return "Suspicious payment request"

    if score >= 30:
        return "Unknown/Other"

    return "Legitimate / Low Suspicion"

def compute_risk_score(
    message_analysis: Dict[str, Any],
    url_analysis: Dict[str, Any],
    payment_analysis: Dict[str, Any],
    intent_analysis: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Computes a composite 0-100 risk score dynamically from detected signals.
    """
    message_signals = message_analysis.get("signals", [])
    url_signals = url_analysis.get("signals", [])
    payment_signals = payment_analysis.get("signals", [])

    all_signals = message_signals + url_signals + payment_signals

    # Deduplicate signals by id
    unique_signals: List[Dict[str, Any]] = []
    seen_ids = set()
    for s in all_signals:
        sid = s.get("id")
        if sid and sid not in seen_ids:
            seen_ids.add(sid)
            unique_signals.append(s)

    # 1. Base Points Sum
    base_points = sum(s.get("points", 0) for s in unique_signals)

    # 2. Multi-Signal Synergy Boost
    # When multiple distinct modalities (Message, Link, Payment) coordinate deceptive cues,
    # the composite threat exceeds individual parts.
    active_modalities = 0
    if message_signals:
        active_modalities += 1
    if url_signals:
        active_modalities += 1
    if payment_signals:
        active_modalities += 1

    synergy_bonus = 0
    if active_modalities >= 3 and base_points >= 40:
        synergy_bonus = 15
        unique_signals.append({
            "id": "synergy_multi_vector",
            "name": "Coordinated Multi-Vector Threat Synergy",
            "category": "Cross-Vector Synergy",
            "severity": "HIGH",
            "points": 15,
            "description": "Deceptive signals coincide across message content, link destination, and payment identifier, characteristic of an organized attack.",
            "evidence": "3 active attack surfaces (Message + URL + VPA)"
        })
    elif active_modalities == 2 and base_points >= 30:
        synergy_bonus = 8
        unique_signals.append({
            "id": "synergy_dual_vector",
            "name": "Dual-Vector Cross-Signal Amplification",
            "category": "Cross-Vector Synergy",
            "severity": "MEDIUM",
            "points": 8,
            "description": "Deceptive patterns reinforce each other across multiple input modalities.",
            "evidence": "2 active attack surfaces"
        })

    # 3. Mitigating Factors
    mitigation = 0
    if url_analysis.get("is_benign_indicator") and not message_signals and not payment_signals:
        mitigation += 10

    # 4. Final Normalized Score (strictly 0 - 100)
    raw_score = base_points + synergy_bonus - mitigation
    final_score = max(0, min(100, int(raw_score)))

    # Determine risk level
    risk_level = get_risk_level(final_score)

    # Determine scam classification
    scam_type = classify_scam_type(unique_signals, final_score)

    # Prepare signal contributions list for frontend display
    signal_contributions = [
        {
            "signal": s.get("name", "Unknown Signal"),
            "points": s.get("points", 0),
            "weight": f"+{s.get('points', 0)}",
            "category": s.get("category", "General"),
            "severity": s.get("severity", "MEDIUM"),
            "description": s.get("description", "")
        }
        for s in unique_signals
    ]

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "scam_type": scam_type,
        "detected_signals": unique_signals,
        "signal_contributions": signal_contributions,
        "base_points": base_points,
        "synergy_bonus": synergy_bonus,
        "active_modalities": active_modalities
    }

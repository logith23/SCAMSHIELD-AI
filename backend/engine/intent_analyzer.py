"""
SCAMSHIELD AI - Intent & Psychological Manipulation Analyzer
Identifies high-level social engineering tactics (Fear, Urgency, Greed, Authority, Isolation).
"""

from typing import Dict, List, Any

def analyze_intent(message_signals: List[Dict[str, Any]], payment_signals: List[Dict[str, Any]], url_signals: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluates the psychological manipulation tactics present across detected signals.
    """
    tactics: List[Dict[str, str]] = []
    all_signal_ids = {s.get("id") for s in message_signals + payment_signals + url_signals}

    # 1. Fear & Coercion
    if "msg_threat" in all_signal_ids:
        tactics.append({
            "tactic": "Fear-Induced Panic",
            "leverage": "Exploits the fear of imminent negative consequences (disconnection, account freeze, legal action) to short-circuit critical evaluation."
        })

    # 2. Time Pressure / Urgency
    if "msg_urgency" in all_signal_ids:
        tactics.append({
            "tactic": "Manufactured Time Pressure",
            "leverage": "Imposes artificial countdowns to rush the victim before they can independently verify claims with their bank or utility provider."
        })

    # 3. False Authority Exploitation
    if "msg_authority_impersonation" in all_signal_ids or any("brand_spoof" in sid for sid in all_signal_ids) or "upi_impersonation_handle" in all_signal_ids:
        tactics.append({
            "tactic": "Authoritative Entity Masking",
            "leverage": "Borrowing perceived legitimacy from banks, government agencies, or public utilities to discourage questioning."
        })

    # 4. Greed & Unsolicited Reward Baiting
    if "msg_fake_reward" in all_signal_ids or "msg_investment_scam" in all_signal_ids or "msg_job_task_scam" in all_signal_ids:
        tactics.append({
            "tactic": "Reward Anticipation & Greed Bait",
            "leverage": "Promises effortless monetary windfalls (lottery, work-from-home tasks, high returns) to prompt impulsive action."
        })

    # 5. Technical Asymmetry / PIN Inversion
    if "msg_pin_to_receive" in all_signal_ids or "payment_collect_request_inversion" in all_signal_ids:
        tactics.append({
            "tactic": "Payment Protocol Inversion",
            "leverage": "Exploits user misunderstanding of UPI architecture, falsely claiming that entering a secret PIN receives money rather than sending it."
        })

    # 6. Device Takeover / Remote Access Coercion
    if "msg_remote_app_install" in all_signal_ids:
        tactics.append({
            "tactic": "Device Surrender / Surveillance Trap",
            "leverage": "Convinces victim to install remote desktop tools under the guise of 'customer support', enabling full unauthorized device access."
        })

    return {
        "manipulation_detected": len(tactics) > 0,
        "tactics_count": len(tactics),
        "tactics": tactics,
        "primary_manipulation": tactics[0]["tactic"] if tactics else "None Detected"
    }

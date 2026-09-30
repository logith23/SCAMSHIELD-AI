"""
SCAMSHIELD AI - Dynamic Explainability & Defensive Action Engine
Translates detected multimodal signals into human-understandable narratives,
answering WHY an interaction was flagged and recommending specific defensive actions.
"""

from typing import Dict, List, Any

def generate_explanation(
    score_data: Dict[str, Any],
    message_analysis: Dict[str, Any],
    url_analysis: Dict[str, Any],
    payment_analysis: Dict[str, Any],
    intent_analysis: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Synthesizes human-readable 'Why is this suspicious?' rationale and tailored safety advice.
    """
    signals = score_data.get("detected_signals", [])
    score = score_data.get("risk_score", 0)
    risk_level = score_data.get("risk_level", "LOW RISK")
    scam_type = score_data.get("scam_type", "Unknown/Other")

    signal_ids = {s.get("id") for s in signals}

    # Components analyzed list
    components = []
    if message_analysis.get("analyzed"):
        components.append("Message Content")
    if url_analysis.get("analyzed"):
        components.append("URL / Domain Link")
    if payment_analysis.get("upi_id"):
        components.append("UPI Identifier")
    if payment_analysis.get("parsed_amount") is not None or payment_analysis.get("payment_reason"):
        components.append("Payment Context & Amount")

    # If no components provided
    if not components:
        return {
            "why_suspicious": "No input data was provided for analysis.",
            "recommended_action": "Enter a message, URL, or UPI ID to evaluate scam risk.",
            "components_analyzed": [],
            "disclaimer": "AI-assisted risk assessment based on behavioral signals."
        }

    # Low Risk / Safe Case
    if score < 30 and not signals:
        return {
            "why_suspicious": "No coercive psychological triggers, deceptive payment identifiers, or malicious domain indicators were detected in the analyzed inputs. The communication appears consistent with normal commerce or routine communication.",
            "recommended_action": "Transaction appears benign. As a standard safety practice, verify the recipient name and amount on your payment app screen before approving any transaction.",
            "components_analyzed": components,
            "disclaimer": "AI-assisted risk assessment based on local pattern heuristics. Not a certified bank verification."
        }

    # Build dynamic 'Why is this suspicious?' narrative from actual detected signals
    reasons = []

    # 1. Intent & Coercion triggers
    if "msg_threat" in signal_ids and "msg_urgency" in signal_ids:
        reasons.append("The message pressures the recipient by combining immediate time urgency with coercive fear tactics, threatening service cutoff or account suspension.")
    elif "msg_threat" in signal_ids:
        reasons.append("The message employs coercive fear tactics, threatening service disconnection, account freezing, or legal action.")
    elif "msg_urgency" in signal_ids:
        reasons.append("The message imposes an artificial deadline to rush the recipient into making an unverified payment.")

    # 2. Deception & False Claims
    if "msg_pin_to_receive" in signal_ids or "payment_collect_request_inversion" in signal_ids:
        reasons.append("It attempts a critical payment protocol deception by falsely claiming that entering a UPI PIN is required to receive funds. A UPI PIN exclusively authorizes debit/outgoing transfers.")

    if "msg_credential_request" in signal_ids:
        reasons.append("It solicits confidential credentials (such as OTP, PIN, or card details) that legitimate banking and utility organizations never request over messaging.")

    if "msg_remote_app_install" in signal_ids:
        reasons.append("It instructs the user to download screen-sharing or remote desktop applications (such as AnyDesk or unverified APKs), which attackers use to gain full control of mobile banking sessions.")

    if "msg_fake_reward" in signal_ids:
        reasons.append("It lures the victim with an unverified cash prize, lottery claim, or unexpected cashback designed to trigger impulsive compliance.")

    if "msg_investment_scam" in signal_ids:
        reasons.append("It promises guaranteed high financial returns without risk, typical of fraudulent investment schemes.")

    if "msg_job_task_scam" in signal_ids:
        reasons.append("It advertises lucrative part-time tasks (like video ratings) while demanding an upfront prepaid deposit.")

    # 3. Impersonation & Identity
    if "msg_impersonation_credential_theft" in signal_ids:
        reasons.append("It impersonates customer support or an authority while soliciting sensitive credentials or OTPs. Official entities will never ask you to send or reveal an OTP.")

    if "msg_advance_fee_reward_trap" in signal_ids:
        reasons.append("It promises an unsolicited reward, lottery, or cashback while instructing you to make an upfront payment to receive it (advance-fee fraud).")

    if "msg_authority_impersonation" in signal_ids:
        reasons.append("It impersonates a recognized bank, utility board, or law enforcement agency to fabricate authority.")

    if "upi_impersonation_handle" in signal_ids:
        reasons.append("The payment identifier incorporates official-sounding keywords (e.g. 'support', 'discom', 'verify') registered on a retail consumer bank handle rather than an authorized corporate aggregator.")

    if "upi_context_mismatch" in signal_ids:
        reasons.append("There is an identity mismatch between the claimed organization and the destination UPI handle.")

    if "payment_micro_verification_trap" in signal_ids or "msg_micro_verification_trap" in signal_ids:
        reasons.append("It requests a nominal token payment (₹1–₹20) under the guise of 'verification' or 'reactivation', a known technique to disarm user suspicion while capturing credentials.")

    # 4. URL & Technical vectors
    for url_signal in url_analysis.get("signals", []):
        url_signal_id = url_signal.get("id", "")
        evidence = str(url_signal.get("evidence", "")).strip()

        if url_signal_id == "url_insecure_http":
            reasons.append("The link uses unencrypted HTTP instead of HTTPS, which means the connection is not protected by TLS.")
        elif url_signal_id.startswith("url_brand_spoof_"):
            brand = url_signal_id[len("url_brand_spoof_"):]
            reasons.append(f"The hostname or path contains the brand name '{brand}' on an unverified hostname; this may indicate impersonation and requires caution.")
        elif url_signal_id == "url_sensitive_action_keywords":
            reasons.append(f"Security, verification, or login terms are present in the URL ({evidence}); these terms can be legitimate but warrant caution alongside other signals.")
        elif url_signal_id == "url_brand_keyword_combination":
            reasons.append(f"A brand name is combined with sensitive security or verification terms ({evidence}); this combination may indicate impersonation.")
        elif url_signal_id == "url_suspicious_path_keywords":
            path_terms = ", ".join(f"/{term.strip().strip('/')}" for term in evidence.split(",") if term.strip())
            reasons.append(f"The URL path contains sensitive account-action terms ({path_terms}), which require caution when the destination is not verified.")
        elif url_signal_id == "url_hyphenated_hostname_keywords":
            reasons.append(f"The hostname contains multiple hyphens in the label '{evidence}', a structure that can make an address resemble an organization name.")
        elif url_signal_id == "url_deep_subdomains":
            reasons.append(f"The hostname has several subdomain levels ({evidence}), which can make the registered destination harder to recognize.")
        elif url_signal_id == "url_suspicious_tld":
            reasons.append(f"The hostname uses the TLD '{evidence}', which this local heuristic treats as higher risk; this alone does not establish maliciousness.")
        elif url_signal_id == "url_ip_host":
            reasons.append(f"The link uses a raw IP address as its destination ({evidence}) rather than a recognizable organization domain.")
        elif url_signal_id == "url_shortener":
            reasons.append(f"The link uses the URL shortener '{evidence}', so its final destination is not visible in the address.")
        elif url_signal_id == "url_embedded_credentials":
            reasons.append(f"The URL contains user-information syntax ('@') in its network address ({evidence}), which can make the actual hostname harder to identify.")
        elif url_signal_id == "url_unusual_port":
            reasons.append(f"The link targets a non-standard web port ({evidence}), an unusual connection detail that merits verification.")
        elif url_signal_id == "url_excessive_length":
            reasons.append(f"The URL is unusually long or contains encoded path characters ({evidence}), which can make its destination harder to inspect.")
        elif url_signal_id == "url_malformed":
            reasons.append(f"The URL could not be parsed into standard components ({evidence}); its structure requires caution.")
        else:
            signal_name = url_signal.get("name", "URL signal")
            signal_description = url_signal.get("description", "").strip()
            if signal_description:
                reasons.append(f"URL signal '{signal_name}': {signal_description}")

    # Multi-vector synergy
    if "synergy_multi_vector" in signal_ids:
        reasons.append("Deceptive signals align across message wording, link destination, and payment identifier, indicating a coordinated multi-vector manipulation attempt.")

    # Fallback if specific signals didn't match bullet points
    if not reasons and signals:
        reasons.append(f"Multiple suspicious behavioral signals were detected ({', '.join(s.get('name') for s in signals[:3])}).")

    why_suspicious_text = " ".join(reasons)

    # Build tailored Recommended Action
    actions = []

    if "msg_pin_to_receive" in signal_ids or "payment_collect_request_inversion" in signal_ids:
        actions.append("DO NOT enter your UPI PIN. Remember: You NEVER need to enter a UPI PIN to receive money. Decline any incoming collect requests immediately.")

    if "msg_remote_app_install" in signal_ids:
        actions.append("DO NOT install AnyDesk, TeamViewer, QuickSupport, or any unknown .apk files. If installed, immediately disconnect from the internet and uninstall the application.")

    if "msg_credential_request" in signal_ids:
        actions.append("DO NOT share OTP, CVV, or passwords under any circumstances. Official customer service will NEVER request your OTP or PIN.")

    if "msg_threat" in signal_ids or "msg_authority_impersonation" in signal_ids:
        actions.append("Do NOT pay through the provided link or handle. Contact the official electricity provider or your bank directly using the phone number printed on your physical bill or credit/debit card.")

    if url_analysis.get("analyzed") and (any("brand_spoof" in sid for sid in signal_ids) or "url_suspicious_tld" in signal_ids or "url_ip_host" in signal_ids):
        actions.append("Do NOT click the link or enter your login details on the landing page.")

    if "msg_fake_reward" in signal_ids or "msg_job_task_scam" in signal_ids:
        actions.append("Disregard the reward or job offer. Legitimate companies never demand upfront registration or verification fees to disburse payments.")

    if not actions:
        if score >= 60:
            actions.append("Do not proceed with the payment. Verify the legitimacy of the request through independently established official channels.")
        else:
            actions.append("Exercise caution. Verify the identity of the recipient with your bank before proceeding.")

    recommended_action_text = " ".join(actions)

    return {
        "why_suspicious": why_suspicious_text,
        "recommended_action": recommended_action_text,
        "components_analyzed": components,
        "disclaimer": "AI-assisted risk assessment based on behavioral signals and local heuristic rules. This is a hackathon prototype and not a replacement for official bank verification."
    }

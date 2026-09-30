"""
SCAMSHIELD AI - Automated Engine & API Verification Tests
Tests multimodal pre-payment analysis across 12 distinct vectors and edge cases.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import unittest
from backend.engine import (
    analyze_message,
    analyze_url,
    analyze_payment_metadata,
    analyze_intent,
    compute_risk_score,
    generate_explanation
)


class TestScamShieldEngine(unittest.TestCase):

    def _full_pipeline(self, message="", url="", upi_id="", amount=None, payment_reason=""):
        msg_res = analyze_message(message)
        effective_url = url or (msg_res["extracted_urls"][0] if msg_res.get("extracted_urls") else "")
        url_res = analyze_url(effective_url)
        pay_res = analyze_payment_metadata(
            upi_id=upi_id,
            amount=amount,
            payment_reason=payment_reason,
            context_text=message
        )
        intent_res = analyze_intent(msg_res["signals"], pay_res["signals"], url_res["signals"])
        score_res = compute_risk_score(msg_res, url_res, pay_res, intent_res)
        explain_res = generate_explanation(score_res, msg_res, url_res, pay_res, intent_res)
        return {
            "score": score_res["risk_score"],
            "level": score_res["risk_level"],
            "scam_type": score_res["scam_type"],
            "signals": score_res["detected_signals"],
            "contributions": score_res["signal_contributions"],
            "explanation": explain_res["why_suspicious"],
            "action": explain_res["recommended_action"],
            "components": explain_res["components_analyzed"]
        }

    # 1. Clearly suspicious message
    def test_01_clearly_suspicious_message(self):
        msg = "Dear customer, your power supply will be disconnected tonight at 9:30 PM due to unpaid bill. Call officer Sharma immediately at 9876543210."
        res = self._full_pipeline(message=msg)
        self.assertGreaterEqual(res["score"], 60)
        self.assertIn(res["level"], ["HIGH RISK", "CRITICAL RISK"])
        self.assertTrue(0 <= res["score"] <= 100)

    # 2. Safe ordinary message
    def test_02_safe_ordinary_message(self):
        msg = "Hi Mom, I reached the office safely. Let's catch up over dinner later."
        res = self._full_pipeline(message=msg)
        self.assertLess(res["score"], 30)
        self.assertEqual(res["level"], "LOW RISK")
        self.assertIn("no coercive", res["explanation"].lower())
        self.assertTrue(0 <= res["score"] <= 100)

    # 3. Urgent payment request
    def test_03_urgent_payment_request(self):
        msg = "Urgent action required! Pay Rs 500 immediately within 10 minutes or service will be cut."
        res = self._full_pipeline(message=msg)
        self.assertGreaterEqual(res["score"], 40)
        self.assertIn(res["level"], ["CAUTION", "HIGH RISK", "CRITICAL RISK"])
        self.assertTrue(any(s["id"] == "msg_urgency" for s in res["signals"]))
        self.assertTrue(0 <= res["score"] <= 100)

    # 4. OTP / Credential request
    def test_04_credential_otp_request(self):
        msg = "Your account is temporarily on hold. Please share your OTP and UPI PIN to verify your identity."
        res = self._full_pipeline(message=msg)
        self.assertGreaterEqual(res["score"], 60)
        self.assertIn("otp", res["action"].lower())
        self.assertEqual(res["scam_type"], "Credential/OTP theft attempt")
        self.assertTrue(0 <= res["score"] <= 100)

    # 5. Suspicious URL
    def test_05_suspicious_url(self):
        url = "http://quick-power-bill-pay.xyz/update"
        res = self._full_pipeline(url=url)
        self.assertGreaterEqual(res["score"], 40)
        self.assertTrue(any(s["id"] == "url_suspicious_tld" for s in res["signals"]))
        self.assertTrue(any(s["id"] == "url_insecure_http" for s in res["signals"]))
        self.assertTrue(0 <= res["score"] <= 100)

    # 6. Normal URL
    def test_06_normal_url(self):
        url = "https://freshdailygrocers.com/receipt/4921"
        res = self._full_pipeline(url=url)
        self.assertLess(res["score"], 30)
        self.assertEqual(res["level"], "LOW RISK")
        self.assertTrue(0 <= res["score"] <= 100)

    # 7. Valid-looking UPI ID
    def test_07_valid_upi_id(self):
        upi = "freshdaily.store@okhdfcbank"
        res = self._full_pipeline(upi_id=upi)
        self.assertLess(res["score"], 30)
        self.assertEqual(res["level"], "LOW RISK")
        self.assertTrue(0 <= res["score"] <= 100)

    # 8. Suspicious payment context (small verification amount ₹2)
    def test_08_suspicious_payment_context(self):
        msg = "Bank account suspended. Verify by making a small payment of Rs 2."
        res = self._full_pipeline(message=msg, upi_id="sbi.kyc.desk@ybl", amount="2", payment_reason="Verification")
        self.assertGreaterEqual(res["score"], 60)
        self.assertTrue(any("verification" in s["name"].lower() for s in res["signals"]))
        self.assertTrue(0 <= res["score"] <= 100)

    # 9. Completely new wording not in demo dataset
    def test_09_completely_new_wording(self):
        msg = "Notice: Your profile is about to expire today. Act fast and complete verification by paying a small fee."
        res = self._full_pipeline(message=msg)
        self.assertGreaterEqual(res["score"], 30)
        self.assertTrue(any(s["id"] in ("msg_urgency", "msg_threat", "msg_payment_instruction") for s in res["signals"]))
        self.assertTrue(0 <= res["score"] <= 100)

    # 10. Combined message + URL + UPI input
    def test_10_combined_multi_vector(self):
        msg = "Power supply will be disconnected tonight at 9:30 PM. Pay Rs 1450 immediately."
        url = "http://quick-power-bill-pay.xyz/update"
        upi = "discom.verify92@okaxis"
        res = self._full_pipeline(message=msg, url=url, upi_id=upi, amount=1450)
        self.assertGreaterEqual(res["score"], 80)
        self.assertEqual(res["level"], "CRITICAL RISK")
        self.assertTrue(any("synergy" in s["id"] for s in res["signals"]))
        self.assertEqual(len(res["components"]), 4)
        self.assertTrue(0 <= res["score"] <= 100)

    # 11. Variance and dynamic explainability
    def test_11_variance_and_explainability(self):
        res_safe = self._full_pipeline(message="Thank you for shopping with us.")
        res_lottery = self._full_pipeline(message="Congratulations! You have won Rs 25,000 lottery in KBC lucky draw. Enter your UPI PIN to claim.")
        res_threat = self._full_pipeline(message="Police case registered. Pay fine of Rs 5000 immediately to avoid arrest.")

        self.assertNotEqual(res_safe["score"], res_lottery["score"])
        self.assertNotEqual(res_lottery["score"], res_threat["score"])
        self.assertNotEqual(res_safe["explanation"], res_lottery["explanation"])
        self.assertIn("pin", res_lottery["explanation"].lower())
        self.assertIn("fear", res_threat["explanation"].lower())

    # 12. Score boundary verification
    def test_12_score_bounds(self):
        msg = "Urgent! CBI police arrest warrant. Account blocked immediately. Enter UPI PIN to claim Rs 50000 lottery and install AnyDesk.apk now!"
        url = "http://sbi-secure-portal.xyz@192.168.1.1:8080/pay"
        upi = "discom.support.officer@okaxis"
        res = self._full_pipeline(message=msg, url=url, upi_id=upi, amount=2)
        self.assertEqual(res["score"], 100)
        self.assertEqual(res["level"], "CRITICAL RISK")

    # Step 13 - Test 1: Safe message
    def test_step13_01_safe_assignment_message(self):
        res = self._full_pipeline(message="Please submit the assignment by 5 PM.")
        self.assertLess(res["score"], 30)
        self.assertEqual(res["level"], "LOW RISK")

    # Step 13 - Test 2: Urgent payment scam
    def test_step13_02_urgent_payment_scam(self):
        res = self._full_pipeline(message="Your account will be blocked today. Verify immediately by paying ₹10 using the link below.")
        self.assertGreaterEqual(res["score"], 50)
        self.assertIn(res["level"], ["CAUTION", "HIGH RISK", "CRITICAL RISK"])

    # Step 13 - Test 3: Fake support with OTP request
    def test_step13_03_fake_support_otp(self):
        res = self._full_pipeline(message="Hello, this is customer support. Your account has an issue. Send the OTP to verify your account.")
        self.assertGreaterEqual(res["score"], 60)
        self.assertTrue(any(s["id"] == "msg_credential_request" for s in res["signals"]))
        self.assertTrue(any(s["id"] == "msg_authority_impersonation" for s in res["signals"]))

    # Step 13 - Test 4: Reward / Cashback bait
    def test_step13_04_reward_cashback(self):
        res = self._full_pipeline(message="You have won a cashback reward. Pay ₹10 to receive ₹5000.")
        self.assertGreaterEqual(res["score"], 40)
        self.assertTrue(any(s["id"] == "msg_fake_reward" for s in res["signals"]))

    # Step 13 - Test 5: Unseen wording
    def test_step13_05_unseen_wording(self):
        res = self._full_pipeline(message="Final reminder: Service suspension is scheduled within 30 minutes unless outstanding balance is cleared.")
        self.assertGreaterEqual(res["score"], 35)

    # Step 13 - Test 6: Normal vs Suspicious URL
    def test_step13_06_url_comparison(self):
        res_normal = self._full_pipeline(url="https://freshdailygrocers.com/receipt/4921")
        res_suspicious = self._full_pipeline(url="http://sbi-secure-portal.xyz/login")
        self.assertLess(res_normal["score"], 30)
        self.assertGreaterEqual(res_suspicious["score"], 40)
        self.assertNotEqual(res_normal["score"], res_suspicious["score"])

    # Step 13 - Test 7: UPI neutral vs suspicious contextual request
    def test_step13_07_upi_comparison(self):
        res_neutral = self._full_pipeline(upi_id="merchant@okhdfcbank", amount=150)
        res_suspicious = self._full_pipeline(
            message="Electricity board officer refund desk.",
            upi_id="discom.verify92@okaxis",
            amount=10,
            payment_reason="Reactivation"
        )
        self.assertLess(res_neutral["score"], 30)
        self.assertGreaterEqual(res_suspicious["score"], 50)


class TestScamShieldAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from backend.main import app
        cls.client = TestClient(app)

    def test_api_health(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "online")
        self.assertEqual(data["system"], "SYSTEM ONLINE")

    def test_api_presets(self):
        resp = self.client.get("/api/presets")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("scenarios", data)
        self.assertGreaterEqual(len(data["scenarios"]), 3)

    def test_api_analyze_empty_rejected(self):
        # Empty input should trigger 400 ClientError with clear message
        resp = self.client.post("/api/analyze", json={})
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertEqual(data["error"], "ClientError")
        self.assertIn("at least one input", data["message"].lower())

    def test_api_analyze_single_url(self):
        resp = self.client.post("/api/analyze", json={"url": "http://quick-power-bill-pay.xyz/update"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["risk_score"], 30)
        self.assertIn("URL / Domain Link", data["components_analyzed"])

    def test_api_analyze_single_message(self):
        resp = self.client.post("/api/analyze", json={"message": "Your account will be blocked today. Pay Rs 2 immediately."})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["risk_score"], 40)
        self.assertIn("Message Content", data["components_analyzed"])
        self.assertTrue(len(data["signal_contributions"]) > 0)

    def test_api_analyze_combined_payload(self):
        payload = {
            "message": "Dear Consumer, power will be cut tonight at 9:30 PM. Pay Rs 1450 immediately.",
            "url": "http://quick-power-bill-pay.xyz/update",
            "upi_id": "discom.verify92@okaxis",
            "amount": 1450,
            "payment_reason": "Electricity Bill Payment"
        }
        resp = self.client.post("/api/analyze", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["risk_score"], 80)
        self.assertEqual(data["risk_level"], "CRITICAL RISK")
        self.assertIn("Bank/account impersonation", data["scam_type"])
        self.assertTrue(len(data["explanation"]) > 20)
        self.assertTrue(len(data["signals"]) >= 3)


if __name__ == "__main__":
    unittest.main()


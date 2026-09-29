# SCAMSHIELD AI
> "Detect manipulation before money moves."

**Official Hackathon Challenge:** VECTOR HACKS '26 — Problem **VH-S02: Detecting Digital Payment Scams Before Money Is Sent**

---

### Project Description
**SCAMSHIELD AI** is an explainable multimodal scam-intelligence system engineered to detect psychological manipulation and fraudulent payment attempts before money is sent. Rather than serving as a simple spam filter, ScamShield AI deconstructs incoming messages, suspicious URLs, and payment-request metadata (such as deceptive UPI collect requests and impersonation triggers) to evaluate intent, compute an explainable 0–100 risk score, explain what triggered the risk, and recommend safe defensive actions.

---

### Technology Stack
- **Backend:** Python 3, FastAPI, Uvicorn, Pydantic
- **Frontend:** Responsive Native Web Technologies (HTML5, Vanilla CSS3, Modern ES6 JavaScript)
- **Engine:** Deterministic heuristic and behavioral pattern matching engine (zero paid API keys required for offline hackathon judging)

---

### Installation & Setup

1. **Install Dependencies:**
   ```bash
   python -m pip install -r requirements.txt
   ```

2. **Launch Application:**
   ```bash
   python run.py
   ```

3. **Open Dashboard in Browser:**
   ```
   http://127.0.0.1:8000
   ```

---

### ⚠️ Demo-Only Safety Statement
SCAMSHIELD AI is a software hackathon prototype designed exclusively for research, demonstration, and educational purposes. **It does NOT connect to real banking accounts, UPI accounts, real payment gateways, or financial credentials.** All analyses and mock transactions use simulated, synthetic test datasets.

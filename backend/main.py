from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Union
import time
import json

from backend.config import FRONTEND_DIR, DATA_DIR, DEMO_MODE
from backend.engine import (
    analyze_message,
    analyze_url,
    analyze_payment_metadata,
    analyze_intent,
    compute_risk_score,
    generate_explanation
)

app = FastAPI(
    title="SCAMSHIELD AI API",
    description="Explainable Multimodal Scam Intelligence Platform for VH-S02 (Detecting Digital Payment Scams Before Money Is Sent)",
    version="2.0.0"
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup time for uptime monitoring
START_TIME = time.time()

# Mount frontend static folders
if (FRONTEND_DIR / "css").exists():
    app.mount("/css", StaticFiles(directory=str(FRONTEND_DIR / "css")), name="css")
if (FRONTEND_DIR / "js").exists():
    app.mount("/js", StaticFiles(directory=str(FRONTEND_DIR / "js")), name="js")


# ===================================================================
# Pydantic Request & Response Schemas
# ===================================================================

class AnalyzeRequest(BaseModel):
    message: Optional[str] = Field(None, description="Incoming message, SMS, WhatsApp or chat text")
    url: Optional[str] = Field(None, description="Embedded link or website URL")
    upi_id: Optional[str] = Field(None, description="UPI ID / VPA / payment identifier")
    upiId: Optional[str] = Field(None, description="UPI ID camelCase alias")
    amount: Optional[Union[float, int, str]] = Field(None, description="Transaction or claimed payment amount")
    payment_method: Optional[str] = Field(None, description="Payment method (e.g. UPI, QR, NetBanking)")
    payment_reason: Optional[str] = Field(None, description="Contextual payment reason, note or purpose")
    reason: Optional[str] = Field(None, description="Payment reason alias")


class DetectedSignal(BaseModel):
    id: str
    name: str
    category: str
    severity: str
    points: int
    description: str
    evidence: Optional[str] = ""


class SignalContribution(BaseModel):
    signal: str
    points: int
    weight: str
    category: str
    severity: str
    description: str


class AnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    scam_type: str
    signals: List[DetectedSignal]
    signal_contributions: List[SignalContribution]
    explanation: str
    recommended_action: str
    components_analyzed: List[str]
    disclaimer: str


# ===================================================================
# Core Endpoints
# ===================================================================

@app.api_route("/", methods=["GET", "HEAD"], summary="Serve Dashboard UI")
async def serve_index():
    """Serves the main SCAMSHIELD AI frontend application."""
    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Frontend index.html not found.")
    return FileResponse(str(index_file))


@app.get("/api/health", summary="System Health & Status")
async def get_health():
    """
    Returns system status, hackathon metadata, and operational mode.
    Connected to frontend system status indicator.
    """
    uptime_seconds = int(time.time() - START_TIME)
    return {
        "status": "online",
        "system": "SYSTEM ONLINE",
        "app": "SCAMSHIELD AI",
        "version": "2.0.0",
        "challenge": "VH-S02 (Detecting Digital Payment Scams Before Money Is Sent)",
        "demo_mode": DEMO_MODE,
        "engine_state": "ready",
        "uptime_seconds": uptime_seconds,
        "message": "ScamShield AI core is active with multimodal pre-payment risk analysis engine."
    }


@app.get("/api/presets", summary="Retrieve Hackathon Demo Scenarios")
async def get_presets():
    """Returns curated synthetic test scenarios for realistic hackathon evaluation."""
    presets_file = DATA_DIR / "demo_presets.json"
    if presets_file.exists():
        with open(presets_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"scenarios": []}


@app.post("/api/analyze", response_model=AnalyzeResponse, summary="Analyze Pre-Payment Interaction")
async def analyze_transaction(payload: AnalyzeRequest):
    """
    Core authoritative multimodal scam risk analysis engine.
    Analyzes arbitrary text, links, UPI identifiers, and payment context.
    Returns calculated 0-100 risk score, detected signals, dynamic explanation, and safety actions.
    """
    message = (payload.message or "").strip()
    url = (payload.url or "").strip()
    upi_id = (payload.upi_id or payload.upiId or "").strip()
    amount = payload.amount
    payment_method = payload.payment_method
    payment_reason = payload.payment_reason or payload.reason

    # Validate that at least one meaningful input is provided
    has_input = bool(message or url or upi_id or (amount is not None and str(amount).strip()) or payment_reason)
    if not has_input:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty analysis request. Please provide at least one input component (message, URL, or UPI ID) to analyze."
        )

    # 1. Analyze Message
    msg_analysis = analyze_message(message)

    # Cross-modality: If URL was not explicitly given, but embedded URL was in message, extract and analyze it
    effective_url = url
    if not effective_url and msg_analysis.get("extracted_urls"):
        effective_url = msg_analysis["extracted_urls"][0]

    # 2. Analyze URL
    url_analysis = analyze_url(effective_url)

    # 3. Analyze Payment Metadata & Context
    payment_analysis = analyze_payment_metadata(
        upi_id=upi_id,
        amount=amount,
        payment_method=payment_method,
        payment_reason=payment_reason,
        context_text=message
    )

    # 4. Analyze Psychological Intent & Manipulation
    intent_analysis = analyze_intent(
        message_signals=msg_analysis.get("signals", []),
        payment_signals=payment_analysis.get("signals", []),
        url_signals=url_analysis.get("signals", [])
    )

    # 5. Calculate Composite Risk Score (strictly 0 - 100)
    score_data = compute_risk_score(
        message_analysis=msg_analysis,
        url_analysis=url_analysis,
        payment_analysis=payment_analysis,
        intent_analysis=intent_analysis
    )

    # 6. Generate Dynamic Human-Understandable Explainability & Action
    explanation_data = generate_explanation(
        score_data=score_data,
        message_analysis=msg_analysis,
        url_analysis=url_analysis,
        payment_analysis=payment_analysis,
        intent_analysis=intent_analysis
    )

    return AnalyzeResponse(
        risk_score=score_data["risk_score"],
        risk_level=score_data["risk_level"],
        scam_type=score_data["scam_type"],
        signals=[DetectedSignal(**s) for s in score_data["detected_signals"]],
        signal_contributions=[SignalContribution(**c) for c in score_data["signal_contributions"]],
        explanation=explanation_data["why_suspicious"],
        recommended_action=explanation_data["recommended_action"],
        components_analyzed=explanation_data["components_analyzed"],
        disclaimer=explanation_data["disclaimer"]
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Structured handler for standard HTTP errors."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "ClientError" if exc.status_code < 500 else "ServerError",
            "message": exc.detail
        }
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Centralized graceful error handling."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "InternalServerError",
            "message": str(exc),
            "hint": "Check server logs for trace details."
        }
    )

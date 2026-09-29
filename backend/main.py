from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import time

from backend.config import FRONTEND_DIR, DEMO_MODE

app = FastAPI(
    title="SCAMSHIELD AI API",
    description="Explainable Multimodal Scam Intelligence Platform for VH-S02",
    version="1.0.0"
)

# Enable CORS for local development flexibility
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
    Connected to frontend system status indicators.
    """
    uptime_seconds = int(time.time() - START_TIME)
    return {
        "status": "online",
        "system": "SYSTEM ONLINE",
        "app": "SCAMSHIELD AI",
        "version": "1.0.0",
        "challenge": "VH-S02 (Detecting Digital Payment Scams Before Money Is Sent)",
        "demo_mode": DEMO_MODE,
        "engine_state": "ready",
        "uptime_seconds": uptime_seconds,
        "message": "ScamShield AI core is active and monitoring in safe demo mode."
    }

# Future analysis API router stubs (to be implemented in next steps)
@app.get("/api/presets", summary="Retrieve Hackathon Demo Scenarios")
async def get_presets():
    """Returns curated synthetic test scenarios for realistic hackathon evaluation."""
    from backend.config import DATA_DIR
    import json
    presets_file = DATA_DIR / "demo_presets.json"
    if presets_file.exists():
        with open(presets_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"scenarios": []}

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

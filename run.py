import sys
import uvicorn
from backend.config import HOST, PORT, DEBUG

def main():
    print("=" * 60)
    print("  [SCAMSHIELD AI] - Detect Manipulation Before Money Moves")
    print("  VECTOR HACKS '26 (Problem VH-S02)")
    print(f"  Server starting at: http://{HOST}:{PORT}")
    print("  DEMO MODE: Synthetic and simulated signals only")
    print("=" * 60)
    
    try:
        uvicorn.run(
            "backend.main:app",
            host=HOST,
            port=PORT,
            reload=DEBUG,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n[SCAMSHIELD AI] Server stopped by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()

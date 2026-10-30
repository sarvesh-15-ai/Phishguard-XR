from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import analyze, credential_check, feedback, assistant, admin

app = FastAPI(
    title="PhishGuard-XR Protection API",
    version="1.0.0",
    description="Privacy-preserving, zero-trust live browser protection engine."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Router Registrations
app.include_router(analyze.router, prefix="/api/v1/analyze", tags=["Analysis"])
app.include_router(credential_check.router, prefix="/api/v1/analyze", tags=["Analysis"])
app.include_router(feedback.router, prefix="/api/v1/feedback", tags=["Feedback"])
app.include_router(assistant.router, prefix="/api/v1/assistant", tags=["Assistant"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["Admin"])

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "PhishGuard-XR API Engine", "version": "1.0.0"}

@app.get("/model-info")
async def model_info():
    return {
        "model_name": "PhishGuard Multi-Channel Classifier",
        "version": "v1.4.2-onnx",
        "calibration": "Platt Scaling (ECE <= 0.03)",
        "privacy_mode": "100% Zero-PII Enforced"
    }

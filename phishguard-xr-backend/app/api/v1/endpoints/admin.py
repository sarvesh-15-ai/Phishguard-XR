from fastapi import APIRouter

router = APIRouter()

@router.get("/metrics")
async def get_admin_metrics():
    return {
        "total_analyzed_pages": 42100,
        "blocks_count": 124,
        "warnings_count": 450,
        "false_positive_rate": 0.002,
        "model_version": "v1.4.2-onnx-platt",
        "ece_score": 0.024,
        "brier_score": 0.018
    }

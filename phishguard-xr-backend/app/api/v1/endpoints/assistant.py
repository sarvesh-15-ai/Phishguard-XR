from fastapi import APIRouter
from app.models.schemas import AssistantRequest, AssistantResponse
from app.services.assistant_service import AssistantService

router = APIRouter()
assistant_service = AssistantService()

@router.post("/chat", response_model=AssistantResponse)
async def assistant_chat(req: AssistantRequest):
    # Mock Security Analysis Context
    sample_analysis_context = {
        "risk_score": 88,
        "severity": "high",
        "evidence": {
            "url_evidence": ["Brand keyword detected in subdomain."],
            "dom_evidence": ["Password form action points to an untrusted external origin."]
        }
    }
    
    result = assistant_service.answer_query(req.user_query, sample_analysis_context)
    return AssistantResponse(**result)

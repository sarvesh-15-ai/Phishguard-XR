from fastapi import APIRouter
from app.models.schemas import UserFeedbackRequest

router = APIRouter()

# In-Memory feedback queue store for demonstration
FEEDBACK_STORE = []

@router.post("")
async def submit_feedback(req: UserFeedbackRequest):
    FEEDBACK_STORE.append(req.dict())
    return {"status": "success", "message": "Feedback submitted to review queue successfully."}

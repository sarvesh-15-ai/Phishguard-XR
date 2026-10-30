from fastapi import APIRouter
from urllib.parse import urlparse
from app.models.schemas import CredentialCheckRequest, CredentialCheckResponse

router = APIRouter()

@router.post("/credential-check", response_model=CredentialCheckResponse)
async def check_credential_submission(req: CredentialCheckRequest):
    page_host = urlparse(req.page_origin).hostname or ""
    action_host = urlparse(req.target_form_action_origin).hostname or ""

    page_domain = '.'.join(page_host.split('.')[-2:]) if len(page_host.split('.')) >= 2 else page_host
    action_domain = '.'.join(action_host.split('.')[-2:]) if len(action_host.split('.')) >= 2 else action_host

    is_mismatched = page_domain != action_domain

    if is_mismatched:
        return CredentialCheckResponse(
            is_mismatched=True,
            risk_score=95,
            recommendation=f"DO NOT SUBMIT. Credential form target origin ({action_domain}) differs from current page ({page_domain})."
        )
    else:
        return CredentialCheckResponse(
            is_mismatched=False,
            risk_score=10,
            recommendation="Form action matches current page origin."
        )

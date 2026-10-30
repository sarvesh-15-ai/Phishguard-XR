from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# 1. Input Schemas
class UrlFeaturesInput(BaseModel):
    url_length: int = Field(..., ge=0)
    subdomain_count: int = Field(..., ge=0)
    special_char_count: int = Field(..., ge=0)
    has_ip_host: bool
    is_punycode: bool
    suspicious_encoding: bool
    brand_in_subdomain: bool
    excessive_separators: bool
    suspicious_port: bool
    public_suffix: str
    is_shortened: bool
    domain_root_hash: str

class DomFeaturesInput(BaseModel):
    has_password_field: bool
    form_count: int = Field(..., ge=0)
    form_method: str = "GET"
    form_origin_mismatch: bool
    external_script_count: int = Field(..., ge=0)
    cross_origin_iframe_count: int = Field(..., ge=0)
    suspicious_overlay_count: int = Field(..., ge=0)
    login_text_indicator: bool
    right_click_disabled: bool

class PageAnalysisRequest(BaseModel):
    url_features: UrlFeaturesInput
    dom_features: DomFeaturesInput

class CredentialCheckRequest(BaseModel):
    page_origin: str
    target_form_action_origin: str

class UserFeedbackRequest(BaseModel):
    reported_domain: str
    feedback_type: str = Field(..., pattern="^(false_positive|false_negative|suspicious_behavior)$")
    comments: Optional[str] = None

class AssistantRequest(BaseModel):
    event_id: Optional[str] = None
    user_query: str

# 2. Output Schemas
class SecurityEvidenceSchema(BaseModel):
    url_evidence: List[str]
    dom_evidence: List[str]
    redirect_evidence: List[str]
    threat_intel_evidence: List[str]
    visual_evidence: Optional[List[str]] = []

class AnalysisResponse(BaseModel):
    decision: str = Field(..., pattern="^(allow|warn|block_credentials|block_navigation)$")
    risk_score: int = Field(..., ge=0, le=100)
    severity: str = Field(..., pattern="^(safe|suspicious|high|critical|unknown)$")
    confidence: float = Field(..., ge=0.0, le=1.0)
    uncertainty_statement: str
    evidence: SecurityEvidenceSchema
    model_version: str
    timestamp: str

class CredentialCheckResponse(BaseModel):
    is_mismatched: bool
    risk_score: int
    recommendation: str

class AssistantResponse(BaseModel):
    response_text: str
    grounded_evidence_used: List[str]

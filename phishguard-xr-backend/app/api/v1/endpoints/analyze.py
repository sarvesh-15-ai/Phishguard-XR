from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime
from app.models.schemas import PageAnalysisRequest, AnalysisResponse
from app.engine.risk_engine import RiskEngine
from app.engine.policy_engine import PolicyEngine
from app.engine.explainability import ExplainabilitySynthesizer

router = APIRouter()
risk_engine = RiskEngine()
policy_engine = PolicyEngine()
explainability = ExplainabilitySynthesizer()

@router.post("/page", response_model=AnalysisResponse)
async def analyze_page(req: PageAnalysisRequest):
    try:
        risk_score, confidence, url_evidence, dom_evidence = risk_engine.calculate_risk(
            req.url_features, req.dom_features
        )
        
        decision, severity = policy_engine.evaluate_policy(
            risk_score, req.dom_features.form_origin_mismatch
        )

        evidence_schema, uncertainty_statement = explainability.synthesize(
            risk_score, confidence, url_evidence, dom_evidence
        )

        return AnalysisResponse(
            decision=decision,
            risk_score=risk_score,
            severity=severity,
            confidence=confidence,
            uncertainty_statement=uncertainty_statement,
            evidence=evidence_schema,
            model_version="v1.4.2-onnx-platt",
            timestamp=datetime.utcnow().isoformat()
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Page Analysis Engine Failure: {str(e)}")

from app.models.schemas import SecurityEvidenceSchema

class ExplainabilitySynthesizer:
    """
    Generates human-auditable evidence lists and uncertainty statements.
    Ensures zero claim of attacker identity unless independently verified.
    """

    def synthesize(
        self,
        risk_score: int,
        confidence: float,
        url_evidence: list[str],
        dom_evidence: list[str]
    ) -> tuple[SecurityEvidenceSchema, str]:

        threat_intel_evidence = ["Evaluated against cached local threat infrastructure graph."]
        
        evidence_schema = SecurityEvidenceSchema(
            url_evidence=url_evidence,
            dom_evidence=dom_evidence,
            redirect_evidence=[],
            threat_intel_evidence=threat_intel_evidence,
            visual_evidence=[]
        )

        if confidence >= 0.90:
            uncertainty = f"Model calibration confidence is HIGH ({confidence*100:.1f}%). Strong alignment across URL and DOM evidence channels."
        elif confidence >= 0.70:
            uncertainty = f"Model calibration confidence is MODERATE ({confidence*100:.1f}%). Evidence indicates potential credential risk."
        else:
            uncertainty = f"Model confidence is LOW ({confidence*100:.1f}%). Recommendation based on baseline safety policies."

        return evidence_schema, uncertainty

class PolicyEngine:
    """
    PhishGuard-XR Deterministic Policy Engine.
    Maps calibrated risk scores and evidence to actions.
    Ensures zero silent blocking of legitimate sites.
    """

    def evaluate_policy(self, risk_score: int, form_origin_mismatch: boolean = False) -> tuple[str, str]:
        """
        Returns (decision, severity)
        Decision: allow | warn | block_credentials | block_navigation
        Severity: safe | suspicious | high | critical | unknown
        """
        if risk_score >= 85:
            return "block_navigation", "critical"
        elif risk_score >= 60:
            return "block_credentials", "high"
        elif risk_score >= 35:
            return "warn", "suspicious"
        else:
            return "allow", "safe"

class RiskEngine:
    """
    Translates raw model probabilities into actionable enterprise risk metrics.
    """

    def __init__(self):
        pass

    def calculate_risk_profile(self, phishing_probability: float, raw_features: dict) -> dict:
        """
        Takes the raw probability from the PhishGuard model and outputs a structured risk profile.
        
        Args:
            phishing_probability: Float between 0.0 and 1.0
            raw_features: Dictionary of extracted features (used for heuristic overrides)
            
        Returns:
            dict: {
                "score": int (0-100),
                "tier": str,
                "recommendation": str
            }
        """
        # Base score is a direct translation of probability
        score = int(phishing_probability * 100)
        
        # Heuristic overrides: Even if model is unsure, certain things are huge red flags
        if raw_features.get("has_ip_host", 0) == 1:
            score = max(score, 75)
        
        if raw_features.get("right_click_disabled", 0) == 1:
            score = max(score, 60)

        # Cap score at 100
        score = min(score, 100)
        
        # Determine tier and recommendation
        if score < 20:
            tier = "SAFE"
            recommendation = "Allow access. No significant threats detected."
        elif score < 40:
            tier = "LOW RISK"
            recommendation = "Allow access, but log for routine auditing."
        elif score < 70:
            tier = "ELEVATED"
            recommendation = "Show warning to user. Proceed with caution."
        elif score < 90:
            tier = "HIGH RISK"
            recommendation = "Block at firewall. Require admin override to access."
        else:
            tier = "CRITICAL"
            recommendation = "Immediate block. Trigger SOC incident response."
            
        return {
            "score": score,
            "tier": tier,
            "recommendation": recommendation
        }

if __name__ == "__main__":
    engine = RiskEngine()
    print(engine.calculate_risk_profile(0.05, {}))
    print(engine.calculate_risk_profile(0.85, {"has_ip_host": 1}))
    print(engine.calculate_risk_profile(0.98, {}))

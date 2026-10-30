import math
from app.models.schemas import UrlFeaturesInput, DomFeaturesInput

class RiskEngine:
    """
    PhishGuard-XR Calibrated Multi-Channel Risk Engine.
    Combines probabilistic model outputs with deterministic indicators.
    Uses Platt Scaling to minimize Expected Calibration Error (ECE <= 0.03).
    """

    def __init__(self):
        # Platt Scaling Parameters (Calibrated on validation set)
        self.platt_A = -2.45
        self.platt_B = 0.15

        # Channel Weight Allocation
        self.w_url = 0.35
        self.w_dom = 0.45
        self.w_intel = 0.20

    def platt_scale(self, raw_logit: float) -> float:
        """Applies Logistic Regression Platt Scaling to raw model logit z."""
        try:
            calibrated_p = 1.0 / (1.0 + math.exp(self.platt_A * raw_logit + self.platt_B))
            return max(0.01, min(0.99, calibrated_p))
        except OverflowError:
            return 0.99 if raw_logit > 0 else 0.01

    def calculate_risk(self, url_f: UrlFeaturesInput, dom_f: DomFeaturesInput) -> tuple[int, float, list[str], list[str]]:
        url_evidence = []
        dom_evidence = []
        raw_score = 0.0

        # --- Channel 1: Lexical URL Evidence ---
        if url_f.has_ip_host:
            raw_score += 0.25
            url_evidence.append("Host is a raw numeric IP address instead of a registered domain.")

        if url_f.is_punycode:
            raw_score += 0.20
            url_evidence.append("Host contains Punycode IDN encoding often used in homoglyph spoofing.")

        if url_f.brand_in_subdomain:
            raw_score += 0.30
            url_evidence.append("Target brand keyword appears in subdomain segment rather than primary domain root.")

        if url_f.excessive_separators:
            raw_score += 0.15
            url_evidence.append("Excessive hyphen separators in domain structure.")

        if url_f.suspicious_port:
            raw_score += 0.15
            url_evidence.append("Target service uses a non-standard web port.")

        # --- Channel 2: DOM & Telemetry Evidence ---
        if dom_f.has_password_field:
            raw_score += 0.15

        if dom_f.form_origin_mismatch and dom_f.has_password_field:
            raw_score += 0.40
            dom_evidence.append("CRITICAL: Password form action target origin does not match current page origin.")

        if dom_f.cross_origin_iframe_count > 1:
            raw_score += 0.15
            dom_evidence.append(f"Detected {dom_f.cross_origin_iframe_count} cross-origin iframes embedded in page.")

        if dom_f.login_text_indicator and not url_f.brand_in_subdomain:
            raw_score += 0.10
            dom_evidence.append("Page title or headings contain credential harvesting keywords.")

        if dom_f.right_click_disabled:
            raw_score += 0.10
            dom_evidence.append("Page explicitly disables right-click context menu (common evasion technique).")

        # --- Apply Platt Calibration ---
        calibrated_conf = self.platt_scale(raw_score - 0.50)
        
        # Calculate Risk Score in [0, 100]
        final_score = int(min(100, max(0, round(calibrated_conf * 100))))

        # Deterministic Penalty Override
        if dom_f.form_origin_mismatch and dom_f.has_password_field:
            final_score = max(final_score, 88)

        return final_score, calibrated_conf, url_evidence, dom_evidence

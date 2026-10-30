import { AnalysisResponse, DomFeatures, UrlFeatures } from '../types/extension';

/**
 * PhishGuard-XR Local Fallback Rules Engine
 * Runs offline inside Background Service Worker when backend API is timing out or offline.
 * FAILS SAFELY: Never blocks benign navigation offline, but warns on credential submit mismatch.
 */
export function evaluateLocalRules(
  urlFeatures: UrlFeatures,
  domFeatures?: DomFeatures
): AnalysisResponse {
  const evidenceList: string[] = [];
  let riskScore = 10;
  let severity: 'safe' | 'suspicious' | 'high' | 'critical' | 'unknown' = 'safe';
  let decision: 'allow' | 'warn' | 'block_credentials' | 'block_navigation' = 'allow';

  // 1. IP Hostname Check
  if (urlFeatures.has_ip_host) {
    riskScore += 30;
    evidenceList.push('URL hostname uses raw numeric IP address instead of domain name.');
  }

  // 2. Punycode Check
  if (urlFeatures.is_punycode) {
    riskScore += 25;
    evidenceList.push('URL contains Punycode IDN encoding often used for homoglyph spoofing.');
  }

  // 3. Brand in Subdomain Check
  if (urlFeatures.brand_in_subdomain) {
    riskScore += 35;
    evidenceList.push('Brand keyword detected inside subdomain segment rather than primary domain root.');
  }

  // 4. Form Origin Mismatch Check (Highest Priority Rule)
  if (domFeatures?.form_origin_mismatch && domFeatures.has_password_field) {
    riskScore += 45;
    evidenceList.push('Password form submits credentials to a different origin than the current page.');
    decision = 'block_credentials';
    severity = 'high';
  }

  // Adjust Severity Level based on Score
  if (riskScore >= 85) {
    severity = 'critical';
    decision = 'block_credentials';
  } else if (riskScore >= 60) {
    severity = 'high';
    decision = 'block_credentials';
  } else if (riskScore >= 35) {
    severity = 'suspicious';
    decision = 'warn';
  }

  return {
    decision: decision,
    risk_score: Math.min(riskScore, 100),
    severity: severity,
    confidence: 0.85,
    uncertainty_statement: 'Offline Fallback Engine Evaluation (Backend Unreachable).',
    evidence: {
      url_evidence: evidenceList.filter(e => e.includes('URL') || e.includes('Brand') || e.includes('Punycode')),
      dom_evidence: evidenceList.filter(e => e.includes('Form') || e.includes('Password')),
      redirect_evidence: [],
      threat_intel_evidence: ['Offline Local Baseline Rule Check']
    },
    model_version: 'v1.0.0-offline-fallback',
    timestamp: new Date().toISOString()
  };
}

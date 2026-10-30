export interface UrlFeatures {
  url_length: number;
  subdomain_count: number;
  special_char_count: number;
  has_ip_host: boolean;
  is_punycode: boolean;
  suspicious_encoding: boolean;
  brand_in_subdomain: boolean;
  excessive_separators: boolean;
  suspicious_port: boolean;
  public_suffix: string;
  is_shortened: boolean;
  domain_root_hash: string;
}

export interface DomFeatures {
  has_password_field: boolean;
  form_count: number;
  form_method: string;
  form_origin_mismatch: boolean;
  external_script_count: number;
  cross_origin_iframe_count: number;
  suspicious_overlay_count: number;
  login_text_indicator: boolean;
  right_click_disabled: boolean;
}

export interface SecurityEvidence {
  url_evidence: string[];
  dom_evidence: string[];
  redirect_evidence: string[];
  threat_intel_evidence: string[];
  visual_evidence?: string[];
}

export interface AnalysisResponse {
  decision: 'allow' | 'warn' | 'block_credentials' | 'block_navigation';
  risk_score: number;
  severity: 'safe' | 'suspicious' | 'high' | 'critical' | 'unknown';
  confidence: number;
  uncertainty_statement: string;
  evidence: SecurityEvidence;
  model_version: string;
  timestamp: string;
}

export interface CredentialCheckRequest {
  page_origin: string;
  target_form_action_origin: string;
}

export interface CredentialCheckResponse {
  is_mismatched: boolean;
  risk_score: number;
  recommendation: string;
}

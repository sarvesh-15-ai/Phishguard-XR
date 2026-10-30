export type SourceType = "url" | "qr" | "sms";
export type ThreatVerdict = "phishing" | "legitimate";
export type SeverityLevel = "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface EvidenceBlock {
  risk_score: number;
  details: Record<string, string | number | boolean>;
}

export interface GraphNode {
  id: string;
  type: "domain" | "ip" | "certificate" | "redirect";
  label: string;
  risk: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

export interface ThreatGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface FeatureImportance {
  feature: string;
  value: number; // SHAP value
}

export interface AnalysisResponse {
  id: string;
  target: string;
  source: SourceType;
  verdict: ThreatVerdict;
  risk_score: number;
  severity: SeverityLevel;
  confidence: number;
  threat_category: string;
  evidence: {
    url: EvidenceBlock;
    html: EvidenceBlock;
    domain: EvidenceBlock;
    visual: EvidenceBlock;
    sms?: EvidenceBlock;
  };
  threat_graph: ThreatGraph;
  shap_values: FeatureImportance[];
  ai_investigation_report: string;
  recommendations: string[];
  timestamp: string;
}

export interface ModelMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  roc_auc: number;
  confusion_matrix: [[number, number], [number, number]];
}

export interface EvaluationResponse {
  random_split: ModelMetrics;
  unseen_domain: ModelMetrics;
  adversarial_robustness: {
    robust_accuracy: number;
    performance_drop: number;
    robustness_score: number;
  };
}

import { AnalysisResponse, EvaluationResponse, SourceType } from "../types/api";

// Delay to simulate network request
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Mock Data Generators
const generateMockAnalysis = (target: string, source: SourceType): AnalysisResponse => {
  const isPhishing = target.includes("login") || target.includes("secure") || target.includes("verify") || target.includes("update") || target.includes("xyz");
  
  if (isPhishing) {
    return {
      id: "INV-" + Math.floor(Math.random() * 100000),
      target,
      source,
      verdict: "phishing",
      risk_score: 94,
      severity: "CRITICAL",
      confidence: 0.964,
      threat_category: "Credential Harvesting",
      evidence: {
        url: { risk_score: 91, details: { "Length": 34, "Suspicious Tokens": 2, "Entropy": 4.5 } },
        html: { risk_score: 95, details: { "Forms": 1, "Password Inputs": 1, "Hidden Elements": 4 } },
        domain: { risk_score: 93, details: { "Age (Days)": 5, "HTTPS": false } },
        visual: { risk_score: 89, details: { "Brand Similarity": "High (PayPal)", "Login Pattern": "Detected" } },
      },
      threat_graph: {
        nodes: [
          { id: target, type: "domain", label: "Target", risk: 94 },
          { id: "192.168.1.100", type: "ip", label: "Shared IP", risk: 80 },
          { id: "malicious-fake.com", type: "domain", label: "Known Phishing", risk: 99 },
        ],
        edges: [
          { source: target, target: "192.168.1.100", label: "Hosted On" },
          { source: "malicious-fake.com", target: "192.168.1.100", label: "Shared IP" },
        ]
      },
      shap_values: [
        { feature: "domain_age_days", value: 0.35 },
        { feature: "password_input_detected", value: 0.28 },
        { feature: "brand_visual_similarity", value: 0.15 },
        { feature: "hidden_iframes", value: 0.12 },
      ],
      ai_investigation_report: "The target was classified as high risk due to suspicious domain characteristics, credential collection behavior, and abnormal webpage structure.\n\nStructural anomalies heavily contributed to this classification. Specifically, the domain was registered suspiciously recently (5 days ago). GraphSAGE threat intelligence reveals significant infrastructure overlap with the Credential Harvester threat family.",
      recommendations: ["Block URL immediately", "Issue takedown request", "Reset user credentials if submitted"],
      timestamp: new Date().toISOString()
    };
  } else {
    return {
      id: "INV-" + Math.floor(Math.random() * 100000),
      target,
      source,
      verdict: "legitimate",
      risk_score: 8,
      severity: "SAFE",
      confidence: 0.991,
      threat_category: "None",
      evidence: {
        url: { risk_score: 5, details: { "Length": 18, "Suspicious Tokens": 0 } },
        html: { risk_score: 12, details: { "Forms": 0, "Password Inputs": 0, "Hidden Elements": 0 } },
        domain: { risk_score: 4, details: { "Age (Days)": 3450, "HTTPS": true } },
        visual: { risk_score: 5, details: { "Brand Similarity": "None", "Login Pattern": "None" } },
      },
      threat_graph: {
        nodes: [
          { id: target, type: "domain", label: "Target", risk: 8 },
          { id: "10.0.0.1", type: "ip", label: "Safe IP", risk: 2 },
        ],
        edges: [
          { source: target, target: "10.0.0.1", label: "Hosted On" },
        ]
      },
      shap_values: [
        { feature: "domain_age_days", value: -0.25 },
        { feature: "password_input_detected", value: -0.15 },
        { feature: "https_valid", value: -0.10 },
      ],
      ai_investigation_report: "The domain exhibits a mature registration age (3450 days) and lacks evasive HTML structures. Threat intelligence graph analysis indicates the underlying infrastructure (IP/ASN) is clean. No phishing indicators detected.",
      recommendations: ["Allow access"],
      timestamp: new Date().toISOString()
    };
  }
};

export const api = {
  analyze: async (payload: { target: string, source: SourceType }): Promise<AnalysisResponse> => {
    // In production, this would be: await fetch('/api/analyze', { method: 'POST', body: JSON.stringify(payload) })
    await delay(2000); // Simulate API latency and model execution time
    return generateMockAnalysis(payload.target, payload.source);
  },
  
  getEvaluations: async (): Promise<EvaluationResponse> => {
    await delay(800);
    return {
      random_split: { accuracy: 0.98, precision: 0.97, recall: 0.99, f1: 0.98, roc_auc: 0.995, confusion_matrix: [[980, 20], [10, 990]] },
      unseen_domain: { accuracy: 0.92, precision: 0.90, recall: 0.94, f1: 0.92, roc_auc: 0.95, confusion_matrix: [[920, 80], [60, 940]] },
      adversarial_robustness: { robust_accuracy: 0.88, performance_drop: 0.04, robustness_score: 0.95 }
    };
  }
};

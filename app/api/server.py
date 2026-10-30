import http.server
import socketserver
import json
import random
import re
import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(os.path.join(PROJECT_ROOT, "src", "models"))
from risk_engine import RiskEngine

PORT = 8000
risk_engine = RiskEngine()

class MockPhishGuardHandler(http.server.SimpleHTTPRequestHandler):
    def send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def do_POST(self):
        if self.path == '/api/analyze':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                req = json.loads(post_data.decode('utf-8'))
                input_type = req.get('type', 'url')
                content = req.get('content', '')
                dom_signals = req.get('dom_signals', {})
            except:
                input_type = "url"
                content = ""
                dom_signals = {}
                
            url = ""
            extracted_from = None
            
            if input_type == 'url':
                url = content.lower()
            elif input_type == 'sms':
                urls = re.findall(r'https?://[^\s]+', content)
                url = urls[0].lower() if urls else ""
                extracted_from = "SMS"
            elif input_type == 'qr':
                url = "http://qr-decoded-suspicious-site.xyz/login"
                extracted_from = "QR Image"
                
            is_phishing = "login" in url or "update" in url or "verify" in url or "secure" in url or "xyz" in url or "0" in url
            
            # More nuanced confidence
            if is_phishing:
                confidence = random.uniform(0.75, 0.99)
            else:
                confidence = random.uniform(0.01, 0.25)
            
            # Extract Live DOM Telemetry from Browser Extension
            hidden_elements = dom_signals.get('hidden_iframes', 0)
            right_click_disabled = 1 if dom_signals.get('right_click_disabled', False) else 0
            password_inputs = dom_signals.get('password_inputs', 0)
            
            raw_features = {
                "domain_length": len(url),
                "num_dots": url.count("."),
                "has_ip_host": 0,
                "has_https": 1 if url.startswith("https") else 0,
                "domain_age_days": random.randint(5, 500) if is_phishing else random.randint(1000, 5000),
                "hidden_elements": hidden_elements,
                "password_inputs": password_inputs,
                "external_resource_ratio": round(random.uniform(0.4, 0.9), 2) if is_phishing else round(random.uniform(0.0, 0.2), 2),
                "right_click_disabled": right_click_disabled
            }
            
            # Phase 5 & 10: Risk Profile Calculation
            risk_profile = risk_engine.calculate_risk_profile(confidence, raw_features)
            
            # Phase 5: Mock SHAP Values
            base_value = 0.5
            shap_values = {}
            for feature, val in raw_features.items():
                if is_phishing:
                    shap_values[feature] = round(random.uniform(0.01, 0.15), 3)
                else:
                    shap_values[feature] = round(random.uniform(-0.15, -0.01), 3)
            
            if raw_features["domain_age_days"] < 30:
                shap_values["domain_age_days"] = 0.25
            elif raw_features["domain_age_days"] > 1000:
                shap_values["domain_age_days"] = -0.20
            
            # Phase 6: Quad-Modal Attention Weights [Text, Struct, Vis, Graph]
            if is_phishing:
                gate_weights = [0.25, 0.2, 0.15, 0.4] # Heavily relies on graph/infrastructure if bad
            else:
                gate_weights = [0.1, 0.6, 0.1, 0.2]
                
            # Phase 6: Threat Graph Mock Data
            domain = url.split("://")[-1].split("/")[0] if "://" in url else url.split("/")[0]
            threat_graph = {
                "nodes": [
                    {"id": domain, "group": 1, "type": "url", "label": "Target URL"},
                    {"id": "192.168.1.100", "group": 2, "type": "ip", "label": "IP Address"},
                    {"id": "AS13335", "group": 3, "type": "asn", "label": "Cloudflare ASN"},
                    {"id": "Registrar-X", "group": 4, "type": "registrar", "label": "Domain Registrar"},
                ],
                "links": [
                    {"source": domain, "target": "192.168.1.100", "label": "Hosted On"},
                    {"source": "192.168.1.100", "target": "AS13335", "label": "Routed By"},
                    {"source": domain, "target": "Registrar-X", "label": "Registered By"},
                ]
            }
            
            # If phishing, add some connected malicious nodes to the graph
            if is_phishing:
                threat_graph["nodes"].extend([
                    {"id": "malicious-login-fake.com", "group": 5, "type": "url", "label": "Known Phishing (99%)"},
                    {"id": "secure-update-alert.net", "group": 5, "type": "url", "label": "Known Phishing (95%)"}
                ])
                threat_graph["links"].extend([
                    {"source": "malicious-login-fake.com", "target": "192.168.1.100", "label": "Shared IP"},
                    {"source": "secure-update-alert.net", "target": "Registrar-X", "label": "Shared Registrar"}
                ])
            
            # Phase 8: AI Investigation Report
            paragraphs = []
            paragraphs.append(f"PhishGuard analyzed the target {url}. The quad-modal architecture indicates a {risk_profile['tier']} threat with a risk score of {risk_profile['score']}/100.")
            
            if is_phishing:
                reasons = []
                if raw_features["domain_age_days"] < 30:
                    reasons.append(f"the domain was registered suspiciously recently ({raw_features['domain_age_days']} days ago)")
                if raw_features["hidden_elements"] > 0:
                    reasons.append(f"detected {raw_features['hidden_elements']} hidden DOM elements often used to evade NLP scanners")
                if raw_features["right_click_disabled"] == 1:
                    reasons.append("right-click functionality was disabled (a common evasion tactic)")
                
                if reasons:
                    paragraphs.append("Structural anomalies heavily contributed to this classification. Specifically, " + ", and ".join(reasons) + ".")
                
                # Threat Family Detection & Graph insight
                threat_families = ["Credential Harvester (Muraena)", "Banking Trojan Dropper", "Typosquatting Campaign", "Fake Login Kit (16Shop)"]
                detected_family = random.choice(threat_families)
                paragraphs.append(f"Threat Family Detection: The Quad-Modal analysis strongly correlates this attack with the **{detected_family}** threat family. GraphSAGE threat intelligence reveals significant infrastructure overlap with this campaign's known malicious infrastructure. The target is hosted on a high-risk IP address shared with other active phishing domains from this actor.")
            else:
                paragraphs.append(f"The domain exhibits a mature registration age ({raw_features['domain_age_days']} days) and lacks evasive HTML structures. Threat intelligence graph analysis indicates the underlying infrastructure (IP/ASN) is clean. No known threat families detected.")
                
            investigation_report = "\n\n".join(paragraphs)
            
            response_data = {
                "url": url,
                "extracted_from": extracted_from,
                "is_phishing": is_phishing,
                "confidence": confidence,
                "raw_features": raw_features,
                "risk_profile": risk_profile,
                "shap_values": shap_values,
                "gate_weights": gate_weights,
                "threat_graph": threat_graph,
                "investigation_report": investigation_report,
                "tokens": ["[CLS]"] + list(url[:10]) + ["[SEP]"]
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        else:
            self.send_response(404)
            self.send_cors_headers()
            self.end_headers()

print(f"Starting robust mock server (Phase 5) on port {PORT}...")
with socketserver.TCPServer(("", PORT), MockPhishGuardHandler) as httpd:
    httpd.serve_forever()

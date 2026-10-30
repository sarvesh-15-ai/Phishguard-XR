import hashlib

class ThreatGraphEngine:
    """
    Builds relationships between URL, Domain, IP, Certificate, and Candidate Campaigns.
    Uses precise terms: 'Related Infrastructure', 'Candidate Campaign', 'Correlation Hypothesis'.
    """

    def generate_graph(self, domain_root: str, risk_score: int) -> dict:
        domain_hash = hashlib.sha256(domain_root.encode('utf-8')).hexdigest()[:12]
        
        nodes = [
            {"id": domain_root, "type": "domain", "risk": risk_score, "label": f"Domain: {domain_root}"},
            {"id": f"ip-{domain_hash}", "type": "ip", "risk": 75 if risk_score > 60 else 10, "label": "IP Address (192.168.1.100)"},
            {"id": f"asn-{domain_hash}", "type": "asn", "risk": 20, "label": "Cloudflare ASN"},
            {"id": f"campaign-{domain_hash}", "type": "candidate_campaign", "risk": risk_score, "label": "Candidate Campaign #842"}
        ]

        edges = [
            {"source": domain_root, "target": f"ip-{domain_hash}", "relationship": "resolves_to"},
            {"source": f"ip-{domain_hash}", "target": f"asn-{domain_hash}", "relationship": "routed_by"},
            {"source": domain_root, "target": f"campaign-{domain_hash}", "relationship": "correlation_hypothesis"}
        ]

        return {"nodes": nodes, "edges": edges}

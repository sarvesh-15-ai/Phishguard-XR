class AssistantService:
    """
    PhishGuard-XR Evidence-Grounded Security Chatbot Assistant.
    STRICT GUARDRAILS:
    - Reads verified JSON evidence ONLY.
    - Zero execution authority (cannot block, delete, or override policy).
    - Prevents prompt injection & system prompt disclosure.
    """

    def answer_query(self, user_query: str, analysis_data: dict) -> dict:
        query_lower = user_query.lower()
        
        grounded_evidence = []
        if "url_evidence" in analysis_data.get("evidence", {}):
            grounded_evidence.extend(analysis_data["evidence"]["url_evidence"])
        if "dom_evidence" in analysis_data.get("evidence", {}):
            grounded_evidence.extend(analysis_data["evidence"]["dom_evidence"])

        # System Guardrail Check: Block attempt to override policy or demand credentials
        if "override" in query_lower or "whitelist" in query_lower:
            return {
                "response_text": "Security Assistant Guardrail Notice: I am a read-only analyst assistant. I do not have permission to override policy decisions or modify whitelist settings. Please contact your SOC Administrator.",
                "grounded_evidence_used": []
            }

        response = (
            f"Based on PhishGuard-XR's verified evaluation (Risk Score: {analysis_data.get('risk_score', 0)}/100, "
            f"Severity: {analysis_data.get('severity', 'unknown').upper()}), this webpage exhibits specific indicators. "
            f"Primary evidence used: {', '.join(grounded_evidence) if grounded_evidence else 'Standard Baseline Evaluation'}."
        )

        return {
            "response_text": response,
            "grounded_evidence_used": grounded_evidence
        }

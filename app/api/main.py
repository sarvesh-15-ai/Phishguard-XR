import os
import sys
import random
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="PhishGuard API (Mock Mode)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    url: str

@app.post("/api/analyze")
def analyze_url(req: AnalyzeRequest):
    url = req.url.lower()
    
    # Simple heuristic for the mock
    is_phishing = "login" in url or "update" in url or "verify" in url or "secure" in url or "xyz" in url or "0" in url
    
    confidence = random.uniform(0.85, 0.99)
    
    # Mock extracted features
    raw_features = {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_subdomains": 1 if url.count(".") > 1 else 0,
        "has_ip_host": 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "has_https": 1 if url.startswith("https") else 0,
        "suspicious_tld": 1 if "xyz" in url else 0,
        "domain_entropy": round(random.uniform(2.0, 4.5), 3),
        "path_length": 15,
        "num_query_params": url.count("=")
    }
    
    # Mock attention matrix: [text_attn, struct_attn]
    if is_phishing:
        text_attn = random.uniform(0.6, 0.9)  # text cues heavily weighted for phishing
        struct_attn = 1.0 - text_attn
    else:
        struct_attn = random.uniform(0.5, 0.8) # structural cues (https, etc) for legit
        text_attn = 1.0 - struct_attn
        
    attn_matrix = [
        [text_attn, 0.0],
        [0.0, struct_attn]
    ]
    
    return {
        "url": url,
        "is_phishing": is_phishing,
        "confidence": confidence,
        "raw_features": raw_features,
        "attention_matrix": attn_matrix,
        "tokens": ["[CLS]"] + list(url[:10]) + ["[SEP]"]
    }

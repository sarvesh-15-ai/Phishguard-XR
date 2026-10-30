import sys
print("importing os", flush=True)
import os
print("importing torch", flush=True)
import torch
print("importing joblib", flush=True)
import joblib
print("importing fastapi", flush=True)
from fastapi import FastAPI
print("importing transformers", flush=True)
import transformers
print("importing tldextract", flush=True)
import tldextract
print("importing src modules", flush=True)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(os.path.join(PROJECT_ROOT, "src", "models"))
sys.path.append(os.path.join(PROJECT_ROOT, "src", "feature_extraction"))
from fusion_classifier import PhishGuardModel
from extract_features import extract_lexical_features
print("done", flush=True)

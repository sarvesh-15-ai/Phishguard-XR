"""
extract_features.py — PhishGuard Phase 2

Turns data/phishguard_dataset.csv (raw url,label) into the two input
formats the model needs:

1. LEXICAL FEATURES  -> data/processed/lexical_features.csv
2. TOKENIZED TEXT     -> data/processed/tokenized.pt
"""

import os
import re
import math
import pandas as pd
import tldextract

DATA_DIR = "data"
INPUT_PATH = os.path.join(DATA_DIR, "phishguard_dataset.csv")
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
LEXICAL_OUTPUT = os.path.join(PROCESSED_DIR, "lexical_features.csv")
TOKENIZED_OUTPUT = os.path.join(PROCESSED_DIR, "tokenized.pt")

SUSPICIOUS_TLDS = {"xyz", "top", "click", "gq", "tk", "ml", "cf", "work", "loan", "site", "online"}
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def extract_lexical_features(url: str) -> dict:
    url = str(url)
    ext = tldextract.extract(url)

    host_match = re.search(r"://([^/]+)", url)
    raw_host = host_match.group(1).split(":")[0] if host_match else url.split("/")[0]

    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_subdomains": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "has_ip_host": int(bool(IP_PATTERN.match(raw_host))),
        "has_at_symbol": int("@" in url),
        "has_https": int(url.lower().startswith("https://")),
        "suspicious_tld": int(ext.suffix.lower() in SUSPICIOUS_TLDS),
        "domain_entropy": round(shannon_entropy(ext.domain), 3),
        "path_length": len(url.split("/", 3)[3]) if url.count("/") >= 3 else 0,
        "num_query_params": url.count("=") if "?" in url else 0,
    }


def build_lexical_features(df: pd.DataFrame) -> pd.DataFrame:
    print("[step] Extracting lexical features...")
    feature_rows = [extract_lexical_features(u) for u in df["url"]]
    features_df = pd.DataFrame(feature_rows)
    features_df["label"] = df["label"].values
    features_df["url"] = df["url"].values
    print(f"[ok] Extracted {len(features_df.columns) - 2} lexical features for {len(features_df)} URLs")
    return features_df


def build_tokenized_inputs(df: pd.DataFrame, model_name: str = "distilbert-base-uncased", max_length: int = 64):
    import torch
    from transformers import AutoTokenizer

    print(f"[step] Tokenizing URLs with '{model_name}'...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)

    encodings = tokenizer(
        list(df["url"].astype(str)),
        padding="max_length",
        truncation=True,
        max_length=max_length,
        return_tensors="pt",
    )

    labels = torch.tensor(df["label"].values, dtype=torch.long)

    payload = {
        "input_ids": encodings["input_ids"],
        "attention_mask": encodings["attention_mask"],
        "labels": labels,
    }
    torch.save(payload, TOKENIZED_OUTPUT)
    print(f"[ok] Saved tokenized tensors to {TOKENIZED_OUTPUT} (shape: {encodings['input_ids'].shape})")


def main():
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    if not os.path.exists(INPUT_PATH):
        print(f"[error] {INPUT_PATH} not found — run build_dataset.py (Phase 1) first.")
        return

    df = pd.read_csv(INPUT_PATH)
    print(f"[ok] Loaded {len(df)} URLs from {INPUT_PATH}")

    lexical_df = build_lexical_features(df)
    lexical_df.to_csv(LEXICAL_OUTPUT, index=False)
    print(f"[ok] Saved lexical features to {LEXICAL_OUTPUT}")

    try:
        build_tokenized_inputs(df)
    except ImportError as e:
        print(f"\n[skip] Tokenization step skipped — missing dependency ({e}).")

    print("\nPhase 2 complete. Outputs in data/processed/:")
    print(f"  - {LEXICAL_OUTPUT}")
    print(f"  - {TOKENIZED_OUTPUT} (if torch/transformers available)")


if __name__ == "__main__":
    main()
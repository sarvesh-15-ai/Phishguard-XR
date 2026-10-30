"""
build_dataset.py — PhishGuard Phase 1 (v2)

Combines the raw downloaded sources (PhishTank, OpenPhish, Tranco) into a
single, cleaned, balanced CSV ready for feature extraction in Phase 2.

Run this from your project root:
    python3 src/feature_extraction/build_dataset.py

Expects these files in data/ (see Step 2a):
    data/phishtank_raw.csv     (real PhishTank export — has extra columns)
    data/openphish_raw.txt     (optional — plain text, one URL per line)
    data/tranco_legit.csv      (rank,domain — no header)
"""

import pandas as pd
import os

DATA_DIR = "data"
OUTPUT_PATH = os.path.join(DATA_DIR, "phishguard_dataset.csv")


def load_phishtank():
    path = os.path.join(DATA_DIR, "phishtank_raw.csv")
    if not os.path.exists(path):
        print(f"[skip] {path} not found")
        return pd.DataFrame(columns=["url", "label"])

    df = pd.read_csv(path)

    if "online" in df.columns:
        before = len(df)
        df = df[df["online"].astype(str).str.lower() == "yes"]
        print(f"[filter] PhishTank: kept {len(df)}/{before} rows still marked online")

    if "verified" in df.columns:
        df = df[df["verified"].astype(str).str.lower() == "yes"]

    df = df[["url"]].copy()
    df["label"] = 1
    print(f"[ok] PhishTank: {len(df)} phishing URLs loaded")
    return df


def load_openphish():
    path = os.path.join(DATA_DIR, "openphish_raw.txt")
    if not os.path.exists(path):
        print(f"[skip] {path} not found")
        return pd.DataFrame(columns=["url", "label"])
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        urls = [line.strip() for line in f if line.strip()]
    print(f"[ok] OpenPhish: {len(urls)} phishing URLs loaded")
    return pd.DataFrame({"url": urls, "label": 1})


def load_tranco():
    path = os.path.join(DATA_DIR, "tranco_legit.csv")
    if not os.path.exists(path):
        print(f"[skip] {path} not found")
        return pd.DataFrame(columns=["url", "label"])
    df = pd.read_csv(path, header=None, names=["rank", "domain"])
    df["url"] = "https://" + df["domain"].astype(str)
    df = df[["url"]]
    df["label"] = 0
    print(f"[ok] Tranco: {len(df)} legitimate URLs loaded")
    return df


def clean_and_balance(df: pd.DataFrame, target_per_class: int = 30000):
    before = len(df)
    df = df.dropna(subset=["url"])
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len() > 0]
    df = df.drop_duplicates(subset=["url"])
    print(f"[clean] {before} -> {len(df)} rows after removing empty/duplicate URLs")

    phishing = df[df["label"] == 1]
    legit = df[df["label"] == 0]

    n = min(len(phishing), len(legit), target_per_class)
    if n == 0:
        raise ValueError(
            "No usable rows for one of the classes — check that your raw "
            "source files downloaded correctly in Step 2a."
        )

    phishing_sample = phishing.sample(n=n, random_state=42)
    legit_sample = legit.sample(n=n, random_state=42)

    balanced = pd.concat([phishing_sample, legit_sample]).sample(frac=1, random_state=42)
    print(f"[balance] Final dataset: {n} phishing + {n} legitimate = {len(balanced)} total")
    return balanced.reset_index(drop=True)


def main():
    os.makedirs(DATA_DIR, exist_ok=True)

    frames = [load_phishtank(), load_openphish(), load_tranco()]
    combined = pd.concat(frames, ignore_index=True)

    if combined.empty:
        print(
            "\nNo data loaded. Make sure at least one phishing source and "
            "the Tranco list are downloaded into data/ (see Step 2a) "
            "before running this script."
        )
        return

    final = clean_and_balance(combined)
    final.to_csv(OUTPUT_PATH, index=False)
    print(f"\nSaved final dataset to {OUTPUT_PATH}")
    print(final["label"].value_counts())


if __name__ == "__main__":
    main()

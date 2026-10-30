import pandas as pd
import time

from downloader import download_page
from parser import parse_html


def extract_dataset(input_file, output_file, limit=20):
    # Read dataset
    df = pd.read_csv(input_file)

    results = []

    # Process only first 'limit' URLs
    for index, row in df.head(limit).iterrows():
        url = row["url"]

        print(f"[{index + 1}/{limit}] Processing: {url}")

        html = download_page(url)

        if html:
            features = parse_html(html)

            # Add URL and label
            features["url"] = url
            features["label"] = row["label"]

            results.append(features)

        # Small delay to avoid sending requests too quickly
        time.sleep(1)

    # Save extracted features
    output_df = pd.DataFrame(results)
    output_df.to_csv(output_file, index=False)

    print(f"\n✅ Saved HTML features to: {output_file}")


if __name__ == "__main__":
    extract_dataset(
        "data/phishguard_dataset.csv",
        "data/processed/html_features.csv",
        limit=20
    )
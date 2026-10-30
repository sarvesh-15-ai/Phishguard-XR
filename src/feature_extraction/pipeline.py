import os
import sys
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

# Adjust sys.path to import from sibling directories
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(os.path.join(PROJECT_ROOT, "src", "domain"))
sys.path.append(os.path.join(PROJECT_ROOT, "src", "webpage"))

from extract_features import extract_lexical_features
from domain_features import extract_domain_features
from downloader import download_page
from parser import parse_html

class UnifiedExtractor:
    def __init__(self):
        pass

    def extract_all(self, url):
        """
        Runs the unified pipeline for a single URL.
        Extracts Lexical, Domain, and HTML features.
        """
        url = str(url)
        unified_features = {"url": url}

        # 1. Lexical Features
        try:
            lexical_feats = extract_lexical_features(url)
            unified_features.update(lexical_feats)
        except Exception as e:
            print(f"[Error] Lexical extraction failed for {url}: {e}")

        # 2. Domain & DNS Features
        try:
            domain_feats = extract_domain_features(url)
            # Remove 'url' key to prevent conflict
            domain_feats.pop("url", None)
            unified_features.update(domain_feats)
        except Exception as e:
            print(f"[Error] Domain extraction failed for {url}: {e}")

        # 3. HTML/DOM Features
        try:
            html = download_page(url)
            if html:
                html_feats = parse_html(html, base_url=url)
                # Remove title string since it's not a numeric feature for ML
                html_feats.pop("title", None)
                unified_features.update(html_feats)
            else:
                self._fill_empty_html_features(unified_features)
        except Exception as e:
            print(f"[Error] HTML extraction failed for {url}: {e}")
            self._fill_empty_html_features(unified_features)

        return unified_features

    def _fill_empty_html_features(self, features):
        """Fill HTML features with zeros if download fails."""
        empty = {
            "num_forms": 0, "num_links": 0, "num_images": 0,
            "num_scripts": 0, "num_iframes": 0, "num_inputs": 0,
            "text_length": 0, "hidden_elements": 0,
            "external_resource_ratio": 0.0, "suspicious_keyword_count": 0,
            "right_click_disabled": 0
        }
        features.update(empty)


def main():
    input_path = os.path.join(PROJECT_ROOT, "data", "phishguard_dataset.csv")
    output_path = os.path.join(PROJECT_ROOT, "data", "processed", "unified_features.csv")
    
    if not os.path.exists(input_path):
        print(f"[Error] Dataset not found at {input_path}")
        return

    df = pd.read_csv(input_path)
    urls = df["url"].tolist()
    labels = df["label"].tolist()
    total = len(urls)

    print(f"🔥 Starting Unified Feature Extraction for {total} URLs...")
    
    extractor = UnifiedExtractor()
    results = [None] * total
    url_to_index = {url: i for i, url in enumerate(urls)}

    # We use a ThreadPool to speed up the network-heavy DNS and HTML requests
    with ThreadPoolExecutor(max_workers=20) as thread_pool:
        futures = {thread_pool.submit(extractor.extract_all, url): url for url in urls}

        done_count = 0
        for future in as_completed(futures):
            url = futures[future]
            result_dict = future.result()
            
            # Attach the ground-truth label
            idx = url_to_index[url]
            result_dict["label"] = labels[idx]
            results[idx] = result_dict
            
            done_count += 1
            if done_count % 10 == 0 or done_count == total:
                print(f"[{done_count}/{total}] URLs processed")

    # Save to CSV
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    out_df = pd.DataFrame(results)
    out_df.to_csv(output_path, index=False)
    
    print(f"\n✅ Unified Feature Pipeline complete!")
    print(f"✅ Generated {len(out_df.columns) - 2} features per URL.")
    print(f"✅ Saved to: {output_path}")

if __name__ == "__main__":
    main()

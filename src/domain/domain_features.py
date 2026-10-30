import pandas as pd
import socket
import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional advanced dependencies (fails gracefully if missing)
try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
except ImportError:
    dns = None

# Short timeout so dead domains fail fast
socket.setdefaulttimeout(2)

def extract_domain_features(url):
    features = {}
    try:
        domain = urlparse(url).netloc
        domain = domain.replace("www.", "")

        # 1. Basic String Features
        features["domain_length"] = len(domain)
        features["has_ip"] = 1 if domain.replace(".", "").isdigit() else 0
        features["https"] = 1 if url.startswith("https") else 0
        features["dot_count"] = domain.count(".")
        features["hyphen_count"] = domain.count("-")
        features["subdomain_count"] = max(domain.count(".") - 1, 0)

        # 2. DNS & IP Features
        try:
            ip_address = socket.gethostbyname(domain)
            features["ip_address"] = ip_address
        except Exception:
            features["ip_address"] = "unknown"

        # 3. 🔥 Advanced DNS Features (MX/TXT)
        features["has_mx_record"] = 0
        features["has_txt_record"] = 0
        if dns:
            try:
                mx = dns.resolver.resolve(domain, 'MX')
                features["has_mx_record"] = 1 if len(mx) > 0 else 0
            except Exception:
                pass
            try:
                txt = dns.resolver.resolve(domain, 'TXT')
                features["has_txt_record"] = 1 if len(txt) > 0 else 0
            except Exception:
                pass

        # 4. 🔥 WHOIS Domain Age
        features["domain_age_days"] = -1
        if whois:
            try:
                w = whois.whois(domain)
                if w.creation_date:
                    creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    if isinstance(creation_date, datetime.datetime):
                        age = (datetime.datetime.now() - creation_date).days
                        features["domain_age_days"] = max(age, 0)
            except Exception:
                pass

    except Exception:
        features["domain_length"] = 0
        features["has_ip"] = 0
        features["ip_address"] = "unknown"
        features["https"] = 0
        features["dot_count"] = 0
        features["hyphen_count"] = 0
        features["subdomain_count"] = 0
        features["has_mx_record"] = 0
        features["has_txt_record"] = 0
        features["domain_age_days"] = -1

    features["url"] = url
    return features


if __name__ == "__main__":
    df = pd.read_csv("data/phishguard_dataset.csv")
    urls = df["url"].tolist()
    total = len(urls)

    results = [None] * total
    url_to_index = {url: i for i, url in enumerate(urls)}

    print(f"Starting advanced domain feature extraction for {total} URLs...")

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(extract_domain_features, url): url for url in urls}

        done_count = 0
        for future in as_completed(futures):
            url = futures[future]
            result = future.result()
            results[url_to_index[url]] = result
            done_count += 1
            if done_count % 100 == 0 or done_count == total:
                print(f"[{done_count}/{total}] processed")

    import os
    os.makedirs("data/processed", exist_ok=True)
    output = pd.DataFrame(results)
    output.to_csv("data/processed/domain_features.csv", index=False)

    print("✅ Saved advanced domain features to: data/processed/domain_features.csv")

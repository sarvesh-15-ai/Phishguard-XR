"""
unseen_domain.py — PhishGuard Phase 7

Evaluates the model on a strict Unseen-Domain split.
Ensures the ML model is generalizing structural/visual/graph features 
rather than simply memorizing the string of a malicious domain.
"""

import pandas as pd
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
import os

def get_base_domain(url):
    try:
        netloc = urlparse(url).netloc
        # Basic parsing, in production use tldextract
        parts = netloc.split('.')
        if len(parts) > 2:
            return ".".join(parts[-2:])
        return netloc
    except:
        return "unknown"

class UnseenDomainEvaluator:
    def __init__(self, dataset_path):
        self.dataset_path = dataset_path
        
    def create_strict_splits(self, test_size=0.2, random_state=42):
        print(f"Loading dataset from {self.dataset_path}...")
        df = pd.read_csv(self.dataset_path)
        
        print("Extracting base domains...")
        df['base_domain'] = df['url'].apply(get_base_domain)
        
        # Get unique domains
        unique_domains = df['base_domain'].unique()
        print(f"Found {len(unique_domains)} unique domains across {len(df)} URLs.")
        
        # Split domains, NOT urls
        train_domains, test_domains = train_test_split(unique_domains, test_size=test_size, random_state=random_state)
        
        train_df = df[df['base_domain'].isin(train_domains)].copy()
        test_df = df[df['base_domain'].isin(test_domains)].copy()
        
        print(f"Split complete. Train URLs: {len(train_df)}, Test URLs: {len(test_df)}")
        
        # Verification
        train_domain_set = set(train_df['base_domain'].unique())
        test_domain_set = set(test_df['base_domain'].unique())
        overlap = train_domain_set.intersection(test_domain_set)
        
        assert len(overlap) == 0, f"CRITICAL ERROR: Found {len(overlap)} overlapping domains in train/test sets!"
        print("✅ Unseen-Domain Verification Passed: 0 overlapping domains.")
        
        return train_df, test_df

if __name__ == "__main__":
    # Example usage for testing the script logic
    # Creating a dummy dataset to verify
    data = {
        'url': [
            'http://google.com/login', 'http://google.com/images', 
            'http://bad-login.xyz/index', 'http://bad-login.xyz/auth',
            'https://chase.com/secure', 'http://phish-chase.net/login'
        ],
        'label': [0, 0, 1, 1, 0, 1]
    }
    df = pd.DataFrame(data)
    os.makedirs('data', exist_ok=True)
    df.to_csv('data/dummy_eval.csv', index=False)
    
    evaluator = UnseenDomainEvaluator('data/dummy_eval.csv')
    train, test = evaluator.create_strict_splits(test_size=0.33)
    
    print("\n--- Train Set ---")
    print(train['url'].values)
    print("\n--- Test Set ---")
    print(test['url'].values)

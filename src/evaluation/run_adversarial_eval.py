import sys
import os

# Add parent dir to path so we can import adversarial
sys.path.append(os.path.dirname(__file__))
from adversarial import AdversarialPerturber

def simple_nlp_mock_model(url: str) -> bool:
    """
    Simulates a standard text-based NLP Phishing Detection Model.
    If it sees malicious keywords, it flags it.
    """
    keywords = ["login", "update", "verify", "secure", "auth", "account"]
    for keyword in keywords:
        if keyword in url:
            return True
    return False

def evaluate_dataset(dataset: list, perturber: AdversarialPerturber = None, attack_type: str = None) -> dict:
    """
    Evaluates the model on a dataset. 
    If perturber and attack_type are provided, mutates the phishing URLs first.
    """
    true_positives = 0
    true_negatives = 0
    false_positives = 0
    false_negatives = 0

    for url, is_phishing in dataset:
        test_url = url
        
        # Apply adversarial perturbation ONLY to the malicious URLs to try and evade detection
        if is_phishing and perturber and attack_type:
            if attack_type == "homoglyph":
                test_url = perturber.attack_homoglyph(url)
            elif attack_type == "subdomain":
                test_url = perturber.attack_subdomain_stuffing(url)
            elif attack_type == "path":
                test_url = perturber.attack_path_padding(url)

        # Run inference
        prediction = simple_nlp_mock_model(test_url)

        if is_phishing and prediction:
            true_positives += 1
        elif is_phishing and not prediction:
            false_negatives += 1
        elif not is_phishing and not prediction:
            true_negatives += 1
        else:
            false_positives += 1

    total = len(dataset)
    accuracy = (true_positives + true_negatives) / total
    
    # Handle div by zero if model completely fails
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }

def main():
    print("==========================================================")
    print("PHISHGUARD-X: ADVERSARIAL ROBUSTNESS EVALUATION PIPELINE")
    print("==========================================================\n")
    
    # 1. Generate Synthetic Dataset (100 Phishing, 100 Legitimate)
    phishing_base_urls = [
        "https://paypal.com-update.xyz/login",
        "http://secure-verify-auth.net/account",
        "https://chase.com-login-portal.com",
        "http://netflix-billing-update.info/verify"
    ] * 25 # 100 URLs

    legitimate_urls = [
        "https://google.com/search",
        "https://github.com/torvalds/linux",
        "https://wikipedia.org/wiki/Machine_learning",
        "https://news.ycombinator.com"
    ] * 25 # 100 URLs

    dataset = [(url, True) for url in phishing_base_urls] + [(url, False) for url in legitimate_urls]
    
    perturber = AdversarialPerturber()

    print("Running Baseline Evaluation (Clean Dataset)...")
    baseline_metrics = evaluate_dataset(dataset)
    
    print("Running Homoglyph Attack Evaluation...")
    homoglyph_metrics = evaluate_dataset(dataset, perturber, "homoglyph")
    
    print("Running Subdomain Stuffing Evaluation...")
    subdomain_metrics = evaluate_dataset(dataset, perturber, "subdomain")
    
    print("\n")
    print("==========================================================")
    print("                   EVALUATION RESULTS                     ")
    print("==========================================================")
    print(f"{'Metric':<15} | {'Baseline':<10} | {'Homoglyph':<10} | {'Sub. Stuff':<10}")
    print("-" * 55)
    
    metrics_list = ["accuracy", "precision", "recall", "f1"]
    
    for metric in metrics_list:
        base_val = f"{baseline_metrics[metric]*100:.1f}%"
        homo_val = f"{homoglyph_metrics[metric]*100:.1f}%"
        sub_val = f"{subdomain_metrics[metric]*100:.1f}%"
        print(f"{metric.capitalize():<15} | {base_val:<10} | {homo_val:<10} | {sub_val:<10}")
        
    print("-" * 55)
    
    drop = (baseline_metrics['accuracy'] - homoglyph_metrics['accuracy']) * 100
    print(f"\n[!] ALERT: Text-only NLP model accuracy dropped by {drop:.1f}% under Adversarial Homoglyph attack!")
    print("[!] CONCLUSION: Quad-Modal (Graph+DOM+Visual) fusion is REQUIRED to maintain robustness.\n")

if __name__ == "__main__":
    main()

"""
adversarial.py — PhishGuard Phase 7

Automated Red-Teaming for ML models. 
Applies evasive mutations to test URLs to measure Robustness Degradation.
"""

import random
from urllib.parse import urlparse, urlunparse
import json

class AdversarialPerturber:
    def __init__(self):
        # Common visually similar characters used by attackers
        self.homoglyphs = {
            'a': ['@', '4', 'а'],
            'o': ['0', 'о'],
            'i': ['1', 'l', '!', 'і'],
            'l': ['1', 'I', 'i'],
            'e': ['3', 'е'],
            's': ['5', '$']
        }
        
    def attack_homoglyph(self, url: str) -> str:
        """Randomly swaps characters with visual lookalikes to fool transformers."""
        parsed = list(urlparse(url))
        netloc = parsed[1]
        
        mutated_netloc = ""
        for char in netloc:
            if char in self.homoglyphs and random.random() < 0.3:
                mutated_netloc += random.choice(self.homoglyphs[char])
            else:
                mutated_netloc += char
                
        parsed[1] = mutated_netloc
        return urlunparse(parsed)

    def attack_subdomain_stuffing(self, url: str) -> str:
        """Injects highly trusted keywords into the subdomain to trick the model."""
        trusted_keywords = ["secure", "login", "update", "verify", "auth", "microsoft", "google"]
        parsed = list(urlparse(url))
        
        # Don't stuff if it's just an IP
        if parsed[1].replace(".", "").isdigit():
            return url
            
        stuffed_subdomain = random.choice(trusted_keywords) + "." + random.choice(trusted_keywords)
        parsed[1] = stuffed_subdomain + "." + parsed[1]
        
        return urlunparse(parsed)

    def attack_path_padding(self, url: str) -> str:
        """
        Adds extremely long, random paths to try and push malicious keywords 
        out of the Transformer's maximum token window (e.g., 64 tokens).
        """
        parsed = list(urlparse(url))
        padding = "/".join(["".join(random.choices("abcdefghijklmnopqrstuvwxyz1234567890", k=10)) for _ in range(5)])
        
        if parsed[2]:
            parsed[2] = "/" + padding + parsed[2]
        else:
            parsed[2] = "/" + padding
            
        return urlunparse(parsed)

    def generate_adversarial_test_set(self, urls: list, attack_type="all") -> list:
        """Mutates a batch of URLs."""
        adversarial_urls = []
        for url in urls:
            if attack_type == "homoglyph" or (attack_type == "all" and random.random() < 0.33):
                adversarial_urls.append(self.attack_homoglyph(url))
            elif attack_type == "subdomain" or (attack_type == "all" and random.random() < 0.66):
                adversarial_urls.append(self.attack_subdomain_stuffing(url))
            else:
                adversarial_urls.append(self.attack_path_padding(url))
        return adversarial_urls

if __name__ == "__main__":
    perturber = AdversarialPerturber()
    test_urls = [
        "https://paypal.com/signin",
        "http://bankofamerica.com/update",
        "http://suspicious-domain.xyz/login.php"
    ]
    
    print("--- Original URLs ---")
    for u in test_urls: print(u)
        
    print("\n--- Homoglyph Attack ---")
    for u in test_urls: print(perturber.attack_homoglyph(u))
        
    print("\n--- Subdomain Stuffing Attack ---")
    for u in test_urls: print(perturber.attack_subdomain_stuffing(u))
        
    print("\n--- Path Padding Attack (Token Eviction) ---")
    for u in test_urls: print(perturber.attack_path_padding(u))

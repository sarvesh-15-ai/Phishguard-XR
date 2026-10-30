import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "account", "secure", "bank", 
    "password", "suspended", "urgent", "confirm"
]

def parse_html(html, base_url=""):
    soup = BeautifulSoup(html, "lxml")
    
    base_domain = urlparse(base_url).netloc.replace("www.", "") if base_url else ""
    
    # 1. Basic Counts
    num_forms = len(soup.find_all("form"))
    num_links = len(soup.find_all("a"))
    num_images = len(soup.find_all("img"))
    num_scripts = len(soup.find_all("script"))
    num_iframes = len(soup.find_all("iframe"))
    num_inputs = len(soup.find_all("input"))
    text_content = soup.get_text().lower()
    
    # 2. 🔥 Hidden Elements Check
    # Attackers often hide legitimate text to fool NLP scanners
    hidden_count = 0
    for style in soup.find_all(style=True):
        css = style['style'].replace(" ", "").lower()
        if "display:none" in css or "visibility:hidden" in css or "opacity:0" in css:
            hidden_count += 1
            
    # 3. 🔥 External Resource Ratio
    # Phishing sites often hotlink images and scripts from legitimate sites
    external_resources = 0
    total_resources = num_images + num_scripts
    
    if base_domain:
        for img in soup.find_all("img", src=True):
            img_domain = urlparse(img["src"]).netloc.replace("www.", "")
            if img_domain and img_domain != base_domain:
                external_resources += 1
                
        for script in soup.find_all("script", src=True):
            script_domain = urlparse(script["src"]).netloc.replace("www.", "")
            if script_domain and script_domain != base_domain:
                external_resources += 1
                
    external_ratio = (external_resources / total_resources) if total_resources > 0 else 0.0

    # 4. 🔥 Suspicious Keyword Density
    # Financial and urgent keywords in visible text
    keyword_count = sum(text_content.count(kw) for kw in SUSPICIOUS_KEYWORDS)
    
    # 5. 🔥 Suspicious Behavior Markers
    # Disabling right-click is a common tactic to prevent inspecting code
    right_click_disabled = 1 if re.search(r'oncontextmenu\s*=\s*["\']return false["\']', html, re.I) else 0

    data = {
        "title": soup.title.string.strip() if soup.title and soup.title.string else "",
        "num_forms": num_forms,
        "num_links": num_links,
        "num_images": num_images,
        "num_scripts": num_scripts,
        "num_iframes": num_iframes,
        "num_inputs": num_inputs,
        "text_length": len(text_content),
        "hidden_elements": hidden_count,
        "external_resource_ratio": round(external_ratio, 3),
        "suspicious_keyword_count": keyword_count,
        "right_click_disabled": right_click_disabled
    }

    return data
def classify_url(url_input: str):
    lower = url_input.lower()
    phish_keywords = ["login", "verify", "update-account", "secure-bank", "free-gift", "token"]
    matches = [kw for kw in phish_keywords if kw in lower]
    
    is_phish = len(matches) > 0 or "@" in lower or len(url_input) > 75
    conf = 0.94 if is_phish else 0.98
    
    return {
        "url": url_input,
        "is_phishing": is_phish,
        "confidence": conf,
        "risk_factors": matches if matches else ["None detected (Safe Structure)"]
    }
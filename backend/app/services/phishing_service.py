import math
import re
from backend.app.schemas.phishing import URLScanRequest, URLScanResponse

class PhishingDetectorEngine:
    @staticmethod
    def _calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum([p * math.log2(p) for p in prob])
        return round(entropy, 2)

    @staticmethod
    def scan_url(payload: URLScanRequest) -> URLScanResponse:
        raw_url = payload.url.strip()
        url_lower = raw_url.lower()
        
        indicators = []
        threat_score = 0.05
        
        # 1. IP address in hostname
        ip_pattern = r"^(http|https)://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        if re.search(ip_pattern, url_lower):
            threat_score += 0.45
            indicators.append("Direct IP address used instead of domain name")

        # 2. Suspicious TLDs
        suspicious_tlds = [".xyz", ".top", ".buzz", ".tk", ".cf", ".ga", ".ml", ".gq"]
        if any(url_lower.endswith(tld) or (tld + "/") in url_lower for tld in suspicious_tlds):
            threat_score += 0.35
            indicators.append("High-risk domain Top-Level Domain (TLD) flagged")

        # 3. Phishing keywords
        keywords = ["secure-login", "account-verify", "bank-update", "signin-support", "wallet-connect", "paypal-auth", "billing-alert"]
        for kw in keywords:
            if kw in url_lower:
                threat_score += 0.30
                indicators.append(f"Deceptive credential harvest cue: '{kw}'")

        # 4. Entropy calculation
        entropy = PhishingDetectorEngine._calculate_entropy(raw_url)
        if entropy > 4.2:
            threat_score += 0.20
            indicators.append(f"High lexical randomness / character entropy ({entropy})")

        # 5. SSL Check simulation
        ssl_valid = url_lower.startswith("https://")
        if not ssl_valid:
            threat_score += 0.15
            indicators.append("Insecure transmission protocol (Plain HTTP / No SSL)")

        threat_score = round(min(max(threat_score, 0.0), 1.0), 2)
        is_phishing = threat_score >= 0.55
        status = "CRITICAL / PHISHING THREAT" if is_phishing else "SAFE / LEGITIMATE URL"

        if not indicators:
            indicators.append("Verified domain syntax with healthy trust metrics")

        return URLScanResponse(
            url=raw_url,
            is_phishing=is_phishing,
            threat_score=threat_score,
            status_label=status,
            entropy_score=entropy,
            ssl_valid=ssl_valid,
            risk_indicators=indicators
        )

phishing_service = PhishingDetectorEngine()

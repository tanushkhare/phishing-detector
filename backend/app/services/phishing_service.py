import math
import re
from datetime import datetime, timezone
from typing import Dict, Any, List

class PhishingDetectionEngine:
    def __init__(self):
        self.suspicious_tlds = [".xyz", ".top", ".club", ".work", ".click", ".gq", ".tk", ".cf", ".ml"]
        self.sensitive_keywords = ["login", "verify", "secure", "banking", "update", "account", "wallet", "signin", "auth", "paypal"]

    def _calculate_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return round(-sum(p * math.log2(p) for p in prob), 3)

    def evaluate_url(self, target_url: str) -> Dict[str, Any]:
        url_lower = target_url.lower()
        threat_score = 0.05
        flags: List[str] = []

        # 1. IP address in domain
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_lower):
            threat_score += 0.40
            flags.append("Raw IP address used in host domain")

        # 2. Suspicious TLD check
        for tld in self.suspicious_tlds:
            if tld in url_lower:
                threat_score += 0.25
                flags.append(f"High-risk top-level domain ({tld})")
                break

        # 3. Excessive subdomains or hyphenation
        subdomains = url_lower.split("/")[2].split(".") if "//" in url_lower else url_lower.split(".")
        if len(subdomains) >= 4:
            threat_score += 0.20
            flags.append(f"Excessive subdomain depth ({len(subdomains)} levels)")
        if url_lower.count("-") >= 3:
            threat_score += 0.15
            flags.append(f"Excessive hyphenation ({url_lower.count('-')} hyphens)")

        # 4. Sensitive credential keyword matching
        kw_hits = [kw for kw in self.sensitive_keywords if kw in url_lower]
        if kw_hits:
            threat_score += min(0.35, len(kw_hits) * 0.15)
            flags.append(f"Credential targeting keywords detected: {', '.join(kw_hits)}")

        entropy = self._calculate_entropy(target_url)
        if entropy > 4.2:
            threat_score += 0.15
            flags.append(f"High Shannon entropy ({entropy}) indicating obfuscation")

        threat_score = round(min(0.99, max(0.01, threat_score)), 3)
        is_phishing = threat_score >= 0.50

        if not flags:
            flags.append("Domain follows standard lexical patterns")

        verdict = "MALICIOUS_PHISHING_URL" if is_phishing else "SAFE_REPUTATION_URL"

        return {
            "url": target_url,
            "is_phishing": is_phishing,
            "threat_score": threat_score,
            "entropy_score": entropy,
            "detected_suspicious_patterns": flags,
            "verdict": verdict,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

phishing_engine = PhishingDetectionEngine()

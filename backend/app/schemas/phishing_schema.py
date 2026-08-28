from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class URLScanRequest(BaseModel):
    url: str = Field(..., min_length=4, description="Target URL to inspect (e.g. http://secure-login.bank-update.xyz/auth)")

class URLScanResponse(BaseModel):
    url: str
    is_phishing: bool
    threat_score: float
    entropy_score: float
    detected_suspicious_patterns: List[str]
    verdict: str
    timestamp: str

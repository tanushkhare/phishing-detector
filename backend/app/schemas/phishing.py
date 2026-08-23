from pydantic import BaseModel, Field
from typing import List

class URLScanRequest(BaseModel):
    url: str = Field(..., min_length=4)

class URLScanResponse(BaseModel):
    url: str
    is_phishing: bool
    threat_score: float
    status_label: str
    entropy_score: float
    ssl_valid: bool
    risk_indicators: List[str]

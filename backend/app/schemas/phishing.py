from pydantic import BaseModel

class URLCheckRequest(BaseModel):
    url: str

class URLCheckResponse(BaseModel):
    url: str
    is_phishing: bool
    confidence: float
    risk_factors: list
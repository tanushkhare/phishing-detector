from fastapi import APIRouter
from app.schemas.phishing import URLCheckRequest, URLCheckResponse
from app.services.phishing_service import classify_url

router = APIRouter(prefix="/api", tags=["Phishing Detector"])

@router.post("/scan-url", response_model=URLCheckResponse)
def scan_url(payload: URLCheckRequest):
    return classify_url(payload.url)
from fastapi import APIRouter
from backend.app.schemas.phishing import URLScanRequest, URLScanResponse
from backend.app.services.phishing_service import phishing_service

router = APIRouter(prefix="/api/v1/phishing", tags=["Phishing & Threat Engine"])

@router.post("/scan", response_model=URLScanResponse)
async def scan_url(payload: URLScanRequest):
    return phishing_service.scan_url(payload)

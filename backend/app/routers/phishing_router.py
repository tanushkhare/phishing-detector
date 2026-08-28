from fastapi import APIRouter, HTTPException
from backend.app.schemas.phishing_schema import URLScanRequest, URLScanResponse
from backend.app.services.phishing_service import phishing_engine

router = APIRouter(prefix="/api/v1/phishing", tags=["Cyber Threat Phishing Detector"])

@router.post("/scan", response_model=URLScanResponse)
@router.post("/scan-url", response_model=URLScanResponse)
async def scan_url(payload: URLScanRequest):
    try:
        result = phishing_engine.evaluate_url(payload.url)
        return URLScanResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

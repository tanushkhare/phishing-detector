from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.routers.phishing import router as phishing_router
import uvicorn

app = FastAPI(
    title="AI Phishing URL & Threat Detector API",
    description="Heuristic lexical parsing, entropy evaluation, and credential harvest classification.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(phishing_router)

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "phishing-detector"}

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.routers import phishing_router
import uvicorn

app = FastAPI(
    title="Phishing Threat Detection & Lexical URL Analyzer API",
    description="Shannon entropy extraction, domain reputation scoring, and heuristic phishing classification.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(phishing_router.router)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "phishing-detector"}

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)

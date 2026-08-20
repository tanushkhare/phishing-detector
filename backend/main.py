from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import phishing

app = FastAPI(title="Phishing Detection API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(phishing.router)

@app.get("/")
def read_root():
    return {"message": "Phishing Detection Backend online!"}
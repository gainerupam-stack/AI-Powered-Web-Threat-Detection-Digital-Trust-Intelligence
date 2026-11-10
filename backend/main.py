from fastapi import FastAPI
from pydantic import BaseModel
from message_analyzer import analyze_message
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException

app = FastAPI(
    title="TrustGuard AI",
    description="AI-powered scam and phishing message detection",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class MessageRequest(BaseModel):
    message: str


@app.get("/")
def home():
    return {
        "status": "online",
        "message": "TrustGuard AI backend is running"
    }


from fastapi import HTTPException

@app.post("/analyze-message")
def analyze(request: MessageRequest):
    if not request.message.strip():
        raise HTTPException(
            status_code=400,
            detail="Message cannot be empty"
        )

    result = analyze_message(request.message)

    if result["status"] == "error":
        raise HTTPException(
            status_code=502,
            detail=result["error"]
        )

    return result
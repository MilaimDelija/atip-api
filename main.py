from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers.scan import router as scan_router

app = FastAPI(
    title="ATIP — Agentic Threat Intelligence Platform",
    description="Detect bots, fake agents, and synthetic personas via URL, domain, and text analysis.",
    version="0.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)

@app.get("/")
async def root():
    return {
        "name": "ATIP API",
        "version": "0.2.0",
        "status": "operational",
        "endpoints": {
            "scan": "POST /scan",
            "quick_scan": "POST /scan/quick",
            "docs": "/docs",
        }
    }

@app.get("/health")
async def health():
    return {"status": "ok"}

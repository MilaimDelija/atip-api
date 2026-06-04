from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers.scan import router as scan_router
from app.routers.campaigns import router as campaigns_router
from app.routers.ip import router as ip_router

app = FastAPI(
    title="ATIP — Agentic Threat Intelligence Platform",
    description="Detect bots, fake agents, and synthetic personas. Track coordinated campaigns.",
    version="0.4.0",
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
app.include_router(campaigns_router)
app.include_router(ip_router)

@app.get("/")
async def root():
    return {
        "name": "ATIP API",
        "version": "0.4.0",
        "status": "operational",
        "endpoints": {
            "scan": "POST /scan",
            "quick_scan": "POST /scan/quick",
            "campaigns": "GET/POST /campaigns",
            "campaign_detail": "GET /campaigns/{id}",
            "add_entity": "POST /campaigns/{id}/entities",
            "export_evidence": "POST /campaigns/{id}/export",
            "ip_analysis": "GET /ip/{ip_address}",
            "ip_batch": "POST /ip/batch",
            "docs": "/docs",
        }
    }

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.4.0"}

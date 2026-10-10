from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import connect_to_postgres, close_postgres_connection
from app.core.config import settings
from app.routers import auth, scans, vulnerabilities, reports, assets, websockets, ai
from app.routers import history, devices, events, incidents, network
from app.routers import devsecops, monitoring, audit, risk, dashboard, findings, snid

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await connect_to_postgres()
    except Exception as error:
        logger.error(
            "Neon Postgres initialization failed (%s); database-backed routes will return 503",
            type(error).__name__,
        )
    try:
        yield
    finally:
        await close_postgres_connection()

app = FastAPI(
    title="VulnAI DevSecOps API",
    version="1.0.0",
    description="Authorized website security assessment and security monitoring API",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.frontend_origins.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(assets.router, prefix="/api/assets", tags=["Assets"])
app.include_router(history.router, prefix="/api/history", tags=["History"])
app.include_router(devices.router, prefix="/api/devices", tags=["IoT Devices"])
app.include_router(events.router, prefix="/api/events", tags=["Security Events"])
app.include_router(incidents.router, prefix="/api/incidents", tags=["Incidents"])
app.include_router(ai.router, prefix="/api/ai", tags=["AI & Risk"])
app.include_router(devsecops.router, prefix="/api/devsecops", tags=["DevSecOps"])
app.include_router(monitoring.router, prefix="/api/monitoring", tags=["Monitoring"])
app.include_router(audit.router, prefix="/api/audit", tags=["Audit"])
app.include_router(risk.router, prefix="/api/risk", tags=["Risk"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(findings.router, prefix="/api/findings", tags=["Findings"])
app.include_router(snid.router, prefix="/api/snid", tags=["SNID Wireless"])

# WebSockets
app.include_router(websockets.router, tags=["WebSockets"])

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "vulnai-backend"
    }

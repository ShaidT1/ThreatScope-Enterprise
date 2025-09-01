from fastapi import FastAPI, HTTPException, Query
from contextlib import asynccontextmanager
from typing import List
from pydantic import BaseModel
from src.database import create_tables
from src.services.database_services import DatabaseService
from src.services.threat_detection_service import ThreatDetectionService
from src.services.file_monitor_services import FileMonitoringService

# Initialize services
db_services = DatabaseService()
threat_services = ThreatDetectionService()
file_monitoring = FileMonitoringService(threat_services.process_event)


# Pydantic model for analyze endpoint
class EventAnalyzeRequest(BaseModel):
    content: str
    source_type: str = "manual"


# Lifespan context for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    await threat_services.mitre_service.load_mitre_data()
    yield
    await threat_services.geo_service.close()
    file_monitoring.stop_monitoring()


# Initialize FastAPI app
app = FastAPI(
    title="ThreatScope Enterprise",
    description="Enterprise security infrastructure platform",
    version="1.0.0",
    lifespan=lifespan
)


# Root endpoints
@app.get("/")
def get():
    return {"message": "ThreatScope Enterprise API"}


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "services": ["database", "threat_detection", "file_monitoring"]
    }


# Monitoring endpoints
@app.post("/api/monitoring/start")
async def start_monitoring(
    watch_path: str = "/tmp/alerts",
    file_type: List[str] = Query(["json", "log", "pcap"])
):
    try:
        file_type_str = ",".join(file_type)
        file_monitoring.start_monitoring(watch_path, file_type_str)
        return {"status": "watching", "folder": watch_path, "file_types": file_type}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/monitoring/stop")
async def stop_monitoring():
    file_monitoring.stop_monitoring()
    return {"status": "stopped"}


# Event analysis endpoint
@app.post("/api/events/analyze")
async def analyze_content(request: EventAnalyzeRequest):
    results = await threat_services.process_event(request.content, request.source_type)
    return results


@app.get("/api/events/recent")
async def get_recent_events(hours: int = 24, limit: int = 100):
    events = db_services.get_recent_events(hours=hours, limit=limit)
    return [
        {
            "id": event['id'],
            "ip_address": event['ip_address'],
            "threat_type": event['threat_type'],
            "severity": event['severity'],
            "score": event['score'],
            "created_at": event['created_at'],
            "country": event['country'],
            "city": event['city'],
            "mitre_id": event['mitre_id'],
            "blocked": event['blocked'],
        } for event in events
    ]


@app.get("/api/events/severity/{severity}")
async def get_events_by_severity(severity: str, limit: int = 100):
    events = db_services.get_events_by_severity(severity, limit)
    return [
        {
            "id": event.id,
            "ip_address": str(event.ip_address),
            "threat_type": event.threat_type,
            "score": event.score,
            "created_at": event.created_at.isoformat(),
            "mitre_id": event.mitre_id
        } for event in events
    ]


# Dashboard stats
@app.get("/api/stats/dashboard")
async def get_dashboard_stats():
    top_threats = db_services.get_top_threat_ips(limit=10)
    recent_critical = len(db_services.get_events_by_severity("critical", 50))
    recent_high = len(db_services.get_events_by_severity("high", 50))
    recent_medium = len(db_services.get_events_by_severity("medium", 50))

    return {
        "top_threats_ips": top_threats,
        "recent_event_by_severity": {
            "critical": recent_critical,
            "high": recent_high,
            "medium": recent_medium
        },
        "monitoring_status": "active" if file_monitoring.running else "stopped"
    }

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from contextlib import asynccontextmanager
from typing import List
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from .database import create_tables
from .services.database_services import DatabaseService
from src.services.notification_service import NotifactionService
from src.services.threat_detection_service import ThreatDetectionService
from .services.threat_intelligence_service import ThreatIntelligenceService
from .services.file_monitor_services import FileMonitoringService
from .services.automated_response_service import AutomateResponseServices
from .services.notification_service import NotifactionService
import json

db_services = DatabaseService()
threat_services = ThreatDetectionService()
file_monitoring = FileMonitoringService(threat_services.process_event)
response_services = AutomateResponseServices()
notification_services = NotifactionService()
threat_intel_services = ThreatIntelligenceService()


class EventAnalyzeRequest(BaseModel):
	content: str
	source_type: str = "manual"


@asynccontextmanager
async def lifespan(app: FastAPI):
	create_tables()
	await threat_services.mitre_service.load_mitre_data()
	yield
	await threat_services.geo_service.close()
	file_monitoring.stop_monitoring()


app = FastAPI(
	title="ThreatScope Enterprise",
	description="Enterprise security infrastructure platform",
	version="1.0.0",
	lifespan=lifespan
)


@app.get("/")
def get():
	return {"message": "ThreatScope Enterprise API"}


@app.get("/health")
def health():
	return {
		"status": "healthy",
		"services": ["database", "threat_detection", "file_monitoring"]
	}


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


@app.post("/api/events/analyze")
async def analyze_content(request: EventAnalyzeRequest):
	results = await threat_services.process_event(request.content, request.source_type)
	return results


@app.get("/api/events/recent")
async def get_recent_events(hours: int = 24, limit: int = 100):
	events = db_services.get_recent_events(hours=hours, limit=limit)
	return [
		{
			"id": event["id"],
			"ip_address": event["ip_address"],
			"threat_type": event["threat_type"],
			"severity": event["severity"],
			"score": event["score"],
			"created_at": event["created_at"],
			"country": event["country"],
			"city": event["city"],
			"mitre_id": event["mitre_id"],
			"blocked": event["blocked"],
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


@app.get("/api/response/block-ips")
def get_blocked_ip():
	return {"blocked_ips": response_services.get_blocked_ips()}


@app.post("/api/response/unblock-ip")
async def unblock_ip(ip_address: str):
	results = await response_services.unblock_ip(ip_address)
	return results


@app.get("/api/response/log")
async def get_response_log(limit: int = 50):
	return {"response_log": response_services.get_response_log(limit)}


@app.post("/api/response/execute")
async def execute_manual_response(ip_address: str, action: List[str], severity: str = "manual"):
	threat_event = {
		"ip_address": ip_address,
		"severity": severity,
		"score": 10,
		"threat_type": "manual_intervention",
		"raw_data": f"raw data request for {ip_address}"
	}
	results = await response_services.execute_response(threat_event, action)
	return results


@app.get("/api/notification/test")
async def test_notification(channels: List[str], severity: str = "high"):
	events = db_services.get_events_by_severity(severity, limit=1)
	if not events:
		raise HTTPException(status_code=404, detail="No events available for testing")

	event = events[0]
	test_event = {
		"ip_address": event.ip_address if hasattr(event, "ip_address") else event["ip_address"],
		"severity": severity,
		"score": event.score if hasattr(event, "score") else event["score"],
		"threat_type": event.threat_type if hasattr(event, "threat_type") else event["threat_type"],
		"country": getattr(event, "country", event.get("country", "")),
		"city": getattr(event, "city", event.get("city", "")),
		"mitre_id": getattr(event, "mitre_id", event.get("mitre_id", None)),
		"raw_data": str(event),
	}
	results = await notification_services.send_threat_alert(test_event, channels)
	return results


@app.get("/api/stats/security-posture")
async def get_security_posture():
	recent_events = db_services.get_recent_events(hours=24, limit=1000)
	total_events = len(recent_events)
	critical_event = len([e for e in recent_events if (e.get("severity") if isinstance(e, dict) else e.severity) == "critical"])
	high_event = len([e for e in recent_events if (e.get("severity") if isinstance(e, dict) else e.severity) == "high"])
	blocked_ips = len(response_services.get_blocked_ips())

	country_count = {}
	for event in recent_events:
		country = event.get("country") if isinstance(event, dict) else event.country
		if country:
			country_count[country] = country_count.get(country, 0) + 1

	top_countries = sorted(country_count.items(), key=lambda x: x[1], reverse=True)[:5]

	return {
		"total_events_24h": total_events,
		"critical_events_24h": critical_event,
		"high_events_24h": high_event,
		"blocked_ips_count": blocked_ips,
		"top_threat_country": top_countries,
		"response_action_taken": len(response_services.get_response_log(100)),
		"monitoring_status": "active" if file_monitoring.running else "stopped"
	}


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


# Static frontend mount
app.mount("/static", StaticFiles(directory="src/static"), name="static")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
	with open('src/static/dashboard.html', 'r') as f:
		return HTMLResponse(content=f.read())


# --- WebSocket Manager ---
class ConnectionManager:
	def __init__(self):
		self.connections: List[WebSocket] = []

	async def connect(self, websocket: WebSocket):
		await websocket.accept()
		self.connections.append(websocket)

	def disconnect(self, websocket: WebSocket):
		if websocket in self.connections:
			self.connections.remove(websocket)

	async def broadcast(self, message: dict):
		for conn in list(self.connections):
			try:
				await conn.send_text(json.dumps(message))
			except:
				self.connections.remove(conn)


manager = ConnectionManager()
threat_services = ThreatDetectionService(websocket_manger=manager)


@app.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
	await manager.connect(websocket)
	try:
		while True:
			await websocket.receive_text()
	except WebSocketDisconnect:
		manager.disconnect(websocket)
	except Exception as e:
		print(f"Dashboard websocket error: {e}")


@app.get('/api/intel/ip/{ip_address}')
async def get_intelligence_ip(ip_address: str):
	try:
		intel_data = await threat_intel_services.get_intelligence_ip(ip_address)
		return {
			'ip_address': ip_address,
			'reputation_score': intel_data.get('reputation_score', 0),
			'threat_level': threat_intel_services.get_threat_level(
				intel_data.get('reputation_score', 0)
			),
			'classification': intel_data.get('classification', []),
			'sources': list(intel_data.get('sources', {}).keys()),
			"associated_malware_count": len(intel_data.get('associated_malware', [])),
			"threat_types": intel_data.get('threat_types', [])
		}
	except Exception as e:
		raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/intel/batch-lookup")
async def batch_ip_lookup(ip_address: List[str]):
	if len(ip_address) > 10:
		raise HTTPException(status_code=400, detail='ip batch cant be greater than 10')

	results = {}
	for ip in ip_address:
		try:
			intel_data = await threat_intel_services.get_intelligence_ip(ip)
			results[ip] = {
				'reputation_score': intel_data.get('reputation_score', 0),
				'threat_type': threat_intel_services.get_threat_level(
					intel_data.get('reputation_score', 0)
				),
				'classification': intel_data.get('classification', [])
			}
		except Exception as e:
			results[ip] = {'error': str(e)}
	return {'results': results}


@app.get("/api/intel/stats")
async def get_intel_stats():
	recent_events = db_services.get_recent_events(hours=24, limit=1000)

	enriched_events = 0
	reps_banned = 0
	intel_source_stats = {}

	for event in recent_events:
		if hasattr(event, 'event_metadata') and event.event_metadata:
			threat_intel = event.event_metadata.get('threat_intelligence', {})
			if threat_intel.get('reputation_score', 0) > 5:
				enriched_events += 1

				if threat_intel.get('reputation_score', 0) >= 50 and event.blocked:
					reps_banned += 1

				for source in threat_intel.get('sources_consulted', []):
					intel_source_stats[source] = intel_source_stats.get(source, 0) + 1

	return {
		'total_events_24h': len(recent_events),
		'enriched_events': enriched_events,
		'enriched_rate': round(enriched_events / len(recent_events) * 100, 1) if recent_events else 0,
		"high_reputation_blocked": reps_banned,
		"intelligence_source": intel_source_stats,
		"cache_size": len(threat_intel_services.intel_cache)
	}

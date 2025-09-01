from sqlalchemy.orm import Session
from sqlalchemy import and_, desc, func
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import ipaddress
import logging

from ..models.threat_event import ThreatEvent
from ..database import get_db_session

logger = logging.getLogger(__name__)

class DatabaseService:
    def create_threat_event(self, event_data: Dict[str, Any]) -> int:
        with get_db_session() as db:
            threat_event = ThreatEvent(
              ip_address=event_data.get('ip_address'),
              threat_type=event_data.get('threat_type'),
              severity=event_data.get('severity'),
              score=event_data.get('score', 0),
              seen_before=event_data.get('seen_before', False),
              country=event_data.get('country'),
              city=event_data.get('city'),
              organization=event_data.get('organization'),
              latitude=event_data.get('latitude'),
              longitude=event_data.get('longitude'),
              mitre_technique=event_data.get('mitre_technique'),
              mitre_id=event_data.get('mitre_id'),
              raw_data=event_data.get('raw_data'),
              event_metadata=event_data.get('metadata', {}),
              source_type=event_data.get('source_type'),
              blocked=event_data.get('blocked', False),
              notified=event_data.get('notified', False)
            )
            db.add(threat_event)
            db.commit()
            db.refresh(threat_event)
            return threat_event.id 
    
    
    def get_events_by_severity(self, severity: str, limit: int = 100) -> List[ThreatEvent]:
        """Get threat events by severity level"""
        with get_db_session() as db:
            return db.query(ThreatEvent)\
                     .filter(ThreatEvent.severity == severity.lower())\
                     .order_by(desc(ThreatEvent.created_at))\
                     .limit(limit)\
                     .all()
    
    def get_recent_events(self, hours: int = 24, limit: int = 100) -> List[Dict]:
        since = datetime.utcnow() - timedelta(hours=hours)
        with get_db_session() as db:
            results = db.query(ThreatEvent)\
                    .filter(ThreatEvent.created_at >= since)\
                    .order_by(desc(ThreatEvent.created_at))\
                    .limit(limit)\
                    .all()
            return [
               {
                "id": event.id,
                "ip_address": str(event.ip_address),
                "threat_type": event.threat_type,
                "severity": event.severity,
                "score": event.score,
                "created_at": event.created_at.isoformat(),
                "country": event.country,
                "city": event.city,
                "mitre_id": event.mitre_id,
                "blocked": event.blocked,
            }
            for event in results
        ]
    
    def check_ip_seen_before(self, ip_address: str, minutes: int = 10) -> bool:
        """Check if IP has been seen in the last N minutes"""
        since = datetime.utcnow() - timedelta(minutes=minutes)
        with get_db_session() as db:
            count = db.query(ThreatEvent)\
                     .filter(and_(
                         ThreatEvent.ip_address == ip_address,
                         ThreatEvent.created_at >= since
                     ))\
                     .count()
            return count >= 3
    
    def get_top_threat_ips(self, limit: int = 10) -> List[Dict]:
        """Get top threatening IP addresses by score"""
        with get_db_session() as db:
            results = db.query(
                ThreatEvent.ip_address,
                func.count(ThreatEvent.id).label('event_count'),
                func.max(ThreatEvent.score).label('max_score'),
                func.max(ThreatEvent.created_at).label('last_seen')
            ).group_by(ThreatEvent.ip_address)\
             .order_by(desc('max_score'))\
             .limit(limit)\
             .all()
            
            return [
                {
                    'ip_address': str(result.ip_address),
                    'event_count': result.event_count,
                    'max_score': result.max_score,
                    'last_seen': result.last_seen.isoformat()
                }
                for result in results
            ]
            
    def update_event(self, event_id: int, updates: Dict[str, any]) -> None:
	    with get_db_session() as db:
		    db.query(ThreatEvent).filter(ThreatEvent.id == event_id).update(updates)
		    db.commit()
			
			
		



		

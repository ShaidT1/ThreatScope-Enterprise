from sqlalchemy import Column, Integer, String, Boolean, Text, Float, Index
from sqlalchemy.dialects.postgresql import INET, JSONB
from .base import Base, TimestampMixin

class ThreatEvent(Base, TimestampMixin):
    __tablename__ = "threat_events"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(INET, nullable=False, index=True)
    threat_type = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False, index=True)
    score = Column(Integer, nullable=False, default=0)
    seen_before = Column(Boolean, default=False)
    
    # Geo data
    country = Column(String(5))
    city = Column(String(100))
    organization = Column(String(255))
    latitude = Column(Float)
    longitude = Column(Float)
    
    # MITRE ATT&CK
    mitre_technique = Column(String(100))
    mitre_id = Column(String(20))
    
    # Raw data and metadata
    raw_data = Column(Text)
    event_metadata = Column(JSONB)
    source_type = Column(String(50))  # 'log', 'pcap', 'json'
    
    # Response actions taken
    blocked = Column(Boolean, default=False)
    notified = Column(Boolean, default=False)
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_threat_events_ip_severity', 'ip_address', 'severity'),
        Index('idx_threat_events_created_at', 'created_at'),
        Index('idx_threat_events_score', 'score'),
    )

# File: src/services/threat_detection_service.py

import ipaddress
import re
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import subprocess

from .geo_intelligence_service import GeointelligenceServices
from .mitre_service import MitreService
from .database_services import DatabaseService

logger = logging.getLogger(__name__)
seen_ip = set()


def ban(ip: str):
    cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
    try:
        subprocess.run(cmd, shell=True, check=True)
        logger.info(f"Banned IP {ip}")
    except Exception as e:
        logger.error(f"Failed to ban IP {ip}: {e}")


class ThreatDetectionService:
    def __init__(self):
        self.geo_service = GeointelligenceServices()
        self.mitre_service = MitreService()
        self.database_service = DatabaseService()

        self.keyword = [
            r"bash.*-i",
            r"nc.*-c",
            r"wget.*http",
            r"curl.*http",
            r"base64.*-d",
            r"socat.*tcp",
            r"python.*-c",
            r"powershell.*-enc",
        ]
        self.bad_countries = {"russia", "ukrain", "china", "iran", "north korea"}
        self.bad_isp = {"unkown", "anonymous", "vpn", "proxy"}

    def extract_ip(self, content: str) -> Optional[str]:
        """Extract the first IP address found in the content"""
        if isinstance(content, dict):
            for v in content.values():
                if isinstance(v, str):
                    m = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", v)
                    if m:
                        ip = m.group(0)
                        try:
                            ipaddress.ip_address(ip)
                            return ip
                        except Exception:
                            continue
        elif isinstance(content, str):
            m = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", content)
            if m:
                ip = m.group(0)
                try:
                    ipaddress.ip_address(ip)
                    return ip
                except Exception:
                    pass
        return None

    def calc_threat_score(self, content: str, geo: Dict) -> Tuple[int, List[str]]:
        score = 0
        threats = []

        for pattern in self.keyword:
            if re.search(pattern, content, re.IGNORECASE):
                if "bash -i" in content or "base64 -d" in content:
                    score += 5
                    threats.append("reverse shell")
                if "nc -e" in content or "socat" in content:
                    score += 5
                    threats.append("backdoor")
                if "wget" in content or "curl" in content:
                    score += 5
                    threats.append("file download")

        country = geo.get("country", "")
        isp = geo.get("isp", "")

        if country.lower() in self.bad_countries:
            score += 5
            threats.append("bad country")
        if isp.lower() in self.bad_isp:
            score += 5
            threats.append("bad isp")

        return score, threats

    def cal_severity(self, score: int) -> str:
        if score >= 15:
            return "critical"
        if score >= 10:
            return "high"
        if score >= 5:
            return "mid"
        return "low"

    async def process_event(self, content: str, source_type: str = "manual") -> Dict:
        try:
            ip = self.extract_ip(content) or "0.0.0.0"

            geo = await self.geo_service.get_geo(ip)
            seen_before = self.database_service.check_ip_seen_before(ip, minutes=10)

            score, threat_types = self.calc_threat_score(content, geo)

            mitre_data = self.mitre_service.lookup_technique(content)
            if mitre_data:
                score += 5
                threat_types.append(mitre_data.get("name", "unknown"))

            severity = self.cal_severity(score)

            event_data = {
                "ip_address": ip,
                "threat_type": ", ".join(threat_types) if threat_types else "unknown",
                "severity": severity,
                "score": score,
                "seen_before": seen_before,
                "country": geo.get("country"),
                "city": geo.get("city"),
                "organization": geo.get("isp"),
                "latitude": geo.get("latitude"),
                "longitude": geo.get("longitude"),
                "mitre_technique": mitre_data.get("name") if mitre_data else None,
                "mitre_id": mitre_data.get("id") if mitre_data else None,
                "raw_data": content[:1000],
                "source_type": source_type,
                "blocked": False,
                "notified": False,
            }

            threat_event_id = self.database_service.create_threat_event(event_data)
			
            banned = False
            if score >= 5 and ip not in seen_ip:
                ban(ip)
                banned = True
                seen_ip.add(ip)
                self.database_service.update_event(threat_event_id, {"blocked": True})

            return {
                "event_id": threat_event_id,
                "ip_address": ip,
                "severity": severity,
                "score": score,
                "action_taken": "banned" if banned else "logged",
            }

        except Exception as e:
            logger.error(f"Error processing event: {e}")
            return {"error": str(e)}

# File: src/services/threat_detection_service.py
from .automated_response_service import AutomateResponseServices
from .notification_service import NotifactionService
import ipaddress
import re
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Callable 
from ..config.response_playbooks import ResponsePlaybooks
import asyncio
import subprocess
from .threat_intelligence_service import ThreatIntelligenceService
from .geo_intelligence_service import GeointelligenceServices
from .mitre_service import MitreService
from .database_services import DatabaseService

logger = logging.getLogger(__name__)
seen_ip = set()


async def ban(ip: str):
    """Asynchronously ban IP using iptables."""
    cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            logger.info(f"Banned IP {ip}")
        else:
            logger.error(f"Failed to ban IP {ip}: {stderr.decode().strip()}")
    except Exception as e:
        logger.error(f"Error banning IP {ip}: {e}")


class ThreatDetectionService:
    def __init__(self, websocket_manger=None):
        self.response_service = AutomateResponseServices()
        self.notification_service = NotifactionService()
        self.geo_service = GeointelligenceServices()
        self.mitre_service = MitreService()
        self.database_service = DatabaseService()
        self.websocket_Connect = websocket_manger
        self.threat_intel_services = ThreatIntelligenceService()

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
        self.bad_countries = {"russia", "ukraine", "china", "iran", "north korea"}
        self.bad_isp = {"unknown", "anonymous", "vpn", "proxy"}

    def extract_ip(self, content: str) -> Optional[str]:
        """Extract the first IP address found in the content."""
        if isinstance(content, dict):
            for v in content.values():
                if isinstance(v, str):
                    m = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", v)
                    if m:
                        ip = m.group(0)
                        try:
                            ipaddress.ip_address(ip)
                            return ip
                        except ValueError:
                            continue
        elif isinstance(content, str):
            m = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", content)
            if m:
                ip = m.group(0)
                try:
                    ipaddress.ip_address(ip)
                    return ip
                except ValueError:
                    pass
        return None

    def calc_threat_score(self, content: str, geo: Dict, threat_intel: Dict = None) -> Tuple[int, List[str]]:
        score = 0
        threats = []

        # Keyword-based detection
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

        # Geo/ISP checks
        country = geo.get("country", "")
        isp = geo.get("isp", "")

        if country.lower() in self.bad_countries:
            score += 5
            threats.append("bad country")
        if isp.lower() in self.bad_isp:
            score += 5
            threats.append("bad isp")

        # Threat intel scoring (fixed indentation + dead code)
        if threat_intel:
            rep_score = threat_intel.get("reputation_score", 0)
            if rep_score >= 75:
                score += 25
                threats.append("known malicious ip")
            elif rep_score >= 50:
                score += 15
                threats.append("suspicious ip")
            elif rep_score >= 25:
                score += 5
                threats.append("questionable ip")

            classification = threat_intel.get("classifications", [])
            if classification:
                if "malicious_ip" in classification:
                    threats.append("virustotal detected malicious ip")
                if "reported_abusive" in classification:
                    threats.append("virustotal detected abuseIPDB")

            malware_list = threat_intel.get("associated_malware", [])
            malware_count = len(malware_list)
            if malware_count > 0:
                score += min(malware_count * 3, 15)  # up to 15 points
                threats.append(f"associated with {malware_count} malware sample(s)")

        return score, threats

    def calc_severity(self, score: int) -> str:
        if score >= 15:
            return "critical"
        if score >= 10:
            return "high"
        if score >= 5:
            return "medium"
        return "low"

    async def process_event(self, content: str, source_type: str = "manual") -> Dict:
        try:
            banned = False
            ip = self.extract_ip(content) or "0.0.0.0"
            blocked_ips = set()
            geo = await self.geo_service.get_geo(ip)

            threat_intel = await self.threat_intel_services.get_intelligence_ip(ip)
            logger.info(f"Threat Intel for: {ip}\nScore: {threat_intel.get('reputation_score', 0)}")

            seen_before = self.database_service.check_ip_seen_before(ip, minutes=10)

            score, threat_types = self.calc_threat_score(content, geo, threat_intel)

            mitre_data = self.mitre_service.lookup_technique(content)
            if mitre_data:
                score += 5
                threat_types.append(mitre_data.get("name", "unknown"))

            severity = self.calc_severity(score)

            # Response actions
            response_actions = self._determine_response_action(severity, ", ".join(threat_types), score)
            if response_actions:
                await self.response_service.execute_response(
                    {
                        "ip_address": ip,
                        "severity": severity,
                        "score": score,
                        "threat_type": ", ".join(threat_types),
                        "raw_data": content,
                    },
                    response_actions,
                )

            # Notifications
            if score >= 10:
                notification_channels = self._get_notification_channel(severity, ", ".join(threat_types), score)
                if notification_channels:
                    await self.notification_service.send_threat_alert(
                        {
                            "ip_address": ip,
                            "score": score,
                            "threat_type": ", ".join(threat_types),
                            "country": geo.get("country", ""),
                            "city": geo.get("city", ""),
                            "mitre_id": mitre_data["id"] if mitre_data else None,
                            "raw_data": content,
                        },
                        notification_channels,
                        severity_threshold="medium",
                    )

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
                "blocked": True if banned else False,
                "notified": True if score >= 10 else False,
                "event_metadata": {
						"threat_intelligence": {
							"reputation_score": threat_intel.get("reputation_score", 0) if threat_intel else 0,
							"classifications": threat_intel.get("classifications", []) if threat_intel else [],
							"threat_types": threat_intel.get("threat_types", []) if threat_intel else [],
							"sources_consulted": list(threat_intel.get("sources", {}).keys()) if threat_intel else [],
							"malware_consulted": len(threat_intel.get("associated_malware", [])) if threat_intel else 0,
							
						},
						"enrichment_timestamp": datetime.now().isoformat(),
				}			

            }

            threat_event_id = self.database_service.create_threat_event(event_data)

            if score >= 5 and ip not in seen_ip:
                await ban(ip)
                banned = True
                seen_ip.add(ip)
                blocked_ips.add(ip)
                self.database_service.update_event(threat_event_id, {"blocked": True})

            if self.websocket_Connect:
                dashboard_updates = {
                    "type": "new_threat",
                    "event": {
                        "event_id": threat_event_id,
                        "ip_address": ip,
                        "severity": severity,
                        "score": score,
                        "threat_type": ", ".join(threat_types) if threat_types else None,
                        "country": geo.get("country"),
                        "city": geo.get("city"),
                        "created_at": datetime.now().isoformat(),
                        "mitre_id": mitre_data["id"] if mitre_data else None,
                    },
                    "stats": {
                        "total_events_today": score,
                        "blocked_ips": list(blocked_ips),
                    },
                }
                try:
                    # add dashboard_updates to websocket for frontend
                    asyncio.create_task(self.websocket_Connect.broadcast(dashboard_updates))
                except Exception as e:
                    logger.error(e)

            return {
                "event_id": threat_event_id,
                "ip_address": ip,
                "severity": severity,
                "score": score,
                "action_taken": "banned" if banned else "logged",
            }

        except Exception as e:
            logger.exception(f"Error processing event: {e}")
            return {"error": str(e)}

    def _determine_response_action(self, severity: str, threat_type: str, score: int) -> List[str]:
        playbook = ResponsePlaybooks.get_playbook(severity, threat_type, score)

        if "actions" in playbook:
            return playbook["actions"]
        if "collection_evidence" in playbook:
            return playbook["collection_evidence"]

        return []

    def _get_notification_channel(self, severity: str, threat_type: str, score: int) -> List[str]:
        playbook = ResponsePlaybooks.get_playbook(severity, threat_type, score)
        return playbook["notification_channels"]

from typing import Dict
from enum import Enum


class ThreatType(Enum):
    REVERSE_SHELL = "reverse_shell"
    MALWARE_DOWNLOAD = "malware_download"
    BACKDOOR = "backdoor"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    BRUTE_FORCE = "brute_force"
    UNKNOWN = "unknown"


class ResponsePlaybooks:
    PLAYBOOK = {
        ThreatType.REVERSE_SHELL: {
            "immediate_actions": ["block_ip", "collect_evidence"],
            "escalation_actions": ["isolate_network", "quarantine_process"],
            "notification_channels": ["slack", "email", "teams"],
            "severity_threshold": 10,
            "auto_execute": True,
        },
        ThreatType.MALWARE_DOWNLOAD: {
            "immediate_actions": ["block_ip", "create_firewall_rule"],
            "escalation_actions": ["isolate_network", "collect_evidence"],
            "notification_channels": ["slack", "email"],
            "severity_threshold": 8,
            "auto_execute": True,
        },
        ThreatType.BACKDOOR: {
            "immediate_actions": ["block_ip", "collect_evidence", "quarantine_process"],
            "escalation_actions": ["isolate_network"],
            "notification_channels": ["slack", "email", "sms", "teams"],
            "severity_threshold": 12,
            "auto_execute": True,
        },
        ThreatType.BRUTE_FORCE: {
            "immediate_actions": ["create_firewall_rule"],
            "escalation_actions": ["block_ip"],
            "notification_channels": ["slack"],
            "severity_threshold": 5,
            "auto_execute": True,
        },
        ThreatType.UNKNOWN: {
            "immediate_actions": ["collect_evidence"],
            "escalation_actions": ["block_ip"],
            "notification_channels": ["slack"],
            "severity_threshold": 8,
            "auto_execute": False,
        },
    }

    @classmethod
    def get_playbook(cls, threat_type: str, severity: str, score: int) -> Dict:
        threat_enum = cls._map_threat_type(threat_type)
        playbook = cls.PLAYBOOK[threat_enum]

        actions = []
        if score >= playbook["severity_threshold"]:
            actions.extend(playbook["immediate_actions"])
        if score >= 15:
            actions.extend(playbook["escalation_actions"])

        return {
            "actions": list(set(actions)),
            "notification_channels": playbook["notification_channels"],
            "auto_execute": playbook["auto_execute"],
            "playbook_type": threat_enum.value,
        }

    @classmethod
    def _map_threat_type(cls, threat_type: str) -> ThreatType:
        t = threat_type.lower()
        if "bash" in t or "base64" in t:
            return ThreatType.REVERSE_SHELL
        if "download" in t or "curl" in t or "wget" in t:
            return ThreatType.MALWARE_DOWNLOAD
        if "socat" in t or "nc" in t:
            return ThreatType.BACKDOOR
        if "brute" in t or "failed" in t:
            return ThreatType.BRUTE_FORCE
        if "lateral" in t or "movement" in t:
            return ThreatType.LATERAL_MOVEMENT
        if "exfil" in t or "data" in t:
            return ThreatType.DATA_EXFILTRATION
        return ThreatType.UNKNOWN

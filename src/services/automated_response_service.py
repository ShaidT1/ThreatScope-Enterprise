import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional
import json
import os

try:
    import aiofiles  # async file I/O
except ImportError:
    aiofiles = None  # handle gracefully in collect_evidence

logger = logging.getLogger(__name__)


class AutomateResponseServices:
    def __init__(self):
        self.blocked_ip = set()
        self.response_log: List[Dict] = []
        self.max_log_entry = 1000

    async def execute_response(self, threat_event: Dict, response_actions: List[str]) -> Dict:
        """
        Valid actions:
          - 'block_ip'
          - 'unblock_ip'
          - 'create_firewall_rule'
          - 'collect_evidence'
          - 'isolate_network'
          - 'quarantine_process'
        """
        results: Dict[str, Dict] = {}

        for action in response_actions:
            try:
                if action == "block_ip":
                    results[action] = await self._block_ip(threat_event.get("ip_address"))
                elif action == "unblock_ip":
                    results[action] = await self.unblock_ip(threat_event.get("ip_address"))
                elif action == "create_firewall_rule":
                    results[action] = await self._create_firewall_rule(threat_event)
                elif action == "collect_evidence":
                    results[action] = await self.collect_evidence(threat_event)
                elif action == "isolate_network":
                    results[action] = await self._isolate_network(threat_event)
                elif action == "quarantine_process":
                    results[action] = await self._quarantine_process(threat_event)
                else:
                    results[action] = {"status": "unknown_action", "success": False, "error": f"Unknown: {action}"}
            except Exception as e:
                logger.exception("Action '%s' failed", action)
                results[action] = {"status": "error", "success": False, "error": str(e)}

        self._log_response(threat_event, results)
        return results

    # -------------------------
    # Network/Firewall actions
    # -------------------------

    async def _block_ip(self, ip_address: Optional[str]) -> Dict:
        if not ip_address:
            return {"status": "invalid_ip", "success": False, "error": "ip_address missing"}

        if ip_address in self.blocked_ip:
            return {"status": "already_blocked", "success": True}

        # Insert DROP rule
        cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode == 0:
                self.blocked_ip.add(ip_address)
                logger.info("Blocked IP %s", ip_address)
                return {"status": "blocked", "success": True, "rule": " ".join(cmd)}
            else:
                return {
                    "status": "failed",
                    "success": False,
                    "error": (stderr.decode() if stderr else "unknown"),
                    "cmd": " ".join(cmd),
                }
        except FileNotFoundError:
            # iptables not present (e.g., dev box). Simulate.
            self.blocked_ip.add(ip_address)
            return {"status": "simulated_block", "success": True, "note": "iptables not found"}

    async def unblock_ip(self, ip_address: Optional[str]) -> Dict:
        if not ip_address:
            return {"status": "invalid_ip", "success": False, "error": "ip_address missing"}

        if ip_address not in self.blocked_ip:
            return {"status": "not_blocked", "success": True}

        # Delete the matching DROP rule
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode == 0:
                self.blocked_ip.discard(ip_address)
                logger.info("Unblocked IP %s", ip_address)
                return {"status": "unblocked", "success": True, "rule": " ".join(cmd)}
            else:
                return {
                    "status": "failed",
                    "success": False,
                    "error": (stderr.decode() if stderr else "unknown"),
                    "cmd": " ".join(cmd),
                }
        except FileNotFoundError:
            # Simulate on systems without iptables
            self.blocked_ip.discard(ip_address)
            return {"status": "simulated_unblock", "success": True, "note": "iptables not found"}

    async def _create_firewall_rule(self, threat_event: Dict) -> Dict:
        ip_address = threat_event.get("ip_address")
        if not ip_address:
            return {"status": "invalid_ip", "success": False, "error": "ip_address missing"}

        severity = (threat_event.get("severity") or "medium").lower()
        if severity == "critical":
            rule = f"sudo iptables -I INPUT -s {ip_address} -j REJECT --reject-with icmp-host-prohibited"
        elif severity == "high":
            # iptables does not support multiple ports in one --dport value with commas.
            # Apply a DROP for common sensitive ports individually.
            rules = [
                f"sudo iptables -I INPUT -s {ip_address} -p tcp --dport 22 -j DROP",
                f"sudo iptables -I INPUT -s {ip_address} -p tcp --dport 80 -j DROP",
                f"sudo iptables -I INPUT -s {ip_address} -p tcp --dport 443 -j DROP",
            ]
            return await self._apply_multiple_rules(rules)
        else:
            # rate-limit ACCEPT example (might be better as limit+LOG in real life)
            rule = f"sudo iptables -I INPUT -s {ip_address} -m limit --limit 10/min -j ACCEPT"

        return await self._apply_rule(rule)

    async def _apply_rule(self, rule: str) -> Dict:
        try:
            process = await asyncio.create_subprocess_exec(
                *rule.split(), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode == 0:
                return {"status": "rule_created", "success": True, "rule": rule}
            else:
                return {
                    "status": "failed",
                    "success": False,
                    "error": (stderr.decode() if stderr else "unknown"),
                    "rule": rule,
                }
        except FileNotFoundError:
            return {"status": "simulated", "success": True, "rule": rule, "note": "iptables not found"}

    async def _apply_multiple_rules(self, rules: List[str]) -> Dict:
        results = []
        for r in rules:
            res = await self._apply_rule(r)
            results.append(res)
        success = all(x.get("success") for x in results)
        return {"status": "rules_created" if success else "partial_failure", "success": success, "results": results}

    async def _isolate_network(self, threat_event: Dict) -> Dict:
        ip_address = threat_event.get("ip_address")
        if not ip_address:
            return {"status": "invalid_ip", "success": False, "error": "ip_address missing"}

        rules = [
            f"sudo iptables -I INPUT -s {ip_address} -j LOG --log-prefix ISOLATED:",
            f"sudo iptables -I INPUT -s {ip_address} -j DROP",
            f"sudo iptables -I OUTPUT -d {ip_address} -j DROP",
        ]
        result = await self._apply_multiple_rules(rules)
        result["status"] = "isolation_applied" if result["success"] else "isolation_failed"
        return result

    # -------------------------
    # Host actions
    # -------------------------

    async def collect_evidence(self, threat_event: Dict) -> Dict:
        """
        Collects basic runtime evidence into /tmp/evidence/{ip}_{timestamp}
        Files: net.txt (ss/netstat), ps.txt, iptables.txt, event.json
        """
        ip = threat_event.get("ip_address", "unknown")
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        event_dir = f"/tmp/evidence/{ip}_{ts}"

        try:
            os.makedirs(event_dir, exist_ok=True)

            files = []

            # Network connections (prefer ss)
            net_file = os.path.join(event_dir, "net.txt")
            cmd_net = ["ss", "-tunap"]
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd_net, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
            except FileNotFoundError:
                # fallback to netstat if ss is not present
                process = await asyncio.create_subprocess_exec(
                    "netstat", "-anp", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
            stdout, _ = await process.communicate()
            if aiofiles:
                async with aiofiles.open(net_file, "wb") as f:
                    await f.write(stdout or b"")
            else:
                with open(net_file, "wb") as f:
                    f.write(stdout or b"")
            files.append(net_file)

            # Process list
            ps_file = os.path.join(event_dir, "ps.txt")
            process = await asyncio.create_subprocess_exec(
                "ps", "aux", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            if aiofiles:
                async with aiofiles.open(ps_file, "wb") as f:
                    await f.write(stdout or b"")
            else:
                with open(ps_file, "wb") as f:
                    f.write(stdout or b"")
            files.append(ps_file)

            # iptables snapshot
            ipt_file = os.path.join(event_dir, "iptables.txt")
            try:
                process = await asyncio.create_subprocess_exec(
                    "sudo", "iptables", "-S", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
            except FileNotFoundError:
                stdout = b"iptables not found"
            if aiofiles:
                async with aiofiles.open(ipt_file, "wb") as f:
                    await f.write(stdout or b"")
            else:
                with open(ipt_file, "wb") as f:
                    f.write(stdout or b"")
            files.append(ipt_file)

            # Event JSON
            event_file = os.path.join(event_dir, "threat_event.json")
            event_bytes = json.dumps(threat_event, indent=2, default=str).encode()
            if aiofiles:
                async with aiofiles.open(event_file, "wb") as f:
                    await f.write(event_bytes)
            else:
                with open(event_file, "wb") as f:
                    f.write(event_bytes)
            files.append(event_file)

            return {
                "status": "evidence_collected",
                "success": True,
                "evidence_dir": event_dir,
                "files": files,
            }
        except Exception as e:
            logger.exception("Evidence collection failed")
            return {"status": "collection_failed", "success": False, "error": str(e)}

    async def _quarantine_process(self, threat_event: Dict) -> Dict:
        """
        Simulation only. Scans raw_data for suspicious process indicators.
        Replace with real process isolation (e.g., kill, cgroup, SELinux policy) in production.
        """
        try:
            raw = (threat_event.get("raw_data") or "").lower()
            indicators = ["nc", "wget", "curl", "powershell", "bash", "socat", "base64", "python"]
            hits = [i for i in indicators if i in raw]

            # Example "actions" you would take (simulated)
            simulated = [f"would_quarantine_processes_matching:{i}" for i in hits]

            return {
                "status": "quarantine_simulated",
                "success": True,
                "quarantine_actions": simulated,
                "note": "simulation only",
            }
        except Exception as e:
            return {"status": "quarantine_failed", "success": False, "error": str(e)}

    # -------------------------
    # Logging / Introspection
    # -------------------------

    def _log_response(self, threat_event: Dict, results: Dict):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event_id": threat_event.get("event_id"),
            "ip_address": threat_event.get("ip_address"),
            "severity": threat_event.get("severity"),
            "actions": results,
        }
        self.response_log.append(entry)
        if len(self.response_log) > self.max_log_entry:
            self.response_log = self.response_log[-self.max_log_entry :]

    def get_response_log(self, limit: int = 100) -> List[Dict]:
        return self.response_log[-limit:]

    def get_blocked_ips(self) -> List[str]:
        return list(self.blocked_ip)
        

import asyncio
import aiohttp
import smtplib
import os
from typing import Dict, List
import logging
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

class NotifactionService:
    def __init__(self):
        # Fixed typo: should be 'notification_channels' and assign a dictionary
        self.notification_channels = {
            'email': self._send_email,
            'slack': self._send_slack,
            'webhook': self._send_webhook,
            'sms': self._send_sms
        }

    async def send_threat_alert(self, threat_event: Dict, channels: List[str], severity_threshold: str = 'medium') -> Dict:
        severity_level = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        event_severity = threat_event.get("severity", "low")
        threshold_level = severity_level.get(severity_threshold, 2)
        event_level = severity_level.get(event_severity, 1)

        if event_level < threshold_level:
            return {"status": "failed", "reason": "below threshold"}

        results = {}
        for channel in channels:
            if channel in self.notification_channels:
                try:
                    func = self.notification_channels[channel]
                    res = await func(threat_event)
                    results[channel] = res
                except Exception as e:
                    results[channel] = {"status": False, "error": str(e)}
        return results

    async def _send_email(self, threat_event: Dict) -> Dict:
        try:
            smtp_server = os.getenv("SMTP")
            smtp_port = int(os.getenv("SMTP_PORT", 587))
            email_user = os.getenv("EMAIL")
            email_password = os.getenv("PASSWORD")
            recipients = [email_user, 'soc@gmail.com']

            msg = MIMEMultipart()
            msg['From'] = email_user
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f'Alert: Severity: {threat_event.get("severity", "UNKNOWN")} | IP: {threat_event.get("ip_address", "0.0.0.0")}'

            body = self._create_email_body(threat_event)
            msg.attach(MIMEText(body, 'html'))

            # For now, just log instead of sending
            logger.info(f'Email ready to send to {recipients} for IP {threat_event.get("ip_address")}')
            return {"status": True, "recipients": recipients, "subject": msg['Subject']}
        except Exception as e:
            return {"status": False, "error": str(e)}

    async def _send_slack(self, threat_event: Dict) -> Dict:
        try:
            webhook = "http://hooks.slack.com/services/YOUR/WEBHOOK/URL"
            slack_message = {
                "text": f"Security Alert: {threat_event.get('severity', 'low').upper()}",
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"Security Threat Detected: {threat_event.get('severity', 'low')}"}
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*IP Address:*\n{threat_event.get('ip_address', '0.0.0.0')}"},
                            {"type": "mrkdwn", "text": f"*Threat Score:*\n{threat_event.get('score', 0)}"},
                            {"type": "mrkdwn", "text": f"*Country:*\n{threat_event.get('country', 'unknown')}"},
                            {"type": "mrkdwn", "text": f"*Threat Type:*\n{threat_event.get('threat_type', 'unknown')}"}
                        ]
                    },
                    {
                        "type": "context",
                        "elements": [{"type": "mrkdwn", "text": f"*Datetime:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}]
                    }
                ]
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(webhook, json=slack_message) as resp:
                    if resp.status == 200:
                        return {"status": True, "channel": "slack"}
                    else:
                        return {"status": False, "error": f"Slack API returned {resp.status}"}
        except Exception as e:
            return {"status": False, "error": str(e)}

    async def _send_webhook(self, threat_event: Dict) -> Dict:
        try:
            webhook = "https://your-custom-endpoint.com/webhook"
            payload = {
                "alert_type": "security_threat",
                "severity": threat_event.get("severity"),
                "timestamp": datetime.now().isoformat(),
                "event": threat_event
            }
            logger.info(f"Webhook notification prepared: {threat_event.get('severity')}")
            return {"status": "sent webhook", "channel": "webhook", "payload": payload}
        except Exception as e:
            return {"status": "failed webhook", "error": str(e)}

    async def _send_sms(self, threat_event: Dict) -> Dict:
        try:
            if threat_event.get("severity") != "critical":
                return {"status": False, "error": "SMS only sent for critical severity"}
            message = f"CRITICAL security: {threat_event.get('ip_address')} | Threat: {threat_event.get('threat_type')} | Score: {threat_event.get('score')}"
            logger.warning(f"SMS prepared: {message}")
            return {"status": True, "channel": "sms", "message": message}
        except Exception as e:
            return {"status": False, "error": str(e)}

    def _create_email_body(self, threat_event: Dict) -> str:
        return f"""
        <html>
        <body style='font-family: Arial, sans-serif;'>
            <div style='background-color: {self._get_severity_color(threat_event.get("severity", ""))}; padding: 10px; color: white; border-radius: 10px;'>
                <h2>Security Threat Detected: {threat_event.get("severity", "")}</h2>
            </div>
            <div style="padding: 10px;">
                <h3>Details</h3>
                <table style="border-collapse: collapse; width: 100%;">
                    <tr><td><strong>IP</strong></td><td>{threat_event.get("ip_address", "")}</td></tr>
                    <tr><td><strong>SCORE</strong></td><td>{threat_event.get("score", 0)}</td></tr>
                    <tr><td><strong>Threat</strong></td><td>{threat_event.get("threat_type", "")}</td></tr>
                    <tr><td><strong>Country</strong></td><td>{threat_event.get("country", "")}</td></tr>
                    <tr><td><strong>Mitre Id</strong></td><td>{threat_event.get("mitre_id", "")}</td></tr>
                    <tr><td><strong>Detection Time</strong></td><td>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</td></tr>
                </table>
                <h3>Raw Data</h3>
                <div style="background-color: #f5f5f5; padding: 10px; border-radius: 3px; font-family: monospace;">
                    {threat_event.get("raw_data", "No raw data")[:500]}
                </div>
            </div>
        </body>
        </html>
        """

    def _get_severity_color(self, severity: str) -> str:
        color = {
            "low": 'green',
            "medium": 'yellow',
            "high": 'orange',
            "critical": 'red'
        }
        return color.get(severity.lower(), '#6c757d')

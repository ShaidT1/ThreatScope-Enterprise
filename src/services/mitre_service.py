import aiohttp
from typing import Optional, Dict
import logging

logger = logging.getLogger(__name__)

class MitreService:
    def __init__(self):
        self.techniques: Dict[str, Dict] = {}
        self.loaded = False

    async def load_mitre_data(self):
        if self.loaded:
            return

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://attack.mitre.org/techniques/enterprise/attack-patterns.json",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        objects = data.get("objects", [])
                        for obj in objects:
                            if obj.get("type") == "attack-pattern":
                                name = obj.get("name", "").lower()
                                for ref in obj.get("external_references", []):
                                    if ref.get("source_name") == "mitre-attack":
                                        self.techniques[name] = {
                                            "name": obj.get("name"),
                                            "id": ref.get("external_id", ""),
                                            "description": obj.get("description", "")
                                        }
                                        break
                        self.loaded = True
                        logger.info(f"LOADED: {len(self.techniques)} MITRE techniques")
        except Exception as e:
            logger.error(f"Error loading MITRE data: {e}")

    def lookup_technique(self, content: str) -> Optional[Dict]:
        """
        Scan the content string to see if it matches any MITRE technique by name.
        Returns the technique data if found, else None.
        """
        if not self.loaded:
            return None

        content_lower = content.lower()
        for technique_name, technique_data in self.techniques.items():
            if technique_name in content_lower:
                return technique_data
        return None

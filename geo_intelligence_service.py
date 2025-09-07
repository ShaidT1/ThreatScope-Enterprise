import aiohttp
import asyncio
import logging
from typing import Dict

logger = logging.getLogger(__name__)


class GeointelligenceServices:
    def __init__(self):
        self.cache: Dict[str, Dict] = {}
        self.session: aiohttp.ClientSession | None = None

    async def get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            self.session = aiohttp.ClientSession()
        return self.session

    async def get_geo(self, ip: str) -> Dict:
        # Return cached result if available
        if ip in self.cache:
            return self.cache[ip]

        try:
            session = await self.get_session()
            async with session.get(f"https://ipapi.co/{ip}/json/", timeout=3) as response:
                if response.status == 200:
                    data = await response.json()
                    results = {
                        "country": data.get("country_name", ""),  # Correct key for country name
                        "city": data.get("city", ""),
                        "isp": data.get("org", ""),  # ipapi returns org for ISP
                        "latitude": data.get("latitude", 0),
                        "longitude": data.get("longitude", 0),
                    }
                else:
                    results = self.default_geo_data()
        except Exception as e:
            logger.error(f"Geo lookup failed for {ip}: {e}")
            results = self.default_geo_data()

        # Cache the result
        self.cache[ip] = results
        return results

    def default_geo_data(self) -> Dict:
        return {
            "country": "",
            "city": "",
            "isp": "",
            "latitude": 0,
            "longitude": 0,
        }

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None

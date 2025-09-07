import aiohttp
import asyncio
from typing import Dict, Optional, List
import logging
from datetime import datetime, timedelta
import hashlib
import json

logger = logging.getLogger(__name__)

class ThreatIntelligenceService:
    """
    Integrates with external threat intelligence sources
    to enrich IP addresses, domains, and file hashes
    """
    
    def __init__(self):
        # VirusTotal API key - you'd get this from config in production
        self.vt_api_key = "your-virustotal-api-key"  # Get free key from virustotal.com
        
        # Cache to avoid duplicate API calls (saves money and time)
        self.intel_cache = {}
        self.cache_ttl_hours = 24
        
        # Rate limiting to stay within free tier limits
        self.vt_requests_per_minute = 4  # Free tier limit
        self.vt_last_request = 0
        
    async def get_intelligence_ip(self, ip_address: str) -> Dict:
        """
        Get comprehensive threat intelligence for an IP address
        This is what makes your tool "enterprise-grade" vs basic detection
        """
        cache_key = f"ip_{ip_address}"
        
        # Check cache first - don't waste API calls on repeated lookups
        if self._is_cached_and_fresh(cache_key):
            logger.debug(f"Using cached intel for IP: {ip_address}")
            return self.intel_cache[cache_key]['data']
        
        # Initialize intelligence data structure
        intel_data = {
            'ip_address': ip_address,
            'sources': {},  # Data from each threat intel source
            'reputation_score': 0,  # 0-100, higher = more malicious
            'classifications': [],  # List of threat classifications
            'first_seen': None,
            'last_seen': None,
            'associated_malware': [],
            'threat_types': []
        }
        
        try:
            # Get VirusTotal data (primary source)
            vt_data = await self._get_virustotal_ip_report(ip_address)
            if vt_data:
                intel_data['sources']['virustotal'] = vt_data
                intel_data = self._process_virustotal_data(intel_data, vt_data)
            
            # Get AbuseIPDB data (secondary source for IP reputation)
            abuse_data = await self._get_abuseipdb_report(ip_address)
            if abuse_data:
                intel_data['sources']['abuseipdb'] = abuse_data
                intel_data = self._process_abuseipdb_data(intel_data, abuse_data)
            
            # Calculate final reputation score based on all sources
            intel_data['reputation_score'] = self._calculate_reputation_score(intel_data)
            
            # Cache the results
            self._cache_intel_data(cache_key, intel_data)
            
            logger.info(f"Enriched IP {ip_address} - Reputation: {intel_data['reputation_score']}")
            
        except Exception as e:
            logger.error(f"Failed to enrich IP intelligence for {ip_address}: {e}")
            # Return basic structure even on failure
            intel_data['error'] = str(e)
        
        return intel_data
    
    async def _get_virustotal_ip_report(self, ip_address: str) -> Optional[Dict]:
        """
        Query VirusTotal for IP reputation data
        This tells us if the IP is known malicious
        """
        # Rate limiting - respect API limits
        await self._wait_for_rate_limit()
        
        try:
            headers = {
                "x-apikey": self.vt_api_key
            }
            
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('data', {})
                    elif response.status == 404:
                        # IP not found in VT database - that's normal
                        return None
                    else:
                        logger.warning(f"VirusTotal API error {response.status} for IP {ip_address}")
                        return None
                        
        except asyncio.TimeoutError:
            logger.warning(f"VirusTotal API timeout for IP {ip_address}")
            return None
        except Exception as e:
            logger.error(f"VirusTotal API error for IP {ip_address}: {e}")
            return None
    
    async def _get_abuseipdb_report(self, ip_address: str) -> Optional[Dict]:
        """
        Query AbuseIPDB for IP abuse reports
        This is a free service that tracks malicious IPs
        """
        try:
            # AbuseIPDB free API - you can get a key at abuseipdb.com
            headers = {
                "Key": "your-abuseipdb-api-key",  # Replace with real key
                "Accept": "application/json"
            }
            
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            url = "https://api.abuseipdb.com/api/v2/check"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('data', {})
                    else:
                        logger.warning(f"AbuseIPDB API error {response.status} for IP {ip_address}")
                        return None
                        
        except Exception as e:
            logger.error(f"AbuseIPDB API error for IP {ip_address}: {e}")
            return None
    
    def _process_virustotal_data(self, intel_data: Dict, vt_data: Dict) -> Dict:
        """
        Extract relevant information from VirusTotal response
        Transform raw API data into structured threat intel
        """
        attributes = vt_data.get('attributes', {})
        
        # Get malicious verdicts from security vendors
        last_analysis = attributes.get('last_analysis_stats', {})
        malicious_count = last_analysis.get('malicious', 0)
        suspicious_count = last_analysis.get('suspicious', 0)
        total_engines = sum(last_analysis.values()) if last_analysis else 0
        
        # Add to reputation score based on vendor detections
        if total_engines > 0:
            malicious_ratio = (malicious_count + suspicious_count) / total_engines
            intel_data['reputation_score'] += int(malicious_ratio * 50)  # Up to 50 points
        
        # Extract threat classifications
        if malicious_count > 0:
            intel_data['classifications'].append('malicious_ip')
            intel_data['threat_types'].append('known_malicious')
        
        # Get reputation history
        reputation = attributes.get('reputation', 0)
        if reputation < -10:
            intel_data['classifications'].append('bad_reputation')
            intel_data['reputation_score'] += 20
        
        # Get associated malware samples
        if 'last_analysis_results' in attributes:
            for engine, result in attributes['last_analysis_results'].items():
                if result.get('category') == 'malicious' and result.get('result'):
                    intel_data['associated_malware'].append({
                        'engine': engine,
                        'detection': result.get('result')
                    })
        
        return intel_data
    
    def _process_abuseipdb_data(self, intel_data: Dict, abuse_data: Dict) -> Dict:
        """
        Extract relevant information from AbuseIPDB response
        """
        abuse_percentage = abuse_data.get('abuseConfidencePercentage', 0)
        
        # Add to reputation score based on abuse reports
        intel_data['reputation_score'] += int(abuse_percentage * 0.3)  # Up to 30 points
        
        if abuse_percentage > 25:
            intel_data['classifications'].append('reported_abusive')
            intel_data['threat_types'].append('abuse_reports')
        
        # Get usage type (datacenter, ISP, etc.)
        usage_type = abuse_data.get('usageType', '')
        if usage_type == 'datacenter':
            intel_data['threat_types'].append('datacenter_ip')
        
        # Get country info
        country = abuse_data.get('countryCode', '')
        if country:
            intel_data['country_code'] = country
        
        return intel_data
    
    def _calculate_reputation_score(self, intel_data: Dict) -> int:
        """
        Calculate final reputation score from all sources
        0 = clean, 100 = definitely malicious
        """
        score = intel_data.get('reputation_score', 0)
        
        # Cap at 100
        return min(score, 100)
    
    def _is_cached_and_fresh(self, cache_key: str) -> bool:
        """
        Check if we have fresh cached data to avoid API calls
        """
        if cache_key not in self.intel_cache:
            return False
        
        cached_time = self.intel_cache[cache_key]['timestamp']
        ttl = timedelta(hours=self.cache_ttl_hours)
        
        return datetime.now() - cached_time < ttl
    
    def _cache_intel_data(self, cache_key: str, data: Dict):
        """
        Cache intelligence data to reduce API calls
        """
        self.intel_cache[cache_key] = {
            'data': data,
            'timestamp': datetime.now()
        }
    
    async def _wait_for_rate_limit(self):
        """
        Respect API rate limits - critical for production use
        """
        now = asyncio.get_event_loop().time()
        time_since_last = now - self.vt_last_request
        min_interval = 60.0 / self.vt_requests_per_minute  # seconds between requests
        
        if time_since_last < min_interval:
            wait_time = min_interval - time_since_last
            logger.debug(f"Rate limiting: waiting {wait_time:.2f} seconds")
            await asyncio.sleep(wait_time)
        
        self.vt_last_request = asyncio.get_event_loop().time()
    
    def get_threat_level(self, reputation_score: int) -> str:
        """
        Convert reputation score to threat level
        """
        if reputation_score >= 75:
            return "critical"
        elif reputation_score >= 50:
            return "high"
        elif reputation_score >= 25:
            return "medium"
        else:
            return "low"

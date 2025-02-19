import aiohttp
import logging
from src.core.config import settings
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class CrowdSecService:
    def __init__(self):
        self.base_url = settings.CROWDSEC_API_URL
        self.api_key = settings.CROWDSEC_API_KEY
        self.enabled = bool(self.api_key)  # Le service est activé seulement si une clé API est fournie
        self.headers = {
            "X-Api-Key": self.api_key,
            "Content-Type": "application/json"
        }

    async def add_decision(self, ip: str, duration: str = "4h", reason: str = "Automated ban") -> Optional[Dict]:
        """Ajoute une décision de blocage dans CrowdSec"""
        if not self.enabled:
            logger.warning("CrowdSec n'est pas configuré")
            return None
        
        async with aiohttp.ClientSession() as session:
            payload = {
                "decisions": [
                    {
                        "duration": duration,
                        "origin": "security-automation",
                        "scenario": "security-automation",
                        "scope": "ip",
                        "type": "ban",
                        "value": ip,
                        "reason": reason
                    }
                ]
            }

            try:
                async with session.post(
                    f"{self.base_url}/decisions",
                    headers=self.headers,
                    json=payload
                ) as response:
                    if response.status == 201:
                        logger.info(f"IP {ip} successfully banned in CrowdSec")
                        return await response.json()
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to ban IP in CrowdSec: {error_text}")
                        return {"error": error_text}
            except Exception as e:
                logger.error(f"Error communicating with CrowdSec: {str(e)}")
                raise

    async def check_ip(self, ip: str) -> Optional[Dict]:
        """Vérifie si une IP est déjà listée dans CrowdSec"""
        if not self.enabled:
            logger.warning("CrowdSec n'est pas configuré")
            return None
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.base_url}/decisions?ip={ip}",
                    headers=self.headers
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
            except Exception as e:
                logger.error(f"Error checking IP in CrowdSec: {str(e)}")
                return None 
import aiohttp
from src.core.config import settings

class VirusTotalService:
    BASE_URL = "https://www.virustotal.com/vtapi/v2"
    
    @staticmethod
    async def check_ip(ip_address: str):
        async with aiohttp.ClientSession() as session:
            params = {
                "apikey": settings.VIRUSTOTAL_API_KEY,
                "ip": ip_address
            }
            async with session.get(f"{VirusTotalService.BASE_URL}/ip-address/report", params=params) as response:
                if response.status == 200:
                    return await response.json()
                raise Exception(f"Erreur VirusTotal: {response.status}") 
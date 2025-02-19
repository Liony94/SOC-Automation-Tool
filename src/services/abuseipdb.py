import aiohttp
from src.core.config import settings

class AbuseIPDBService:
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    @staticmethod
    async def check_ip(ip_address: str):
        async with aiohttp.ClientSession() as session:
            headers = {
                'Key': settings.ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90'
            }
            async with session.get(f"{AbuseIPDBService.BASE_URL}/check", headers=headers, params=params) as response:
                if response.status == 200:
                    return await response.json()
                raise Exception(f"Erreur AbuseIPDB: {response.status}") 
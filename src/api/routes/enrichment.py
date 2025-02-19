from fastapi import APIRouter, HTTPException
from typing import Dict
from src.api.schemas.enrichment import IPCheckRequest
from src.services.virustotal import VirusTotalService
from src.services.abuseipdb import AbuseIPDBService

router = APIRouter()

@router.post("/check-ip")
async def check_ip(request: IPCheckRequest) -> Dict:
    try:
        # Vérification VirusTotal
        vt_results = await VirusTotalService.check_ip(request.ip_address)
        
        # Vérification AbuseIPDB
        abuse_results = await AbuseIPDBService.check_ip(request.ip_address)
        
        return {
            "ip": request.ip_address,
            "virustotal_results": vt_results,
            "abuseipdb_results": abuse_results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 
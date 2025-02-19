from fastapi import APIRouter, HTTPException
from typing import Dict
from src.api.schemas.enrichment import IPCheckRequest
from src.services.virustotal import VirusTotalService
from src.services.abuseipdb import AbuseIPDBService
from src.playbooks.ip_investigation import IPInvestigationPlaybook

router = APIRouter()
playbook = IPInvestigationPlaybook()

@router.post("/check-ip")
async def check_ip(request: IPCheckRequest) -> Dict:
    try:
        # Vérification VirusTotal
        vt_results = await VirusTotalService.check_ip(request.ip_address)
        
        # Vérification AbuseIPDB
        abuse_results = await AbuseIPDBService.check_ip(request.ip_address)
        
        # Exécution du playbook
        analysis_results = await playbook.analyze_results(
            request.ip_address,
            vt_results,
            abuse_results
        )
        
        return analysis_results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 
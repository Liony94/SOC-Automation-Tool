from fastapi import APIRouter, HTTPException
from typing import Dict
from src.api.schemas.enrichment import IPCheckRequest
from src.services.virustotal import VirusTotalService
from src.services.abuseipdb import AbuseIPDBService
from src.playbooks.ip_investigation import IPInvestigationPlaybook, PlaybookStatus

router = APIRouter()

@router.post("/check-ip")
async def check_ip(request: IPCheckRequest) -> Dict:
    try:
        # Vérification VirusTotal
        vt_results = await VirusTotalService.check_ip(request.ip_address)
        
        # Vérification AbuseIPDB
        abuse_results = await AbuseIPDBService.check_ip(request.ip_address)
        
        # Exécution du playbook
        playbook = IPInvestigationPlaybook()
        result = await playbook.execute({"ip_address": request.ip_address})
        
        if result.status == PlaybookStatus.FAILURE:
            raise HTTPException(
                status_code=500,
                detail={"message": "Playbook execution failed", "errors": result.errors}
            )
        
        # Formatage de la réponse
        analysis_data = next(
            (f["details"] for f in result.findings if f["source"] == "analysis"),
            {}
        )
        
        return {
            "risk_level": analysis_data.get("risk_level", "UNKNOWN"),
            "analysis": {
                "virustotal": analysis_data.get("virustotal", {}),
                "abuseipdb": analysis_data.get("abuseipdb", {})
            },
            "recommendations": result.recommendations,
            "actions_taken": result.actions_taken
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 
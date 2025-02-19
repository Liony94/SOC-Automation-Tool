from .base import BasePlaybook, PlaybookStatus, PlaybookResult
from src.services.virustotal import VirusTotalService
from src.services.abuseipdb import AbuseIPDBService
from src.services.crowdsec import CrowdSecService
from src.core.risk_levels import RiskLevel, RiskAssessment
from typing import Dict, List
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class IPInvestigationPlaybook(BasePlaybook):
    def __init__(self):
        super().__init__(
            name="IP Investigation",
            description="Analyse complète d'une adresse IP suspecte"
        )
        self.risk_assessment = RiskAssessment()
        self.vt_service = VirusTotalService()
        self.abuse_service = AbuseIPDBService()
        self.crowdsec = CrowdSecService()

    async def execute(self, context: Dict) -> PlaybookResult:
        ip_address = context.get("ip_address")
        if not ip_address:
            self.add_error("IP address not provided")
            self.result.status = PlaybookStatus.FAILURE
            return self.result

        try:
            # Étape 1: Collecte des données
            vt_results = await self.vt_service.check_ip(ip_address)
            abuse_results = await self.abuse_service.check_ip(ip_address)
            
            # Étape 2: Analyse des résultats
            vt_risk = self._analyze_virustotal(vt_results)
            abuse_risk = self._analyze_abuseipdb(abuse_results)
            overall_risk = self._determine_overall_risk([vt_risk, abuse_risk])

            # Ajout des résultats à l'objet result
            self.result.findings.append({
                "source": "analysis",
                "details": {
                    "risk_level": overall_risk.value,
                    "virustotal": {
                        "risk_level": vt_risk.value,
                        "detection_ratio": f"{vt_results.get('positives', 0)}/{vt_results.get('total', 0)}",
                        "last_analysis_stats": vt_results.get("last_analysis_stats", {})
                    },
                    "abuseipdb": {
                        "risk_level": abuse_risk.value,
                        "confidence_score": abuse_results.get("data", {}).get("abuseConfidenceScore", 0)
                    }
                }
            })

            # Étape 3: Actions automatiques basées sur le risque
            await self._take_actions(ip_address, overall_risk)

            # Étape 4: Génération des recommandations
            self._generate_recommendations(ip_address, overall_risk)

            # Finalisation
            self.result.status = PlaybookStatus.SUCCESS
            self.result.end_time = datetime.utcnow()
            return self.result

        except Exception as e:
            self.add_error(f"Playbook execution failed: {str(e)}")
            self.result.status = PlaybookStatus.FAILURE
            return self.result

    def _analyze_virustotal(self, results: Dict) -> RiskLevel:
        malicious = results.get("last_analysis_stats", {}).get("malicious", 0)
        total = results.get("total", 0)
        
        if total == 0:
            return RiskLevel.LOW
        
        detection_rate = (malicious / total) * 100
        self.add_finding(
            severity="info",
            source="VirusTotal",
            details={"detection_rate": detection_rate, "raw_results": results}
        )
        
        return self.risk_assessment.evaluate_virustotal(malicious, total)

    def _analyze_abuseipdb(self, results: Dict) -> RiskLevel:
        confidence_score = results.get("data", {}).get("abuseConfidenceScore", 0)
        self.add_finding(
            severity="info",
            source="AbuseIPDB",
            details={"confidence_score": confidence_score, "raw_results": results}
        )
        
        return self.risk_assessment.evaluate_abuseipdb(confidence_score)

    def _determine_overall_risk(self, risk_levels: List[RiskLevel]) -> RiskLevel:
        """
        Détermine le niveau de risque global basé sur les différentes évaluations
        Prend le niveau de risque le plus élevé comme référence
        """
        if not risk_levels:
            return RiskLevel.LOW
        
        risk_values = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4
        }
        
        # Trouve le niveau de risque le plus élevé
        max_risk = max(risk_levels, key=lambda x: risk_values[x])
        return max_risk

    async def _take_actions(self, ip: str, risk_level: RiskLevel):
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            # Vérifier si CrowdSec est configuré
            if not self.crowdsec.enabled:
                self.add_action("CrowdSec n'est pas configuré - Blocage automatique désactivé")
                return

            # Vérifier si l'IP est déjà bloquée
            existing = await self.crowdsec.check_ip(ip)
            if not existing:
                duration = "24h" if risk_level == RiskLevel.CRITICAL else "4h"
                await self.crowdsec.add_decision(ip, duration=duration)
                self.add_action(f"IP {ip} blocked in CrowdSec for {duration}")

    def _generate_recommendations(self, ip: str, risk_level: RiskLevel):
        base_recommendations = {
            RiskLevel.LOW: [
                "Surveillance passive recommandée",
                "Aucune action immédiate nécessaire"
            ],
            RiskLevel.MEDIUM: [
                f"Surveiller activement le trafic depuis {ip}",
                "Envisager l'ajout de règles de détection spécifiques"
            ],
            RiskLevel.HIGH: [
                f"Bloquer immédiatement l'IP {ip} sur les systèmes critiques",
                "Analyser les logs pour détecter d'autres activités suspectes"
            ],
            RiskLevel.CRITICAL: [
                f"URGENT: Bloquer {ip} sur tous les systèmes",
                "Lancer une investigation complète",
                "Vérifier les systèmes pour compromission"
            ]
        }
        
        for rec in base_recommendations[risk_level]:
            self.add_recommendation(rec) 
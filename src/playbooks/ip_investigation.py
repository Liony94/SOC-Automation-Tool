from src.core.risk_levels import RiskLevel, RiskAssessment
import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class IPInvestigationPlaybook:
    def __init__(self):
        self.risk_assessment = RiskAssessment()
        
    async def analyze_results(self, ip: str, vt_results: Dict, abuse_results: Dict) -> Dict:
        # Évaluer les résultats de VirusTotal
        vt_positives = vt_results.get('positives', 0)
        vt_total = vt_results.get('total', 0)
        vt_risk = RiskAssessment.evaluate_virustotal(vt_positives, vt_total)
        
        # Évaluer les résultats d'AbuseIPDB
        abuse_score = abuse_results.get('data', {}).get('abuseConfidenceScore', 0)
        abuse_risk = RiskAssessment.evaluate_abuseipdb(abuse_score)
        
        # Déterminer le niveau de risque global (prendre le plus élevé)
        overall_risk = max(vt_risk, abuse_risk, key=lambda x: list(RiskLevel).index(x))
        
        # Générer les recommandations
        recommendations = self._generate_recommendations(overall_risk, ip)
        
        return {
            "ip": ip,
            "timestamp": datetime.utcnow().isoformat(),
            "risk_level": overall_risk.value,
            "analysis": {
                "virustotal": {
                    "risk_level": vt_risk.value,
                    "detection_ratio": f"{vt_positives}/{vt_total}",
                },
                "abuseipdb": {
                    "risk_level": abuse_risk.value,
                    "confidence_score": abuse_score,
                }
            },
            "recommendations": recommendations
        }
    
    def _generate_recommendations(self, risk_level: RiskLevel, ip: str) -> List[str]:
        recommendations = []
        
        if risk_level == RiskLevel.LOW:
            recommendations.extend([
                "Surveillance passive recommandée",
                "Aucune action immédiate nécessaire"
            ])
            
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.extend([
                f"Surveiller activement le trafic depuis {ip}",
                "Envisager l'ajout de règles de détection spécifiques",
                "Documenter l'activité suspecte"
            ])
            
        elif risk_level == RiskLevel.HIGH:
            recommendations.extend([
                f"Bloquer immédiatement l'IP {ip} sur les systèmes critiques",
                "Analyser les logs pour détecter d'autres activités suspectes",
                "Créer un ticket d'incident",
                "Notifier l'équipe sécurité"
            ])
            
        elif risk_level == RiskLevel.CRITICAL:
            recommendations.extend([
                f"URGENT: Bloquer {ip} sur tous les systèmes",
                "Lancer une investigation complète",
                "Vérifier les systèmes pour compromission",
                "Escalader à l'équipe de réponse aux incidents",
                "Préparer un rapport détaillé"
            ])
            
        return recommendations 
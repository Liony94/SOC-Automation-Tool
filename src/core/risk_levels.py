from enum import Enum

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class RiskAssessment:
    @staticmethod
    def evaluate_virustotal(positives: int, total: int) -> RiskLevel:
        if total == 0:
            return RiskLevel.LOW
        
        detection_rate = (positives / total) * 100
        if detection_rate < 5:
            return RiskLevel.LOW
        elif detection_rate < 15:
            return RiskLevel.MEDIUM
        elif detection_rate < 30:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    @staticmethod
    def evaluate_abuseipdb(confidence_score: float) -> RiskLevel:
        if confidence_score < 25:
            return RiskLevel.LOW
        elif confidence_score < 50:
            return RiskLevel.MEDIUM
        elif confidence_score < 75:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL 
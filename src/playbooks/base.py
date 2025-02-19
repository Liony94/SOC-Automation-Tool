from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class PlaybookStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    WARNING = "warning"
    IN_PROGRESS = "in_progress"

class PlaybookResult:
    def __init__(self):
        self.status: PlaybookStatus = PlaybookStatus.IN_PROGRESS
        self.actions_taken: List[str] = []
        self.findings: List[Dict] = []
        self.start_time: datetime = datetime.utcnow()
        self.end_time: Optional[datetime] = None
        self.recommendations: List[str] = []
        self.errors: List[str] = []

    def to_dict(self) -> Dict:
        return {
            "status": self.status.value,
            "actions_taken": self.actions_taken,
            "findings": self.findings,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "recommendations": self.recommendations,
            "errors": self.errors
        }

class BasePlaybook:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.result = PlaybookResult()

    async def execute(self, context: Dict) -> PlaybookResult:
        """Méthode principale à implémenter par les playbooks spécifiques"""
        raise NotImplementedError

    def add_finding(self, severity: str, source: str, details: Dict):
        self.result.findings.append({
            "severity": severity,
            "source": source,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        })

    def add_action(self, action: str):
        self.result.actions_taken.append(action)
        logger.info(f"[{self.name}] Action taken: {action}")

    def add_recommendation(self, recommendation: str):
        self.result.recommendations.append(recommendation)

    def add_error(self, error: str):
        self.result.errors.append(error)
        logger.error(f"[{self.name}] Error: {error}") 
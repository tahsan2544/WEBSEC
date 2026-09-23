from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    PASS = "PASS"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Status(str, Enum):
    VERIFIED = "VERIFIED"
    DETECTED = "DETECTED"
    HEURISTIC = "HEURISTIC"
    INFO = "INFO"
    PASS = "PASS"


@dataclass
class Finding:
    check: str
    severity: Severity
    title: str
    detail: str
    recommendation: str = ""
    evidence: str = ""
    location: str = ""
    confidence: Confidence = Confidence.MEDIUM
    status: Status = Status.DETECTED
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "status": self.status.value,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "location": self.location,
            "metadata": self.metadata,
        }


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.PASS: 5,
}

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class DoSMatch:
    dos_type: str
    description: str
    evidence: str
    severity_weight: int
    confidence: float = 1.0

@dataclass
class DetectionResult:
    agent_name: str
    threat_found: bool
    threat_type: str
    matched: List[DoSMatch]
    severity: str
    summary: str

class ContextFloodingDetectorAgent:
    def __init__(self, max_chars: int = 4000):
        self.name = "Context Flooding Detector"
        self.max_chars = max_chars

    def run(self, text: str) -> DetectionResult:
        text_length = len(text)
        
        if text_length > self.max_chars:
            match = DoSMatch(
                dos_type="context_flooding",
                description="Input exceeds maximum allowed length for DoS protection",
                evidence=f"Length: {text_length} chars, limit: {self.max_chars}",
                severity_weight=4
            )
            return DetectionResult(
                agent_name=self.name,
                threat_found=True,
                threat_type="DOS",
                matched=[match],
                severity="CRITICAL",
                summary=f"Input exceeds maximum allowed length ({text_length}/{self.max_chars} chars). Potential DoS context flooding attack."
            )
            
        return DetectionResult(
            agent_name=self.name,
            threat_found=False,
            threat_type="DOS",
            matched=[],
            severity="NONE",
            summary="Input length is within safe limits."
        )

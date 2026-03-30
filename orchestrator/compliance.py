"""
Compliance Profiles for Semantic Firewall

Pre-configured compliance settings for GDPR, HIPAA, SOC2, and other regulations.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class ComplianceProfile:
    """Configuration for compliance standards"""
    
    name: str
    description: str
    
    # Agent activation levels
    pii_sensitive: bool
    secrets_sensitive: bool
    abuse_sensitive: bool
    injection_sensitive: bool
    unsafe_content_sensitive: bool
    
    # Thresholds (lower = stricter)
    pii_severity_threshold: str  # BLOCK on this severity or higher
    secrets_severity_threshold: str
    abuse_severity_threshold: str
    injection_severity_threshold: str
    unsafe_content_severity_threshold: str
    
    # Session thresholds
    session_flag_threshold: float  # When to start flagging
    session_block_threshold: float  # When to block
    
    # Action overrides per threat type
    action_overrides: Dict[str, Dict[str, str]]  # e.g., {"PII": {"HIGH": "BLOCK"}}
    
    # Audit requirements
    log_all_decisions: bool  # Even ALLOW decisions
    require_reasons: bool
    require_explanations: bool
    
    # Data retention
    log_retention_days: int
    require_consent: bool
    
    # Additional features
    redact_aggressively: bool  # Redact anything suspicious
    enable_output_scanning: bool
    enable_session_memory: bool
    enable_multi_turn_detection: bool


class ComplianceProfileManager:
    """
    Manages compliance profiles for regulatory requirements.
    
    Standards:
    - GDPR: EU data protection (focus on PII)
    - HIPAA: US healthcare data (focus on medical PII)
    - SOC2: Internal controls (focus on secrets + audit)
    - FERPA: Student records (focus on student PII)
    - COPPA: Children's privacy (focus on minor data)
    - CCPA: California privacy (focus on PII + consent)
    """
    
    # ============================================================================
    # GDPR: General Data Protection Regulation (EU)
    # ============================================================================
    GDPR = ComplianceProfile(
        name="GDPR",
        description="EU General Data Protection Regulation - Strict PII protection, right to erasure",
        
        # Extra strict on PII
        pii_sensitive=True,
        secrets_sensitive=True,
        abuse_sensitive=False,
        injection_sensitive=True,
        unsafe_content_sensitive=True,
        
        # Block at HIGH or CRITICAL for PII
        pii_severity_threshold="HIGH",
        secrets_severity_threshold="CRITICAL",
        abuse_severity_threshold="CRITICAL",
        injection_severity_threshold="HIGH",
        unsafe_content_severity_threshold="HIGH",
        
        session_flag_threshold=3.0,
        session_block_threshold=6.0,
        
        action_overrides={
            "PII": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "REDACT",
                "LOW": "REDACT"
            },
            "SECRET": {
                "CRITICAL": "BLOCK",
                "HIGH": "REDACT",
                "MEDIUM": "FLAG",
            },
            "INJECTION": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
            },
            "UNSAFE_CONTENT": {
                "CRITICAL": "BLOCK",
                "HIGH": "FLAG",
            }
        },
        
        log_all_decisions=True,
        require_reasons=True,
        require_explanations=True,
        
        log_retention_days=2555,  # 7 years for EU compliance
        require_consent=True,
        
        redact_aggressively=True,
        enable_output_scanning=True,
        enable_session_memory=True,
        enable_multi_turn_detection=True
    )
    
    # ============================================================================
    # HIPAA: Health Insurance Portability and Accountability Act (US Healthcare)
    # ============================================================================
    HIPAA = ComplianceProfile(
        name="HIPAA",
        description="US Healthcare - Protected Health Information (PHI) protection",
        
        # Extreme strictness on medical PII
        pii_sensitive=True,
        secrets_sensitive=True,
        abuse_sensitive=False,
        injection_sensitive=True,
        unsafe_content_sensitive=False,
        
        # Block at MEDIUM or higher for PII (medical data is highly sensitive)
        pii_severity_threshold="MEDIUM",
        secrets_severity_threshold="HIGH",
        abuse_severity_threshold="CRITICAL",
        injection_severity_threshold="HIGH",
        unsafe_content_severity_threshold="CRITICAL",
        
        session_flag_threshold=2.0,
        session_block_threshold=4.0,
        
        action_overrides={
            "PII": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "BLOCK",
                "LOW": "REDACT"
            },
            "SECRET": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "REDACT",
            },
            "INJECTION": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "FLAG",
            }
        },
        
        log_all_decisions=True,
        require_reasons=True,
        require_explanations=True,
        
        log_retention_days=2555,  # 7 years minimum for medical records
        require_consent=True,
        
        redact_aggressively=True,
        enable_output_scanning=True,
        enable_session_memory=True,
        enable_multi_turn_detection=True
    )
    
    # ============================================================================
    # SOC2: Service Organization Control (Internal Controls & Compliance)
    # ============================================================================
    SOC2 = ComplianceProfile(
        name="SOC2",
        description="Security, Availability, Processing Integrity, Confidentiality - Focus on secrets and access",
        
        pii_sensitive=True,
        secrets_sensitive=True,  # CRITICAL for SOC2
        abuse_sensitive=True,
        injection_sensitive=True,
        unsafe_content_sensitive=False,
        
        # Block at HIGH+ for secrets (API keys are critical)
        pii_severity_threshold="HIGH",
        secrets_severity_threshold="MEDIUM",  # Extra strict on secrets
        abuse_severity_threshold="HIGH",
        injection_severity_threshold="HIGH",
        unsafe_content_severity_threshold="CRITICAL",
        
        session_flag_threshold=4.0,
        session_block_threshold=8.0,
        
        action_overrides={
            "SECRET": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "BLOCK",
                "LOW": "REDACT"
            },
            "ABUSE": {
                "CRITICAL": "BLOCK",
                "HIGH": "REDACT",
                "MEDIUM": "FLAG",
            },
            "INJECTION": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
            },
            "PII": {
                "CRITICAL": "BLOCK",
                "HIGH": "REDACT",
                "MEDIUM": "REDACT",
            }
        },
        
        log_all_decisions=True,
        require_reasons=True,
        require_explanations=True,
        
        log_retention_days=365,  # 1 year minimum
        require_consent=False,
        
        redact_aggressively=True,
        enable_output_scanning=True,
        enable_session_memory=True,
        enable_multi_turn_detection=True
    )
    
    # ============================================================================
    # FERPA: Family Educational Rights and Privacy Act (Student Records)
    # ============================================================================
    FERPA = ComplianceProfile(
        name="FERPA",
        description="US Education Records - Student PII and academic information protection",
        
        pii_sensitive=True,
        secrets_sensitive=False,
        abuse_sensitive=False,
        injection_sensitive=True,
        unsafe_content_sensitive=True,
        
        pii_severity_threshold="HIGH",
        secrets_severity_threshold="CRITICAL",
        abuse_severity_threshold="CRITICAL",
        injection_severity_threshold="MEDIUM",
        unsafe_content_severity_threshold="HIGH",
        
        session_flag_threshold=3.5,
        session_block_threshold=7.0,
        
        action_overrides={
            "PII": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "REDACT",
            },
            "UNSAFE_CONTENT": {
                "CRITICAL": "BLOCK",
                "HIGH": "FLAG",
            },
            "INJECTION": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
            }
        },
        
        log_all_decisions=True,
        require_reasons=True,
        require_explanations=True,
        
        log_retention_days=1095,  # 3 years
        require_consent=True,
        
        redact_aggressively=True,
        enable_output_scanning=True,
        enable_session_memory=True,
        enable_multi_turn_detection=True
    )
    
    # ============================================================================
    # COPPA: Children's Online Privacy Protection Act
    # ============================================================================
    COPPA = ComplianceProfile(
        name="COPPA",
        description="Children under 13 - Extremely strict PII and behavioral protection",
        
        pii_sensitive=True,
        secrets_sensitive=True,
        abuse_sensitive=True,
        injection_sensitive=True,
        unsafe_content_sensitive=True,
        
        # Maximum strictness for children
        pii_severity_threshold="LOW",  # Block even low severity PII
        secrets_severity_threshold="HIGH",
        abuse_severity_threshold="MEDIUM",
        injection_severity_threshold="MEDIUM",
        unsafe_content_severity_threshold="MEDIUM",
        
        session_flag_threshold=1.0,
        session_block_threshold=3.0,
        
        action_overrides={
            "PII": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "BLOCK",
                "LOW": "BLOCK"
            },
            "UNSAFE_CONTENT": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "FLAG",
            },
            "INJECTION": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "FLAG",
            },
            "ABUSE": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
            }
        },
        
        log_all_decisions=True,
        require_reasons=True,
        require_explanations=True,
        
        log_retention_days=365,
        require_consent=True,
        
        redact_aggressively=True,
        enable_output_scanning=True,
        enable_session_memory=True,
        enable_multi_turn_detection=True
    )
    
    # ============================================================================
    # CCPA: California Consumer Privacy Act
    # ============================================================================
    CCPA = ComplianceProfile(
        name="CCPA",
        description="California Privacy - Consumer data protection and right to deletion",
        
        pii_sensitive=True,
        secrets_sensitive=True,
        abuse_sensitive=False,
        injection_sensitive=True,
        unsafe_content_sensitive=False,
        
        pii_severity_threshold="HIGH",
        secrets_severity_threshold="CRITICAL",
        abuse_severity_threshold="CRITICAL",
        injection_severity_threshold="HIGH",
        unsafe_content_severity_threshold="CRITICAL",
        
        session_flag_threshold=3.5,
        session_block_threshold=7.0,
        
        action_overrides={
            "PII": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "REDACT",
                "LOW": "FLAG"
            },
            "SECRET": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
            },
            "INJECTION": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
            }
        },
        
        log_all_decisions=True,
        require_reasons=True,
        require_explanations=True,
        
        log_retention_days=2555,
        require_consent=True,
        
        redact_aggressively=True,
        enable_output_scanning=True,
        enable_session_memory=True,
        enable_multi_turn_detection=True
    )
    
    # ============================================================================
    # Custom Development Profile (Permissive for testing)
    # ============================================================================
    DEVELOPMENT = ComplianceProfile(
        name="DEVELOPMENT",
        description="Development/Testing - Permissive for catching obvious issues only",
        
        pii_sensitive=False,
        secrets_sensitive=False,
        abuse_sensitive=False,
        injection_sensitive=False,
        unsafe_content_sensitive=False,
        
        pii_severity_threshold="CRITICAL",
        secrets_severity_threshold="CRITICAL",
        abuse_severity_threshold="CRITICAL",
        injection_severity_threshold="CRITICAL",
        unsafe_content_severity_threshold="CRITICAL",
        
        session_flag_threshold=100.0,
        session_block_threshold=1000.0,
        
        action_overrides={},
        
        log_all_decisions=False,
        require_reasons=False,
        require_explanations=False,
        
        log_retention_days=7,
        require_consent=False,
        
        redact_aggressively=False,
        enable_output_scanning=False,
        enable_session_memory=False,
        enable_multi_turn_detection=False
    )
    
    # Available profiles
    PROFILES = {
        "GDPR": GDPR,
        "HIPAA": HIPAA,
        "SOC2": SOC2,
        "FERPA": FERPA,
        "COPPA": COPPA,
        "CCPA": CCPA,
        "DEVELOPMENT": DEVELOPMENT
    }

    @classmethod
    def get_profile(cls, name: str) -> Optional[ComplianceProfile]:
        """Get a compliance profile by name"""
        return cls.PROFILES.get(name.upper())

    @classmethod
    def list_profiles(cls) -> List[str]:
        """List all available profiles"""
        return list(cls.PROFILES.keys())

    @classmethod
    def get_profile_description(cls, name: str) -> str:
        """Get description of a profile"""
        profile = cls.get_profile(name)
        return profile.description if profile else "Profile not found"

    def get_policy_config(self, profile: ComplianceProfile) -> Dict:
        """
        Convert compliance profile to policy configuration
        Compatible with orchestrator.policy_store format
        """
        return {
            "name": f"compliance_{profile.name}",
            "description": profile.description,
            "source": "compliance_profile",
            "enabled": True,
            
            # Thresholds
            "session_flag_threshold": profile.session_flag_threshold,
            "session_block_threshold": profile.session_block_threshold,
            
            # Action overrides
            "action_overrides": profile.action_overrides,
            
            # Features
            "features": {
                "output_scanning": profile.enable_output_scanning,
                "session_memory": profile.enable_session_memory,
                "multi_turn_detection": profile.enable_multi_turn_detection,
            },
            
            # Audit settings
            "audit": {
                "log_all_decisions": profile.log_all_decisions,
                "require_reasons": profile.require_reasons,
                "require_explanations": profile.require_explanations,
                "log_retention_days": profile.log_retention_days
            }
        }

    @classmethod
    def get_recommendation_for_industry(cls, industry: str) -> Optional[str]:
        """Get recommended compliance profile by industry"""
        recommendations = {
            "healthcare": "HIPAA",
            "finance": "SOC2",
            "education": "FERPA",
            "eu_based": "GDPR",
            "california": "CCPA",
            "children": "COPPA",
            "retail": "CCPA",
            "government": "SOC2",
            "saas": "SOC2",
            "tech": "SOC2"
        }
        return recommendations.get(industry.lower())

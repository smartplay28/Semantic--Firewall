import re
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class PIIMatch:
    pii_type: str
    value: str
    description: str


@dataclass
class DetectionResult:
    agent_name: str
    threat_found: bool
    threat_type: str
    matched: List[PIIMatch]
    severity: str  # NONE / LOW / MEDIUM / HIGH / CRITICAL
    summary: str


class PIIDetectorAgent:
    def __init__(self):
        self.name = "PII Detector"

        # Each pattern: (regex, description)
        self.patterns: Dict[str, tuple] = {

            # ── Identity ──────────────────────────────────────────────────────
            "aadhaar": (
                r'\b\d{4}\s?\d{4}\s?\d{4}\b',
                "Indian Aadhaar number"
            ),
            "pan_card": (
                r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
                "Indian PAN card number"
            ),
            "passport_india": (
                r'\b[A-Z][0-9]{7}\b',
                "Indian passport number"
            ),
            "voter_id": (
                r'\b[A-Z]{3}[0-9]{7}\b',
                "Indian Voter ID"
            ),
            "driving_license_india": (
                r'\b[A-Z]{2}[0-9]{2}\s?[0-9]{11}\b',
                "Indian driving license"
            ),
            "ssn_us": (
                r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b',
                "US Social Security Number"
            ),
            "nhs_uk": (
                r'\b\d{3}\s?\d{3}\s?\d{4}\b',
                "UK NHS number"
            ),

            # ── Contact ───────────────────────────────────────────────────────
            "email": (
                r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
                "Email address"
            ),
            "phone_india": (
                r'(\+91[-\s]?)?[6-9]\d{9}\b',
                "Indian mobile number"
            ),
            "phone_us": (
                r'\b(\+1[-\s.]?)?\(?\d{3}\)?[-\s.]?\d{3}[-\s.]?\d{4}\b',
                "US phone number"
            ),
            "phone_uk": (
                r'\b(\+44[-\s]?)?0?7\d{3}[-\s]?\d{6}\b',
                "UK phone number"
            ),
            "phone_generic": (
                r'\b\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b',
                "Generic international phone number"
            ),

            # ── Financial ─────────────────────────────────────────────────────
            "credit_card_visa": (
                r'\b4[0-9]{12}(?:[0-9]{3})?\b',
                "Visa credit card number"
            ),
            "credit_card_mastercard": (
                r'\b5[1-5][0-9]{14}\b',
                "Mastercard credit card number"
            ),
            "credit_card_amex": (
                r'\b3[47][0-9]{13}\b',
                "American Express card number"
            ),
            "credit_card_generic": (
                r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                "Generic credit/debit card number"
            ),
            "cvv": (
                r'\b(?:cvv|cvc|cvv2|cvc2|security code)[\s:]*\d{3,4}\b',
                "Card CVV/CVC code"
            ),
            "bank_account_india": (
                r'\b[0-9]{9,18}\b(?=.*\b(account|acc|bank)\b)',
                "Indian bank account number (contextual)"
            ),
            "ifsc_code": (
                r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
                "Indian IFSC code"
            ),
            "iban": (
                r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b',
                "International Bank Account Number (IBAN)"
            ),
            "upi_id": (
                r'\b[a-zA-Z0-9.\-_]+@[a-zA-Z]{3,}\b',
                "UPI payment ID"
            ),

            # ── Network / Digital ─────────────────────────────────────────────
            "ipv4": (
                r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
                "IPv4 address"
            ),
            "ipv6": (
                r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
                "IPv6 address"
            ),
            "mac_address": (
                r'\b([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b',
                "MAC address"
            ),

            # ── Location ──────────────────────────────────────────────────────
            "pincode_india": (
                r'\b[1-9][0-9]{5}\b',
                "Indian PIN code"
            ),
            "zipcode_us": (
                r'\b\d{5}(?:[-\s]\d{4})?\b',
                "US ZIP code"
            ),
            "coordinates": (
                r'\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b',
                "GPS coordinates (lat, lng)"
            ),

            # ── Medical ───────────────────────────────────────────────────────
            "blood_group": (
                r'\b(AB|A|B|O)\s*[+\-]',
                "Blood group"
            ),
            "health_id_india": (
                r'\b\d{2}-\d{4}-\d{4}-\d{4}\b',
                "Indian Health ID (ABHA)"
            ),

            # ── Vehicle ───────────────────────────────────────────────────────
            "vehicle_reg_india": (
                r'\b[A-Z]{2}[0-9]{2}[A-Z]{1,2}[0-9]{4}\b',
                "Indian vehicle registration number"
            ),

            # ── Personal ──────────────────────────────────────────────────────
            "date_of_birth": (
                r'\b(?:dob|date of birth|born on|d\.o\.b)[\s:]*\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\b',
                "Date of birth (contextual)"
            ),
            "age_with_context": (
                r'\b(?:age|aged|i am|i\'m)[\s:]*\d{1,3}\s*(?:years?|yrs?)?\b',
                "Age with context"
            ),
            "gender": (
                r'\b(?:gender|sex)[\s:]*(?:male|female|transgender|non-binary|m|f)\b',
                "Gender information"
            ),
            "name_with_title": (
                r'\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Shri|Smt)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b',
                "Full name with title"
            ),
            "religion": (
                r'\b(?:religion|religious|faith|i am a?)[\s:]*(?:hindu|muslim|christian|sikh|buddhist|jain|jewish|parsi)\b',
                "Religion (contextual)"
            ),
            "caste": (
                r'\b(?:caste|community|belong to)[\s:]*[A-Za-z\s]{3,30}\b',
                "Caste/community (contextual)"
            ),
        }

    def _calculate_severity(self, matched: List[PIIMatch]) -> str:
        if not matched:
            return "NONE"

        # Critical PII types
        critical_types = {"aadhaar", "ssn_us", "credit_card_visa",
                          "credit_card_mastercard", "credit_card_amex",
                          "credit_card_generic", "cvv", "passport_india",
                          "health_id_india"}

        high_types = {"pan_card", "bank_account_india", "iban",
                      "ifsc_code", "date_of_birth", "driving_license_india"}

        types_found = {m.pii_type for m in matched}

        if types_found & critical_types:
            return "CRITICAL"
        elif types_found & high_types:
            return "HIGH"
        elif len(matched) >= 3:
            return "HIGH"   # combination of multiple PII = high risk
        elif len(matched) == 2:
            return "MEDIUM"
        else:
            return "LOW"

    def run(self, text: str) -> DetectionResult:
        matched: List[PIIMatch] = []
        text_lower = text.lower()  # for case-insensitive contextual patterns

        for pii_type, (pattern, description) in self.patterns.items():
            # Use case-insensitive flag for contextual patterns
            flags = re.IGNORECASE if any(
                kw in description.lower() for kw in ["contextual", "context"]
            ) else 0

            try:
                found = re.findall(pattern, text if not flags else text_lower, flags)
                for value in found:
                    # re.findall returns strings or tuples (for groups)
                    val = value if isinstance(value, str) else value[0]
                    if val.strip():
                        matched.append(PIIMatch(
                            pii_type=pii_type,
                            value=val.strip(),
                            description=description
                        ))
            except re.error:
                continue  # skip malformed patterns gracefully

        severity = self._calculate_severity(matched)
        threat_found = len(matched) > 0

        summary = (
            f"Detected {len(matched)} PII item(s) across "
            f"{len({m.pii_type for m in matched})} category(ies). "
            f"Severity: {severity}."
            if threat_found else "No PII detected. Input is clean."
        )

        return DetectionResult(
            agent_name=self.name,
            threat_found=threat_found,
            threat_type="PII",
            matched=matched,
            severity=severity,
            summary=summary
        )

    def redact(self, text: str) -> str:
        """Returns the text with all detected PII replaced by [REDACTED]."""
        redacted = text
        for pii_type, (pattern, _) in self.patterns.items():
            flags = re.IGNORECASE if "contextual" in pii_type else 0
            redacted = re.sub(pattern, "[REDACTED]", redacted, flags=flags)
        return redacted


import re
import os
import json
from dataclasses import dataclass
from typing import List
from groq import Groq
from dotenv import load_dotenv

load_dotenv()


@dataclass
class UnsafeMatch:
    content_type: str
    description: str
    confidence: float  # 0.0 to 1.0
    evidence: str
    severity_weight: int


@dataclass
class DetectionResult:
    agent_name: str
    threat_found: bool
    threat_type: str
    matched: List[UnsafeMatch]
    severity: str  # NONE / LOW / MEDIUM / HIGH / CRITICAL
    summary: str


class UnsafeContentDetectorAgent:
    def __init__(self):
        self.name = "Unsafe Content Detector"
        self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        self.model = "llama-3.3-70b-versatile"
        self.confidence_threshold = 0.5

        # ── Regex pre-screening ────────────────────────────────────────────────
        self.quick_patterns = {

            # Violence & Threats
            "explicit_violence": (
                r'\b(how to (kill|murder|torture|stab|shoot|strangle|poison|beat up)'
                r'|step(s)? to (kill|murder|harm|hurt|attack)'
                r'|ways? to (kill|murder|hurt|harm|eliminate) (a |an |someone|people|humans?))\b',
                "Explicit violence instruction request",
                4
            ),
            "direct_threat": (
                r'\b(i (will|am going to|want to|plan to) (kill|murder|hurt|harm|attack|destroy)'
                r'|you (will|are going to) (die|be hurt|be killed|regret)'
                r'|i know where you (live|are|work))\b',
                "Direct personal threat",
                4
            ),
            "mass_violence": (
                r'\b(mass (shooting|killing|murder|casualt)'
                r'|how to (make|build|create) a (bomb|explosive|weapon)'
                r'|(school|church|mosque|temple|concert) (shooting|attack|bombing))\b',
                "Mass violence planning or glorification",
                4
            ),

            # Self Harm & Suicide
            "self_harm_methods": (
                r'\b(how to (cut|harm|hurt) (myself|yourself|oneself)'
                r'|methods? (of|for) self.?harm'
                r'|ways? to (hurt|injure) (myself|yourself))\b',
                "Self-harm method request",
                4
            ),
            "suicide_methods": (
                r'\b(how to (commit suicide|kill myself|end my life|take my own life)'
                r'|best (method|way|means) (of|to) (suicide|die|end it)'
                r'|painless (way|method) to (die|suicide|end))\b',
                "Suicide method request",
                4
            ),
            "suicide_ideation": (
                r'\b(i (want|wish) (to die|i was dead|i were dead|to kill myself)'
                r'|no (reason|point) (to|in) (live|living|going on)'
                r'|better off (dead|without me))\b',
                "Suicidal ideation expression",
                3
            ),

            # Sexual & Explicit Content
            "explicit_sexual": (
                r'\b(explicit (sexual|porn|nude|naked) (content|material|image|video)'
                r'|generate (porn|nude|naked|sexual) (image|content|story)'
                r'|write (explicit|graphic) (sex|sexual|erotic) (scene|story|content))\b',
                "Explicit sexual content request",
                3
            ),
            "csam_indicators": (
                r'\b(child(ren)? (nude|naked|sexual|porn)'
                r'|minor(s)? (nude|naked|sexual|explicit)'
                r'|(nude|naked|sexual) (image|photo|content) of (a child|children|minors?|underage))\b',
                "Child sexual abuse material indicators",
                4
            ),

            # Hate Speech & Discrimination
            "hate_speech": (
                r'\b((all|those) (jews?|muslims?|christians?|blacks?|whites?|asians?|hispanics?)'
                r'\s+(are|should|deserve|must|need to)\b'
                r'|(racial|ethnic|religious) (slur|slurs?|epithet)'
                r'|white (supremac|nationalist|power)'
                r'|(exterminate|eliminate|eradicate|genocide).{0,30}(race|religion|group|people))\b',
                "Hate speech or discriminatory content",
                4
            ),
            "extremist_content": (
                r'\b(join (isis|isil|al.?qaeda|taliban|kkk|neo.?nazi)'
                r'|how to (radicalize|recruit) (people|someone|others)'
                r'|(terrorist|extremist) (manifesto|ideology|propaganda)'
                r'|how to (plan|carry out|execute) (a terror|an attack|a terrorist))\b',
                "Extremist or terrorist content",
                4
            ),

            # Weapons & Dangerous Items
            "weapons_manufacturing": (
                r'\b(how to (make|build|create|synthesize|manufacture)'
                r'.{0,30}(gun|weapon|explosive|bomb|grenade|knife|poison|toxin|nerve agent))\b',
                "Weapon manufacturing instructions",
                4
            ),
            "drug_manufacturing": (
                r'\b(how to (make|cook|synthesize|manufacture|produce)'
                r'.{0,30}(meth|methamphetamine|heroin|cocaine|fentanyl|lsd|mdma|ecstasy))\b',
                "Drug manufacturing instructions",
                4
            ),
            "biological_chemical": (
                r'\b(how to (make|create|synthesize|weaponize)'
                r'.{0,30}(bioweapon|biological weapon|chemical weapon|anthrax|sarin|vx gas|ricin))\b',
                "Biological or chemical weapon instructions",
                4
            ),

            # Cybercrime
            "hacking_instructions": (
                r'\b(how to (hack|crack|exploit|bypass|brute force)'
                r'.{0,40}(account|system|network|server|database|password|firewall)'
                r'|write (a|me a) (keylogger|trojan|ransomware|malware|virus|worm|rootkit)'
                r'|how to (steal|exfiltrate) (data|credentials|passwords?))\b',
                "Hacking or cybercrime instructions",
                3
            ),
            "phishing": (
                r'\b(create (a )?phishing (email|page|site|link|message)'
                r'|how to (phish|scam|defraud|trick) (people|someone|users?)'
                r'|write (a )?fake (email|login|bank|paypal) (page|site|message))\b',
                "Phishing or social engineering attack",
                3
            ),

            # Illegal Activities
            "human_trafficking": (
                r'\b(how to (traffic|smuggle) (humans?|people|women|children)'
                r'|recruit (victims?|people) for (trafficking|exploitation|prostitution)'
                r'|how to (control|exploit) (victims?|workers?) (through|using) (debt|force|threat))\b',
                "Human trafficking related content",
                4
            ),
            "child_grooming": (
                r'\b(how to (groom|manipulate|gain trust of) (a child|children|minors?|kids?)'
                r'|how to (approach|talk to|befriend) (a child|children|minors?) (online|secretly)'
                r'|how to (hide|keep secret) (relationship|contact) (with|from) (a child|minors?))\b',
                "Child grooming instructions",
                4
            ),
            "illegal_financial": (
                r'\b(how to (launder|wash) (money|funds|cash)'
                r'|how to (evade|avoid|hide from) (taxes?|irs|hmrc|tax authority)'
                r'|how to (commit|do|execute) (fraud|identity theft|credit card fraud|insurance fraud))\b',
                "Illegal financial activity instructions",
                3
            ),

            # Dangerous/Harmful Misinformation
            "medical_misinformation": (
                r'\b(vaccines? (cause|causes?) (autism|death|harm|cancer|disease)'
                r'|how to (cure|treat) (cancer|hiv|aids|diabetes) (with|using) (bleach|mms|miracle)'
                r'|covid (is|was) (fake|hoax|not real|made up))\b',
                "Dangerous medical misinformation",
                3
            ),
        }

        # ── LLM system prompt ──────────────────────────────────────────────────
        self.system_prompt = """You are a content safety expert specializing in detecting harmful, dangerous, and policy-violating content in AI system inputs and outputs.

Your job is to analyze a given text and identify if it contains any of the following unsafe content categories:

1. VIOLENCE — explicit violence, threats, instructions for harming others, glorification of violence
2. SELF_HARM — self-harm methods, suicide instructions, encouragement of self-destructive behavior
3. SEXUAL_EXPLICIT — explicit sexual content, pornography requests, non-consensual scenarios
4. CSAM — any sexual content involving minors (zero tolerance)
5. HATE_SPEECH — hate speech, discrimination, slurs targeting protected groups
6. EXTREMISM — terrorist content, extremist recruitment, radicalization
7. WEAPONS — instructions for making weapons, explosives, or obtaining illegal arms
8. DRUG_MANUFACTURING — instructions for synthesizing illegal drugs
9. BIOWEAPONS_CHEM — biological or chemical weapon instructions
10. CYBERCRIME — hacking tutorials, malware creation, phishing attacks
11. HUMAN_TRAFFICKING — trafficking, exploitation, grooming instructions
12. ILLEGAL_ACTIVITY — fraud, money laundering, other serious illegal activity
13. DANGEROUS_MISINFORMATION — health/medical misinformation that could cause harm
14. HARASSMENT — targeted harassment, doxxing, stalking instructions
15. PRIVACY_VIOLATION — instructions for spying on or surveilling individuals without consent

Respond ONLY with a valid JSON object in exactly this format (no explanation, no markdown):
{
  "is_unsafe": true or false,
  "content_found": [
    {
      "content_type": "category from list above",
      "description": "brief description of what makes this unsafe",
      "confidence": 0.0 to 1.0,
      "evidence": "the specific part of the text that triggered this detection"
    }
  ],
  "overall_risk": "NONE or LOW or MEDIUM or HIGH or CRITICAL"
}

Important rules:
- Educational discussions ABOUT dangerous topics are usually NOT unsafe
- News reporting, historical analysis, and research questions are usually NOT unsafe
- Creative fiction that doesn't provide real harmful instructions is usually NOT unsafe
- ONLY flag content that could directly enable real-world harm or violates clear ethical boundaries
- Be precise — do NOT over-flag normal conversation"""

    # ── Severity helpers ───────────────────────────────────────────────────────

    def _calculate_severity(self, matched: List[UnsafeMatch]) -> str:
        if not matched:
            return "NONE"
        max_weight = max(m.severity_weight for m in matched)
        if max_weight == 4:
            return "CRITICAL"
        elif max_weight == 3:
            return "HIGH"
        elif max_weight == 2:
            return "MEDIUM"
        else:
            return "LOW"

    # ── Regex pre-screen ───────────────────────────────────────────────────────

    def _regex_prescreen(self, text: str) -> List[UnsafeMatch]:
        matches = []
        for content_type, (pattern, description, weight) in self.quick_patterns.items():
            try:
                found = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                if found:
                    matches.append(UnsafeMatch(
                        content_type=content_type,
                        description=description,
                        confidence=0.80,
                        evidence=found.group(0)[:100],
                        severity_weight=weight
                    ))
            except re.error:
                continue
        return matches

    # ── LLM detection ─────────────────────────────────────────────────────────

    def _llm_detect(self, text: str) -> List[UnsafeMatch]:
        matches = []
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": f"Analyze this text for unsafe content:\n\n{text}"}
                ],
                temperature=0.0,
                max_tokens=1000,
            )

            raw = response.choices[0].message.content.strip()

            # Strip markdown fences if present
            raw = re.sub(r'^```json\s*', '', raw)
            raw = re.sub(r'\s*```$', '', raw)

            result = json.loads(raw)

            if result.get("is_unsafe") and result.get("content_found"):
                for item in result["content_found"]:
                    confidence = float(item.get("confidence", 0.5))
                    if confidence >= self.confidence_threshold:
                        matches.append(UnsafeMatch(
                            content_type=item.get("content_type", "UNKNOWN"),
                            description=item.get("description", ""),
                            confidence=confidence,
                            evidence=item.get("evidence", "")[:150],
                            severity_weight=4 if confidence >= 0.85 else 3
                        ))

        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"[UnsafeContentDetector] LLM call failed: {e}")

        return matches

    # ── Deduplication ──────────────────────────────────────────────────────────

    def _deduplicate(self, regex_matches: List[UnsafeMatch],
                     llm_matches: List[UnsafeMatch]) -> List[UnsafeMatch]:
        seen_types = set()
        final = []

        # LLM results take priority
        for m in llm_matches:
            if m.content_type not in seen_types:
                seen_types.add(m.content_type)
                final.append(m)

        # Add regex results not covered by LLM
        for m in regex_matches:
            if m.content_type not in seen_types:
                seen_types.add(m.content_type)
                final.append(m)

        return final

    # ── Main run ───────────────────────────────────────────────────────────────

    def run(self, text: str) -> DetectionResult:

        # Step 1: Fast regex pre-screen
        regex_matches = self._regex_prescreen(text)

        # Step 2: LLM semantic detection
        llm_matches = self._llm_detect(text)

        # Step 3: Merge and deduplicate
        matched = self._deduplicate(regex_matches, llm_matches)

        severity = self._calculate_severity(matched)
        threat_found = len(matched) > 0

        summary = (
            f"Detected {len(matched)} unsafe content type(s) across "
            f"{len({m.content_type for m in matched})} category(ies). "
            f"Severity: {severity}."
            if threat_found else "No unsafe content detected. Input is clean."
        )

        return DetectionResult(
            agent_name=self.name,
            threat_found=threat_found,
            threat_type="UNSAFE_CONTENT",
            matched=matched,
            severity=severity,
            summary=summary
        )
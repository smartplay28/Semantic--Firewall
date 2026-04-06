import re
import os
import json
import hashlib
import threading
import time
from copy import deepcopy
from dataclasses import dataclass
from typing import List, Dict, Tuple
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
    meta: Dict[str, object]


class UnsafeContentDetectorAgent:
    def __init__(self):
        self.name = "Unsafe Content Detector"
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.client = Groq(api_key=self.groq_api_key) if self.groq_api_key else None
        self.fast_model = os.getenv("SEMANTIC_FIREWALL_UNSAFE_MODEL_FAST", "llama-3.1-8b-instant")
        self.strong_model = os.getenv("SEMANTIC_FIREWALL_UNSAFE_MODEL_STRONG", "llama-3.3-70b-versatile")
        self.enable_model_tiering = os.getenv("SEMANTIC_FIREWALL_UNSAFE_MODEL_TIERING", "1") != "0"
        self.confidence_threshold = float(os.getenv("SEMANTIC_FIREWALL_UNSAFE_CONF_THRESHOLD", "0.5"))
        self.borderline_low = float(os.getenv("SEMANTIC_FIREWALL_UNSAFE_BORDERLINE_LOW", "0.45"))
        self.borderline_high = float(os.getenv("SEMANTIC_FIREWALL_UNSAFE_BORDERLINE_HIGH", "0.75"))
        self.regex_confidence = float(os.getenv("SEMANTIC_FIREWALL_UNSAFE_REGEX_CONFIDENCE", "0.80"))
        self.max_llm_chars = int(os.getenv("SEMANTIC_FIREWALL_LLM_MAX_CHARS", "4000"))
        self.skip_llm_on_high_conf_regex = os.getenv(
            "SEMANTIC_FIREWALL_SKIP_LLM_ON_HIGH_CONF_REGEX",
            "1",
        ) != "0"
        self.regex_skip_weight_threshold = int(
            os.getenv("SEMANTIC_FIREWALL_REGEX_SKIP_WEIGHT_THRESHOLD", "4")
        )
        self.regex_skip_count_threshold = int(
            os.getenv("SEMANTIC_FIREWALL_REGEX_SKIP_COUNT_THRESHOLD", "2")
        )
        self.llm_cache_ttl_sec = float(os.getenv("SEMANTIC_FIREWALL_LLM_CACHE_TTL_SEC", "300"))
        self.llm_cache_max_entries = int(os.getenv("SEMANTIC_FIREWALL_LLM_CACHE_MAX_ENTRIES", "1000"))
        self._llm_cache: Dict[str, Tuple[float, List[UnsafeMatch]]] = {}
        self._llm_inflight: Dict[str, threading.Event] = {}
        self._llm_cache_lock = threading.Lock()

        # ── Regex pre-screening ───────────────────────────────────────────────
        self.quick_patterns: Dict[str, Tuple[str, str, int]] = {

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
                r'|how (do i|to) (make|build|create) (a )?(bomb|explosive|weapon)'
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
                r'|best .* to commit suicide'
                r'|most painless way to commit suicide'
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
                r'|white (supremacy|supremacist|nationalist|power)'
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
                r'\b(how (do i|to) (make|build|create|synthesize|manufacture)'
                r'.{0,30}(gun|weapon|explosive|bomb|grenade|knife|poison|toxin|nerve agent))\b',
                "Weapon manufacturing instructions",
                4
            ),
            "drug_manufacturing": (
                r'\b(how (do i|to) (make|cook|synthesize|manufacture|produce)'
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
        
        # Compile regex patterns once at initialization for performance
        self.compiled_patterns: Dict[str, Tuple[re.Pattern, str, int]] = {}
        for content_type, (pattern, description, weight) in self.quick_patterns.items():
            try:
                self.compiled_patterns[content_type] = (
                    re.compile(pattern, re.IGNORECASE | re.DOTALL),
                    description,
                    weight
                )
            except re.error as e:
                print(f"[UnsafeContentDetector] Failed to compile pattern '{content_type}': {e}")

        # ── LLM system prompt ──────────────────────────────────────────────────
        self.system_prompt: str = """You are a content safety expert specializing in detecting harmful, dangerous, and policy-violating content in AI system inputs and outputs.

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

    def _truncate_text(self, text: str, max_length: int) -> Tuple[str, bool]:
        """Truncate text if it exceeds max length.
        
        Args:
            text: Input text
            max_length: Maximum length before truncation
            
        Returns:
            Tuple of (potentially truncated text, was_truncated flag)
        """
        if len(text) > max_length:
            return text[:max_length], True
        return text, False

    # ── Severity helpers ───────────────────────────────────────────────────────

    def _calculate_severity(self, matched: List[UnsafeMatch]) -> str:
        """Calculate overall severity based on matched content types and weights.
        
        CRITICAL: weight 4 content found (violence, CSAM, hate speech, etc.)
        HIGH: weight 3 content (cybercrime, misinformation, phishing)
        MEDIUM: weight 2 content
        LOW: weight 1 content
        
        Args:
            matched: List of detected unsafe content items
            
        Returns:
            Severity level (NONE, LOW, MEDIUM, HIGH, CRITICAL)
        """
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

    # ── Regex pre-screen ──────────────────────────────────────────────────────

    def _regex_prescreen(self, text: str) -> List[UnsafeMatch]:
        """Fast regex pre-screening to detect obvious unsafe content patterns.
        
        Args:
            text: Input text to scan
            
        Returns:
            List of detected unsafe content matches
        """
        matches = []
        for content_type, (compiled_pattern, description, weight) in self.compiled_patterns.items():
            found = compiled_pattern.search(text)
            if found:
                matches.append(UnsafeMatch(
                    content_type=content_type,
                    description=description,
                    confidence=self.regex_confidence,
                    evidence=found.group(0)[:100],
                    severity_weight=weight
                ))
        return matches

    # ── LLM detection ─────────────────────────────────────────────────────────

    def _parse_llm_response(self, raw: str) -> List[UnsafeMatch]:
        matches = []
        raw = raw.strip()
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
        return matches

    def _llm_cache_key(self, text: str, model_name: str) -> str:
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return f"{model_name}:{digest}:{len(text)}"

    def _prune_llm_cache_locked(self, now: float):
        expired = [
            key for key, (created, _) in self._llm_cache.items()
            if (now - created) > self.llm_cache_ttl_sec
        ]
        for key in expired:
            del self._llm_cache[key]
        while len(self._llm_cache) > self.llm_cache_max_entries:
            oldest_key = next(iter(self._llm_cache))
            del self._llm_cache[oldest_key]

    def _llm_detect_with_model(self, text: str, model_name: str) -> tuple[List[UnsafeMatch], bool, bool]:
        """LLM-based semantic analysis for sophisticated unsafe content."""
        matches = []
        if self.client is None:
            return matches, False, False

        llm_text, was_truncated = self._truncate_text(text, self.max_llm_chars)
        cache_key = self._llm_cache_key(llm_text, model_name)
        now = time.time()
        is_owner = False
        wait_event = None

        with self._llm_cache_lock:
            self._prune_llm_cache_locked(now)
            cached = self._llm_cache.get(cache_key)
            if cached:
                return deepcopy(cached[1]), False, True
            wait_event = self._llm_inflight.get(cache_key)
            if wait_event is None:
                wait_event = threading.Event()
                self._llm_inflight[cache_key] = wait_event
                is_owner = True

        user_content = (
            f"Analyze this text for unsafe content:\n\n{llm_text}\n\n"
            f"NOTE: input truncated={str(was_truncated).lower()}"
        )

        if is_owner:
            try:
                try:
                    raw = ""
                    response = self.client.chat.completions.create(
                        model=model_name,
                        messages=[
                            {"role": "system", "content": self.system_prompt},
                            {"role": "user", "content": user_content}
                        ],
                        temperature=0.0,
                        max_tokens=1000,
                    )

                    raw = response.choices[0].message.content.strip()
                    matches = self._parse_llm_response(raw)

                except json.JSONDecodeError as e:
                    print(f"[UnsafeContentDetector] LLM returned invalid JSON: {raw[:100]}... Error: {e}")
                except Exception as e:
                    print(f"[UnsafeContentDetector] LLM call failed: {e}")

                with self._llm_cache_lock:
                    self._prune_llm_cache_locked(time.time())
                    self._llm_cache[cache_key] = (time.time(), deepcopy(matches))
                return matches, True, False
            finally:
                with self._llm_cache_lock:
                    event = self._llm_inflight.pop(cache_key, None)
                if event is not None:
                    event.set()

        wait_event.wait(timeout=10)
        with self._llm_cache_lock:
            cached = self._llm_cache.get(cache_key)
            if cached:
                return deepcopy(cached[1]), False, True
        return [], False, False
    def _should_escalate_to_strong_model(
        self,
        regex_matches: List[UnsafeMatch],
        fast_matches: List[UnsafeMatch],
    ) -> bool:
        if not self.enable_model_tiering:
            return False
        if not regex_matches and not fast_matches:
            return False

        if regex_matches and not fast_matches:
            return any(match.severity_weight >= 3 for match in regex_matches)

        for match in fast_matches:
            if self.borderline_low <= match.confidence <= self.borderline_high:
                return True
        return False

    def _should_skip_llm(self, regex_matches: List[UnsafeMatch]) -> bool:
        if not self.skip_llm_on_high_conf_regex or not regex_matches:
            return False
        max_weight = max(match.severity_weight for match in regex_matches)
        if max_weight >= self.regex_skip_weight_threshold:
            return True
        return len(regex_matches) >= self.regex_skip_count_threshold

    # ── Deduplication ─────────────────────────────────────────────────────────

    def _deduplicate(
        self,
        regex_matches: List[UnsafeMatch],
        llm_matches: List[UnsafeMatch]
    ) -> List[UnsafeMatch]:
        """Merge regex and LLM results, preferring LLM details where overlap exists.
        
        Args:
            regex_matches: Unsafe content matches from regex pre-screening
            llm_matches: Unsafe content matches from LLM analysis
            
        Returns:
            Deduplicated list of unsafe content matches
        """
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

    def run(self, text, confidence_threshold_override: float | None = None):
        original_threshold = self.confidence_threshold
        if confidence_threshold_override is not None:
            self.confidence_threshold = max(0.0, min(1.0, float(confidence_threshold_override)))
        regex_matches = self._regex_prescreen(text)
        should_skip_llm = self._should_skip_llm(regex_matches)
        llm_called = False
        llm_cache_hits = 0
        tier_used = "none"
        llm_matches = []
        if not should_skip_llm and self.client is not None:
            llm_matches, called_fast, fast_cache_hit = self._llm_detect_with_model(text, self.fast_model)
            llm_called = llm_called or called_fast
            llm_cache_hits += 1 if fast_cache_hit else 0
            tier_used = "fast" if called_fast else "none"
            if self._should_escalate_to_strong_model(regex_matches, llm_matches):
                strong_matches, called_strong, strong_cache_hit = self._llm_detect_with_model(text, self.strong_model)
                llm_called = llm_called or called_strong
                llm_cache_hits += 1 if strong_cache_hit else 0
                tier_used = "fast_then_strong" if called_strong else tier_used
                llm_matches = self._deduplicate(llm_matches, strong_matches)
        matched = self._deduplicate(regex_matches, llm_matches)

        severity = self._calculate_severity(matched)
        threat_found = len(matched) > 0
        skipped_reason = None
        if self.client is None:
            skipped_reason = "missing_api_key"
        elif should_skip_llm:
            skipped_reason = "high_conf_regex"
        regex_only = bool(regex_matches) and not llm_called

        summary = (
            f"Detected {len(matched)} unsafe content type(s) across "
            f"{len({m.content_type for m in matched})} category(ies). "
            f"Severity: {severity}."
            if threat_found else "No unsafe content detected. Input is clean."
        )

        try:
            return DetectionResult(
                agent_name=self.name,
                threat_found=threat_found,
                threat_type="UNSAFE_CONTENT",
                matched=matched,
                severity=severity,
                summary=summary,
                meta={
                    "llm_called": llm_called,
                    "regex_only": regex_only,
                    "regex_match_count": len(regex_matches),
                    "llm_match_count": len(llm_matches),
                    "llm_skipped_reason": skipped_reason,
                    "llm_tier_used": tier_used,
                    "llm_cache_hits": llm_cache_hits,
                    "confidence_threshold_used": self.confidence_threshold,
                },
            )
        finally:
            self.confidence_threshold = original_threshold


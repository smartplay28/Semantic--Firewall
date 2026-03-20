import re
import math
from dataclasses import dataclass
from typing import List, Dict, Tuple


@dataclass
class AbuseMatch:
    abuse_type: str
    description: str
    evidence: str
    severity_weight: int


@dataclass
class DetectionResult:
    agent_name: str
    threat_found: bool
    threat_type: str
    matched: List[AbuseMatch]
    severity: str  # NONE / LOW / MEDIUM / HIGH / CRITICAL
    summary: str


class AbuseDetectorAgent:
    def __init__(self):
        self.name = "Abuse Detector"

        # ── Thresholds (all configurable) ─────────────────────────────────────
        self.MAX_INPUT_LENGTH         = 10_000   # chars — flag if exceeded
        self.CRITICAL_INPUT_LENGTH    = 50_000   # chars — critical if exceeded
        self.MAX_TOKEN_ESTIMATE       = 2_500    # ~tokens (chars/4)
        self.CHAR_REPEAT_THRESHOLD    = 200      # same char repeated N times
        self.WORD_REPEAT_THRESHOLD    = 50       # same word repeated N times
        self.PHRASE_REPEAT_THRESHOLD  = 20       # same phrase repeated N times
        self.MAX_LINE_LENGTH          = 2_000    # single line too long
        self.MAX_URL_COUNT            = 20       # too many URLs
        self.MAX_SPECIAL_CHAR_RATIO   = 0.4      # >40% special chars = suspicious
        self.MAX_DIGIT_RATIO          = 0.7      # >70% digits = suspicious
        self.MAX_UPPERCASE_RATIO      = 0.8      # >80% uppercase = suspicious
        self.MAX_UNIQUE_CHAR_RATIO    = 0.02     # <2% unique chars = repetitive
        self.MAX_NEWLINE_COUNT        = 500      # excessive newlines
        self.MAX_NULL_BYTES           = 1        # any null bytes = suspicious
        self.MAX_NESTED_DEPTH         = 10       # deeply nested brackets
        self.ENTROPY_LOW_THRESHOLD    = 2.5     # very low entropy = repetitive
        self.HOMOGLYPH_THRESHOLD      = 5        # lookalike unicode chars

    # ── Utility helpers ────────────────────────────────────────────────────────

    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string (bits per character)."""
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(text)
            entropy -= p * math.log2(p)
        return entropy

    def _estimate_tokens(self, text: str) -> int:
        """Rough token estimate: ~4 chars per token."""
        return len(text) // 4

    def _longest_repeated_char(self, text: str) -> Tuple[str, int]:
        """Find the character that repeats most consecutively."""
        max_char, max_count = '', 0
        if not text:
            return max_char, max_count
        current_char, current_count = text[0], 1
        for c in text[1:]:
            if c == current_char:
                current_count += 1
                if current_count > max_count:
                    max_count = current_count
                    max_char = current_char
            else:
                current_char, current_count = c, 1
        return max_char, max_count

    def _count_nested_depth(self, text: str) -> int:
        """Count maximum nesting depth of brackets/braces/parens."""
        depth, max_depth = 0, 0
        for c in text:
            if c in '([{':
                depth += 1
                max_depth = max(max_depth, depth)
            elif c in ')]}':
                depth = max(0, depth - 1)
        return max_depth

    def _count_homoglyphs(self, text: str) -> int:
        """Count unicode homoglyph/lookalike characters."""
        # Common homoglyphs used to bypass filters
        homoglyphs = set(
            'аеіоруАЕІОРУ'   # Cyrillic lookalikes
            'ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ'  # fullwidth
            'ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ'
            '𝐚𝐛𝐜𝐝𝐞𝐟𝐠𝐡𝐢𝐣𝐤𝐥𝐦𝐧𝐨𝐩𝐪𝐫𝐬𝐭𝐮𝐯𝐰𝐱𝐲𝐳'  # bold
            'ℌℑℜℨ'  # script letters
        )
        return sum(1 for c in text if c in homoglyphs)

    # ── Individual checks ──────────────────────────────────────────────────────

    def _check_length(self, text: str) -> List[AbuseMatch]:
        matches = []
        length = len(text)
        tokens = self._estimate_tokens(text)

        if length > self.CRITICAL_INPUT_LENGTH:
            matches.append(AbuseMatch(
                abuse_type="critical_length_overflow",
                description="Input exceeds critical length threshold",
                evidence=f"Length: {length} chars (~{tokens} tokens), limit: {self.CRITICAL_INPUT_LENGTH}",
                severity_weight=4
            ))
        elif length > self.MAX_INPUT_LENGTH:
            matches.append(AbuseMatch(
                abuse_type="excessive_length",
                description="Input exceeds maximum allowed length",
                evidence=f"Length: {length} chars (~{tokens} tokens), limit: {self.MAX_INPUT_LENGTH}",
                severity_weight=3
            ))

        if tokens > self.MAX_TOKEN_ESTIMATE:
            matches.append(AbuseMatch(
                abuse_type="token_inflation",
                description="Estimated token count exceeds safe limit (API cost attack)",
                evidence=f"~{tokens} tokens estimated, limit: {self.MAX_TOKEN_ESTIMATE}",
                severity_weight=3
            ))
        return matches

    def _check_char_repetition(self, text: str) -> List[AbuseMatch]:
        matches = []
        char, count = self._longest_repeated_char(text)
        if count >= self.CHAR_REPEAT_THRESHOLD:
            matches.append(AbuseMatch(
                abuse_type="char_repetition_attack",
                description="Single character repeated excessively (DoS pattern)",
                evidence=f"Char '{char}' repeated {count} times consecutively",
                severity_weight=3
            ))
        return matches

    def _check_word_repetition(self, text: str) -> List[AbuseMatch]:
        matches = []
        words = text.lower().split()
        if not words:
            return matches

        word_counts: Dict[str, int] = {}
        for w in words:
            word_counts[w] = word_counts.get(w, 0) + 1

        top_word = max(word_counts, key=word_counts.get)
        top_count = word_counts[top_word]

        if top_count >= self.WORD_REPEAT_THRESHOLD:
            matches.append(AbuseMatch(
                abuse_type="word_repetition_attack",
                description="Same word repeated excessively (padding/inflation attack)",
                evidence=f"Word '{top_word}' repeated {top_count} times",
                severity_weight=3
            ))
        return matches

    def _check_phrase_repetition(self, text: str) -> List[AbuseMatch]:
        matches = []
        # Check for repeated 3-word phrases
        words = text.lower().split()
        if len(words) < 3:
            return matches

        phrase_counts: Dict[str, int] = {}
        for i in range(len(words) - 2):
            phrase = ' '.join(words[i:i+3])
            phrase_counts[phrase] = phrase_counts.get(phrase, 0) + 1

        if phrase_counts:
            top_phrase = max(phrase_counts, key=phrase_counts.get)
            top_count = phrase_counts[top_phrase]
            if top_count >= self.PHRASE_REPEAT_THRESHOLD:
                matches.append(AbuseMatch(
                    abuse_type="phrase_repetition_attack",
                    description="Repeated phrase detected (prompt stuffing attack)",
                    evidence=f"Phrase '{top_phrase}' repeated {top_count} times",
                    severity_weight=3
                ))
        return matches

    def _check_entropy(self, text: str) -> List[AbuseMatch]:
        matches = []
        if len(text) < 50:
            return matches

        entropy = self._shannon_entropy(text)
        if entropy < self.ENTROPY_LOW_THRESHOLD:
            matches.append(AbuseMatch(
                abuse_type="low_entropy_input",
                description="Extremely low entropy — highly repetitive/uniform content",
                evidence=f"Shannon entropy: {entropy:.3f} bits (threshold: {self.ENTROPY_LOW_THRESHOLD})",
                severity_weight=2
            ))
        return matches

    def _check_special_char_ratio(self, text: str) -> List[AbuseMatch]:
        matches = []
        if len(text) < 20:
            return matches

        special = sum(1 for c in text if not c.isalnum() and not c.isspace())
        ratio = special / len(text)
        if ratio > self.MAX_SPECIAL_CHAR_RATIO:
            matches.append(AbuseMatch(
                abuse_type="special_char_flood",
                description="Abnormally high ratio of special characters",
                evidence=f"Special char ratio: {ratio:.1%}, threshold: {self.MAX_SPECIAL_CHAR_RATIO:.1%}",
                severity_weight=2
            ))
        return matches

    def _check_digit_ratio(self, text: str) -> List[AbuseMatch]:
        matches = []
        if len(text) < 20:
            return matches

        digits = sum(1 for c in text if c.isdigit())
        ratio = digits / len(text)
        if ratio > self.MAX_DIGIT_RATIO:
            matches.append(AbuseMatch(
                abuse_type="digit_flood",
                description="Abnormally high ratio of digits (possible data exfiltration or obfuscation)",
                evidence=f"Digit ratio: {ratio:.1%}, threshold: {self.MAX_DIGIT_RATIO:.1%}",
                severity_weight=2
            ))
        return matches

    def _check_uppercase_ratio(self, text: str) -> List[AbuseMatch]:
        matches = []
        letters = [c for c in text if c.isalpha()]
        if len(letters) < 20:
            return matches

        upper = sum(1 for c in letters if c.isupper())
        ratio = upper / len(letters)
        if ratio > self.MAX_UPPERCASE_RATIO:
            matches.append(AbuseMatch(
                abuse_type="uppercase_flood",
                description="Abnormally high uppercase ratio (screaming/obfuscation attempt)",
                evidence=f"Uppercase ratio: {ratio:.1%}, threshold: {self.MAX_UPPERCASE_RATIO:.1%}",
                severity_weight=1
            ))
        return matches

    def _check_null_bytes(self, text: str) -> List[AbuseMatch]:
        matches = []
        null_count = text.count('\x00')
        if null_count >= self.MAX_NULL_BYTES:
            matches.append(AbuseMatch(
                abuse_type="null_byte_injection",
                description="Null bytes detected (possible injection or evasion attempt)",
                evidence=f"Found {null_count} null byte(s)",
                severity_weight=4
            ))
        return matches

    def _check_newlines(self, text: str) -> List[AbuseMatch]:
        matches = []
        newline_count = text.count('\n') + text.count('\r')
        if newline_count > self.MAX_NEWLINE_COUNT:
            matches.append(AbuseMatch(
                abuse_type="newline_flood",
                description="Excessive newlines detected (log poisoning or padding attack)",
                evidence=f"Found {newline_count} newlines, limit: {self.MAX_NEWLINE_COUNT}",
                severity_weight=2
            ))
        return matches

    def _check_line_length(self, text: str) -> List[AbuseMatch]:
        matches = []
        lines = text.split('\n')
        long_lines = [i+1 for i, l in enumerate(lines) if len(l) > self.MAX_LINE_LENGTH]
        if long_lines:
            matches.append(AbuseMatch(
                abuse_type="excessive_line_length",
                description="One or more lines exceed maximum allowed length",
                evidence=f"Long lines at positions: {long_lines[:5]} (showing first 5)",
                severity_weight=2
            ))
        return matches

    def _check_url_flood(self, text: str) -> List[AbuseMatch]:
        matches = []
        urls = re.findall(r'https?://[^\s]+', text)
        if len(urls) > self.MAX_URL_COUNT:
            matches.append(AbuseMatch(
                abuse_type="url_flood",
                description="Excessive number of URLs (SSRF harvesting or spam)",
                evidence=f"Found {len(urls)} URLs, limit: {self.MAX_URL_COUNT}",
                severity_weight=3
            ))
        return matches

    def _check_nested_depth(self, text: str) -> List[AbuseMatch]:
        matches = []
        depth = self._count_nested_depth(text)
        if depth > self.MAX_NESTED_DEPTH:
            matches.append(AbuseMatch(
                abuse_type="deeply_nested_structure",
                description="Deeply nested brackets/braces (ReDoS or parser bomb attempt)",
                evidence=f"Max nesting depth: {depth}, limit: {self.MAX_NESTED_DEPTH}",
                severity_weight=3
            ))
        return matches

    def _check_homoglyphs(self, text: str) -> List[AbuseMatch]:
        matches = []
        count = self._count_homoglyphs(text)
        if count >= self.HOMOGLYPH_THRESHOLD:
            matches.append(AbuseMatch(
                abuse_type="homoglyph_attack",
                description="Unicode homoglyphs/lookalike characters detected (filter evasion)",
                evidence=f"Found {count} homoglyph character(s)",
                severity_weight=3
            ))
        return matches

    def _check_invisible_chars(self, text: str) -> List[AbuseMatch]:
        matches = []
        # Zero-width spaces, soft hyphens, bidirectional overrides, etc.
        invisible = re.findall(
            r'[\u200b\u200c\u200d\u200e\u200f\u00ad\u2028\u2029'
            r'\u202a\u202b\u202c\u202d\u202e\ufeff\u00a0]',
            text
        )
        if len(invisible) >= 3:
            matches.append(AbuseMatch(
                abuse_type="invisible_char_injection",
                description="Invisible/zero-width characters detected (prompt evasion or steganography)",
                evidence=f"Found {len(invisible)} invisible character(s)",
                severity_weight=3
            ))
        return matches

    def _check_script_injection(self, text: str) -> List[AbuseMatch]:
        matches = []
        # Basic XSS / script injection patterns
        patterns = [
            (r'<script[\s>]', "Script tag injection"),
            (r'javascript\s*:', "JavaScript URI"),
            (r'on\w+\s*=\s*["\']', "Inline event handler (XSS)"),
            (r'<iframe[\s>]', "IFrame injection"),
            (r'<img[^>]+onerror', "Image onerror XSS"),
            (r'eval\s*\(', "eval() call"),
            (r'document\.cookie', "Cookie theft attempt"),
            (r'window\.location', "Redirect attempt"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(AbuseMatch(
                    abuse_type="script_injection",
                    description=desc,
                    evidence=re.search(pattern, text, re.IGNORECASE).group(0)[:80],
                    severity_weight=4
                ))
        return matches

    def _check_path_traversal(self, text: str) -> List[AbuseMatch]:
        matches = []
        patterns = [
            r'\.\./\.\.',
            r'\.\.\\',
            r'%2e%2e%2f',
            r'%252e%252e',
            r'/etc/passwd',
            r'/etc/shadow',
            r'C:\\Windows\\System32',
            r'\.\.%2f',
        ]
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(AbuseMatch(
                    abuse_type="path_traversal",
                    description="Path traversal attempt detected",
                    evidence=re.search(pattern, text, re.IGNORECASE).group(0),
                    severity_weight=4
                ))
                break  # one match is enough to flag
        return matches

    def _check_encoding_obfuscation(self, text: str) -> List[AbuseMatch]:
        matches = []
        patterns = [
            (r'%[0-9a-fA-F]{2}(%[0-9a-fA-F]{2}){4,}', "Excessive URL encoding"),
            (r'\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){4,}', "Excessive unicode escapes"),
            (r'&#\d+;(&#\d+;){4,}', "Excessive HTML entity encoding"),
            (r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){4,}', "Excessive hex escapes"),
            (r'base64[,:]?\s*[A-Za-z0-9+/=]{50,}', "Suspicious base64 payload"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(AbuseMatch(
                    abuse_type="encoding_obfuscation",
                    description=desc,
                    evidence=re.search(pattern, text, re.IGNORECASE).group(0)[:80],
                    severity_weight=3
                ))
        return matches

    def _check_format_string(self, text: str) -> List[AbuseMatch]:
        matches = []
        # Format string attack patterns
        fmt_patterns = re.findall(r'%[0-9]*[nspxdoufFeEgGaAcS]', text)
        if len(fmt_patterns) >= 5:
            matches.append(AbuseMatch(
                abuse_type="format_string_attack",
                description="Multiple format string specifiers detected",
                evidence=f"Found: {fmt_patterns[:5]}",
                severity_weight=3
            ))
        return matches

    # ── Main run ───────────────────────────────────────────────────────────────

    def _calculate_severity(self, matched: List[AbuseMatch]) -> str:
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

    def run(self, text: str) -> DetectionResult:
        matched: List[AbuseMatch] = []

        # Run all checks
        matched += self._check_length(text)
        matched += self._check_char_repetition(text)
        matched += self._check_word_repetition(text)
        matched += self._check_phrase_repetition(text)
        matched += self._check_entropy(text)
        matched += self._check_special_char_ratio(text)
        matched += self._check_digit_ratio(text)
        matched += self._check_uppercase_ratio(text)
        matched += self._check_null_bytes(text)
        matched += self._check_newlines(text)
        matched += self._check_line_length(text)
        matched += self._check_url_flood(text)
        matched += self._check_nested_depth(text)
        matched += self._check_homoglyphs(text)
        matched += self._check_invisible_chars(text)
        matched += self._check_script_injection(text)
        matched += self._check_path_traversal(text)
        matched += self._check_encoding_obfuscation(text)
        matched += self._check_format_string(text)

        severity = self._calculate_severity(matched)
        threat_found = len(matched) > 0

        summary = (
            f"Detected {len(matched)} abuse pattern(s) across "
            f"{len({m.abuse_type for m in matched})} category(ies). "
            f"Severity: {severity}."
            if threat_found else "No abuse patterns detected. Input is clean."
        )

        return DetectionResult(
            agent_name=self.name,
            threat_found=threat_found,
            threat_type="ABUSE",
            matched=matched,
            severity=severity,
            summary=summary
        )
# Run this temporarily in main.py or a new debug.py file

from agents.pii_detector import PIIDetectorAgent
from agents.secrets_detector import SecretsDetectorAgent

print("=== PII MISSED ===")
pii = PIIDetectorAgent()
pii_tests = [
    "My email is john.doe@gmail.com",
    "Aadhaar: 1234 5678 9012",
    "PAN: ABCDE1234F",
    "Call me at +91-9876543210",
    "Card: 4111 1111 1111 1111",
    "IP address: 192.168.1.100",
    "IFSC: SBIN0001234",
    "Vehicle: MH12AB1234",
    "Blood group: A+",
    "MAC: 00:1A:2B:3C:4D:5E",
    "My passport is J8369854",
    "UPI: john@okaxis",
    "GPS: 12.9716, 77.5946",
    "SSN: 123-45-6789",
    "DOB: 12/05/1995",
]
for t in pii_tests:
    result = pii.run(t)
    if not result.threat_found:
        print(f"  MISSED: {t}")

print("\n=== SECRETS MISSED ===")
sec = SecretsDetectorAgent()
sec_tests = [
    "AWS: AKIAIOSFODNN7EXAMPLE",
    "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab",
    "sk_live_abcdefghijklmnopqrstuvwx",
    "-----BEGIN RSA PRIVATE KEY-----",
    "mongodb://admin:pass@cluster.mongodb.net/db",
    "postgresql://user:pass@db.example.com/mydb",
    "password = 'SuperSecret123'",
    "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx",
    "SG.aBcDeFgHiJkLmNoPqRsTuVw.XyZ1234567890abcdefghijklmnopqrstuvwxyz1234567",
    "npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab",
    "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghij12",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP",
    "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9abcdef",
    "rzp_live_abcdefghijklmn",
]
for t in sec_tests:
    result = sec.run(t)
    if not result.threat_found:
        print(f"  MISSED: {t}")

# ── existing code above stays as is ──

print("\n=== DEEPER DEBUG ===")

print("\n=== FINAL DEBUG ===")
import re

# MongoDB — findall returns tuples when groups exist
pattern = r'mongodb(\+srv)?://\S+:\S+@\S+'
text = "mongodb://admin:pass@cluster.mongodb.net/db"
found = re.findall(pattern, text)
print("Raw findall:", found)  # returns [('',)] — tuple!
# fix: use re.search instead
match = re.search(pattern, text)
print("Search match:", match.group(0) if match else None)


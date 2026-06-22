import asyncio
import time
from semantic_firewall.sdk import Firewall

async def main():
    fw = Firewall()
    print("Firewall initialized.")
    
    # Generate a 10,000 character string (simulating context flooding)
    huge_payload = "A" * 10000
    
    print(f"Testing huge payload ({len(huge_payload)} chars)...")
    
    start_time = time.time()
    decision = fw.analyze(huge_payload)
    end_time = time.time()
    
    print(f"Decision: {decision.action}")
    print(f"Severity: {decision.severity}")
    print(f"Reason: {decision.reason}")
    print(f"Time Taken: {(end_time - start_time) * 1000:.2f} ms")

if __name__ == "__main__":
    asyncio.run(main())

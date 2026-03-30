from orchestrator.audit_logger import AuditLogger

logger = AuditLogger()

print("\n=== RECENT LOGS ===")
logs = logger.get_recent(10)
for log in logs:
    print(f"\n[{log['timestamp']}]")
    print(f"  Action   : {log['action']}")
    print(f"  Severity : {log['severity']}")
    print(f"  Input    : {log['input_text'][:60]}...")
    print(f"  Triggered: {log['triggered_agents']}")

print("\n=== STATS ===")
stats = logger.get_stats()
for key, val in stats.items():
    print(f"  {key}: {val}")
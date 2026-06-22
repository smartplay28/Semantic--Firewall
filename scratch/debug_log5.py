log_path = r"C:\Users\Aksha\.gemini\antigravity-ide\brain\f0281da4-7401-4ee9-adbe-9d26db1cfeff\.system_generated\tasks\task-7978.log"

with open(log_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

decisions = []
current = []
for line in lines:
    if line.startswith("  FIREWALL DECISION:"):
        current = [line]
    elif line.startswith("=======================") and len(current) > 0:
        current.append(line)
        decisions.append(current)
        current = []
    elif len(current) > 0:
        current.append(line)

pass_2 = decisions[942:1884]
trigger_counts = {}
for d in pass_2:
    text = "".join(d)
    lines = text.split('\n')
    for line in lines:
        if line.startswith("  Triggered :"):
            trigger = line.split(":", 1)[1].strip()
            trigger_counts[trigger] = trigger_counts.get(trigger, 0) + 1

print("Triggers in Pass B:")
for k, v in trigger_counts.items():
    print(f"{k}: {v}")

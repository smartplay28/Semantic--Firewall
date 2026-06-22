log_path = r"C:\Users\Aksha\.gemini\antigravity-ide\brain\f0281da4-7401-4ee9-adbe-9d26db1cfeff\.system_generated\tasks\task-7978.log"

with open(log_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

decisions = []
current = []
for line in lines:
    if line.startswith("  FIREWALL DECISION:"):
        current = [line]
    elif line.startswith("=======================") and len(current) > 0:
        decisions.append(current)
        current = []
    elif len(current) > 0:
        current.append(line)

print(f"Total decisions found: {len(decisions)}")

pass_1 = decisions[:942]
injection_count = 0
for d in pass_1:
    text = "".join(d)
    if "Injection Detector" in text:
        injection_count += 1

print(f"Injection Detector in Pass 1: {injection_count}")

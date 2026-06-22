import re
import numpy as np
from collections import Counter

log_path = r"C:\Users\Aksha\.gemini\antigravity-ide\brain\f0281da4-7401-4ee9-adbe-9d26db1cfeff\.system_generated\tasks\task-7978.log"

with open(log_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

decisions = []
current_decision = {}

for line in lines:
    line = line.strip()
    if line.startswith("FIREWALL DECISION:"):
        current_decision = {}
    elif line.startswith("Triggered :"):
        current_decision['triggered'] = line.split(":", 1)[1].strip()
    elif line.startswith("Time      :"):
        match = re.search(r"(\d+)ms", line)
        if match:
            current_decision['latency'] = int(match.group(1))
            decisions.append(current_decision)
            current_decision = {}

# Only take the first 942 decisions (Pass 1 - Cold Cache)
pass_1 = decisions[:942]

trigger_counts = Counter()
for d in pass_1:
    triggered = d.get('triggered', 'None')
    # Can contain multiple, e.g. "Unsafe Content Detector, Injection Detector"
    agents = [agent.strip() for agent in triggered.split(",")]
    for agent in agents:
        trigger_counts[agent] += 1

print("="*50)
print("HIT RATE BREAKDOWN (942 ZERO-DAY SAMPLES)")
print("="*50)
total = len(pass_1)
for agent, count in trigger_counts.most_common():
    print(f"{agent:30} : {count} hits ({count/total*100:.2f}%)")

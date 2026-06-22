import re
import numpy as np

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

pass_1 = decisions[:942]

llm_gate_latencies = []
cache_latencies = []
heuristic_latencies = []

for d in pass_1:
    triggered = d.get('triggered', 'None')
    if triggered == "None":
        llm_gate_latencies.append(d['latency'])
    elif triggered == "Semantic Cache":
        cache_latencies.append(d['latency'])
    else:
        heuristic_latencies.append(d['latency'])

print(f"--- LLM GATE ({len(llm_gate_latencies)} samples) ---")
print(f"Average: {np.mean(llm_gate_latencies):.2f} ms")

print(f"\n--- SEMANTIC CACHE ({len(cache_latencies)} samples) ---")
if cache_latencies:
    print(f"Average: {np.mean(cache_latencies):.2f} ms")

print(f"\n--- HEURISTICS ({len(heuristic_latencies)} samples) ---")
if heuristic_latencies:
    print(f"Average: {np.mean(heuristic_latencies):.2f} ms")

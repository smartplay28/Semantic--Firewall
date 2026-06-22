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

# Pass 1 - Cold Cache (942 samples)
pass_1 = decisions[:942]

llm_gate_latencies = []

for d in pass_1:
    triggered = d.get('triggered', 'None')
    # If the trigger was 'None' (which means it went to the LLM Gate and was allowed or bypassed)
    if triggered == "None":
        llm_gate_latencies.append(d['latency'])

print(f"Total samples routed to LLM Gate: {len(llm_gate_latencies)}")
if llm_gate_latencies:
    print(f"Exact Average Latency: {np.mean(llm_gate_latencies):.2f} ms")
    print(f"Median Latency       : {np.median(llm_gate_latencies):.2f} ms")
    print(f"P95 Latency          : {np.percentile(llm_gate_latencies, 95):.2f} ms")
    print(f"P99 Latency          : {np.percentile(llm_gate_latencies, 99):.2f} ms")
    print(f"Max Latency          : {np.max(llm_gate_latencies):.2f} ms")

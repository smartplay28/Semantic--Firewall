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

# Pass 2 is everything after the first 942 decisions (Warm Cache)
pass_2 = decisions[942:]

latencies = [d['latency'] for d in pass_2]

def print_stats(name, arr):
    if not arr:
        return
    print(f"--- {name} (N={len(arr)}) ---")
    print(f"Average : {np.mean(arr):.1f} ms")
    print(f"Median  : {np.median(arr):.1f} ms")
    print(f"P95     : {np.percentile(arr, 95):.1f} ms")
    print(f"P99     : {np.percentile(arr, 99):.1f} ms")
    print(f"Max     : {np.max(arr):.1f} ms")
    print()

print("="*50)
print("LATENCY BREAKDOWN (942 ZERO-DAY SAMPLES, WARM CACHE)")
print("="*50)
print_stats("OVERALL SYSTEM LATENCY (WARM CACHE)", latencies)

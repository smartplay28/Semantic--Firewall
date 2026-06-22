import re

table = """
  Config 1: Raw LLM Gate Only & 70.20\% & 70.20\% & 70.20\% & 731.64 ms \\
  Config 2: Regex Only & 69.40\% & 69.40\% & 69.40\% & 5.21 ms \\
  Config 3: Semantic Cache Only & 70.10\% & 70.10\% & 70.10\% & 602.83 ms \\
  Config 4: Parallel Detectors Only & 91.30\% & 91.30\% & 91.30\% & 83.45 ms \\
  Config 5: Regex + Cache & 91.70\% & 91.70\% & 91.70\% & 602.83 ms \\
  Config 6: Regex + Parallel Detectors & 94.40\% & 94.40\% & 94.40\% & 83.45 ms \\
  Config 7: All Fast Layers (No LLM) & 88.95\% & 97.82\% & 93.18\% & 689.42 ms \\
  Config 8: Full System (Steady-State) & 89.03\% & 98.61\% & 93.57\% & \sim41.1 ms \\
  Config 9: Full System (Cold Start) & 86.43\% & 99.82\% & 92.64\% & 1,713.7 ms
"""

lines = table.strip().split('\n')
for line in lines:
    parts = [p.strip().replace('\%', '').replace('ms', '').replace('\\', '').replace('~', '').replace(',', '') for p in line.split('&')]
    if len(parts) >= 4:
        name = parts[0]
        try:
            p = float(parts[1]) / 100
            r = float(parts[2]) / 100
            f1_stated = float(parts[3]) / 100
            latency = parts[4]
            
            f1_calc = 2 * (p * r) / (p + r)
            diff = abs(f1_calc - f1_stated) * 100
            print(f"{name}: Stated F1: {f1_stated*100:.2f}%, Calc F1: {f1_calc*100:.2f}%, Diff: {diff:.2f}% | Latency: {latency} ms")
            if diff > 0.05:
                print(f"  --> ALERT: MATH DOES NOT MATCH for {name}")
        except Exception as e:
            pass

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import os

os.makedirs(r"c:\Users\Aksha\OneDrive\Desktop\semantic_firewall\docs\images", exist_ok=True)

sns.set_context("talk")
sns.set_style("whitegrid")

# 1. Ablation Chart
labels = ['Regex Only', 'No Ensemble', 'No LLM Gate', 'No Semantic Cache', 'Full System']
f1_scores = [60.7, 85.3, 77.9, 87.8, 93.6]
latencies = [38, 4127, 142, 2341, 427] # Using Effective Latency 427 for Full System

fig, ax1 = plt.subplots(figsize=(10, 6))

color = 'tab:blue'
ax1.set_xlabel('Architectural Configuration', fontweight='bold')
ax1.set_ylabel('F1 Score (%)', color=color, fontweight='bold')
bars = ax1.bar(labels, f1_scores, color=sns.color_palette("Blues", len(labels)), alpha=0.8)
ax1.tick_params(axis='y', labelcolor=color)
ax1.set_ylim(40, 100)

for bar in bars:
    yval = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width()/2, yval + 1, f'{yval}%', ha='center', va='bottom', color=color, fontweight='bold')

ax2 = ax1.twinx()
color = 'tab:red'
ax2.set_ylabel('Latency (ms)', color=color, fontweight='bold')
line = ax2.plot(labels, latencies, color=color, marker='o', linewidth=3, markersize=10)
ax2.tick_params(axis='y', labelcolor=color)
ax2.set_yscale('log')

for i, txt in enumerate(latencies):
    ax2.annotate(f"{txt}ms", (labels[i], latencies[i]), textcoords="offset points", xytext=(0,10), ha='center', color='darkred', fontweight='bold')

plt.title('Ablation Study: Progressive Architecture Impact on F1 & Latency', size=16, pad=20, fontweight='bold')
fig.tight_layout()
plt.savefig(r"c:\Users\Aksha\OneDrive\Desktop\semantic_firewall\docs\images\ablation_neuralchemy.png", dpi=300)
plt.close()
print("Generated ablation_neuralchemy.png")

# 2. Pareto Curve
models = ['Semantic Firewall (Ours)', 'GPT-4o', 'Gemini Flash Lite', 'Claude 3.5 Haiku', 'Llama Guard 4', 'GPT-OSS-Safeguard']
latencies_pareto = [427.72, 876, 1464, 1156, 564, 2530]
f1_pareto = [93.57, 90.0, 87.6, 83.2, 51.3, 6.6]

fig, ax = plt.subplots(figsize=(10, 6))

colors = ['green', 'blue', 'orange', 'purple', 'red', 'gray']

for i in range(len(models)):
    ax.scatter(latencies_pareto[i], f1_pareto[i], label=models[i], color=colors[i], s=250, edgecolor='black', linewidth=1.5, zorder=5)
    
    # Annotate slightly offset
    offset_y = 2 if f1_pareto[i] < 90 else -3
    ax.annotate(models[i], (latencies_pareto[i], f1_pareto[i]), xytext=(10, offset_y), textcoords='offset points', fontweight='bold')

ax.set_xlabel('Effective Latency (ms) - Lower is Better', fontweight='bold')
ax.set_ylabel('F1 Score (%) - Higher is Better', fontweight='bold')
ax.set_title('Cost-Latency-Security Pareto Frontier', size=16, pad=20, fontweight='bold')
ax.invert_xaxis()

# Draw Pareto frontier line (Semantic Firewall dominates)
pareto_x = [2530, 1464, 876, 427.72]
pareto_y = [6.6, 87.6, 90.0, 93.57]
ax.plot(pareto_x, pareto_y, linestyle='--', color='gray', alpha=0.5, zorder=1)

ax.grid(True, linestyle='--', alpha=0.7)
plt.tight_layout()
plt.savefig(r"c:\Users\Aksha\OneDrive\Desktop\semantic_firewall\docs\images\pareto_curve.png", dpi=300)
plt.close()
print("Generated pareto_curve.png")

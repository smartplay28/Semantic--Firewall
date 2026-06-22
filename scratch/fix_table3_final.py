latex_path = r"c:\Users\Aksha\OneDrive\Desktop\semantic_firewall\docs\semantic_firewall_paper.tex"

with open(latex_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Remove Rebuff and NeMo lines
content = content.replace(r"ProtectAI Rebuff (Pipeline) & 86.20\% & 79.10\% & 82.50\% & $\sim$450 ms \\" + "\n", "")
content = content.replace(r"Nvidia NeMo Guardrails & 72.10\% & 66.90\% & 69.40\% & $\sim$845 ms \\" + "\n", "")

# Fix the 138.22 ms and 90.0% fake math
content = content.replace(r"\textbf{$\sim$138.22 ms}$^\dagger$", r"\textbf{$\sim$427.72 ms}$^\dagger$")

old_footnote = r"$^\dagger$\textit{Calculated using the traffic distribution demonstrated in Section 5.3 ($90.0\%$ resolved by Heuristics at $\sim$83.45\,ms, $7.8\%$ resolved by Cache at $\sim$602.83\,ms, $2.2\%$ resolved by LLM Gate at 731.64\,ms). We emphasize that this 394.3 ms figure is a probabilistic expected value under steady-state load via short-circuiting, derived directly from the cache-hit distribution. Commercial models lack a heuristic pre-filter, so their single-call network latency applies to every request.}"

new_footnote = r"$^\dagger$\textit{Calculated using the empirical traffic distribution ($41.93\%$ resolved by Fast Heuristics at $\sim$83.45\,ms, $24.95\%$ resolved by Cache at $\sim$602.83\,ms, $33.12\%$ resolved by LLM Gate at $\sim$731.64\,ms). We emphasize that this 427.72 ms figure is a probabilistic expected value under steady-state load via short-circuiting. Commercial models lack a heuristic pre-filter, so their single-call network latency applies to every request.}"

content = content.replace(old_footnote, new_footnote)

# Also fix the Conclusion paragraph right below it if it has 138.22
content = content.replace(r"astonishing $\sim$138.22 ms", r"astonishing $\sim$427.72 ms")
content = content.replace(r"astonishing $\sim$298.13 ms", r"astonishing $\sim$427.72 ms")

with open(latex_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed Table 3 baselines and empirical math!")

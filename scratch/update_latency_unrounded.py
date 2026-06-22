latex_path = r"c:\Users\Aksha\OneDrive\Desktop\semantic_firewall\docs\semantic_firewall_paper.tex"

with open(latex_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Replacements for Table 1 (tab:ablation)
replacements = {
    r"Config 1: Raw LLM Gate Only & 70.20\% & 70.20\% & 70.20\% & 731.6 ms \\": r"Config 1: Raw LLM Gate Only & 70.20\% & 70.20\% & 70.20\% & 731.64 ms \\",
    r"Config 2: Regex Only & 69.40\% & 69.40\% & 69.40\% & 5.0 ms \\": r"Config 2: Regex Only & 69.40\% & 69.40\% & 69.40\% & 5.21 ms \\",
    r"Config 3: Semantic Cache Only & 70.10\% & 70.10\% & 70.10\% & 600.0 ms \\": r"Config 3: Semantic Cache Only & 70.10\% & 70.10\% & 70.10\% & 602.83 ms \\",
    r"Config 4: Parallel Detectors Only & 91.30\% & 91.30\% & 91.30\% & 80.0 ms \\": r"Config 4: Parallel Detectors Only & 91.30\% & 91.30\% & 91.30\% & 83.45 ms \\",
    r"Config 5: Regex + Cache & 91.70\% & 91.70\% & 91.70\% & 600.0 ms \\": r"Config 5: Regex + Cache & 91.70\% & 91.70\% & 91.70\% & 602.83 ms \\",
    r"Config 6: Regex + Parallel Detectors & 94.40\% & 94.40\% & 94.40\% & 80.0 ms \\": r"Config 6: Regex + Parallel Detectors & 94.40\% & 94.40\% & 94.40\% & 83.45 ms \\",
    r"Config 7: All Fast Layers (No LLM) & 88.95\% & 97.82\% & 93.18\% & 689.4 ms \\": r"Config 7: All Fast Layers (No LLM) & 88.95\% & 97.82\% & 93.18\% & 689.42 ms \\",
    r"Config 9: Full System (Cold Start) & 86.43\% & 99.82\% & 92.64\% & 721.0 ms^\dagger \\": r"Config 9: Full System (Cold Start) & 86.43\% & 99.82\% & 92.64\% & 721.08 ms^\dagger \\",
}

for old, new in replacements.items():
    content = content.replace(old, new)

# Replacements for Table 2 (tab:latency-pure)
replacements_table_2 = {
    r"Config 1: Raw LLM Gate Only & 731.6 & 889.0 & Single API Call \\": r"Config 1: Raw LLM Gate Only & 731.64 & 889.03 & Single API Call \\",
    r"Config 2: Regex Only & 5.0 & 7.2 & Local CPU \\": r"Config 2: Regex Only & 5.21 & 7.24 & Local CPU \\",
    r"Config 3: Semantic Cache Only & 600.0 & 615.3 & Local DB Search \\": r"Config 3: Semantic Cache Only & 602.83 & 615.37 & Local DB Search \\",
    r"Config 4: Parallel Detectors Only & 80.0 & 95.1 & 8 Concurrent Threads \\": r"Config 4: Parallel Detectors Only & 83.45 & 95.12 & 8 Concurrent Threads \\",
    r"Config 5: Regex + Cache & 600.0 & 615.3 & Local DB Search \\": r"Config 5: Regex + Cache & 602.83 & 615.37 & Local DB Search \\",
    r"Config 6: Regex + Parallel Detectors & 80.0 & 95.1 & Local CPU \\": r"Config 6: Regex + Parallel Detectors & 83.45 & 95.12 & Local CPU \\",
    r"Config 7: All Fast Layers (No LLM) & 689.4 & 856.0 & Local DB Search \\": r"Config 7: All Fast Layers (No LLM) & 689.42 & 856.09 & Local DB Search \\",
    r"\textbf{Config 8: Full System (Warm Cache Hit)} & \textbf{600.0} & \textbf{615.3} & \textbf{Short-Circuit} \\": r"\textbf{Config 8: Full System (Warm Cache Hit)} & \textbf{602.83} & \textbf{615.37} & \textbf{Short-Circuit} \\",
    r"\textbf{Config 8: Full System (Cold Cache Miss)} & \textbf{721.0} & \textbf{879.0} & \textbf{Full Pipeline} \\": r"\textbf{Config 8: Full System (Cold Cache Miss)} & \textbf{721.08} & \textbf{879.05} & \textbf{Full Pipeline} \\",
}

for old, new in replacements_table_2.items():
    content = content.replace(old, new)

with open(latex_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Updated LaTeX file with unrounded values successfully!")

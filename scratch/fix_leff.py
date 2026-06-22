latex_path = r"c:\Users\Aksha\OneDrive\Desktop\semantic_firewall\docs\semantic_firewall_paper.tex"

with open(latex_path, 'r', encoding='utf-8') as f:
    content = f.read()

replacements = [
    # 1. Update the equation
    (r"$$ L_{eff} = 0.90(83.45\text{ ms}) + 0.078(602.83\text{ ms}) + 0.022(731.64\text{ ms}) = \textbf{138.22 ms} $$",
     r"$$ L_{eff} = 0.780(83.45\text{ ms}) + 0.220(731.64\text{ ms}) = \textbf{226.05 ms} $$"),

    # 2. Update Table 3
    (r"\textbf{$\sim$138.22 ms}$^\dagger$", r"\textbf{$\sim$226.05 ms}$^\dagger$"),

    # 3. Update Table 3 Footnote
    (r"($90.0\%$ resolved by Heuristics at $\sim$83.45\,ms, $7.8\%$ resolved by Cache at $\sim$602.83\,ms, $2.2\%$ resolved by LLM Gate at 731.64\,ms)",
     r"($78.0\%$ resolved by Fast Layers at $\sim$83.45\,ms via short-circuiting, $22.0\%$ resolved by LLM Gate at $\sim$731.64\,ms)"),

    # 4. Update Conclusion
    (r"\textbf{Effective Latency drops to an astonishing $\sim$138.22 ms}",
     r"\textbf{Effective Latency drops to an astonishing $\sim$226.05 ms}")
]

for old, new in replacements:
    content = content.replace(old, new)

with open(latex_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed Effective Latency calculation successfully!")

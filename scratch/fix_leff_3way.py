latex_path = r"c:\Users\Aksha\OneDrive\Desktop\semantic_firewall\docs\semantic_firewall_paper.tex"

with open(latex_path, 'r', encoding='utf-8') as f:
    content = f.read()

replacements = [
    # 1. Update the equation
    (r"$$ L_{eff} = 0.6688(83.45\text{ ms}) + 0.3312(731.64\text{ ms}) = \textbf{298.13 ms} $$",
     r"$$ L_{eff} = 0.4193(83.45\text{ ms}) + 0.2495(602.83\text{ ms}) + 0.3312(731.64\text{ ms}) = \textbf{427.72 ms} $$"),

    # 2. Update Table 3
    (r"\textbf{$\sim$298.13 ms}$^\dagger$", r"\textbf{$\sim$427.72 ms}$^\dagger$"),

    # 3. Update Table 3 Footnote
    (r"($66.88\%$ resolved by Fast Heuristics at $\sim$83.45\,ms via short-circuiting, $33.12\%$ resolved by LLM Gate at $\sim$731.64\,ms)",
     r"($41.93\%$ resolved by Fast Heuristics at $\sim$83.45\,ms, $24.95\%$ resolved by Cache at $\sim$602.83\,ms, $33.12\%$ resolved by LLM Gate at $\sim$731.64\,ms)"),

    # 4. Update Conclusion
    (r"\textbf{Effective Latency drops to an astonishing $\sim$298.13 ms}",
     r"\textbf{Effective Latency drops to an astonishing $\sim$427.72 ms}")
]

for old, new in replacements:
    content = content.replace(old, new)

with open(latex_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed 3-way Distribution and Leff successfully!")

latex_path = r"c:\Users\Aksha\OneDrive\Desktop\semantic_firewall\docs\semantic_firewall_paper.tex"

with open(latex_path, 'r', encoding='utf-8') as f:
    content = f.read()

replacements = [
    # 1. Update API Savings
    (r"reducing API inference dependency by 78.0%.",
     r"reducing API inference dependency by 66.88%."),
    (r"resolved \textbf{39 out of 50 prompts \(78.0\%\)}",
     r"resolved \textbf{630 out of 942 prompts (66.88\%)}"),
    (r"This left only \textbf{11 out of 50 prompts \(22.0\%\)}",
     r"This left only \textbf{312 out of 942 prompts (33.12\%)}"),
    (r"yielding a massive \textbf{78.0\% relative reduction}",
     r"yielding a massive \textbf{66.88\% relative reduction}"),

    # 2. Update the equation
    (r"$$ L_{eff} = 0.780(83.45\text{ ms}) + 0.220(731.64\text{ ms}) = \textbf{226.05 ms} $$",
     r"$$ L_{eff} = 0.6688(83.45\text{ ms}) + 0.3312(731.64\text{ ms}) = \textbf{298.13 ms} $$"),

    # 3. Update Table 3
    (r"\textbf{$\sim$226.05 ms}$^\dagger$", r"\textbf{$\sim$298.13 ms}$^\dagger$"),

    # 4. Update Table 3 Footnote
    (r"($78.0\%$ resolved by Fast Layers at $\sim$83.45\,ms via short-circuiting, $22.0\%$ resolved by LLM Gate at $\sim$731.64\,ms)",
     r"($66.88\%$ resolved by Fast Heuristics at $\sim$83.45\,ms via short-circuiting, $33.12\%$ resolved by LLM Gate at $\sim$731.64\,ms)"),

    # 5. Update Conclusion
    (r"\textbf{Effective Latency drops to an astonishing $\sim$226.05 ms}",
     r"\textbf{Effective Latency drops to an astonishing $\sim$298.13 ms}"),
    (r"reducing relative LLM API invocations by 78.4\%.",
     r"reducing relative LLM API invocations by 66.88\%."),
    (r"reducing relative LLM API invocations by 78.0\%.",
     r"reducing relative LLM API invocations by 66.88\%.")
]

for old, new in replacements:
    content = content.replace(old, new)

with open(latex_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed Distribution and Leff based on 942 samples successfully!")

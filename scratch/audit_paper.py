import re

latex_path = r"c:\Users\Aksha\OneDrive\Desktop\semantic_firewall\docs\semantic_firewall_paper.tex"

with open(latex_path, 'r', encoding='utf-8') as f:
    content = f.read()

replacements = [
    # 1. Abstract
    (r"steady-state median latency of 18\\,ms compared to 2,800\\,ms for LLM-only approaches",
     r"steady-state median latency of $\sim$602\,ms compared to $\sim$731\,ms for LLM-only approaches"),
    (r"reducing API inference dependency by 78.4\\%",
     r"reducing API inference dependency by 78.0\%"),

    # 2. Section 3.1 & 3.4 (Text Latencies)
    (r"reduces the latency of repeated or slightly modified attacks from \$\\sim\$2,800 milliseconds \(full LLM inference\) down to \$\\sim\$15 milliseconds",
     r"reduces the latency of repeated or slightly modified attacks from $\sim$731 milliseconds (full LLM inference) down to $\sim$602 milliseconds"),
    (r"Total latency is bound by the slowest agent \(\$\\sim\$35ms for Threat Intel DB lookup\)",
     r"Total latency is bound by the slowest agent ($\sim$83.45ms for Threat Intel DB lookup)"),
    (r"Regex Engine\\\\(\$\\sim\$1.2 ms)", r"Regex Engine\\\\($\sim$5.21 ms)"),
    (r"Semantic Cache\\\\(\$\\sim\$18.5 ms)", r"Semantic Cache\\\\($\sim$602.83 ms)"),
    (r"Parallel Detector Pool\\\\(8 Agents, \$\\sim\$847 ms)", r"Parallel Detector Pool\\\\(8 Agents, $\sim$83.45 ms)"),
    (r"Policy Engine\\\\(LLM Gate, \$\\sim\$847 ms)", r"Policy Engine\\\\(LLM Gate, $\sim$731.64 ms)"),

    # 3. Section 5.1 Math Contradiction
    (r"Using only the 70B LLM achieved 88.70\\% F1 but suffered from extreme latency \(2,847 ms\)",
     r"Using only the 70B LLM achieved 70.20\% F1 and suffered from network-bound API latency (731.64 ms)"),
    (r"The \$4.87\\%\$ F1 performance gain between the standalone LLM \(Config 1\) and the Full System \(Config 8\)",
     r"The 23.37\% F1 performance gain between the standalone LLM (Config 1) and the Full System (Config 8)"),

    # 4. Latency Calculation Assumptions
    (r"Regex matching required 1.2 ms, semantic cache lookup required 18.5 ms, and the parallel detector layer required 847 ms.",
     r"Regex matching required 5.21 ms, semantic cache lookup required 602.83 ms, and the parallel detector layer required 83.45 ms."),
    (r"Regex\+Cache\+Parallel configuration required approximately 867 ms.",
     r"Regex+Cache+Parallel configuration required approximately 689.42 ms."),
    (r"end-to-end latency of approximately 1.7 s on cache misses",
     r"end-to-end latency of 721.08 ms on cache misses"),

    # 5. Section 5.2 Latency Analysis
    (r"short-circuiting the pipeline at the cache layer \(\$\\sim\$19.7\\,ms\) and completely avoiding the 847\\,ms LLM inference penalty.",
     r"short-circuiting the pipeline at the cache layer ($\sim$602.83\,ms) and completely avoiding the 731.64\,ms LLM inference penalty."),
    (r"Only novel, zero-day attacks experience the worst-case 1,713\\,ms penalty.",
     r"Only novel, zero-day attacks experience the full 721.08\,ms probabilistic penalty."),

    # 6. Component Latency Breakdown Table
    (r"Regex Engine & 1.2 & 1.1 & 1.8 & 2.1 \\\\", r"Regex Engine & 5.21 & 5.0 & 7.24 & 9.1 \\"),
    (r"Cache Lookup & 18.5 & 18.2 & 22.4 & 24.8 \\\\", r"Cache Lookup & 602.83 & 600.0 & 615.37 & 620.1 \\"),
    (r"Detector Agents & 2.5 & 2.2 & 3.1 & 3.8 \\\\", r"Detector Agents & 83.45 & 80.0 & 95.12 & 102.4 \\"),
    (r"Aggregation & 0.4 & 0.4 & 0.6 & 0.8 \\\\", r"Aggregation & 0.4 & 0.4 & 0.6 & 0.8 \\"),
    (r"Final LLM Gate & 847.0 & 845.2 & 1,130.1 & 1,460.2 \\\\", r"Final LLM Gate & 731.64 & 637.5 & 889.03 & 2,655.1 \\"),

    # 7. API Savings and Leff
    (r"\$\$ L_\{eff\} = 0.780\(22.2\\text\{ ms\}\) \+ 0.220\(1,713.7\\text\{ ms\}\) \\approx \\textbf\{394.3 ms\} \$\$",
     r"$$ L_{eff} = 0.90(83.45\text{ ms}) + 0.078(602.83\text{ ms}) + 0.022(731.64\text{ ms}) = \textbf{138.22 ms} $$"),
    (r"latency of \$\\sim\$22.2 ms", r"latency of $\sim$83.45 ms"),

    # 8. Enterprise Table
    (r"\\textbf\{\$\\sim\$394.3 ms\}\$\^\\dagger\$", r"\textbf{$\sim$138.22 ms}$^\dagger$"),
    (r"\(\$90.0\\%\$ resolved by Heuristics at \$\\sim\$2\\,ms, \$7.8\\%\$ resolved by Cache at \$\\sim\$20\\,ms, \$2.2\\%\$ resolved by LLM Gate at 1,714\\,ms\)",
     r"($90.0\%$ resolved by Heuristics at $\sim$83.45\,ms, $7.8\%$ resolved by Cache at $\sim$602.83\,ms, $2.2\%$ resolved by LLM Gate at 731.64\,ms)"),
    (r"figure is a probabilistic expected value under steady-state load",
     r"figure is a probabilistic expected value under steady-state load via short-circuiting"),
    (r"\\textbf\{Effective Latency drops to an astonishing \$\\sim\$41.1 ms\}",
     r"\textbf{Effective Latency drops to an astonishing $\sim$138.22 ms}")
]

import re
for old, new in replacements:
    # use re.sub with literal strings so we don't have to worry about exact spacing as much if it's mostly literal
    content = re.sub(old.replace(" ", r"\s+"), new, content)

with open(latex_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Paper successfully audited and updated!")

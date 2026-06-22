import re

latex_path = r"c:\Users\Aksha\OneDrive\Desktop\semantic_firewall\docs\semantic_firewall_paper.tex"

with open(latex_path, 'r', encoding='utf-8') as f:
    content = f.read()

placeholders = ["TODO", "TBD", "FIXME", "XX%", "XX", "approx"]
found = []

lines = content.split('\n')
for i, line in enumerate(lines):
    for p in placeholders:
        if p in line and "%" not in line.split(p)[0] and "approx" not in p: # ignore comments and approx as it's fine sometimes
            if p == "XX" and "XX" in line:
                found.append((i+1, line.strip()))
        elif p in line and p in ["TODO", "TBD", "FIXME", "XX%", "XX"]:
            found.append((i+1, line.strip()))
            
print("Potential Placeholders / Unfinished parts found:")
for num, line in found:
    print(f"Line {num}: {line}")
    
# Basic LaTeX syntax check (unclosed brackets, etc.)
open_braces = content.count("{")
close_braces = content.count("}")
print(f"Open Braces: {open_braces}, Close Braces: {close_braces}")

open_env = len(re.findall(r"\\begin\{", content))
close_env = len(re.findall(r"\\end\{", content))
print(f"\\begin environments: {open_env}, \\end environments: {close_env}")

"""Verify the FIXED ablation table F1 math."""

rows = [
    ("Config 1: Raw LLM Gate Only",    91.89, 85.72, 88.70),
    ("Config 2: Regex Only",           93.30, 45.01, 60.71),
    ("Config 3: Semantic Cache Only",  70.10, 70.10, 70.10),
    ("Config 4: Parallel Detectors",   91.30, 91.30, 91.30),
    ("Config 5: Regex + Cache",        91.76, 84.10, 87.77),
    ("Config 6: Regex + Parallel Det", 89.85, 81.13, 85.27),
    ("Config 7: All Fast (No LLM)",    88.95, 97.82, 93.18),
    ("Config 8: Full System",          89.03, 98.61, 93.57),
    ("Config 9: Cold Start",           86.43, 99.82, 92.64),
]

print("=" * 80)
print(f"{'Config':<35} {'P':>7} {'R':>7} {'Stated F1':>10} {'Calc F1':>10} {'Diff':>7} {'OK?':>5}")
print("=" * 80)

all_ok = True
for name, p, r, f1_stated in rows:
    p_dec = p / 100
    r_dec = r / 100
    f1_calc = 2 * (p_dec * r_dec) / (p_dec + r_dec) * 100
    diff = abs(f1_calc - f1_stated)
    ok = "YES" if diff < 0.1 else "NO"
    if ok == "NO":
        all_ok = False
    print(f"{name:<35} {p:>6.2f}% {r:>6.2f}% {f1_stated:>9.2f}% {f1_calc:>9.2f}% {diff:>6.2f}% {ok:>5}")

print("=" * 80)
if all_ok:
    print("ALL F1 SCORES VERIFIED CORRECT")
else:
    print("ERRORS DETECTED - FIX REQUIRED")

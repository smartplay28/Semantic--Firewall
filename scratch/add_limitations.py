latex_path = r"c:\Users\Aksha\OneDrive\Desktop\semantic_firewall\docs\semantic_firewall_paper.tex"

with open(latex_path, 'r', encoding='utf-8') as f:
    content = f.read()

target_anchor = r"% ====================================================================" + "\n" + r"\section{Conclusion}"

limitations_section = r"""% ====================================================================
\section{Limitations \& Future Work}
% ====================================================================

While the Semantic Firewall demonstrates robust empirical performance, deploying this architecture in extreme high-throughput enterprise environments exposes three primary limitations that direct our future work:

\textbf{1. Throughput vs. The Python GIL:} Our current orchestrator achieves concurrent execution of the 8 fast-layer heuristics using Python's \texttt{ThreadPoolExecutor}. While I/O-bound API calls effectively release the Global Interpreter Lock (GIL), the Regex engine and local heuristics remain CPU-bound. At hyper-scale (e.g., $>10{,}000$ Requests Per Second), the GIL will inevitably bottleneck throughput. A production-grade enterprise deployment should port the orchestrator layer to a lock-free systems language like Go or Rust, pairing it with a distributed vector database (e.g., Redis Enterprise) to horizontally scale the Semantic Cache across Kubernetes clusters.

\textbf{2. Adversarial Embeddings \& Cache Evasion:} The Semantic Cache achieves a 24.95\% hit rate against zero-day prompts by clustering mathematically similar payloads. However, a sophisticated attacker could theoretically utilize adversarial optimization to generate synonymous payloads that retain the malicious instruction but intentionally maximize cosine distance in the embedding space (e.g., dropping similarity below the $\tau=0.90$ threshold). This evasion forces a cache miss and routes the prompt back to the slower LLM Gate, effectively degrading the system's primary defense against latency. Future iterations must explore adversarial training for the embedding models to compress the latent space of synonymous attacks.

\textbf{3. Optimizing the Slow Layer via SLMs:} Currently, the slow layer relies on the massive 70B parameter Llama-3.3 model to ensure maximum security recall. While our 66.88\% short-circuit rate heavily insulates users from this latency, maintaining a 70B gate is computationally expensive. Future implementations should explore locally fine-tuning quantized Small Language Models (SLMs), such as Llama-3-8B-Instruct, specifically for the LLM Gate role. A highly optimized SLM executing via vLLM could theoretically reduce the slow-path penalty from 731.64 ms to under 150 ms without sacrificing F1 performance, fundamentally eliminating the need for cloud-hosted safety models entirely.

""" + target_anchor

if target_anchor in content:
    content = content.replace(target_anchor, limitations_section)
    with open(latex_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("Successfully added Limitations section to the paper!")
else:
    print("Could not find the target anchor to insert the section.")

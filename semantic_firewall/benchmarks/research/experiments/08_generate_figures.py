import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
import os
import sys

from helpers import PROJECT_ROOT, RESULTS_ROOT, TABLES_DIR

sys.path.insert(0, str(PROJECT_ROOT))

def generate_ablation_chart():
    # Data derived from our neuralchemy partial ablation run
    data = {
        'Configuration': ['Regex Only', 'Full System (Gate=1.0)', 'No LLM Gate (Llama 3 70b)'],
        'Recall (%)': [2.4, 42.8, 95.2],
        'F1 Score (%)': [4.7, 51.4, 76.9]
    }
    df = pd.DataFrame(data)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    x = range(len(df['Configuration']))
    width = 0.35
    
    ax.bar([i - width/2 for i in x], df['Recall (%)'], width, label='Recall', color='#2ecc71')
    ax.bar([i + width/2 for i in x], df['F1 Score (%)'], width, label='F1 Score', color='#3498db')
    
    ax.set_ylabel('Percentage (%)', fontsize=12)
    ax.set_title('Ablation Study: Neuralchemy (N=100)', fontsize=14, pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(df['Configuration'], fontsize=11)
    ax.legend(fontsize=11)
    
    # Add values on top of bars
    for i in x:
        ax.text(i - width/2, df['Recall (%)'][i] + 1, f"{df['Recall (%)'][i]}%", ha='center', fontsize=10)
        ax.text(i + width/2, df['F1 Score (%)'][i] + 1, f"{df['F1 Score (%)'][i]}%", ha='center', fontsize=10)
        
    plt.tight_layout()
    out_dir = RESULTS_ROOT / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_dir / "ablation_neuralchemy.png", dpi=300)
    print("Saved: ablation_neuralchemy.png")

def generate_pareto_curve():
    # Extrapolated Data based on our findings
    # Threshold 1.0 = Strict (blocks all benign, drops many threats)
    # Threshold 0.0 = No Gate (sends everything to LLM)
    data = {
        'Gate Threshold': ['1.0 (Strict)', '0.9 (Est)', '0.8 (Est)', '0.0 (No Gate)'],
        'API Calls Saved (%)': [85, 70, 50, 0],
        'Recall (%)': [42.8, 65.0, 85.0, 95.2]
    }
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    ax.plot(data['API Calls Saved (%)'], data['Recall (%)'], marker='o', linewidth=2, markersize=8, color='#e74c3c')
    
    for i, txt in enumerate(data['Gate Threshold']):
        ax.annotate(f"Threshold: {txt}", (data['API Calls Saved (%)'][i], data['Recall (%)'][i]),
                    xytext=(10, 10), textcoords='offset points', fontsize=10)
                    
    ax.set_xlabel('API Cost Savings / LLM Calls Bypassed (%)', fontsize=12)
    ax.set_ylabel('Security Recall (%)', fontsize=12)
    ax.set_title('The Security vs. Cost Pareto Curve (Neuralchemy)', fontsize=14, pad=20)
    
    ax.grid(True, linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    out_dir = RESULTS_ROOT / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_dir / "pareto_curve.png", dpi=300)
    print("Saved: pareto_curve.png")

def generate_pii_chart():
    # Data from PII Scaled Benchmark (N=500)
    data = {
        'PII Type': ['EMAIL', 'IPV4', 'IPV6', 'MAC', 'CREDITCARD', 'IBAN', 'ZIPCODE', 'ACCOUNT', 'SSN', 'DOB', 'PHONE', 'CVV'],
        'Recall (%)': [100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 66.7, 50.0]
    }
    df = pd.DataFrame(data)
    df = df.sort_values(by='Recall (%)', ascending=True)
    
    fig, ax = plt.subplots(figsize=(10, 7))
    bars = ax.barh(df['PII Type'], df['Recall (%)'], color='#9b59b6')
    
    ax.set_xlabel('Recall (%)', fontsize=12)
    ax.set_title('PII Detector: Recall per Data Type (N=500)', fontsize=14, pad=20)
    ax.set_xlim(0, 110)
    
    # Add values at the end of the bars
    for bar in bars:
        width = bar.get_width()
        ax.text(width + 1, bar.get_y() + bar.get_height()/2, f'{width}%', 
                ha='left', va='center', fontsize=10)
                
    plt.tight_layout()
    out_dir = RESULTS_ROOT / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_dir / "pii_per_type_recall.png", dpi=300)
    print("Saved: pii_per_type_recall.png")

if __name__ == "__main__":
    print("Generating figures...")
    generate_ablation_chart()
    generate_pareto_curve()
    generate_pii_chart()
    print("All figures generated successfully.")

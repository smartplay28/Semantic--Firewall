import csv
import io
import json
from collections import Counter

import streamlit as st


def render_batch_tab(load_firewall, get_current_workspace, get_policy_names, parse_lines):
    firewall = load_firewall()
    workspace_id = get_current_workspace()
    st.markdown("**Batch Scan**")
    batch_mode = st.radio("Batch Source", ["manual", "csv", "text_file"], horizontal=True)
    scan_target = st.radio("Scan Target", ["input", "output"], horizontal=True, key="batch_target")
    policy_profile = st.selectbox("Policy Profile", get_policy_names(), key="batch_profile")
    rows = []

    if batch_mode == "manual":
        raw_text = st.text_area(
            "Batch inputs",
            height=180,
            placeholder="One text per line",
            help="Paste one input/output per line.",
        )
        rows = parse_lines(raw_text)
    elif batch_mode == "csv":
        uploaded = st.file_uploader("Upload CSV", type=["csv"], key="batch_csv")
        if uploaded is not None:
            decoded = uploaded.getvalue().decode("utf-8")
            reader = csv.DictReader(io.StringIO(decoded))
            csv_rows = list(reader)
            if csv_rows:
                selected_col = st.selectbox("Text Column", list(csv_rows[0].keys()))
                rows = [row.get(selected_col, "").strip() for row in csv_rows if row.get(selected_col, "").strip()]
    else:
        uploaded_text = st.file_uploader("Upload text file", type=["txt"], key="batch_txt")
        if uploaded_text is not None:
            decoded = uploaded_text.getvalue().decode("utf-8")
            rows = parse_lines(decoded)

    if st.button("Run Batch Scan"):
        if not rows:
            st.warning("Provide at least one row to scan.")
            return
        results = []
        for row in rows[:20]:
            decision = (
                firewall.analyze(
                    row,
                    session_id=st.session_state.get("session_id"),
                    policy_profile=policy_profile,
                    workspace_id=workspace_id,
                )
                if scan_target == "input"
                else firewall.analyze_output(row, policy_profile=policy_profile, workspace_id=workspace_id)
            )
            results.append(
                {
                    "text": row,
                    "action": decision.action,
                    "severity": decision.severity,
                    "triggered_agents": ", ".join(decision.triggered_agents),
                    "reason": decision.reason,
                }
            )
        st.dataframe(results, use_container_width=True)
        st.json(dict(Counter(result["action"] for result in results)))
        st.download_button(
            "Download Batch Results",
            data=json.dumps(results, indent=2),
            file_name="semantic_firewall_batch_results.json",
            mime="application/json",
        )


from collections import Counter

import plotly.graph_objects as go
import streamlit as st


def render_history_tab(load_audit_logger, get_current_workspace, parse_json_field, action_config):
    logger = load_audit_logger()
    st.markdown("**Recent Analyses**")
    c1, c2, c3 = st.columns(3)
    with c1:
        history_limit = st.slider("Entries", min_value=5, max_value=50, value=15, step=5)
    with c2:
        action_filter = st.selectbox("Action", ["all", "ALLOW", "FLAG", "REDACT", "BLOCK"])
    with c3:
        search_filter = st.text_input("Search", placeholder="Reason or text")

    recent_entries = logger.get_recent(
        limit=history_limit,
        action=None if action_filter == "all" else action_filter,
        search=search_filter or None,
        workspace_id=get_current_workspace(),
    )

    if not recent_entries:
        st.info("No history yet. Run a few analyses and this view will populate automatically.")
        return

    for entry in recent_entries:
        triggered_agents = parse_json_field(entry.get("triggered_agents"), [])
        cfg = action_config.get(entry.get("action"), action_config["FLAG"])
        timestamp = (entry.get("timestamp") or "").replace("T", " ")[:19]
        title = f"{cfg['icon']} {entry.get('action', 'UNKNOWN')} | {entry.get('severity', 'NONE')} | {timestamp}"

        with st.expander(title, expanded=False):
            st.caption(entry.get("reason", ""))
            st.code(entry.get("input_text", ""), language=None)
            if triggered_agents:
                st.write(f"Triggered: {', '.join(triggered_agents)}")

            with st.form(f"feedback_{entry['id']}"):
                feedback_type = st.selectbox(
                    "Feedback",
                    ["false_positive", "false_negative"],
                    key=f"feedback_type_{entry['id']}",
                )
                notes = st.text_input(
                    "Notes",
                    key=f"feedback_notes_{entry['id']}",
                    placeholder="Optional note",
                )
                if st.form_submit_button("Save Feedback"):
                    logger.submit_feedback(entry["id"], feedback_type, notes)
                    st.success("Feedback saved.")
                    st.rerun()


def render_stats_tab(
    load_audit_logger,
    get_current_workspace,
    parse_json_field,
    action_config,
    severity_colors,
    load_public_leaderboard,
    run_benchmark_pipeline,
):
    logger = load_audit_logger()
    workspace_id = get_current_workspace()
    stats = logger.get_stats(workspace_id=workspace_id)
    feedback_insights = logger.get_feedback_insights(workspace_id=workspace_id)
    recent_entries = logger.get_recent(limit=200, workspace_id=workspace_id)
    action_counts = stats.get("action_counts", {})
    severity_counts = stats.get("severity_counts", {})
    target_counts = stats.get("target_counts", {})
    feedback_counts = logger.get_feedback_summary(workspace_id=workspace_id)

    triggered_counter = Counter()
    date_counter = Counter()
    for entry in recent_entries:
        for agent_name in parse_json_field(entry.get("triggered_agents"), []):
            triggered_counter[agent_name] += 1
        timestamp = entry.get("timestamp", "")
        if timestamp:
            date_counter[timestamp[:10]] += 1

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Requests", stats.get("total_requests", 0))
    with c2:
        st.metric("Avg Latency", f"{stats.get('avg_latency_ms', 0):.1f}ms")
    with c3:
        st.metric("Blocks Last Hour", stats.get("blocks_last_hour", 0))
    with c4:
        st.metric("Feedback Items", sum(feedback_counts.values()))

    upper_left, upper_right = st.columns(2)
    lower_left, lower_right = st.columns(2)

    with upper_left:
        st.markdown("**Action Distribution**")
        if action_counts:
            fig = go.Figure(
                go.Pie(
                    labels=list(action_counts.keys()),
                    values=list(action_counts.values()),
                    hole=0.45,
                    marker=dict(colors=[action_config.get(a, action_config["FLAG"])["color"] for a in action_counts]),
                )
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#c9d1e0"),
                margin=dict(t=20, b=20, l=20, r=20),
                height=320,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No action stats yet.")

    with upper_right:
        st.markdown("**Severity Distribution**")
        if severity_counts:
            labels = list(severity_counts.keys())
            fig = go.Figure(
                go.Bar(
                    x=labels,
                    y=list(severity_counts.values()),
                    marker=dict(color=[severity_colors.get(label, "#4b5563") for label in labels], opacity=0.85),
                )
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#c9d1e0"),
                xaxis=dict(gridcolor="#1e2535", linecolor="#1e2535"),
                yaxis=dict(gridcolor="#1e2535", linecolor="#1e2535"),
                margin=dict(t=20, b=20, l=20, r=20),
                height=320,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No severity stats yet.")

    with lower_left:
        st.markdown("**Top Triggered Agents**")
        if triggered_counter:
            top_agents = triggered_counter.most_common(5)
            fig = go.Figure(
                go.Bar(
                    x=[count for _, count in top_agents],
                    y=[name for name, _ in top_agents],
                    orientation="h",
                    marker=dict(color="#1a56db", opacity=0.85),
                )
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#c9d1e0"),
                xaxis=dict(gridcolor="#1e2535", linecolor="#1e2535"),
                yaxis=dict(gridcolor="#1e2535", linecolor="#1e2535"),
                margin=dict(t=20, b=20, l=20, r=20),
                height=320,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No triggered-agent history yet.")

    with lower_right:
        st.markdown("**Request Trend**")
        if date_counter:
            dates = sorted(date_counter.keys())
            fig = go.Figure(
                go.Scatter(
                    x=dates,
                    y=[date_counter[d] for d in dates],
                    mode="lines+markers",
                    line=dict(color="#10b981", width=2),
                    marker=dict(size=8, color="#10b981"),
                )
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#c9d1e0"),
                xaxis=dict(gridcolor="#1e2535", linecolor="#1e2535"),
                yaxis=dict(gridcolor="#1e2535", linecolor="#1e2535"),
                margin=dict(t=20, b=20, l=20, r=20),
                height=320,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Not enough history to show a trend yet.")

    if target_counts or feedback_counts:
        extra_left, extra_right = st.columns(2)
        with extra_left:
            st.markdown("**Scan Targets**")
            if target_counts:
                st.json(target_counts)
            else:
                st.info("No scan-target data yet.")
        with extra_right:
            st.markdown("**Feedback Summary**")
            if feedback_counts:
                st.json(feedback_counts)
            else:
                st.info("No reviewer feedback yet.")

    insight_left, insight_right = st.columns(2)
    with insight_left:
        st.markdown("**Policy Profiles**")
        if stats.get("profile_counts"):
            st.json(stats["profile_counts"])
        else:
            st.info("No profile data yet.")
    with insight_right:
        st.markdown("**Reviewer Hotspots**")
        if feedback_insights.get("hotspot_agents"):
            st.json(feedback_insights["hotspot_agents"])
        else:
            st.info("No reviewer hotspots yet.")

    if feedback_insights.get("hotspot_terms"):
        st.markdown("**Common Feedback Terms**")
        st.json(feedback_insights["hotspot_terms"])
    adjustments = logger.suggest_policy_adjustments(limit=5, workspace_id=workspace_id)
    if adjustments:
        st.markdown("**Recommended Policy Adjustments**")
        st.json(adjustments)
    promotions = logger.get_promotion_history(limit=20, workspace_id=workspace_id)
    if promotions:
        st.markdown("**Recent Promotions**")
        st.dataframe(
            [
                {
                    "timestamp": item["timestamp"][:19].replace("T", " "),
                    "type": item["item_type"],
                    "name": item["item_name"],
                    "note": item.get("note", ""),
                }
                for item in promotions
            ],
            use_container_width=True,
            hide_index=True,
        )
    review_analytics = logger.get_review_queue_analytics(workspace_id=workspace_id)
    if review_analytics.get("pending_total"):
        st.markdown("**Review Queue Aging**")
        st.json(review_analytics)

    st.markdown("**Public Leaderboard**")
    col_refresh, col_note = st.columns([1, 2])
    with col_refresh:
        regenerate = st.button("Regenerate Leaderboard")
    with col_note:
        st.caption("Build benchmark corpus from tests and rerun adapters.")

    if regenerate:
        with st.spinner("Running benchmark pipeline..."):
            ok, logs = run_benchmark_pipeline()
        st.session_state["leaderboard_run_logs"] = logs
        if ok:
            st.success("Leaderboard regenerated.")
        else:
            st.error("Leaderboard regeneration failed. See logs below.")

    if st.session_state.get("leaderboard_run_logs"):
        with st.expander("Benchmark Run Logs", expanded=False):
            st.code(st.session_state["leaderboard_run_logs"], language=None)

    leaderboard_rows = load_public_leaderboard()
    if leaderboard_rows:
        ranked_rows = sorted(
            leaderboard_rows,
            key=lambda row: row.get("overall_score", 0.0),
            reverse=True,
        )
        st.dataframe(ranked_rows, use_container_width=True, hide_index=True)
        fig = go.Figure(
            go.Bar(
                x=[row.get("tool", "unknown") for row in ranked_rows],
                y=[row.get("overall_score", 0.0) for row in ranked_rows],
                marker=dict(color="#1a56db", opacity=0.85),
            )
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#c9d1e0"),
            xaxis=dict(gridcolor="#1e2535", linecolor="#1e2535"),
            yaxis=dict(gridcolor="#1e2535", linecolor="#1e2535"),
            margin=dict(t=20, b=20, l=20, r=20),
            height=320,
        )
        st.plotly_chart(fig, use_container_width=True)
        st.caption("Leaderboard source: leaderboard.json (generated by benchmarking scripts).")
    else:
        st.info("No leaderboard rows found. Generate one using the button above.")


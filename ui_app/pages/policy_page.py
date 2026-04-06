import json

import streamlit as st


def render_policy_tab(
    load_firewall,
    load_audit_logger,
    get_current_workspace,
    parse_lines,
    render_diff_changes,
):
    firewall = load_firewall()
    logger = load_audit_logger()
    workspace_id = get_current_workspace()
    presets = firewall.list_policy_presets(workspace_id=workspace_id)
    drafts = firewall.list_policy_drafts(workspace_id=workspace_id)
    st.markdown("**Policy Presets**")

    with st.form("policy_preset_form"):
        name = st.text_input("Preset Name", placeholder="enterprise_guard")
        description = st.text_input("Description", placeholder="High-safety preset for enterprise assistants")
        p1, p2, p3 = st.columns(3)
        with p1:
            flag_threshold = st.number_input("Session Flag Threshold", min_value=0.0, max_value=100.0, value=8.0, step=0.5)
        with p2:
            block_threshold = st.number_input("Session Block Threshold", min_value=0.0, max_value=100.0, value=12.0, step=0.5)
        with p3:
            allowlist_max = st.selectbox("Allowlist Max Severity", ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"], index=1)
        allowlist_patterns = st.text_area("Allowlist Patterns", placeholder="Project Falcon Public Demo\nApproved Research Sample", height=90)
        override_text = st.text_area(
            "Action Overrides JSON",
            value='{\n  "PII": {"LOW": "REDACT"}\n}',
            height=130,
        )
        if st.form_submit_button("Save Preset"):
            try:
                overrides = json.loads(override_text) if override_text.strip() else {}
                firewall.save_policy_preset(
                    name=name,
                    description=description,
                    action_overrides=overrides,
                    session_flag_threshold=flag_threshold,
                    session_block_threshold=block_threshold,
                    allowlist_patterns=parse_lines(allowlist_patterns),
                    allowlist_max_severity=allowlist_max,
                    workspace_id=workspace_id,
                )
                st.success("Policy preset saved.")
                st.rerun()
            except Exception as exc:
                st.error(f"Could not save preset: {exc}")

    for preset in presets:
        with st.expander(f"{preset['name']} | flag {preset.get('session_flag_threshold', 8.0)} | block {preset.get('session_block_threshold', 12.0)}"):
            st.write(preset.get("description", ""))
            st.json(preset.get("action_overrides", {}))
            if preset.get("allowlist_patterns"):
                st.write(f"Allowlist: {', '.join(preset['allowlist_patterns'])}")
            if preset["name"] not in {"balanced", "strict", "developer_assistant", "customer_support", "research"}:
                if st.button("Delete Preset", key=f"delete_preset_{preset['name']}"):
                    firewall.delete_policy_preset(preset["name"], workspace_id=workspace_id)
                    st.rerun()

    adjustments = logger.suggest_policy_adjustments(limit=8, workspace_id=workspace_id)
    if adjustments:
        st.markdown("**Reviewer-Driven Tuning Suggestions**")
        for index, adjustment in enumerate(adjustments):
            with st.expander(f"{adjustment['profile']} | {adjustment['agent']} | {adjustment['feedback_type']}"):
                st.write(adjustment["recommendation"])
                st.write(f"Priority: {adjustment['priority']} | Count: {adjustment['count']}")
                if st.button("Create Policy Draft", key=f"policy_adjustment_draft_{index}"):
                    firewall.create_policy_draft_from_adjustment(adjustment, workspace_id=workspace_id)
                    st.success("Policy draft created.")
                    st.rerun()

    if drafts:
        st.markdown("**Policy Drafts**")
        for draft in drafts:
            with st.expander(f"{draft['name']} | draft"):
                st.write(draft.get("description", ""))
                st.json(draft.get("action_overrides", {}))
                st.write(
                    f"Flag threshold: {draft.get('session_flag_threshold', 8.0)} | "
                    f"Block threshold: {draft.get('session_block_threshold', 12.0)}"
                )
                st.write(f"Approval: {draft.get('approval_status', 'not_requested')}")
                preview = firewall.preview_policy_draft(draft["name"], workspace_id=workspace_id)
                if preview and preview.get("changes"):
                    st.caption(f"Compared to: {preview.get('base_profile', 'balanced')}")
                    render_diff_changes(preview["changes"], title="Policy Diff")
                requested_by = st.text_input("Requester", key=f"policy_requester_{draft['name']}")
                approved_by = st.text_input("Approver", key=f"policy_approver_{draft['name']}")
                promote_note = st.text_input("Promotion Note", key=f"policy_note_{draft['name']}")
                d1, d2, d3, d4 = st.columns(4)
                if d1.button("Request Approval", key=f"request_policy_{draft['name']}"):
                    firewall.request_policy_approval(draft["name"], requested_by)
                    st.rerun()
                if d2.button("Approve", key=f"approve_policy_{draft['name']}"):
                    try:
                        firewall.approve_policy_draft(draft["name"], approved_by)
                    except ValueError as exc:
                        st.error(str(exc))
                    else:
                        st.rerun()
                if d3.button("Promote Policy Draft", key=f"promote_policy_{draft['name']}"):
                    promoted = firewall.promote_policy_draft(
                        draft["name"],
                        note=promote_note,
                        workspace_id=workspace_id,
                    )
                    if promoted:
                        st.success("Policy draft promoted.")
                        st.rerun()
                    else:
                        st.warning("Policy draft must be approved before promotion.")
                if d4.button("Delete Policy Draft", key=f"delete_policy_{draft['name']}"):
                    firewall.delete_policy_preset(draft["name"], workspace_id=workspace_id)
                    st.rerun()


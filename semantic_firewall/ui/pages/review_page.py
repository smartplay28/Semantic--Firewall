import streamlit as st


def render_review_tab(load_audit_logger, get_current_workspace):
    logger = load_audit_logger()
    workspace_id = get_current_workspace()
    st.markdown("**Review Queue**")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        queue_limit = st.slider("Queue Size", min_value=5, max_value=50, value=30, step=5)
    with c2:
        severity_filter = st.selectbox("Severity Filter", ["all", "LOW", "MEDIUM", "HIGH", "CRITICAL"], key="review_severity")
    with c3:
        target_filter = st.selectbox("Target Filter", ["all", "input", "output"], key="review_target")
    with c4:
        assignee_filter = st.text_input("Assignee Filter", key="review_assignee_filter")
    queue_items = logger.get_review_queue(
        limit=queue_limit,
        severity=None if severity_filter == "all" else severity_filter,
        scan_target=None if target_filter == "all" else target_filter,
        workspace_id=workspace_id,
    )
    if assignee_filter.strip():
        queue_items = [
            item for item in queue_items
            if assignee_filter.strip().lower() in (item.get("review_assignee", "") or "").lower()
        ]
    if not queue_items:
        st.info("No pending review items right now.")
    analytics = logger.get_review_queue_analytics(workspace_id=workspace_id)
    st.caption(
        f"Pending: {analytics['pending_total']} | "
        f"Aging: {analytics['age_buckets']}"
    )
    if not queue_items:
        return

    for item in queue_items:
        title = f"{item['action']} | {item['severity']} | {item.get('scan_target', 'input')} | #{item['id']}"
        with st.expander(title, expanded=False):
            st.code(item.get("input_text", ""), language=None)
            st.write(item.get("reason", ""))
            review_assignee = st.text_input("Assignee", value=item.get("review_assignee", ""), key=f"assignee_{item['id']}")
            review_notes = st.text_area("Review Notes", value=item.get("review_notes", ""), height=80, key=f"notes_{item['id']}")
            c1, c2, c3, c4 = st.columns(4)
            if c1.button("True Positive", key=f"review_tp_{item['id']}"):
                logger.set_review_status(
                    item["id"],
                    "reviewed_true_positive",
                    review_assignee=review_assignee,
                    review_notes=review_notes,
                )
                st.rerun()
            if c2.button("False Positive", key=f"review_fp_{item['id']}"):
                logger.set_review_status(
                    item["id"],
                    "reviewed_false_positive",
                    review_assignee=review_assignee,
                    review_notes=review_notes,
                )
                st.rerun()
            if c3.button("False Negative", key=f"review_fn_{item['id']}"):
                logger.set_review_status(
                    item["id"],
                    "reviewed_false_negative",
                    review_assignee=review_assignee,
                    review_notes=review_notes,
                )
                st.rerun()
            if c4.button("Dismiss", key=f"review_dismiss_{item['id']}"):
                logger.set_review_status(
                    item["id"],
                    "dismissed",
                    review_assignee=review_assignee,
                    review_notes=review_notes,
                )
                st.rerun()


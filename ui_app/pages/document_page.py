import streamlit as st

from orchestrator.document_extractor import DocumentExtractionError


def render_document_tab(
    load_firewall,
    load_document_extractor,
    get_current_workspace,
    get_policy_names,
    render_analysis_result,
):
    firewall = load_firewall()
    extractor = load_document_extractor()
    workspace_id = get_current_workspace()
    st.markdown("**Document Scan**")
    scan_target = st.radio("Scan Target", ["input", "output"], horizontal=True, key="document_target")
    policy_profile = st.selectbox("Policy Profile", get_policy_names(), key="document_profile")
    document = st.file_uploader("Upload document", type=["txt", "md", "csv", "pdf", "png", "jpg", "jpeg"], key="document_upload")

    if st.button("Analyze Document"):
        if document is None:
            st.warning("Upload a document first.")
            return
        try:
            extracted = extractor.extract_text(document.name, document.getvalue())
            st.caption(f"Extracted {extracted['char_count']} characters from {document.name}")
            st.caption(
                f"Mode: {extracted['extraction_mode']} | Quality: {extracted['extraction_quality']}"
            )
            for warning in extracted.get("warnings", []):
                st.warning(warning)
            decision = (
                firewall.analyze(
                    extracted["text"],
                    session_id=st.session_state.get("session_id"),
                    policy_profile=policy_profile,
                    workspace_id=workspace_id,
                )
                if scan_target == "input"
                else firewall.analyze_output(
                    extracted["text"],
                    policy_profile=policy_profile,
                    workspace_id=workspace_id,
                )
            )
            render_analysis_result(decision, extracted["text"], decision.processing_time_ms)
            with st.expander("Extracted Text Preview", expanded=False):
                st.code(extracted["text"][:4000], language=None)
        except DocumentExtractionError as exc:
            st.error(str(exc))


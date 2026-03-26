# suggestions.py
from google import genai
import os
import json
import requests
from dotenv import load_dotenv

# Load environment variables from a .env file if present
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

client = None
if GEMINI_API_KEY:
    client = genai.Client(api_key=GEMINI_API_KEY)

# Define a fallback dictionary that is highly customer friendly AND technical
FALLBACK_SUGGESTIONS = {
    "malware_download": {
        "summary": "Someone tried to download a harmful file (like a virus) onto your system to cause trouble.",
        "recommendations": [
            "Block access to known unsafe websites.",
            "Use antivirus software to scan and remove any bad files.",
            "Make sure your system doesn't allow strangers to run programs."
        ],
        "expert_summary": "Detected an unauthorized inbound file transfer attempt indicative of a second-stage malware payload drop.",
        "expert_recommendations": [
            "Implement strict egress filtering to block outbound connections to untrusted autonomous systems.",
            "Audit execution permissions in world-writable directories (/tmp, /dev/shm) via AppArmor/SELinux.",
            "Review firewall rules and quarantine offending IPs at the perimeter via automated WAF/IPS integration."
        ]
    },
    "unknown": {
        "summary": "We noticed some unusual activity that doesn't match typical known issues.",
        "recommendations": [
            "Keep a close eye on your system for any strange behavior.",
            "Make sure all your software is fully updated to stay safe."
        ],
        "expert_summary": "Unclassified anomalous command sequence detected deviating from strictly modeled baseline behavior.",
        "expert_recommendations": [
            "Perform deep forensic analysis of the captured process tree and raw network PCAP data.",
            "Triage via memory forensics if necessary and feed the telemetry back into the ML classifier for retraining."
        ]
    }
}

def call_chatgpt_api(label):
    """
    Calls OpenAI's ChatGPT API to get both a naive and expert suggestion.
    """
    if not OPENAI_API_KEY:
        return None
        
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}"
    }
    
    prompt = f"""
    You are a dual-persona cybersecurity assistant. An attack of type '{label}' has been detected.
    1. Explain the attack in very simple terms for beginners.
    2. Explain the attack in highly technical terms for an experienced security engineer.
    
    Respond with ONLY valid JSON containing:
    'summary' (a very simple explanation),
    'recommendations' (a list of 3 simple tips),
    'expert_summary' (a highly technical, expert-level analysis of the attack mechanics),
    'expert_recommendations' (a list of 3 highly technical, advanced countermeasures).
    """
    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3
    }
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            res_text = response.json()["choices"][0]["message"]["content"].strip()
            if res_text.startswith("```json"):
                res_text = res_text[7:]
            if res_text.startswith("```"):
                res_text = res_text[3:]
            if res_text.endswith("```"):
                res_text = res_text[:-3]
            try:
                return json.loads(res_text.strip())
            except json.JSONDecodeError:
                pass
    except Exception as e:
        print(f"ChatGPT API error: {e}")
    
    return None

def get_suggestion(label):
    prompt = f"""
    You are a dual-persona cybersecurity intelligence agent. An attack of type '{label}' has been detected. 
    1. Explain the attack in very simple, easy-to-understand terms for a non-technical person.
    2. Explain the attack in highly technical, low-level terms for a seasoned cybersecurity engineer.
    
    You MUST respond with ONLY a valid JSON object matching this exact structure:
    {{
        "summary": "Simple, customer-friendly explanation of what happened.",
        "recommendations": [
            "Easy to understand recommendation 1",
            "Easy to understand recommendation 2",
            "Easy to understand recommendation 3"
        ],
        "expert_summary": "Highly technical, low-level analysis of the attack vector, tooling, and potential impact.",
        "expert_recommendations": [
            "Technical, advanced countermeasure 1 (e.g. firewall rule, kernel hardening)",
            "Technical, advanced countermeasure 2",
            "Technical, advanced countermeasure 3"
        ]
    }}
    """
    
    # 1. Get ChatGPT Suggestion
    chatgpt_data = call_chatgpt_api(label)
    
    # 2. Get Gemini Suggestion
    gemini_data = None
    if client:
        try:
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt,
            )
            res_text = response.text.strip()
            if res_text.startswith("```json"):
                res_text = res_text[7:]
            if res_text.startswith("```"):
                res_text = res_text[3:]
            if res_text.endswith("```"):
                res_text = res_text[:-3]
            gemini_data = json.loads(res_text.strip())
        except Exception as e:
            print(f"Error calling Gemini API for suggestions: {e}")
            
    # Combine results
    combined_summary = ""
    combined_recs = []
    combined_expert_summary = ""
    combined_expert_recs = []
    
    if gemini_data:
        combined_summary += gemini_data.get('summary', '').strip()
        combined_recs.extend(gemini_data.get('recommendations', []))
        combined_expert_summary += gemini_data.get('expert_summary', '').strip()
        combined_expert_recs.extend(gemini_data.get('expert_recommendations', []))
        
    if chatgpt_data:
        if combined_summary:
            combined_summary += " Additionally, " + chatgpt_data.get('summary', '').strip()
        else:
            combined_summary += chatgpt_data.get('summary', '').strip()
            
        combined_recs.extend(chatgpt_data.get('recommendations', []))
        
        if combined_expert_summary:
            combined_expert_summary += " Furthermore, " + chatgpt_data.get('expert_summary', '').strip()
        else:
            combined_expert_summary += chatgpt_data.get('expert_summary', '').strip()
            
        combined_expert_recs.extend(chatgpt_data.get('expert_recommendations', []))
        
    # If both failed, use fallback
    if not combined_summary and not combined_expert_summary:
        fallback = FALLBACK_SUGGESTIONS.get(label, {
            "summary": f"We detected some unusual activity related to '{label}' that needs attention.",
            "recommendations": ["Seek help from a security expert.", "Check your system logs.", "Update your passwords."],
            "expert_summary": f"Anomalous telemetry detected associated with the '{label}' archetype requiring manual review.",
            "expert_recommendations": ["Initiate incident response protocol.", "Isolate the compromised segment.", "Retain logs for evidentiary analysis."]
        })
        return fallback

    # Deduplicate recommendations simply by ignoring case
    def deduplicate(recs):
        unique = []
        seen = set()
        for r in recs:
            lr = r.lower().strip()
            if lr not in seen:
                seen.add(lr)
                unique.append(r)
        return unique
            
    return {
        "summary": combined_summary,
        "recommendations": deduplicate(combined_recs),
        "expert_summary": combined_expert_summary,
        "expert_recommendations": deduplicate(combined_expert_recs)
    }

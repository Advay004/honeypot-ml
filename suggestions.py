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

# Define a fallback dictionary that is highly customer friendly
FALLBACK_SUGGESTIONS = {
    "malware_download": {
        "summary": "Someone tried to download a harmful file (like a virus) onto your system to cause trouble.",
        "recommendations": [
            "Block access to known unsafe websites.",
            "Use antivirus software to scan and remove any bad files.",
            "Make sure your system doesn't allow strangers to run programs."
        ]
    },
    "unknown": {
        "summary": "We noticed some unusual activity that doesn't match typical known issues.",
        "recommendations": [
            "Keep a close eye on your system for any strange behavior.",
            "Make sure all your software is fully updated to stay safe."
        ]
    }
}

def call_chatgpt_api(label):
    """
    Calls OpenAI's ChatGPT API to get an easily understood suggestion.
    """
    if not OPENAI_API_KEY:
        return None
        
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}"
    }
    
    prompt = f"""
    You are a friendly, helpful cybersecurity assistant. Explain the cyber attack '{label}' in very simple terms for beginners.
    Respond with ONLY valid JSON containing 'summary' (a very simple explanation) and 'recommendations' (a list of 3 simple tips).
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
    You are a friendly, helpful, and customer-centric cybersecurity assistant. 
    An attack of type '{label}' has been detected. 
    Explain this attack in very simple, easy-to-understand terms that a non-technical person can easily grasp. Avoid technical jargon.
    
    You MUST respond with ONLY a valid JSON object matching this exact structure:
    {{
        "summary": "Simple, customer-friendly explanation of what happened.",
        "recommendations": [
            "Easy to understand recommendation 1",
            "Easy to understand recommendation 2",
            "Easy to understand recommendation 3"
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
    
    if gemini_data:
        combined_summary += gemini_data.get('summary', '').strip()
        combined_recs.extend(gemini_data.get('recommendations', []))
        
    if chatgpt_data:
        if combined_summary:
            combined_summary += " Additionally, " + chatgpt_data.get('summary', '').strip()
        else:
            combined_summary += chatgpt_data.get('summary', '').strip()
        combined_recs.extend(chatgpt_data.get('recommendations', []))
        
    # If both failed, use fallback
    if not combined_summary:
        fallback = FALLBACK_SUGGESTIONS.get(label, {
            "summary": f"We detected some unusual activity related to '{label}' that needs attention.",
            "recommendations": ["Seek help from a security expert.", "Check your system logs.", "Update your passwords."]
        })
        return fallback

    # Deduplicate recommendations simply by ignoring case
    unique_recs = []
    seen = set()
    for rec in combined_recs:
        lower_rec = rec.lower().strip()
        if lower_rec not in seen:
            seen.add(lower_rec)
            unique_recs.append(rec)
            
    return {
        "summary": combined_summary,
        "recommendations": unique_recs
    }

# suggestions.py
from google import genai
import os
import json
from dotenv import load_dotenv

# Load environment variables from a .env file if present
load_dotenv()

# Retrieve API key from environment variable
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

client = None
if GEMINI_API_KEY:
    client = genai.Client(api_key=GEMINI_API_KEY)

# Define a fallback dictionary in case the API fails or is not configured
FALLBACK_SUGGESTIONS = {
    "malware_download": {
        "summary": "Attacker attempted to fetch and execute remote payload(s).",
        "recommendations": [
            "Block outgoing HTTP(S) to known malicious domains or apply egress filtering.",
            "Scan the filesystem for newly downloaded files and quarantine them.",
            "Harden execution permissions (use AppArmor/SELinux) and disallow execution from /tmp."
        ]
    },
    "unknown": {
        "summary": "Unrecognized or ambiguous command sequence.",
        "recommendations": [
            "Collect more context (process list, network connections) and re-analyze.",
            "Add rules or labeled examples for the new pattern."
        ]
    }
}

def get_suggestion(label):
    if not client:
        print("Warning: GEMINI_API_KEY not set or client init failed. Using fallback suggestions.")
        return FALLBACK_SUGGESTIONS.get(label, FALLBACK_SUGGESTIONS['unknown'])

    prompt = f"""
    You are an expert cybersecurity analyst. An attack of type '{label}' has been detected in a honeypot.
    Provide a concise, professional summary of what this attack entails,
    and list 3-4 actionable technical recommendations to mitigate or investigate this attack.

    You MUST respond with ONLY a valid JSON object matching this exact structure:
    {{
        "summary": "High-level description of the attack.",
        "recommendations": [
            "Recommendation 1",
            "Recommendation 2",
            "Recommendation 3"
        ]
    }}
    """

    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        # Parse the JSON from the Gemini response
        res_text = response.text.strip()
        
        # Remove markdown JSON wrappers if present
        if res_text.startswith("```json"):
            res_text = res_text[7:]
        if res_text.startswith("```"):
            res_text = res_text[3:]
        if res_text.endswith("```"):
            res_text = res_text[:-3]
            
        return json.loads(res_text.strip())
    except Exception as e:
        print(f"Error calling Gemini API for suggestions: {e}")
        return FALLBACK_SUGGESTIONS.get(label, FALLBACK_SUGGESTIONS['unknown'])


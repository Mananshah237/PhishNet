import os
import json
from openai import OpenAI

def _get_client():
    base_url = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
    # append /v1 for OpenAI compatibility if not present (though sometimes handled by client)
    # The user snippet used: base_url=f"{os.getenv('OLLAMA_BASE_URL')}/v1"
    if not base_url.endswith("/v1"):
        base_url = f"{base_url}/v1"
        
    return OpenAI(
        base_url=base_url,
        api_key="ollama" # Dummy key
    )

def analyze_url_with_local_ai(text_content: str) -> str:
    """
    Analyzes text content for phishing risk using local Ollama instance.
    """
    client = _get_client()
    try:
        response = client.chat.completions.create(
            model="llama3.2:1b",
            messages=[
                {"role": "system", "content": "You are a phishing detector. Analyze the following email/site content. Return a score from 0-100 and reasons."},
                {"role": "user", "content": text_content}
            ],
            # Low hardware trick: Tell the model to stay in RAM for only 5 mins
            extra_body={"keep_alive": "5m"} 
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"Error calling Ollama: {e}")
        return json.dumps({"score": 50, "label": "suspicious", "reasons": ["AI analysis failed"]})

def detect_email_with_local_ai(subject: str, from_addr: str, body_text: str, urls: list[str]) -> dict:
    """
    Structured detection for emails. Similar to the previous Gemini prompt but adapted for Llama.
    """
    prompt = f"""
You are a paranoid security analyst. Analyze this email for phishing.
Be suspicious. If there is ANY doubt, mark it as suspicious.

Return ONLY a JSON object with these EXACT keys:
- "label": "benign", "suspicious", or "phishing"
- "score": integer 0-100 (0=safe, 100=phishing). Be aggressive.
- "reasons": array of strings (brief bullet points)

DATA:
Subject: {subject}
From: {from_addr}
Body: {body_text[:2000]}
URLs: {json.dumps(urls[:10], ensure_ascii=False)}
""".strip()

    client = _get_client()
    try:
        response = client.chat.completions.create(
            model="llama3.2:1b",
            messages=[
                {"role": "system", "content": "You are a security analyst. Output JSON only."},
                {"role": "user", "content": prompt}
            ],
            extra_body={"keep_alive": "5m"},
            response_format={"type": "json_object"} 
        )
        content = response.choices[0].message.content
        print(f"DEBUG: AI Raw Response: {content}") # Log raw output for debugging
        
        data = json.loads(content)
        
        # Normalize keys just in case
        normalized = {}
        for k, v in data.items():
            normalized[k.lower()] = v
            
        # Ensure score is present
        if "score" not in normalized and "risk_score" in normalized:
            normalized["score"] = normalized["risk_score"]
            
        return normalized

    except Exception as e:
        print(f"Error calling Ollama: {e}")
        return {"score": 50, "label": "suspicious", "reasons": [f"AI Error: {str(e)}"]}

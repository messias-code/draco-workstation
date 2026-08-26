import json
import urllib.request
import urllib.error
import time

def translate_and_summarize(text: str, api_key: str, model: str = "gemini-flash-latest") -> str:
    """Uses Gemini API to translate and summarize a technical vulnerability description."""
    if not api_key or not text or len(text) < 10:
        return text
        
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    headers = {
        "Content-Type": "application/json",
        "X-goog-api-key": api_key
    }
    
    prompt = (
        "Traduza para pt-BR e resuma o impacto dessa falha de segurança em 1 a 2 linhas curtas, "
        "sem usar jargões técnicos complexos, focando no risco para o negócio. "
        f"Texto original:\n\n{text}"
    )
    
    data = {
        "contents": [{"parts": [{"text": prompt}]}]
    }
    
    # Simple retry logic for 429 Too Many Requests
    max_retries = 3
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode("utf-8"))
                
            candidates = result.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "").strip().replace('\n', ' ')
            break
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < max_retries - 1:
                time.sleep(2)  # Wait 2 seconds and retry
            else:
                break
        except Exception:
            break
            
    return text

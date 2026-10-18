"""Minimal Ollama client. Local only: talks to the Ollama server on your network."""
import json
import requests


class OllamaClient:
    def __init__(self, model="gemma4:e4b", base_url="http://localhost:11434",
                 num_ctx=8192, timeout=300):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.num_ctx = num_ctx
        self.timeout = timeout

    def chat_json(self, system, user):
        """Send a chat request and return the parsed JSON object from the reply."""
        response = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}],
                "stream": False,
                "format": "json",
                "think": False,
                "options": {"num_ctx": self.num_ctx, "temperature": 0},
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        return json.loads(response.json()["message"]["content"])


GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def extract_json(text):
    """Pull the first JSON object out of plain model text (handles ```json fences)."""
    text = text.strip()
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch == "{":
            try:
                obj, _ = decoder.raw_decode(text[i:])
                return obj
            except ValueError:
                continue
    raise ValueError("No JSON object found in the model reply.")


class GeminiClient:
    """Gemini API client (also serves Gemma models). Sends one plain prompt, no system
    instruction and no JSON mode, then extracts the JSON from the text itself."""

    def __init__(self, model=None, api_key=None, timeout=90):
        import os
        model = model or os.environ.get("VERISLIT_GEMINI_MODEL", "")
        self.model = model.replace("models/", "", 1).strip()
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.timeout = timeout

    def chat_json(self, system, user):
        if not self.api_key or not self.model:
            raise RuntimeError("Set GEMINI_API_KEY and VERISLIT_GEMINI_MODEL to use the Gemini backend.")
        response = requests.post(
            GEMINI_URL.format(model=self.model),
            headers={"x-goog-api-key": self.api_key, "Content-Type": "application/json"},
            json={"contents": [{"parts": [{"text": system + "\n\n" + user}]}],
                  "generationConfig": {"temperature": 0.2}},
            timeout=self.timeout,
        )
        if response.status_code != 200:   # never include the key or the full URL in errors
            raise RuntimeError(f"Gemini API returned HTTP {response.status_code}")
        try:
            text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, ValueError) as exc:
            raise RuntimeError("Unexpected Gemini API response shape.") from exc
        return extract_json(text)

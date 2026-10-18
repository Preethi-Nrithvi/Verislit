import base64
import os
import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "gemma4:e4b"
DEFAULT_GEMINI_MODEL = "gemma-4-26b-a4b-it"


def build_prompt(message, language):
    return (
        "You help people in India understand confusing or scary messages.\n"
        f"Reply ONLY in simple {language}, using short sentences.\n"
        "Give three parts:\n"
        "1) What this message means.\n"
        "2) Does it look like a scam? Say Yes, No or Not sure, and why.\n"
        "3) What the person should do.\n"
        "Never tell the person to share an OTP, PIN or password.\n\n"
        f"Message:\n{message}"
    )


def explain_gemini(prompt_text, api_key, model_id, image_bytes=None):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent"
    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json",
    }

    parts = [{"text": prompt_text}]
    if image_bytes:
        parts.append(
            {
                "inline_data": {
                    "mime_type": "image/jpeg",
                    "data": base64.b64encode(image_bytes).decode("utf-8"),
                }
            }
        )

    payload = {
        "contents": [{"parts": parts}],
        "generationConfig": {"temperature": 0.2},
    }

    response = requests.post(url, headers=headers, json=payload, timeout=60)
    response.raise_for_status()
    data = response.json()
    return data["candidates"][0]["content"]["parts"][0]["text"]


def explain_ollama(prompt_text, image_bytes=None, model=OLLAMA_MODEL):
    msg = {"role": "user", "content": prompt_text}
    if image_bytes:
        msg["images"] = [base64.b64encode(image_bytes).decode("utf-8")]
    response = requests.post(
        OLLAMA_URL,
        json={"model": model, "messages": [msg], "stream": False, "think": False},
        timeout=300,
    )
    response.raise_for_status()
    return response.json()["message"]["content"]


def explain(message, language="Hindi", image_bytes=None, model=None):
    prompt_text = build_prompt(message or "(see the attached screenshot)", language)
    gemini_key = os.getenv("GEMINI_API_KEY")

    if gemini_key:
        model_id = os.getenv("VERISLIT_GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
        return explain_gemini(prompt_text, gemini_key, model_id, image_bytes)

    return explain_ollama(prompt_text, image_bytes, model or OLLAMA_MODEL)
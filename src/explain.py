import base64
import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "gemma4:e4b"


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


def explain(message, language="Hindi", image_bytes=None, model=MODEL):
    msg = {"role": "user", "content": build_prompt(message or "(see the attached screenshot)", language)}
    if image_bytes:
        msg["images"] = [base64.b64encode(image_bytes).decode()]
    response = requests.post(
        OLLAMA_URL,
        json={"model": model, "messages": [msg], "stream": False, "think": False},
        timeout=300,
    )
    response.raise_for_status()
    return response.json()["message"]["content"]
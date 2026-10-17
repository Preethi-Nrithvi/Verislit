from explain import build_prompt


def test_prompt_contains_message_and_language():
    prompt = build_prompt("Your account will be blocked", "Tamil")
    assert "Your account will be blocked" in prompt
    assert "Tamil" in prompt


def test_prompt_warns_about_otp():
    assert "OTP" in build_prompt("hello", "Hindi")
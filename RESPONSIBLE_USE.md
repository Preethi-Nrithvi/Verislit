# Responsible Use

Verislit helps people understand security scan results. Please use it responsibly.

## Authorized testing only

- Only analyze scans of systems you own or have clear written permission to test.
- The app asks you to confirm permission before it analyzes a scan. That checkbox is a reminder, not a legal protection. You are responsible for how you use the tool.
- Verislit only reads scan output. It does not run scans.

## No exploit generation

- Verislit gives fix advice only.
- It does not write attack code, and it is not meant to.
- The Verifier rejects AI wording that contains exploit phrases and uses the rule-based text instead.
- Please do not try to turn this project into an exploit tool. Contributions that do so will be declined.

## Warning: the hosted demo sends text to an API

The hosted demo can use the Gemini API to reword explanations. This means finding text from your scan may be sent to an outside API.

- Do NOT paste sensitive data into the hosted demo.
- That includes real internal IP addresses, hostnames, credentials, tokens, customer data, or scans of systems you do not own.
- Use the sample scans, or scans of your own lab machines.
- For private data, run Verislit offline with a local model through Ollama, so scan text stays on your own computer.

## What Verislit cannot promise

- Verislit may miss problems. A report with few findings does not mean a system is secure.
- The Verifier blocks certain kinds of invented claims. It does not guarantee that every sentence in a report is correct.
- Always check important findings yourself, and look up any CVE or CWE id on https://nvd.nist.gov before acting on it.

## Reporting misuse or problems

For security problems in Verislit itself, see `SECURITY.md`.

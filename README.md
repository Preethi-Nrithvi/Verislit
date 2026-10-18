# Verislit

**Verislit reads your Nmap scan, explains each finding in plain language, and checks every claim against the raw scan.**

Security scan output is long and technical. Verislit turns it into a clear report that says what the problem is, how serious it is, and how to fix it. Code decides the facts. The AI only helps with wording, and a Verifier checks that wording.

Live demo: [LIVE URL]

> Warning: the hosted demo may send finding text to an AI API. Do not paste sensitive data. See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).

## How it works

1. **Parse (plain code).** Verislit reads Nmap output (text or XML) and turns it into structured findings. No AI is used here.
2. **Set severity (plain code).** Severity comes from a fixed table of 14 rules plus a generic open-port rule. The AI cannot change it.
3. **Reword (AI, optional).** An AI model rewrites the explanation and fix steps in plain language. It has no tools.
4. **Verify (plain code).** A Verifier checks every finding against the raw scan.
5. **Report.** You get a readable report, validated against a JSON schema, with the number of blocked AI claims shown.

## What the Verifier checks

- The evidence quote must appear verbatim in the raw scan.
- References (CVE or CWE ids) must come from the rule table.
- AI wording that invents a CVE id, version, port or link is rejected.
- AI wording that contradicts the severity is rejected.
- AI wording with exploit phrases or "no vulnerabilities" claims is rejected.

When wording is rejected, Verislit uses the rule-based text instead.

## Prompt injection

Instruction-like text hidden in scan banners is detected, logged and ignored. The AI step has no tools, and the web page escapes all scan text.

## AI backends

- **Ollama (local, offline).** Runs an open-weight model on your own computer, so scan text stays on your machine.
- **Gemini API (hosted demo).** Uses a Gemma/Gemini model. Set `GEMINI_API_KEY` and, optionally, `VERISLIT_GEMINI_MODEL` as environment variables. Never commit keys.

Backends live in `src/verislit/llm.py`.

## Run it yourself

```
pip install -r requirements.txt
pytest
flask --app app run
```

Then open the address Flask prints, load a sample scan, tick the permission checkbox and click Analyze.

## Project layout

- `src/verislit/parser.py` - parses Nmap output
- `src/verislit/rules.py` - the severity rule table
- `src/verislit/verifier.py` - the Verifier
- `src/verislit/llm.py` - AI backends
- `schema/report.schema.json` - report schema
- `tests/` - automated tests (run with `pytest`)

## What Verislit does not do

- It does not run scans. It only reads scan output you give it.
- It does not generate exploits. It gives fix advice only.
- It cannot promise a system is secure. A short report does not prove safety.

## Not built yet

- Nikto support
- Separate Planner and Critic agents
- An air-gapped Docker setup
- Full benchmarks

## Contributing

Small contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the good first issues. For security problems, see [SECURITY.md]  (SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

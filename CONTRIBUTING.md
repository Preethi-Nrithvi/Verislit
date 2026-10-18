# Contributing to Verislit

Thank you for helping. Verislit is small on purpose, so most contributions are small too.

## What Verislit does (so you know where things live)

- It reads Nmap scan output (text or XML) and turns it into structured findings with plain code.
- Severity comes from a fixed rule table in `src/verislit/rules.py`.
- An optional AI model only rewrites the explanation and fix steps. Backends (Ollama local, Gemini API) are in `src/verislit/llm.py`.
- A Verifier in `src/verislit/verifier.py` checks every finding against the raw scan.

## Set up and run the tests

1. Clone the repo and go into the folder.
2. (Optional) Create a virtual environment: `python -m venv .venv`, then activate it.
3. Install dependencies: `pip install -r requirements.txt`
4. Run the tests: `pytest`

All tests must pass before you open a pull request.

## How to add a rule

1. Open `src/verislit/rules.py`.
2. Copy an existing rule and change it. Each rule is a dict with these keys:
   `id`, `severity`, `title` (may use `{port}` and `{service}`), `match` (a lambda),
   `explanation`, `risk`, `remediation` (a list), and `refs` (a list).
3. Keep the severity defensible for a non-expert reader.
4. Only add a CVE or CWE id to `refs` if you are certain it is correct, and check it on https://nvd.nist.gov first. If you are not sure, use an empty list. The Verifier only allows references that come from this table.
5. Add one test for your rule in `tests/test_rules.py`.
6. Run `pytest`.

## How to add a parser for a new tool

1. Open `src/verislit/parser.py` and see how the Nmap parser turns raw text into findings.
2. Add your parser as a separate function. Parsing must stay plain code. No AI in the parser.
3. Add a small sample scan file and tests for your parser in `tests/`.
4. Nikto support is not built yet, so a Nikto parser is a welcome contribution.

## Code style

- Plain Python. Keep it simple and readable.
- Keep functions short and add a short comment when something is not obvious.
- Do not add new dependencies without asking in an issue first.
- Keep the tests passing. If you fix a bug, add a test that would have caught it.

## Do not weaken the safety checks

The Verifier exists to block invented CVE ids, versions, ports and links, severity contradictions, and exploit phrases. Changes that make these checks weaker will not be accepted. Changes that make them more accurate are welcome.

## Opening a pull request

- One small change per pull request.
- Say what you changed and how you tested it.
- Do not include real scan data from systems you do not own.

## Not built yet

Nikto support, separate Planner and Critic agents, and an air-gapped Docker setup are planned but not built.

## License

By contributing you agree that your work is released under the Apache License 2.0.

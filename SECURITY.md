# Security Policy

## Reporting a vulnerability

Please do NOT open a public issue for a security problem.

Report it privately using GitHub private vulnerability reporting:

1. Go to the Verislit repository on GitHub.
2. Click the **Security** tab.
3. Click **Report a vulnerability**.
4. Describe the problem and submit.

Please include:

- What the problem is and where it is (file, page or feature).
- Steps to reproduce it.
- What you think the impact is.
- A sample scan file or input if it helps. Do not include real data from systems you do not own.

We will read every report and reply as soon as we can. Please give us a reasonable amount of time to fix the issue before sharing it publicly.

## What is in scope

- Bugs in the web app, parser, Verifier or report output that could be abused.
- Ways to get scan text past the page escaping (cross-site scripting).
- Ways to make instruction-like text in a scan banner (prompt injection) change a report, change a severity, or get past the Verifier.
- Ways to make the Verifier accept invented CVE ids, versions, ports or links.
- Secrets (such as API keys) committed to the repository.

## What is out of scope

- Problems in the systems that your scans describe.
- Problems in third-party services such as Gemini, Ollama, Render or Hugging Face.
- Reports that need you to scan systems you do not have permission to test.

## Supported versions

Only the latest code on the `main` branch is supported.

## Your own API keys

Never commit API keys. The app reads `GEMINI_API_KEY` from an environment variable. If you think a key was exposed, revoke it right away.

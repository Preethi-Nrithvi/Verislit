# Security Policy

## Reporting a vulnerability

Please do NOT post details of a security problem in a public issue.

To report one privately:

1. Open a new issue in this repository titled **Security contact request**.
2. Write only that you found a security problem. Do NOT include any details, steps, files or code.
3. A maintainer will reply and arrange a private way for you to share the details.

Please include in your private message:

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

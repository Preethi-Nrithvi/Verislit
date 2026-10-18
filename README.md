# Verislit

Verislit explains confusing or scary messages in plain language. It sends the
message, and optionally a screenshot, to a local Ollama model and asks for:

1. What the message means.
2. Whether it looks like a scam, and why.
3. What the person should do.

The current repository is the early application described by `src/app.py` and
`src/explain.py`. It does not yet contain the later parser, rules, or verifier
architecture. The report schema in `schema/report.schema.json` and its tests
are retained.

## Run it yourself

Install the dependencies:

```text
pip install -r requirements.txt
```

Start Ollama with the configured model (`gemma4:e4b` by default), then run:

```text
python src/app.py --language Tamil --message "Your account will be blocked"
```

You can also read the message from standard input:

```text
echo "Your account will be blocked" | python src/app.py --language Hindi
```

To include a screenshot:

```text
python src/app.py --image screenshot.png --message "Review this message"
```

Use `--model` to select a different Ollama model. The Ollama endpoint and
default model are defined in `src/explain.py`.

## Tests

```text
python -m pytest
```

## Responsible use

Only analyze messages you are allowed to inspect. Do not share sensitive
information, passwords, PINs, or one-time passwords. See
[RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

"""Command line: python -m verislit analyze scan.xml --authorized"""
import argparse
import json
import sys
from pathlib import Path

from .llm import OllamaClient
from .pipeline import run_file
from .report import to_html, to_markdown


def main(argv=None):
    ap = argparse.ArgumentParser(prog="verislit", description="Explain and verify security scan output.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze an Nmap XML file")
    a.add_argument("scan", help="path to Nmap XML (nmap -oX)")
    a.add_argument("--backend", choices=["none", "ollama", "cache"], default="none",
                   help="none = rule-based text only; ollama = local model; cache = saved model output")
    a.add_argument("--model", default="gemma4:e4b")
    a.add_argument("--ollama-url", default="http://localhost:11434")
    a.add_argument("--cache", help="analysis cache file (for --backend cache)")
    a.add_argument("--save-analysis", help="save the model output here (for --backend ollama)")
    a.add_argument("--out", default="reports")
    a.add_argument("--authorized", action="store_true",
                   help="confirm you have written permission to test this target")
    args = ap.parse_args(argv)

    if not args.authorized:
        answer = input("Do you have written permission to test the scanned systems? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Stopping: Verislit is for authorized testing only.")
            return 2

    llm = OllamaClient(args.model, args.ollama_url) if args.backend == "ollama" else None
    report = run_file(args.scan, True, args.backend, llm, args.cache, args.save_analysis)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out / "report.md").write_text(to_markdown(report), encoding="utf-8")
    (out / "report.html").write_text(to_html(report), encoding="utf-8")
    counts = report["summary"]["counts"]
    print("Done. " + ", ".join(f"{k}: {v}" for k, v in counts.items()))
    print(f"Blocked items: {len(report['blocked'])}. Reports written to {out}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())

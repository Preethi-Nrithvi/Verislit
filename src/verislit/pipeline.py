"""Glue: parse -> rules -> (optional AI) -> verify -> report."""
import json
from pathlib import Path

from .analyzer import analyze
from .nmap_parser import parse_nmap_text
from .report import build_report, enrich_findings
from .verifier import verify


def load_cache(path, input_sha256):
    """Load saved AI analyses. Returns (analyses, model) or ({}, None) if missing or for another file."""
    p = Path(path)
    if not p.exists():
        return {}, None
    data = json.loads(p.read_text(encoding="utf-8"))
    if data.get("input_sha256") != input_sha256:
        return {}, None
    return data["analyses"], data.get("model", "cached")


def save_cache(path, input_sha256, model, analyses):
    Path(path).write_text(json.dumps(
        {"input_sha256": input_sha256, "model": model, "analyses": analyses},
        indent=1, ensure_ascii=False), encoding="utf-8")


def run_text(text, filename, authorized, analyses=None, source="rules_only", model="none"):
    """Run the full pipeline on scan text. `analyses` are AI outputs to verify (optional)."""
    parsed = parse_nmap_text(text, filename)
    findings = enrich_findings(parsed)
    results, blocked = verify(findings, analyses or {}, parsed["raw_text"])
    return build_report(parsed, findings, results, blocked, authorized, source, model)


def run_file(path, authorized, backend="none", llm=None, cache_path=None, save_to=None):
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    parsed = parse_nmap_text(text, path.name)
    analyses, source, model = {}, "rules_only", "none"
    if backend == "ollama":
        findings = enrich_findings(parsed)
        analyses = analyze(findings, llm)
        source, model = "llm", llm.model
        if save_to:
            save_cache(save_to, parsed["input_sha256"], model, analyses)
    elif backend == "cache":
        analyses, cached_model = load_cache(cache_path, parsed["input_sha256"])
        if analyses:
            source, model = "cache", cached_model
    return run_text(text, path.name, authorized, analyses, source, model)

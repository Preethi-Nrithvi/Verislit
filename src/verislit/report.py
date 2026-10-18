"""Build the report dict (matches schema/report.schema.json) and render it as Markdown or HTML."""
import html

from .rules import SEVERITY_ORDER, matching_rules, DEFAULT_RULE, title_for

NOT_CHECKED = [
    "Vulnerabilities that do not show up in this scan's output",
    "Password strength and authentication settings",
    "Web application flaws (the scan reads service banners, not site logic)",
    "Patch level beyond the version strings the services reported",
    "Hosts and ports that were not part of the scan",
]


def enrich_findings(parsed):
    """Apply the rules to parsed findings and return them sorted by severity."""
    findings = []
    for f in parsed["findings"]:
        hits = matching_rules(f)
        rule = hits[0] if hits else DEFAULT_RULE
        note, fix = rule["note"], list(rule["fix"])
        for extra in hits[1:]:        # keep lower-severity issues on the same port visible
            note += f" Also detected on this port: {extra['title']}."
            fix += [x for x in extra["fix"] if x not in fix]
        findings.append({**f, "severity": rule["severity"], "rule_id": rule["id"],
                         "title": title_for(f, rule), "rule_note": note,
                         "rule_risk": rule["risk"], "rule_fix": fix,
                         "refs": list(rule["refs"]), "confidence": rule["confidence"]})
    findings.sort(key=lambda x: (SEVERITY_ORDER.index(x["severity"]), x["port"] or 0))
    return findings


def build_report(parsed, findings, results, blocked, authorized, source, model):
    out = []
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        r = results[f["id"]]
        counts[f["severity"]] += 1
        out.append({
            "id": f["id"], "title": f["title"], "severity": f["severity"],
            "severity_source": "rules", "rule_id": f["rule_id"], "host": f["host"],
            "port": f["port"], "protocol": f["protocol"], "service": f["service"],
            "version": " ".join(x for x in (f["product"], f["version"]) if x),
            "evidence": f["evidence"], "plain_explanation": r["explanation"],
            "risk": r["risk"], "remediation": r["fix_steps"], "references": f["refs"],
            "confidence": f["confidence"], "explanation_origin": r["origin"],
            "verified": r["verified"], "verifier_notes": r["notes"],
        })
    return {
        "schema_version": "1.1",
        "scan_metadata": {
            "tool": parsed["tool"], "tool_version": parsed["tool_version"],
            "target": parsed["target"], "scope_authorized": bool(authorized),
            "scanned_at": parsed["scanned_at"], "input_sha256": parsed["input_sha256"],
            "explanation_source": source, "model": model,
        },
        "findings": out, "not_checked": NOT_CHECKED, "blocked": blocked,
        "summary": {"counts": counts},
    }


def to_markdown(report):
    m = report["scan_metadata"]
    lines = ["# Verislit report", "",
             f"- Target: {m['target']}", f"- Scanned at: {m['scanned_at']}",
             f"- Tool: {m['tool']} {m['tool_version']}",
             f"- Explanations from: {m['explanation_source']} (model: {m['model']})",
             f"- Scope confirmed by user: {'yes' if m['scope_authorized'] else 'NO'}",
             f"- Input SHA-256: `{m['input_sha256']}`", "", "## Summary", ""]
    lines += [f"- {s}: {n}" for s, n in report["summary"]["counts"].items()]
    lines += ["", "## Findings", ""]
    for f in report["findings"]:
        badge = "verified" if f["verified"] else "AI text blocked, rule text shown"
        lines += [f"### {f['id']} [{f['severity'].upper()}] {f['title']}", "",
                  f"Rule: `{f['rule_id']}` | Confidence: {f['confidence']} | Status: {badge}", ""]
        for e in f["evidence"]:
            lines += [f"Evidence {e['id']} (line {e['line']}):", "```", e["quote"], "```", ""]
        lines += [f["plain_explanation"], "", f"**Why it matters:** {f['risk']}", "", "**Fix:**"]
        lines += [f"- {s}" for s in f["remediation"]]
        if f["references"]:
            lines += ["", "References: " + ", ".join(f["references"])]
        lines.append("")
    if report["blocked"]:
        lines += ["## Blocked by the Verifier", ""]
        lines += [f"- {b['reason']}" for b in report["blocked"]]
        lines.append("")
    lines += ["## What this analysis did NOT check", ""]
    lines += [f"- {x}" for x in report["not_checked"]]
    return "\n".join(lines) + "\n"


COLORS = {"critical": "#b00020", "high": "#d9480f", "medium": "#b7791f", "low": "#2b6cb0", "info": "#4a5568"}


def to_html(report):
    e = html.escape
    m = report["scan_metadata"]
    parts = ["<!doctype html><html><head><meta charset='utf-8'><title>Verislit report</title>",
             "<style>body{font-family:system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#1a202c}"
             "pre{background:#f1f3f5;padding:.6rem;overflow:auto;white-space:pre-wrap}"
             ".sev{color:#fff;padding:2px 8px;border-radius:4px;font-size:.8rem}"
             ".card{border:1px solid #d0d7de;border-radius:8px;padding:1rem;margin:1rem 0}"
             ".ok{color:#1a7f37}.bad{color:#b00020}</style></head><body>",
             "<h1>Verislit report</h1>",
             f"<p>Target: {e(m['target'])}<br>Scanned at: {e(m['scanned_at'])}<br>"
             f"Tool: {e(m['tool'])} {e(m['tool_version'])}<br>"
             f"Explanations from: {e(m['explanation_source'])} (model: {e(m['model'])})<br>"
             f"Input SHA-256: <code>{e(m['input_sha256'])}</code></p>", "<h2>Summary</h2><ul>"]
    parts += [f"<li>{e(s)}: {n}</li>" for s, n in report["summary"]["counts"].items()]
    parts.append("</ul><h2>Findings</h2>")
    for f in report["findings"]:
        status = ("<span class='ok'>verified against raw output</span>" if f["verified"]
                  else "<span class='bad'>AI text blocked, rule-based text shown</span>")
        parts.append(f"<div class='card'><h3><span class='sev' style='background:{COLORS[f['severity']]}'>"
                     f"{e(f['severity'].upper())}</span> {e(f['id'])} {e(f['title'])}</h3>"
                     f"<p>Rule {e(f['rule_id'])} | confidence {e(f['confidence'])} | {status}</p>")
        for ev in f["evidence"]:
            parts.append(f"<p>Evidence {e(ev['id'])} (line {e(str(ev['line']))}):</p><pre>{e(ev['quote'])}</pre>")
        parts.append(f"<p>{e(f['plain_explanation'])}</p><p><b>Why it matters:</b> {e(f['risk'])}</p><p><b>Fix:</b></p><ul>")
        parts += [f"<li>{e(s)}</li>" for s in f["remediation"]]
        parts.append("</ul>")
        if f["references"]:
            parts.append("<p>References: " + e(", ".join(f["references"])) + "</p>")
        parts.append("</div>")
    if report["blocked"]:
        parts.append("<h2>Blocked by the Verifier</h2><ul>")
        parts += [f"<li>{e(b['reason'])}</li>" for b in report["blocked"]]
        parts.append("</ul>")
    parts.append("<h2>What this analysis did NOT check</h2><ul>")
    parts += [f"<li>{e(x)}</li>" for x in report["not_checked"]]
    parts.append("</ul></body></html>")
    return "".join(parts)

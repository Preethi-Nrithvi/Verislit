"""Verifier: plain code (no AI) that checks every AI claim before it reaches the report.

If the AI text for a finding fails any check, it is dropped and the rule-based text is
shown instead. The reason is logged in the report's `blocked` list.
"""
import re

from .analyzer import injected_values

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}|CWE-\d+", re.I)
URL_RE = re.compile(r"https?://[^\s)\]>\"']+|www\.[^\s)\]>\"']+", re.I)
VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)*(?:p\d+)?\b")
PORT_RES = [re.compile(r"\b(\d{1,5})/(?:tcp|udp)\b", re.I), re.compile(r"\bport (\d{1,5})\b", re.I)]
FORBIDDEN_RE = re.compile(
    r"msfconsole|metasploit|meterpreter|exploit/|reverse shell|payload|nc -e|bash -i", re.I)
CONTRADICTION_RE = re.compile(
    r"no vulnerabilit|not vulnerable|nothing to worry|no (security )?(risk|issues?)\b|"
    r"is (completely )?safe\b", re.I)


def _analysis_text(a):
    steps = a.get("fix_steps") or []
    return " ".join([str(a.get("explanation", "")), str(a.get("why_it_matters", ""))] +
                    [str(s) for s in steps])


def _corpus(f):
    parts = [e["quote"] for e in f["evidence"]]
    parts += [f["rule_note"], f["rule_risk"], " ".join(f["rule_fix"]), " ".join(f["refs"]),
              f["title"], f["host"], str(f["port"]), f["service"], f["product"], f["version"]]
    return "\n".join(parts).lower()


def _has_number(corpus, number):
    return re.search(rf"(?<!\d){re.escape(number)}(?!\d)", corpus) is not None


def check_analysis(f, a, raw_text):
    """Return a list of problems found in one AI analysis (empty list = passed)."""
    problems = []
    steps = a.get("fix_steps")
    if (not isinstance(a.get("explanation"), str) or not a["explanation"].strip()
            or not isinstance(a.get("why_it_matters"), str)
            or not isinstance(steps, list) or not steps
            or not all(isinstance(s, str) for s in steps)):
        return ["incomplete or wrongly shaped analysis"]

    own = {e["id"] for e in f["evidence"]}
    cited = a.get("evidence_ids")
    if not isinstance(cited, list) or not cited:
        problems.append("no evidence cited")
    elif not set(cited) <= own:
        problems.append(f"cites evidence that does not exist: {sorted(set(cited) - own)}")

    if any(e["quote"] not in raw_text for e in f["evidence"]):
        problems.append("evidence text not found in the raw scan file")

    if "severity" in a and str(a["severity"]).lower() != f["severity"]:
        problems.append(f"tried to change severity from {f['severity']} to {a['severity']}")

    text = _analysis_text(a)
    corpus = _corpus(f)

    unverified = sorted({c.upper() for c in CVE_RE.findall(text) if c.lower() not in corpus})
    unverified += sorted({v for v in VERSION_RE.findall(text) if v.lower() not in corpus})
    unverified += sorted({u.rstrip(".,;") for u in URL_RE.findall(text)
                          if u.rstrip(".,;").lower() not in corpus})
    for rx in PORT_RES:
        unverified += sorted({f"port {n}" for n in rx.findall(text) if not _has_number(corpus, n)})
    if unverified:
        problems.append(f"identifiers not found in the scan or rule table: {unverified}")

    if FORBIDDEN_RE.search(text):
        problems.append("contains exploit or attack tooling content")

    if f["severity"] in ("critical", "high", "medium") and CONTRADICTION_RE.search(text):
        problems.append("claims no risk, contradicting the rules-set severity")

    low = text.lower()
    for value in (v for e in f["evidence"] for v in injected_values(e["quote"])):
        words = re.findall(r"[a-z0-9']+", value.lower())
        shingles = {" ".join(words[i:i + 3]) for i in range(len(words) - 2)}
        if any(s in low for s in shingles):
            problems.append("repeats instruction-like text from the scan data")
            break
    return problems


def verify(findings, analyses, raw_text):
    """Return (results_by_id, blocked_list)."""
    results, blocked = {}, []
    for f in findings:
        rule_text = {"explanation": f["rule_note"], "risk": f["rule_risk"],
                     "fix_steps": list(f["rule_fix"])}

        inj = [v for e in f["evidence"] for v in injected_values(e["quote"])]
        if inj:
            blocked.append({"finding_id": f["id"],
                            "reason": f"blocked: instruction-like text in scan data ({f['id']})"})

        a = analyses.get(f["id"])
        if a is None:
            results[f["id"]] = {**rule_text, "origin": "rules", "verified": True,
                                "notes": "Text comes from the fixed rule table. "
                                         "Evidence line exists in the raw scan."}
            continue

        problems = check_analysis(f, a, raw_text)
        if problems:
            for p in problems:
                blocked.append({"finding_id": f["id"], "reason": f"AI text rejected: {p}"})
            results[f["id"]] = {**rule_text, "origin": "rules", "verified": False,
                                "notes": "AI text was rejected by the Verifier (" +
                                         "; ".join(problems) + "). Showing rule-based text instead."}
        else:
            results[f["id"]] = {
                "explanation": a["explanation"].strip(), "risk": a["why_it_matters"].strip(),
                "fix_steps": [s.strip() for s in a["fix_steps"]], "origin": "llm", "verified": True,
                "notes": "AI text checked: cited evidence exists, no unverified identifiers, "
                         "severity unchanged, no exploit content."}
    return results, blocked

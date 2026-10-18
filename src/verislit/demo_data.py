"""A SIMULATED bad AI answer, used only to demonstrate the Verifier. Not real model output."""


def hallucinated_analysis(findings):
    """Return fake 'AI' analyses containing the mistakes small models really make."""
    out = {}
    for f in findings:
        if f["rule_id"] == "R-FTP-VSFTPD-234":
            out[f["id"]] = {
                "id": f["id"], "severity": "low",
                "explanation": "This FTP server is fine. It was patched under CVE-2099-12345 and there are no vulnerabilities.",
                "why_it_matters": "Nothing to worry about.",
                "fix_steps": ["No action needed."], "evidence_ids": ["E-001"]}
        elif f["rule_id"] == "R-TELNET":
            out[f["id"]] = {
                "id": f["id"],
                "explanation": "Telnet on port 9999 lets you log in remotely.",
                "why_it_matters": "Attackers can use msfconsole against it.",
                "fix_steps": ["Disable telnet."], "evidence_ids": ["E-404"]}
        elif f["rule_id"] == "R-OLD-SSH":      # an honest answer, which must still pass
            out[f["id"]] = {
                "id": f["id"],
                "explanation": "The SSH service on port 22 reports OpenSSH 4.7p1, an old release.",
                "why_it_matters": "Old SSH releases miss years of security fixes.",
                "fix_steps": ["Upgrade OpenSSH to a release your operating system vendor supports."],
                "evidence_ids": [f["evidence"][0]["id"]]}
    return out

"""Severity comes from these fixed rules, never from the AI model.

Every identifier in `refs` was checked against an official advisory (NVD) before
being added. Do not add an identifier you have not checked.
"""
import re

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

RULES = [
    {
        "id": "R-FTP-VSFTPD-234",
        "severity": "critical",
        "confidence": "high",
        "title": "vsftpd 2.3.4 (backdoored release) is exposed",
        "match": lambda f: "vsftpd" in f["product"].lower() and f["version"].startswith("2.3.4"),
        "note": ("The scan reports vsftpd 2.3.4. A copy of this release downloaded in July 2011 "
                 "contained a backdoor that opens a shell on port 6200/tcp."),
        "risk": "A backdoored FTP server can give an attacker control of the whole machine.",
        "fix": ["Remove this vsftpd build and install the current version from your distribution's "
                "package repository.",
                "Block the FTP port at the firewall from untrusted networks until it is replaced.",
                "Treat the host as possibly compromised: review accounts, logs and running services."],
        "refs": ["CVE-2011-2523"],
    },
    {
        "id": "R-FTP-ANON",
        "severity": "high",
        "confidence": "high",
        "title": "FTP allows anonymous login",
        "match": lambda f: "anonymous ftp login allowed" in f["scripts"].get("ftp-anon", "").lower(),
        "note": "The Nmap ftp-anon script reports that anyone can log in to FTP without an account.",
        "risk": "Anyone on the network can read, and possibly upload, files without credentials.",
        "fix": ["Disable anonymous access in the FTP server configuration.",
                "Restrict the FTP port to the hosts that need it, or replace FTP with SFTP."],
        "refs": [],
    },
    {
        "id": "R-TELNET",
        "severity": "high",
        "confidence": "high",
        "title": "Telnet service is exposed",
        "match": lambda f: f["service"] == "telnet" or f["port"] == 23,
        "note": "Telnet sends logins and commands as plain text, so anyone on the path can read them.",
        "risk": "Passwords and commands can be captured on the network.",
        "fix": ["Disable the telnet service.",
                "Use SSH with key-based login for remote administration."],
        "refs": [],
    },
    {
        "id": "R-VNC",
        "severity": "high",
        "confidence": "medium",
        "title": "VNC remote desktop is exposed",
        "match": lambda f: f["service"] == "vnc" or f["port"] == 5900,
        "note": "A remote-desktop service is reachable from the scanning machine.",
        "risk": "Weak or default VNC passwords can give full remote control of the desktop.",
        "fix": ["Close the port at the firewall, or tunnel VNC through SSH or a VPN.",
                "Use a strong password and keep the VNC software up to date."],
        "refs": [],
    },
    {
        "id": "R-SMB-OPEN",
        "severity": "medium",
        "confidence": "medium",
        "title": "Windows file sharing (SMB) is exposed",
        "match": lambda f: f["port"] in (139, 445),
        "note": "SMB file-sharing ports are reachable from the scanning machine.",
        "risk": "Exposed SMB is a common target for attackers moving between machines.",
        "fix": ["Restrict SMB to the networks that need it using a firewall.",
                "Disable the old SMBv1 protocol and keep the file-sharing software updated."],
        "refs": [],
    },
    {
        "id": "R-DB-EXPOSED",
        "severity": "medium",
        "confidence": "medium",
        "title": "Database service is reachable over the network",
        "match": lambda f: f["service"] in ("mysql", "postgresql") or f["port"] in (3306, 5432),
        "note": "A database port is reachable from the scanning machine.",
        "risk": "A database reachable from other machines can be attacked with password guessing.",
        "fix": ["Bind the database to localhost or a private interface.",
                "Allow connections only from the application servers that need them."],
        "refs": [],
    },
    {
        "id": "R-OLD-SSH",
        "severity": "medium",
        "confidence": "medium",
        "title": "Old OpenSSH version reported",
        "match": lambda f: (f["service"] == "ssh" and "openssh" in f["product"].lower()
                            and _major(f["version"]) is not None and _major(f["version"]) < 7),
        "note": "The SSH service reports an OpenSSH release older than version 7.",
        "risk": "Old SSH releases lack years of security fixes and modern defaults.",
        "fix": ["Upgrade OpenSSH to a release supported by your operating system vendor.",
                "Disable password login and use key-based login."],
        "refs": [],
    },
    {
        "id": "R-HTTP-PLAIN",
        "severity": "low",
        "confidence": "medium",
        "title": "Web server without encryption",
        "match": lambda f: f["service"] == "http",
        "note": "A web server answers on plain HTTP. This scan did not test the web application itself.",
        "risk": "Traffic to this server can be read or changed on the network.",
        "fix": ["Serve the site over HTTPS and redirect HTTP to HTTPS.",
                "Run a web scanner such as Nikto against this server for deeper checks."],
        "refs": [],
    },
]

DEFAULT_RULE = {
    "id": "R-OPEN-PORT",
    "severity": "info",
    "confidence": "low",
    "title": "Open port",
    "note": "The port is open. No specific rule matched this service.",
    "risk": "Every open port is extra attack surface if the service is not needed.",
    "fix": ["Close the port if the service is not needed, or restrict it with a firewall."],
    "refs": [],
}


def _major(version):
    m = re.match(r"(\d+)", version or "")
    return int(m.group(1)) if m else None


def matching_rules(finding):
    """All rules that match, highest severity first."""
    hits = [r for r in RULES if r["match"](finding)]
    return sorted(hits, key=lambda r: SEVERITY_ORDER.index(r["severity"]))


def apply_rules(finding):
    """Return the highest-severity matching rule (first one wins on ties)."""
    hits = matching_rules(finding)
    return hits[0] if hits else DEFAULT_RULE


def title_for(finding, rule):
    if rule is DEFAULT_RULE:
        return f"Open port {finding['port']}/{finding['protocol']} ({finding['service']})"
    return rule["title"]

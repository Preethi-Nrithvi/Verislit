"""Deterministic Nmap XML parser. No AI involved.

Produces structured findings, each with evidence copied verbatim from the raw file.
"""
import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

MAX_EVIDENCE_CHARS = 800


def _raw_port_blocks(text):
    """Map (host_index, protocol, portid) -> (line_number, raw_text) from the raw file."""
    blocks = {}
    for host_idx, hm in enumerate(re.finditer(r"<host\b.*?</host>", text, re.S)):
        for pm in re.finditer(r"<port\b[^>]*?(?:/>|>.*?</port>)", hm.group(0), re.S):
            raw = pm.group(0)
            proto = re.search(r'protocol="([^"]*)"', raw)
            pid = re.search(r'portid="([^"]*)"', raw)
            if not (proto and pid):
                continue
            start = hm.start() + pm.start()
            line = text.count("\n", 0, start) + 1
            blocks[(host_idx, proto.group(1), pid.group(1))] = (line, raw[:MAX_EVIDENCE_CHARS])
    return blocks


def parse_nmap_text(text, filename="scan.xml"):
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Not valid XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError("Not an Nmap XML report (root element is not <nmaprun>).")

    blocks = _raw_port_blocks(text)
    start = root.get("start")
    scanned_at = (
        datetime.fromtimestamp(int(start), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if start and start.isdigit()
        else "unknown"
    )

    findings, targets = [], []
    counter, ev_counter = 0, 0
    for host_idx, host in enumerate(root.findall("host")):
        addr = next((a.get("addr") for a in host.findall("address")
                     if a.get("addrtype") in ("ipv4", "ipv6")), "unknown")
        targets.append(addr)
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            svc = svc if svc is not None else ET.Element("service")
            scripts = {s.get("id", ""): s.get("output", "") for s in port.findall("script")}
            proto, pid = port.get("protocol", "tcp"), port.get("portid", "0")
            line, raw = blocks.get((host_idx, proto, pid), (None, ""))
            counter += 1
            ev_counter += 1
            findings.append({
                "id": f"F-{counter:03d}",
                "host": addr,
                "port": int(pid) if pid.isdigit() else None,
                "protocol": proto,
                "service": svc.get("name", "unknown"),
                "product": svc.get("product", ""),
                "version": svc.get("version", ""),
                "extrainfo": svc.get("extrainfo", ""),
                "scripts": scripts,
                "evidence": [{
                    "id": f"E-{ev_counter:03d}",
                    "source": "nmap",
                    "line": line,
                    "quote": raw,
                }],
            })
    return {
        "tool": "nmap",
        "tool_version": root.get("version", "unknown"),
        "target": ", ".join(dict.fromkeys(targets)) or "unknown",
        "scanned_at": scanned_at,
        "input_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "filename": filename,
        "raw_text": text,
        "findings": findings,
    }


def parse_nmap(path):
    path = Path(path)
    return parse_nmap_text(path.read_text(encoding="utf-8"), path.name)

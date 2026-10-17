import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "report.schema.json").read_text(encoding="utf-8"))
EXAMPLE = json.loads((ROOT / "tests" / "fixtures" / "example_report.json").read_text(encoding="utf-8"))
validator = Draft202012Validator(SCHEMA)


def errors(doc):
    return list(validator.iter_errors(doc))


def test_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_example_report_is_valid():
    assert errors(EXAMPLE) == []


def test_rejects_unknown_severity():
    bad = copy.deepcopy(EXAMPLE)
    bad["findings"][0]["severity"] = "catastrophic"
    assert errors(bad)


def test_rejects_finding_without_evidence():
    bad = copy.deepcopy(EXAMPLE)
    bad["findings"][0]["evidence"] = []
    assert errors(bad)


def test_rejects_extra_fields():
    bad = copy.deepcopy(EXAMPLE)
    bad["findings"][0]["exploit_code"] = "nope"
    assert errors(bad)


def test_counts_match_findings():
    counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    for f in EXAMPLE["findings"]:
        counts[f["severity"]] += 1
    assert counts == EXAMPLE["summary"]["counts"]

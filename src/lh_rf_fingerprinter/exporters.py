"""Output Exporters: ANSI Terminal Table, Canonical JSON, and OASIS SARIF v2.1.0.

Provides multi-format serializations for RF physical-layer security audit reports.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .auditor import AuditReport


def format_terminal_table(report: AuditReport) -> str:
    """Formats an AuditReport into a clean, human-readable terminal table."""
    lines: List[str] = []

    lines.append("")
    lines.append("========================================================================================")
    lines.append("            LOGIHERTZ RF TRANSMITTER FINGERPRINTER: AUDIT REPORT (lh-rf)                ")
    lines.append("========================================================================================")
    lines.append(f" Timestamp (UTC) : {report.timestamp_utc}")
    lines.append(f" Posture Score   : {report.score} / 100")
    lines.append(f" Security Status : {report.status}")
    lines.append(
        f" Total Invariants: {report.total_rules} | Passed: {report.passed_rules} | Failed: {report.failed_rules}"
    )
    lines.append("----------------------------------------------------------------------------------------")
    lines.append(f" {'RULE ID':<12} | {'STATUS':<8} | {'DEDUCT':<6} | {'SEVERITY':<8} | TITLE")
    lines.append("----------------------------------------------------------------------------------------")

    for f in report.findings:
        status_str = "[PASS]" if f.passed else "[FAIL]"
        deduct_str = " 0" if f.passed else f"-{f.deduction}"
        lines.append(
            f" {f.rule_id:<12} | {status_str:<8} | {deduct_str:<6} | {f.severity:<8} | {f.title}"
        )

    lines.append("----------------------------------------------------------------------------------------")

    if report.failed_rules > 0:
        lines.append("\nDETAILED REMEDIATION ACTIONS REQUIRED:")
        for f in report.findings:
            if not f.passed:
                lines.append(f" -> [{f.rule_id}] ({f.severity}, {f.cwe_number}): {f.title}")
                lines.append(f"    Issue:       {f.description}")
                lines.append(f"    Remediation: {f.remediation}\n")
    else:
        lines.append(
            "\nAll 10 physical-layer RF security invariants satisfied. Receiver posture is HARDENED."
        )

    lines.append("========================================================================================")

    return "\n".join(lines)


def format_canonical_json(report: AuditReport) -> str:
    """Formats an AuditReport into formatted Canonical JSON."""
    return json.dumps(report.to_dict(), indent=2)


def format_sarif(report: AuditReport) -> str:
    """Formats an AuditReport into OASIS SARIF v2.1.0 JSON format."""
    rules_sarif: List[Dict[str, Any]] = []
    results_sarif: List[Dict[str, Any]] = []

    for f in report.findings:
        level = "note"
        if f.severity in ("CRITICAL", "HIGH"):
            level = "error"
        elif f.severity == "MEDIUM":
            level = "warning"
        elif f.severity == "LOW":
            level = "note"

        rules_sarif.append(
            {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {
                    "text": f"[{f.cwe_number}] {f.description} Remediation: {f.remediation}"
                },
                "defaultConfiguration": {"level": level},
                "helpUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-rf-fingerprinter",
            }
        )

        if not f.passed:
            results_sarif.append(
                {
                    "ruleId": f.rule_id,
                    "level": level,
                    "message": {
                        "text": f"{f.title} ({f.cwe_number}): {f.description} Action: {f.remediation}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "config/rff_policy.json"
                                }
                            }
                        }
                    ],
                }
            )

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-rf-fingerprint",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-rf-fingerprinter",
                        "rules": rules_sarif,
                    }
                },
                "results": results_sarif,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)

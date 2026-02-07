#!/usr/bin/env python3
"""
SARIF Aggregator for FuzzForge systemd campaigns.

Reads all .sarif files from the sarif/ directory and produces:
1. A summary report (JSON) with counts by severity, category, file
2. A unified SARIF file combining all runs
3. A human-readable markdown report

Usage: python3 aggregate_sarif.py [sarif_dir]
"""

import json
import sys
import os
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime


def load_sarif_files(sarif_dir: str) -> list[tuple[str, dict]]:
    """Load all .sarif files from directory."""
    results = []
    sarif_path = Path(sarif_dir)
    for f in sorted(sarif_path.glob("*.sarif")):
        try:
            data = json.loads(f.read_text())
            results.append((f.name, data))
        except (json.JSONDecodeError, OSError) as e:
            print(f"  Warning: Could not parse {f.name}: {e}", file=sys.stderr)
    return results


def extract_findings(sarif_files: list[tuple[str, dict]]) -> list[dict]:
    """Extract all findings from SARIF files with source tracking."""
    findings = []
    for filename, sarif in sarif_files:
        for run in sarif.get("runs", []):
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
            for result in run.get("results", []):
                finding = {
                    "source_file": filename,
                    "tool": tool_name,
                    "rule_id": result.get("ruleId", "unknown"),
                    "level": result.get("level", "none"),
                    "message": result.get("message", {}).get("text", ""),
                    "locations": [],
                }
                for loc in result.get("locations", []):
                    phys = loc.get("physicalLocation", {})
                    art = phys.get("artifactLocation", {})
                    region = phys.get("region", {})
                    finding["locations"].append({
                        "file": art.get("uri", "unknown"),
                        "line": region.get("startLine", 0),
                    })
                findings.append(finding)
    return findings


def generate_summary(findings: list[dict]) -> dict:
    """Generate summary statistics."""
    severity_counts = Counter(f["level"] for f in findings)
    category_counts = Counter(f["rule_id"] for f in findings)
    source_counts = Counter(f["source_file"] for f in findings)
    tool_counts = Counter(f["tool"] for f in findings)

    affected_files = Counter()
    for f in findings:
        for loc in f["locations"]:
            affected_files[loc["file"]] += 1

    return {
        "total_findings": len(findings),
        "by_severity": dict(severity_counts.most_common()),
        "by_rule": dict(category_counts.most_common(20)),
        "by_source_sarif": dict(source_counts.most_common()),
        "by_tool": dict(tool_counts.most_common()),
        "top_affected_files": dict(affected_files.most_common(30)),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


def generate_unified_sarif(sarif_files: list[tuple[str, dict]]) -> dict:
    """Combine all SARIF runs into a single file."""
    all_runs = []
    for filename, sarif in sarif_files:
        for run in sarif.get("runs", []):
            run_copy = dict(run)
            run_copy.setdefault("properties", {})["sourceFile"] = filename
            all_runs.append(run_copy)

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": all_runs,
    }


def generate_markdown(summary: dict, findings: list[dict]) -> str:
    """Generate human-readable markdown report."""
    lines = [
        "# FuzzForge systemd Security Report",
        "",
        f"Generated: {summary['generated_at']}",
        f"Total findings: **{summary['total_findings']}**",
        "",
        "## Severity Breakdown",
        "",
        "| Level | Count |",
        "|-------|-------|",
    ]

    for level, count in sorted(summary["by_severity"].items(),
                                key=lambda x: {"error": 0, "warning": 1, "note": 2, "none": 3}.get(x[0], 4)):
        lines.append(f"| {level} | {count} |")

    lines.extend([
        "",
        "## Top Affected Files",
        "",
        "| File | Findings |",
        "|------|----------|",
    ])

    for f, count in list(summary["top_affected_files"].items())[:20]:
        lines.append(f"| `{f}` | {count} |")

    lines.extend([
        "",
        "## By Analysis Tool",
        "",
        "| Tool | Findings |",
        "|------|----------|",
    ])

    for tool, count in summary["by_tool"].items():
        lines.append(f"| {tool} | {count} |")

    # Critical findings detail
    critical = [f for f in findings if f["level"] == "error"]
    if critical:
        lines.extend([
            "",
            "## Critical Findings (error level)",
            "",
        ])
        for i, f in enumerate(critical[:50], 1):
            locs = ", ".join(f'{l["file"]}:{l["line"]}' for l in f["locations"]) or "unknown"
            lines.append(f"{i}. **[{f['rule_id']}]** {f['message'][:120]}")
            lines.append(f"   Location: `{locs}` | Source: {f['source_file']}")
            lines.append("")

    return "\n".join(lines)


def main():
    sarif_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "sarif"
    )

    print(f"Scanning {sarif_dir} for SARIF files...")

    sarif_files = load_sarif_files(sarif_dir)
    if not sarif_files:
        print("No SARIF files found. Run FuzzForge workflows first.")
        sys.exit(0)

    print(f"Loaded {len(sarif_files)} SARIF files")

    findings = extract_findings(sarif_files)
    summary = generate_summary(findings)

    # Write summary JSON
    summary_path = os.path.join(sarif_dir, "summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary: {summary_path}")

    # Write unified SARIF
    unified_path = os.path.join(sarif_dir, "unified.sarif")
    unified = generate_unified_sarif(sarif_files)
    with open(unified_path, "w") as f:
        json.dump(unified, f, indent=2)
    print(f"Unified SARIF: {unified_path}")

    # Write markdown report
    report_path = os.path.join(sarif_dir, "REPORT.md")
    md = generate_markdown(summary, findings)
    with open(report_path, "w") as f:
        f.write(md)
    print(f"Report: {report_path}")

    # Print summary
    print(f"\nTotal findings: {summary['total_findings']}")
    for level, count in sorted(summary["by_severity"].items()):
        print(f"  {level}: {count}")


if __name__ == "__main__":
    main()

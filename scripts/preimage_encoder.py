#!/usr/bin/env python3
"""Independent encoder for the Assay evidence preimage.

This file is a second implementation of the canonical evidence encoding in
`docs/contract-interface.md` ("Formal grammar (ABNF)"). It was written from
that document (plus the report-shape notes in `conformance/README.md`) and does
not call, import, or transcribe the Go encoder in `internal/attest`. The point
of the cross-implementation check is that two readings of the specification
independently produce the same bytes.

It is exercised by `internal/attest/independent_encoder_test.go` and the CI
job `preimage-cross-check` over:

  * every committed vector in `internal/attest/testdata/vectors/`,
  * every subject in `internal/mechanics/testdata/`, and
  * every case in `conformance/cases.json`.

The script is standard-library only. It accepts a report in the scanner's
JSON shape and writes `{"version": ..., "preimage": ..., "digest": ...}` to
stdout. `digest` is the lowercase hex SHA-256 of the preimage bytes.

Usage:
    python3 scripts/preimage_encoder.py REPORT.json
    python3 scripts/preimage_encoder.py --scanner-identity v1.2.3 REPORT.json
    python3 scripts/preimage_encoder.py --version v1 REPORT.json

`REPORT.json` may be `-` to read from stdin. Malformed input exits non-zero;
CI must not mistake a parse failure for agreement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

# Severity values are ABI values from docs/contract-interface.md. Do not
# renumber them.
SEVERITY_VALUES = {
    "clear": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Mechanic bit positions are ABI values. The first six are in the contract
# interface table; the last two are the trustline bits named by the report
# shape in conformance/README.md and emitted by holder scans.
MECHANIC_VALUES = {
    "auth_required": 1 << 0,
    "auth_revocable": 1 << 1,
    "auth_clawback_enabled": 1 << 2,
    "auth_immutable": 1 << 3,
    "domain_unverified": 1 << 4,
    "blocklisted": 1 << 5,
    "trustline_clawback_enabled": 1 << 6,
    "trustline_deauthorized": 1 << 7,
}

VERSION_LINES = {
    "v1": "assay-evidence-v1",
    "v2": "assay-evidence-v2",
    "v3": "assay-evidence-v3",
    "assay-evidence-v1": "assay-evidence-v1",
    "assay-evidence-v2": "assay-evidence-v2",
    "assay-evidence-v3": "assay-evidence-v3",
}


def escape(value: str) -> str:
    """Apply the documented field escaping (backslash first)."""
    return (
        value.replace("\\", "\\\\")
        .replace("\t", "\\t")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def severity_value(report: dict[str, Any], key: str) -> int:
    value = report.get(key)
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"{key} must be a severity name or number, got {value!r}")
    if isinstance(value, int):
        return value
    try:
        return SEVERITY_VALUES[value]
    except KeyError as exc:
        raise ValueError(f"unknown severity {value!r}") from exc


def mechanics_bits(report: dict[str, Any]) -> int:
    names = report.get("mechanics") or []
    if not isinstance(names, list):
        raise ValueError(f"mechanics must be a list, got {names!r}")
    bits = 0
    for name in names:
        try:
            bits |= MECHANIC_VALUES[name]
        except KeyError as exc:
            raise ValueError(f"unknown mechanic {name!r}") from exc
    return bits


def asset_name(report: dict[str, Any]) -> str:
    asset = report.get("asset")
    if not isinstance(asset, dict):
        raise ValueError(f"asset must be an object, got {asset!r}")
    code = asset.get("code")
    issuer = asset.get("issuer")
    if not isinstance(code, str) or not isinstance(issuer, str):
        raise ValueError("asset must carry string code and issuer fields")
    return f"{code}-{issuer}"


def normalize_version(version: str) -> str:
    try:
        return VERSION_LINES[version]
    except KeyError as exc:
        raise ValueError(
            f"unknown preimage version {version!r}; want v1, v2, v3, or assay-evidence-vN"
        ) from exc


def select_version(report: dict[str, Any]) -> str:
    """Name the newest binding the report carries, per the spec."""
    if report.get("scanner_bound") or report.get("network"):
        return VERSION_LINES["v3"]
    if report.get("checks"):
        return VERSION_LINES["v2"]
    return VERSION_LINES["v1"]


def render(
    report: dict[str, Any],
    scanner_identity: str | None = None,
    version: str | None = None,
) -> tuple[str, bytes]:
    """Render the canonical preimage bytes for one report."""
    if version is None:
        version_line = select_version(report)
    else:
        version_line = normalize_version(version)

    lines = [version_line]

    # The scanner line is v3-only and only when the report opts into identity
    # binding. It comes immediately after the version line.
    if version_line == VERSION_LINES["v3"] and report.get("scanner_bound"):
        if scanner_identity is None:
            raise ValueError("scanner_bound report requires --scanner-identity")
        lines.append("scanner\t" + escape(scanner_identity))

    lines.append("asset\t" + escape(asset_name(report)))
    lines.append("severity\t" + str(severity_value(report, "severity")))
    lines.append("base_severity\t" + str(severity_value(report, "base_severity")))
    escalated = report.get("escalated")
    if not isinstance(escalated, bool):
        raise ValueError(f"escalated must be a boolean, got {escalated!r}")
    lines.append("escalated\t" + ("true" if escalated else "false"))
    lines.append("mechanics\t" + str(mechanics_bits(report)))

    accountability = report.get("accountability")
    if accountability not in ("unknown", "unverified", "verified"):
        raise ValueError(f"unknown accountability {accountability!r}")
    lines.append("accountability\t" + accountability)

    # v1 never had a checks line, even when the report carries a set. The line
    # is absent, not empty (#269).
    checks = report.get("checks") or []
    if not isinstance(checks, list):
        raise ValueError(f"checks must be a list, got {checks!r}")
    if version_line != VERSION_LINES["v1"] and checks:
        for check in checks:
            if not isinstance(check, str):
                raise ValueError(f"check id must be a string, got {check!r}")
        sorted_checks = sorted(checks, key=lambda c: c.encode("utf-8"))
        lines.append("checks\t" + ",".join(sorted_checks))

    network = report.get("network") or ""
    if version_line == VERSION_LINES["v3"] and network:
        if not isinstance(network, str):
            raise ValueError(f"network must be a string, got {network!r}")
        lines.append("network\t" + escape(network))

    evidence = report.get("evidence") or []
    if not isinstance(evidence, list):
        raise ValueError(f"evidence must be a list, got {evidence!r}")
    evidence_lines = []
    for item in evidence:
        if not isinstance(item, dict):
            raise ValueError(f"evidence item must be an object, got {item!r}")
        try:
            source = item["source"]
            url = item["url"]
            claim = item["claim"]
        except KeyError as exc:
            raise ValueError(f"evidence item is missing {exc.args[0]!r}") from exc
        if not all(isinstance(v, str) for v in (source, url, claim)):
            raise ValueError("evidence source, url, and claim must be strings")
        evidence_lines.append(
            "evidence\t"
            + escape(source)
            + "\t"
            + escape(url)
            + "\t"
            + escape(claim)
        )

    # The spec sorts the rendered evidence lines bytewise, including the key
    # and separators, so input order cannot move the hash.
    evidence_lines.sort(key=lambda line: line.encode("utf-8"))
    lines.extend(evidence_lines)

    preimage = ("\n".join(lines) + "\n").encode("utf-8")
    return version_line, preimage


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render the independent Assay evidence preimage encoder."
    )
    parser.add_argument(
        "report",
        help="report JSON file in the scanner's shape, or - for stdin",
    )
    parser.add_argument(
        "--scanner-identity",
        default=None,
        help="identity to render on the v3 scanner line when scanner_bound is set",
    )
    parser.add_argument(
        "--version",
        default=None,
        choices=sorted(VERSION_LINES),
        help="render under an explicit version instead of the newest binding",
    )
    args = parser.parse_args(argv)

    try:
        if args.report == "-":
            doc = json.load(sys.stdin)
        else:
            with open(args.report, encoding="utf-8") as fh:
                doc = json.load(fh)
        if not isinstance(doc, dict):
            raise ValueError("report must be a JSON object")
        version, preimage = render(doc, args.scanner_identity, args.version)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"preimage_encoder: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "version": version,
                "preimage": preimage.decode("utf-8"),
                "digest": hashlib.sha256(preimage).hexdigest(),
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

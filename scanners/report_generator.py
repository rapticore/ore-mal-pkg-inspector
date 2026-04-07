#!/usr/bin/env python3
"""
Report Generator Module
Generates JSON and HTML reports for malicious packages found during scans.
"""

from __future__ import annotations

import html
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Module logger
logger = logging.getLogger(__name__)
ABSOLUTE_PATH_REDACTED = "<absolute-path-redacted>"


def get_timestamp() -> str:
    """
    Get current UTC timestamp in ISO 8601 format.

    Returns:
        Timestamp string like "2025-12-17T10:30:00Z"
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get_project_root() -> str:
    """
    Get the project root directory (where malicious_package_scanner.py is located).

    Returns:
        Absolute path to project root
    """
    current_file = os.path.abspath(__file__)
    scanners_dir = os.path.dirname(current_file)
    return os.path.dirname(scanners_dir)


def _redact_path(path: str) -> str:
    """Remove absolute filesystem path disclosure from reports."""
    if not path:
        return path

    normalized = os.path.normpath(path)
    if not os.path.isabs(normalized):
        return normalized
    return ABSOLUTE_PATH_REDACTED


def get_html_report_path(report_path: str) -> str:
    """Return the HTML sibling path for a report artifact path."""
    root, ext = os.path.splitext(report_path)
    if ext.lower() in {".html", ".htm"}:
        return report_path
    if ext:
        return root + ".html"
    return report_path + ".html"


def get_json_report_path(report_path: str) -> str:
    """Return the JSON sibling path for a report artifact path."""
    root, ext = os.path.splitext(report_path)
    if ext.lower() == ".json":
        return report_path
    if ext.lower() in {".html", ".htm"}:
        return root + ".json"
    return report_path + ".json"


def _resolve_report_paths(output_path: Optional[str]) -> Tuple[str, str]:
    """Resolve JSON and HTML output paths from one optional caller path."""
    if output_path is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        project_root = _get_project_root()
        scan_output_dir = os.path.join(project_root, "scan-output")
        json_path = os.path.join(
            scan_output_dir,
            f"malicious_packages_report_{timestamp}.json",
        )
        return json_path, get_html_report_path(json_path)

    resolved_output = output_path
    if not os.path.isabs(resolved_output):
        resolved_output = os.path.abspath(resolved_output)

    if os.path.splitext(resolved_output)[1].lower() in {".html", ".htm"}:
        return get_json_report_path(resolved_output), resolved_output
    return resolved_output, get_html_report_path(resolved_output)


def _build_report_payload(
    ecosystem: str,
    scanned_path: str,
    total_packages_scanned: int,
    malicious_packages: List[Dict[str, Any]],
    iocs: List[Dict[str, Any]],
    data_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """Build the normalized report payload shared by JSON and HTML outputs."""
    filtered_packages = []
    for pkg in malicious_packages:
        filtered_packages.append({k: v for k, v in pkg.items() if k != "source_details"})

    return {
        "scan_timestamp": get_timestamp(),
        "ecosystem": ecosystem,
        "scanned_path": _redact_path(scanned_path),
        "total_packages_scanned": total_packages_scanned,
        "data_status": data_metadata.get("data_status", "not_applicable"),
        "sources_used": data_metadata.get("sources_used", []),
        "experimental_sources_used": data_metadata.get("experimental_sources_used", []),
        "missing_ecosystems": data_metadata.get("missing_ecosystems", []),
        "promotion_decision": data_metadata.get("promotion_decision", ""),
        "kept_last_known_good": data_metadata.get("kept_last_known_good", False),
        "anomalies": data_metadata.get("anomalies", []),
        "malicious_packages_found": len(malicious_packages),
        "iocs_found": len(iocs),
        "malicious_packages": filtered_packages,
        "iocs": iocs,
    }


def _ensure_parent_dir(path: str) -> None:
    """Ensure the output directory for one file exists."""
    output_dir = os.path.dirname(path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)


def _escape(value: Any) -> str:
    """HTML-escape any display value."""
    return html.escape("" if value is None else str(value), quote=True)


def _severity_badge_class(severity: str) -> str:
    normalized = str(severity or "info").strip().lower()
    if normalized == "block":
        return "critical"
    if normalized in {"warn", "warning"}:
        return "medium"
    if normalized in {"critical", "high", "medium", "low", "info"}:
        return normalized
    return "neutral"


def _data_status_badge_class(status: str) -> str:
    normalized = str(status or "not_applicable").strip().lower()
    if normalized == "complete":
        return "low"
    if normalized == "partial":
        return "medium"
    if normalized == "failed":
        return "critical"
    return "info"


def _format_locations(locations: List[Dict[str, Any]]) -> List[str]:
    """Convert SARIF-like locations to display strings."""
    formatted = []
    for loc in locations or []:
        phys_loc = loc.get("physicalLocation", {}) or {}
        artifact_loc = phys_loc.get("artifactLocation", {}) or {}
        region = phys_loc.get("region", {}) or {}
        file_path = artifact_loc.get("uri", "unknown")
        start_line = region.get("startLine")
        start_col = region.get("startColumn")
        end_col = region.get("endColumn")
        if start_line and start_col and end_col:
            formatted.append(f"{file_path}:{start_line}:{start_col}-{end_col}")
        elif start_line:
            formatted.append(f"{file_path}:{start_line}")
        else:
            formatted.append(str(file_path))
    return formatted


def _ioc_detail_rows(ioc: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Return label/value rows for one IoC card."""
    rows = []
    path_value = ioc.get("path") or ioc.get("filename")
    if path_value:
        rows.append(("Path", str(path_value)))
    if ioc.get("variant"):
        rows.append(("Variant", str(ioc["variant"])))
    if ioc.get("pattern"):
        rows.append(("Pattern", str(ioc["pattern"])))
    if ioc.get("url"):
        rows.append(("URL", str(ioc["url"])))
    if ioc.get("hash"):
        rows.append(("SHA-256", str(ioc["hash"])))
    if ioc.get("filename"):
        rows.append(("Filename", str(ioc["filename"])))
    return rows


def _render_badges(items: List[str], badge_class: str = "neutral") -> str:
    if not items:
        return '<span class="badge badge-neutral">none</span>'
    return "".join(
        f'<span class="badge badge-{badge_class}">{_escape(item)}</span>'
        for item in items
    )


def _render_threat_data_section(report: Dict[str, Any]) -> str:
    anomalies = report.get("anomalies", []) or []
    anomaly_html = ""
    if anomalies:
        anomaly_items = []
        for anomaly in anomalies:
            severity = _severity_badge_class(str(anomaly.get("severity", "info")))
            message = anomaly.get("message", "Threat-data anomaly")
            anomaly_items.append(
                "<div class=\"finding-item severity-{severity}\">"
                "<div class=\"finding-header\">"
                "<span>{message}</span>"
                "<span class=\"badge badge-{severity}\">{severity_label}</span>"
                "</div>"
                "</div>".format(
                    severity=severity,
                    message=_escape(message),
                    severity_label=_escape(str(anomaly.get("severity", "info")).upper()),
                )
            )
        anomaly_html = (
            "<div class=\"section-subtitle\">Live update anomalies</div>"
            + "".join(anomaly_items)
        )

    return """
    <section class="section">
        <h2>Threat Data</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Data Status</div>
                <div class="value value-text">
                    <span class="badge badge-{data_status_class}">{data_status}</span>
                </div>
            </div>
            <div class="stat-card">
                <div class="label">Core Sources</div>
                <div class="value value-text">{sources_used}</div>
            </div>
            <div class="stat-card">
                <div class="label">Experimental Sources</div>
                <div class="value value-text">{experimental_sources}</div>
            </div>
            <div class="stat-card">
                <div class="label">Promotion Decision</div>
                <div class="value value-text">{promotion_decision}</div>
            </div>
        </div>
        <div class="meta-grid">
            <div class="meta-card">
                <div class="meta-label">Unavailable ecosystems</div>
                <div class="meta-value">{missing_ecosystems}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Kept last-known-good data</div>
                <div class="meta-value">{kept_last_known_good}</div>
            </div>
        </div>
        {anomaly_html}
    </section>
    """.format(
        data_status_class=_data_status_badge_class(str(report.get("data_status", "not_applicable"))),
        data_status=_escape(str(report.get("data_status", "not_applicable")).replace("_", " ")),
        sources_used=_render_badges(list(report.get("sources_used", []) or []), "info"),
        experimental_sources=_render_badges(
            list(report.get("experimental_sources_used", []) or []),
            "medium",
        ),
        promotion_decision=_escape(
            str(report.get("promotion_decision", "") or "not_applicable").replace("_", " ")
        ),
        missing_ecosystems=_render_badges(
            list(report.get("missing_ecosystems", []) or []),
            "critical",
        ),
        kept_last_known_good=_escape(
            "yes" if report.get("kept_last_known_good") else "no"
        ),
        anomaly_html=anomaly_html,
    )


def _render_malicious_packages_section(report: Dict[str, Any]) -> str:
    packages = list(report.get("malicious_packages", []) or [])
    if not packages:
        return """
        <section class="section">
            <h2>Malicious Packages</h2>
            <div class="empty-state">No malicious packages were detected in this scan.</div>
        </section>
        """

    items = []
    for pkg in packages:
        severity = _severity_badge_class(str(pkg.get("severity", "info")))
        locations = _format_locations(list(pkg.get("locations", []) or []))
        location_html = ""
        if locations:
            location_html = (
                "<div class=\"detail-block\">"
                "<div class=\"detail-label\">Found in</div>"
                "<ul class=\"detail-list\">"
                + "".join(f"<li><span class=\"code\">{_escape(loc)}</span></li>" for loc in locations)
                + "</ul></div>"
            )
        description_html = ""
        if pkg.get("description"):
            description_html = (
                "<div class=\"detail-block\">"
                "<div class=\"detail-label\">Description</div>"
                f"<div class=\"detail-text\">{_escape(pkg.get('description'))}</div>"
                "</div>"
            )
        items.append(
            """
            <article class="finding-item severity-{severity}">
                <div class="finding-header">
                    <div>
                        <div class="finding-title">{name}</div>
                        <div class="finding-subtitle">
                            <span class="code">{version}</span>
                            <span>{ecosystem}</span>
                        </div>
                    </div>
                    <span class="badge badge-{severity}">{severity_label}</span>
                </div>
                <div class="meta-grid compact">
                    <div class="meta-card">
                        <div class="meta-label">Sources</div>
                        <div class="meta-value">{sources}</div>
                    </div>
                </div>
                {description_html}
                {location_html}
            </article>
            """.format(
                severity=severity,
                name=_escape(pkg.get("name", "unknown")),
                version=_escape(pkg.get("version", "unknown")),
                ecosystem=_escape(pkg.get("ecosystem", report.get("ecosystem", "unknown"))),
                severity_label=_escape(str(pkg.get("severity", "info")).upper()),
                sources=_render_badges(list(pkg.get("sources", []) or []), "info"),
                description_html=description_html,
                location_html=location_html,
            )
        )

    return """
    <section class="section">
        <h2>Malicious Packages</h2>
        {items}
    </section>
    """.format(items="".join(items))


def _render_iocs_section(report: Dict[str, Any]) -> str:
    iocs = list(report.get("iocs", []) or [])
    if not iocs:
        return """
        <section class="section">
            <h2>Indicators of Compromise</h2>
            <div class="empty-state">No indicators of compromise were detected in this scan.</div>
        </section>
        """

    items = []
    for ioc in iocs:
        severity = _severity_badge_class(str(ioc.get("severity", "info")))
        detail_rows = []
        for label, value in _ioc_detail_rows(ioc):
            detail_rows.append(
                "<div class=\"meta-card\"><div class=\"meta-label\">{label}</div>"
                "<div class=\"meta-value\"><span class=\"code\">{value}</span></div></div>".format(
                    label=_escape(label),
                    value=_escape(value),
                )
            )
        items.append(
            """
            <article class="finding-item severity-{severity}">
                <div class="finding-header">
                    <div>
                        <div class="finding-title">{ioc_type}</div>
                        <div class="finding-subtitle">{variant}</div>
                    </div>
                    <span class="badge badge-{severity}">{severity_label}</span>
                </div>
                <div class="meta-grid compact">{detail_rows}</div>
            </article>
            """.format(
                severity=severity,
                ioc_type=_escape(str(ioc.get("type", "unknown")).replace("_", " ").upper()),
                variant=_escape(str(ioc.get("variant", ""))),
                severity_label=_escape(str(ioc.get("severity", "info")).upper()),
                detail_rows="".join(detail_rows),
            )
        )

    return """
    <section class="section">
        <h2>Indicators of Compromise</h2>
        {items}
    </section>
    """.format(items="".join(items))


def _render_html_report(report: Dict[str, Any], json_report_path: str, html_report_path: str) -> str:
    """Render the complete HTML report using the shared Ore report styling language."""
    issue_count = int(report.get("malicious_packages_found", 0) or 0) + int(
        report.get("iocs_found", 0) or 0
    )
    summary_class = "alert" if issue_count else "clean"
    summary_title = "Threats detected" if issue_count else "No threats detected"
    summary_body = (
        "{pkg_count} malicious package(s) and {ioc_count} IoC(s) were identified.".format(
            pkg_count=report.get("malicious_packages_found", 0),
            ioc_count=report.get("iocs_found", 0),
        )
        if issue_count
        else "This scan did not identify malicious packages or IoCs."
    )

    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OreWatch Scan Report</title>
    <style>
        :root {{
            --neutral-0: #FFFFFF;
            --neutral-50: #F8FAFC;
            --neutral-100: #F2F4F7;
            --neutral-200: #EAECF0;
            --neutral-300: #D0D5DD;
            --neutral-500: #667085;
            --neutral-700: #344054;
            --neutral-900: #101828;

            --report-bg: #FFFFFF;
            --card-bg: #F8FAFC;

            --text-primary: #1A1A1A;
            --text-secondary: #475467;
            --text-muted: #667085;

            --border: #EAECF0;
            --border-dark: #D0D5DD;

            --accent-primary: #2E90FA;
            --accent-secondary: #12B76A;

            --critical: #D92D20;
            --high: #F04438;
            --medium: #F79009;
            --low: #12B76A;
            --info: #2E90FA;

            --space-xs: 4px;
            --space-sm: 8px;
            --space-md: 16px;
            --space-lg: 24px;
            --space-xl: 32px;

            --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.05);
            --shadow-md: 0 2px 6px rgba(0, 0, 0, 0.08);
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: Inter, "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            font-size: 14px;
            line-height: 1.5;
            color: var(--text-primary);
            background: var(--neutral-100);
            padding: var(--space-lg);
            -webkit-font-smoothing: antialiased;
        }}

        .container {{
            max-width: 1280px;
            margin: 0 auto;
            background: var(--report-bg);
            padding: var(--space-xl);
            box-shadow: var(--shadow-sm);
            border-radius: 8px;
            border: 1px solid var(--border);
        }}

        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: var(--space-lg);
            margin-bottom: var(--space-xl);
            padding-bottom: var(--space-lg);
            border-bottom: 2px solid var(--border);
        }}

        .header-left h1 {{
            font-size: 28px;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: var(--space-sm);
        }}

        .subtitle {{
            color: var(--text-muted);
            font-size: 14px;
        }}

        .header-right {{
            text-align: right;
        }}

        .logo {{
            font-size: 20px;
            font-weight: 700;
            color: var(--accent-primary);
            margin-bottom: var(--space-xs);
        }}

        .date {{
            color: var(--text-muted);
            font-size: 12px;
        }}

        .summary-banner {{
            padding: var(--space-lg);
            border-radius: 8px;
            margin-bottom: var(--space-xl);
            border: 1px solid var(--border);
        }}

        .summary-banner.clean {{
            background: rgba(18, 183, 106, 0.08);
            border-left: 4px solid var(--low);
        }}

        .summary-banner.alert {{
            background: rgba(240, 68, 56, 0.08);
            border-left: 4px solid var(--high);
        }}

        .summary-banner h2 {{
            font-size: 22px;
            font-weight: 700;
            margin: 0 0 var(--space-sm) 0;
            padding: 0;
            background: transparent;
            border: none;
            border-radius: 0;
        }}

        .summary-banner p {{
            color: var(--text-secondary);
        }}

        h2 {{
            color: var(--text-primary);
            margin-top: 0;
            margin-bottom: var(--space-lg);
            padding: var(--space-md) var(--space-lg);
            background: var(--neutral-50);
            border-left: 4px solid var(--accent-primary);
            border-radius: 6px;
            font-size: 20px;
            font-weight: 600;
        }}

        .section {{
            margin-bottom: var(--space-xl);
            padding: var(--space-lg);
            background: var(--card-bg);
            border-radius: 8px;
            border: 1px solid var(--border);
            box-shadow: var(--shadow-sm);
        }}

        .section-subtitle {{
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin: var(--space-md) 0;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: var(--space-md);
            margin: var(--space-lg) 0;
        }}

        .stat-card {{
            background: var(--report-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: var(--space-lg);
            text-align: center;
        }}

        .stat-card .value {{
            font-size: 32px;
            font-weight: 700;
            color: var(--text-primary);
        }}

        .stat-card .value.value-text {{
            font-size: 16px;
            line-height: 1.6;
        }}

        .stat-card .label {{
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: var(--space-xs);
        }}

        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: var(--space-md);
            margin-top: var(--space-md);
        }}

        .meta-grid.compact {{
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        }}

        .meta-card {{
            background: var(--report-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: var(--space-md);
        }}

        .meta-label {{
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: var(--space-xs);
        }}

        .meta-value {{
            color: var(--text-primary);
            font-weight: 500;
            word-break: break-word;
        }}

        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin: 0 4px 4px 0;
        }}

        .badge-critical {{ background: var(--critical); color: white; }}
        .badge-high {{ background: var(--high); color: white; }}
        .badge-medium {{ background: var(--medium); color: white; }}
        .badge-low {{ background: var(--low); color: white; }}
        .badge-info {{ background: var(--info); color: white; }}
        .badge-neutral {{ background: var(--neutral-300); color: var(--text-primary); }}

        .code {{
            font-family: "IBM Plex Sans", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            background: var(--neutral-100);
            padding: 2px 6px;
            border-radius: 4px;
            border: 1px solid var(--border);
            color: var(--text-primary);
            font-size: 13px;
        }}

        .finding-item {{
            padding: var(--space-lg);
            margin: var(--space-md) 0;
            background: var(--report-bg);
            border-radius: 6px;
            border: 1px solid var(--border);
        }}

        .finding-item.severity-critical {{ border-left: 4px solid var(--critical); }}
        .finding-item.severity-high {{ border-left: 4px solid var(--high); }}
        .finding-item.severity-medium {{ border-left: 4px solid var(--medium); }}
        .finding-item.severity-low {{ border-left: 4px solid var(--low); }}
        .finding-item.severity-info {{ border-left: 4px solid var(--info); }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: var(--space-md);
            margin-bottom: var(--space-md);
        }}

        .finding-title {{
            font-size: 18px;
            font-weight: 700;
            color: var(--text-primary);
        }}

        .finding-subtitle {{
            display: flex;
            flex-wrap: wrap;
            gap: var(--space-sm);
            color: var(--text-secondary);
            margin-top: var(--space-xs);
        }}

        .detail-block {{
            margin-top: var(--space-md);
        }}

        .detail-label {{
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: var(--space-xs);
        }}

        .detail-text {{
            color: var(--text-secondary);
        }}

        .detail-list {{
            margin: 0;
            padding-left: 18px;
            color: var(--text-secondary);
        }}

        .detail-list li {{
            margin: 6px 0;
        }}

        .empty-state {{
            padding: var(--space-lg);
            border: 1px dashed var(--border-dark);
            border-radius: 8px;
            color: var(--text-secondary);
            background: var(--report-bg);
        }}

        .footer {{
            margin-top: var(--space-xl);
            padding-top: var(--space-lg);
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 12px;
            display: flex;
            justify-content: space-between;
            gap: var(--space-md);
            flex-wrap: wrap;
        }}

        @media (max-width: 768px) {{
            body {{ padding: var(--space-sm); }}
            .container {{ padding: var(--space-lg); }}
            .header {{ flex-direction: column; }}
            .header-right {{ text-align: left; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="header-left">
                <h1>OreWatch Scan Report</h1>
                <div class="subtitle">Malicious package and IoC analysis</div>
            </div>
            <div class="header-right">
                <div class="logo">OreWatch</div>
                <div class="date">{scan_timestamp}</div>
            </div>
        </header>

        <section class="summary-banner {summary_class}">
            <h2>{summary_title}</h2>
            <p>{summary_body}</p>
        </section>

        <section class="section">
            <h2>Overview</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="label">Packages Scanned</div>
                    <div class="value">{packages_scanned}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Malicious Packages</div>
                    <div class="value">{malicious_packages_found}</div>
                </div>
                <div class="stat-card">
                    <div class="label">IoCs</div>
                    <div class="value">{iocs_found}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Ecosystem</div>
                    <div class="value value-text"><span class="code">{ecosystem}</span></div>
                </div>
            </div>
            <div class="meta-grid">
                <div class="meta-card">
                    <div class="meta-label">Scanned path</div>
                    <div class="meta-value"><span class="code">{scanned_path}</span></div>
                </div>
                <div class="meta-card">
                    <div class="meta-label">JSON artifact</div>
                    <div class="meta-value"><span class="code">{json_report_name}</span></div>
                </div>
                <div class="meta-card">
                    <div class="meta-label">HTML artifact</div>
                    <div class="meta-value"><span class="code">{html_report_name}</span></div>
                </div>
            </div>
        </section>

        {threat_data_section}
        {malicious_packages_section}
        {iocs_section}

        <footer class="footer">
            <div>Generated by OreWatch</div>
            <div>JSON: {json_report_name} | HTML: {html_report_name}</div>
        </footer>
    </div>
</body>
</html>
    """.format(
        scan_timestamp=_escape(report.get("scan_timestamp", "")),
        summary_class=summary_class,
        summary_title=_escape(summary_title),
        summary_body=_escape(summary_body),
        packages_scanned=_escape(report.get("total_packages_scanned", 0)),
        malicious_packages_found=_escape(report.get("malicious_packages_found", 0)),
        iocs_found=_escape(report.get("iocs_found", 0)),
        ecosystem=_escape(report.get("ecosystem", "unknown")),
        scanned_path=_escape(report.get("scanned_path", "")),
        json_report_name=_escape(os.path.basename(json_report_path)),
        html_report_name=_escape(os.path.basename(html_report_path)),
        threat_data_section=_render_threat_data_section(report),
        malicious_packages_section=_render_malicious_packages_section(report),
        iocs_section=_render_iocs_section(report),
    )


def generate_html_report(
    report: Dict[str, Any],
    json_report_path: str,
    html_report_path: str,
) -> str:
    """Write the styled HTML companion report and return its path."""
    _ensure_parent_dir(html_report_path)
    html_content = _render_html_report(report, json_report_path, html_report_path)
    try:
        with open(html_report_path, "w", encoding="utf-8") as handle:
            handle.write(html_content)
        return html_report_path
    except Exception as exc:
        logger.error(
            "Error writing HTML report to %s: %s",
            html_report_path,
            exc,
            exc_info=True,
        )
        raise


def generate_report(
    ecosystem: str,
    scanned_path: str,
    total_packages_scanned: int,
    malicious_packages: List[Dict],
    iocs: Optional[List[Dict]] = None,
    output_path: Optional[str] = None,
    data_metadata: Optional[Dict] = None,
) -> str:
    """
    Generate JSON and HTML reports for malicious packages found and IoCs detected.

    Args:
        ecosystem: Ecosystem name (npm, pypi, etc.) or comma-separated string for multiple
        scanned_path: Path that was scanned (directory or file)
        total_packages_scanned: Total number of packages scanned
        malicious_packages: List of malicious packages found
        iocs: Optional list of IoCs (Indicators of Compromise) found
        output_path: Optional custom output path. JSON remains the primary artifact.
        data_metadata: Optional threat-data availability metadata

    Returns:
        Path to the generated JSON report file
    """
    if iocs is None:
        iocs = []
    if data_metadata is None:
        data_metadata = {
            "data_status": "not_applicable",
            "sources_used": [],
            "experimental_sources_used": [],
            "missing_ecosystems": [],
        }

    report = _build_report_payload(
        ecosystem=ecosystem,
        scanned_path=scanned_path,
        total_packages_scanned=total_packages_scanned,
        malicious_packages=malicious_packages,
        iocs=iocs,
        data_metadata=data_metadata,
    )
    json_report_path, html_report_path = _resolve_report_paths(output_path)
    _ensure_parent_dir(json_report_path)

    try:
        with open(json_report_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(
            "Error writing report to %s: %s",
            json_report_path,
            exc,
            exc_info=True,
        )
        raise

    generate_html_report(report, json_report_path, html_report_path)
    return json_report_path


def print_report_summary(report_path: str):
    """
    Print a human-readable summary of the report.

    Args:
        report_path: Path to the JSON report file
    """
    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    except Exception as exc:
        logger.error("Error reading report %s: %s", report_path, exc, exc_info=True)
        return

    print("\n" + "=" * 60)
    print("SCAN REPORT SUMMARY")
    print("=" * 60)
    print(f"Ecosystem: {report.get('ecosystem', 'unknown')}")
    print(f"Scanned Path: {report.get('scanned_path', 'unknown')}")
    print(f"Scan Timestamp: {report.get('scan_timestamp', 'unknown')}")
    print(f"Total Packages Scanned: {report.get('total_packages_scanned', 0)}")
    print(f"Threat Data Status: {report.get('data_status', 'unknown')}")
    sources_used = report.get("sources_used", [])
    print(f"Threat Sources Used: {', '.join(sources_used) if sources_used else 'none'}")
    experimental_sources = report.get("experimental_sources_used", [])
    if experimental_sources:
        print(f"Experimental Sources Used: {', '.join(experimental_sources)}")
    missing_ecosystems = report.get("missing_ecosystems", [])
    if missing_ecosystems:
        print(f"Unavailable Ecosystems: {', '.join(missing_ecosystems)}")
    print(f"Malicious Packages Found: {report.get('malicious_packages_found', 0)}")
    print(f"IoCs Found: {report.get('iocs_found', 0)}")
    print("=" * 60)

    malicious_packages = report.get("malicious_packages", [])
    if malicious_packages:
        print("\n🚨 MALICIOUS PACKAGES DETECTED:\n")
        for index, pkg in enumerate(malicious_packages, 1):
            print(f"{index}. {pkg.get('name', 'unknown')}")
            if pkg.get("version"):
                print(f"   Version: {pkg.get('version')}")
            print(f"   Severity: {pkg.get('severity', 'unknown').upper()}")

            locations = _format_locations(list(pkg.get("locations", []) or []))
            if locations:
                print("   Found in:")
                for location in locations:
                    print(f"      {location}")

            if pkg.get("description"):
                print(f"   Description: {pkg.get('description')}")
            if pkg.get("sources"):
                print(f"   Sources: {', '.join(pkg.get('sources', []))}")
            print()
    else:
        print("\n✅ No malicious packages found!")

    iocs = report.get("iocs", [])
    if iocs:
        print("\n🚨 INDICATORS OF COMPROMISE (IoCs) DETECTED:\n")
        for index, ioc in enumerate(iocs, 1):
            severity_emoji = "🔴" if ioc.get("severity") == "CRITICAL" else "🟠"
            variant_info = f" [{ioc.get('variant', 'unknown')}]" if "variant" in ioc else ""
            print(
                f"{index}. {severity_emoji} {ioc.get('type', 'unknown').upper()}{variant_info}: "
                f"{ioc.get('path', 'unknown')}"
            )
            for label, value in _ioc_detail_rows(ioc):
                if label == "Path":
                    continue
                print(f"   {label}: {value}")
            print()
    else:
        print("\n✅ No IoCs detected!")

    html_report_path = get_html_report_path(report_path)
    if os.path.exists(html_report_path):
        print(f"\nHTML report saved to: {html_report_path}")
    print(f"JSON report saved to: {report_path}")
    print("=" * 60)

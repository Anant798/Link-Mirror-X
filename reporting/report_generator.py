"""
report_generator.py

Produces a structured, evidence-backed Markdown report for one case
(or a set of correlated cases). This is the final deliverable an
investigator would hand off — not just a score, but the evidence
behind the conclusion, matching the project's "explainability" principle.
"""

from __future__ import annotations
from typing import List, Optional
from datetime import datetime, timezone

from case.case_manager import Case
from intelligence.domain_intel import lookup_ip


def generate_case_report(case: Case, shared_with: Optional[List[str]] = None) -> str:
    """
    Returns a Markdown-formatted forensic report for a single case.
    shared_with: optional list of other case subjects that share
    infrastructure with this one (from the correlation engine).
    """
    lines = []
    lines.append(f"# Forensic report — case {case.case_id}")
    lines.append(f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_")
    lines.append("")
    lines.append(f"**Subject:** {case.parsed.subject}")
    lines.append(f"**From:** {case.parsed.from_display_name} <{case.parsed.from_address}>")
    lines.append(f"**Reply-To:** {case.parsed.reply_to or '(none)'}")
    lines.append(f"**Date:** {case.parsed.date}")
    lines.append(f"**Overall severity:** {case.highest_severity.upper()}")
    lines.append("")

    lines.append("## 1. Sender identity findings")
    if not case.header_findings:
        lines.append("No anomalies detected.")
    else:
        for f in case.header_findings:
            lines.append(f"- **[{f.severity.upper()}]** {f.message}")
    lines.append("")

    lines.append("## 2. Extracted indicators")
    lines.append(f"- URLs: {', '.join(case.indicators.urls) or 'none'}")
    lines.append(f"- Domains: {', '.join(case.indicators.domains) or 'none'}")
    lines.append(f"- IPs: {', '.join(case.indicators.ips) or 'none'}")
    lines.append(f"- Email addresses: {', '.join(case.indicators.email_addresses) or 'none'}")
    lines.append(f"- Attachment hashes: {', '.join(case.indicators.attachment_hashes) or 'none'}")
    lines.append("")

    lines.append("## 3. Infrastructure intelligence")
    if not case.indicators.ips:
        lines.append("No IP addresses extracted from this message.")
    else:
        for ip in case.indicators.ips:
            intel = lookup_ip(ip)
            demo_note = " *(synthetic demo data — reserved test range)*" if intel.is_demo else ""
            lines.append(f"- **{ip}**: {intel.org}, {intel.country}{demo_note}")
    lines.append("")

    lines.append("## 4. LinkMirror visual/URL analysis")
    if not case.url_analyses:
        lines.append("No URLs required visual analysis.")
    else:
        for ua in case.url_analyses:
            lines.append(f"### {ua.url}")
            lines.append(f"- URL trust score: {ua.result.url_score}/100")
            for r in ua.result.url_reasons:
                lines.append(f"  - {r}")
            if ua.result.screenshot_score >= 0:
                lines.append(f"- Visual similarity to closest reference "
                              f"(\"{ua.result.screenshot_best_match}\"): {ua.result.screenshot_score:.1f}%")
            else:
                lines.append("- No screenshot available for visual comparison.")
            lines.append(f"- **Verdict:** {ua.result.verdict}")
            lines.append(f"- Fused trust score: {ua.result.fused}/100")
    lines.append("")

    lines.append("## 5. Campaign correlation")
    if shared_with:
        lines.append("This case shares infrastructure with the following other reported emails, "
                      "suggesting a coordinated campaign rather than an isolated incident:")
        for subj in shared_with:
            lines.append(f"- {subj}")
    else:
        lines.append("No shared infrastructure found with other currently loaded cases.")
    lines.append("")

    lines.append("## 6. Conclusion")
    if case.highest_severity == "high" and any(ua.result.verdict_color == "red" for ua in case.url_analyses):
        lines.append("This message shows strong indicators of a phishing attempt: sender identity "
                      "could not be authenticated, and the linked page shows visual and/or URL-based "
                      "similarity to known-legitimate references. Recommended action: block sender/domain, "
                      "alert affected recipients, and investigate related infrastructure.")
    elif case.highest_severity in ("high", "warning"):
        lines.append("This message shows some suspicious indicators. Manual review by an analyst "
                      "is recommended before final classification.")
    else:
        lines.append("No significant threat indicators were found in this message.")

    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    from case.case_manager import process_email

    if len(sys.argv) != 2:
        print("Usage: python report_generator.py <path_to.eml>")
        sys.exit(1)

    case = process_email(sys.argv[1])
    report = generate_case_report(case)
    print(report)

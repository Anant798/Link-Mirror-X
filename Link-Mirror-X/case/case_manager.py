"""
case_manager.py

The orchestrator. Given a raw .eml file, this runs it through every
stage we've built so far and produces one Case object:

  parse email -> header forensics -> extract indicators ->
  (for each URL) look up screenshot -> run LinkMirror engine ->
  store everything as one Case

This is what the dashboard (not built yet) will call per uploaded
email, and what the correlation engine (built already) consumes
across multiple cases.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional
import uuid

from ingestion.eml_parser import parse_eml_file, ParsedEmail
from ingestion.header_forensics import analyze_headers, Finding
from ingestion.indicator_extractor import extract_indicators, IndicatorSet
from engine.capture import get_webpage_screenshot
from engine.linkmirror_engine import analyze_url_and_screenshot, EngineResult


@dataclass
class UrlAnalysis:
    url: str
    had_screenshot: bool
    result: EngineResult


@dataclass
class Case:
    case_id: str
    source_filename: str
    parsed: ParsedEmail
    header_findings: List[Finding]
    indicators: IndicatorSet
    url_analyses: List[UrlAnalysis] = field(default_factory=list)

    @property
    def highest_severity(self) -> str:
        severities = [f.severity for f in self.header_findings]
        if "high" in severities:
            return "high"
        if "warning" in severities:
            return "warning"
        return "info"

    @property
    def summary_line(self) -> str:
        return (
            f"[{self.highest_severity.upper()}] {self.parsed.subject!r} "
            f"from {self.parsed.from_address} — "
            f"{len(self.header_findings)} header finding(s), "
            f"{len(self.indicators.urls)} URL(s), "
            f"{len(self.indicators.ips)} IP(s)"
        )


def process_email(eml_path: str, reference_dir: str = "reference_images") -> Case:
    parsed = parse_eml_file(eml_path)
    header_findings = analyze_headers(parsed)
    indicators = extract_indicators(parsed)

    url_analyses: List[UrlAnalysis] = []
    for url in indicators.urls:
        screenshot = get_webpage_screenshot(url)
        result = analyze_url_and_screenshot(url, screenshot, ref_dir=reference_dir)
        url_analyses.append(UrlAnalysis(
            url=url,
            had_screenshot=screenshot is not None,
            result=result,
        ))

    return Case(
        case_id=str(uuid.uuid4())[:8],
        source_filename=eml_path,
        parsed=parsed,
        header_findings=header_findings,
        indicators=indicators,
        url_analyses=url_analyses,
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python case_manager.py <path_to.eml>")
        sys.exit(1)

    case = process_email(sys.argv[1])
    print(f"Case ID: {case.case_id}")
    print(case.summary_line)
    print()
    print("Header findings:")
    for f in case.header_findings:
        print(f"  [{f.severity.upper():7}] {f.message}")
    print()
    print("URL analyses:")
    for ua in case.url_analyses:
        print(f"  {ua.url}")
        print(f"    Screenshot available: {ua.had_screenshot}")
        print(f"    Verdict: {ua.result.verdict}")
        print(f"    Fused score: {ua.result.fused}")

"""
correlation_engine.py

Takes indicators from MULTIPLE processed emails/cases and finds shared
infrastructure between them (same IP, same hosting pattern, etc).
This is what turns "5 separate phishing reports" into "1 campaign
using 3 different fake brands."

Output is a simple graph structure (nodes + edges) that the UI layer
can hand to a graph-drawing library.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Set
from collections import defaultdict

from ingestion.indicator_extractor import IndicatorSet


@dataclass
class CaseIndicators:
    case_id: str
    label: str                 # human-readable, e.g. email subject
    indicators: IndicatorSet


@dataclass
class GraphNode:
    id: str
    type: str        # "case" | "domain" | "ip" | "email"
    label: str


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str     # e.g. "resolves_to", "sent_from", "contains_link"


@dataclass
class ThreatGraph:
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)


def build_threat_graph(cases: List[CaseIndicators]) -> ThreatGraph:
    graph = ThreatGraph()
    seen_node_ids: Set[str] = set()

    def add_node(node_id: str, node_type: str, label: str):
        if node_id not in seen_node_ids:
            graph.nodes.append(GraphNode(id=node_id, type=node_type, label=label))
            seen_node_ids.add(node_id)

    for case in cases:
        case_node_id = f"case:{case.case_id}"
        add_node(case_node_id, "case", case.label)

        for domain in case.indicators.domains:
            domain_node_id = f"domain:{domain}"
            add_node(domain_node_id, "domain", domain)
            graph.edges.append(GraphEdge(case_node_id, domain_node_id, "contains_link"))

        for ip in case.indicators.ips:
            ip_node_id = f"ip:{ip}"
            add_node(ip_node_id, "ip", ip)
            graph.edges.append(GraphEdge(case_node_id, ip_node_id, "hosted_at"))
            # also connect each domain in this case to the shared IP, so the
            # IP becomes the pivot point when multiple cases share it
            for domain in case.indicators.domains:
                graph.edges.append(GraphEdge(f"domain:{domain}", ip_node_id, "resolves_to"))

        for addr in case.indicators.email_addresses:
            addr_node_id = f"email:{addr}"
            add_node(addr_node_id, "email", addr)
            graph.edges.append(GraphEdge(case_node_id, addr_node_id, "sent_from"))

    return graph


def find_shared_infrastructure(cases: List[CaseIndicators]) -> Dict[str, List[str]]:
    """
    Returns a mapping of {shared_ip_or_domain: [case_ids that share it]}
    for any indicator seen in 2+ cases. This is the plain-data version
    of "these cases are connected" — useful for a summary table above
    the graph.
    """
    indicator_to_cases: Dict[str, Set[str]] = defaultdict(set)

    for case in cases:
        for ip in case.indicators.ips:
            indicator_to_cases[f"ip:{ip}"].add(case.case_id)
        for domain in case.indicators.domains:
            indicator_to_cases[f"domain:{domain}"].add(case.case_id)

    shared = {
        indicator: sorted(case_ids)
        for indicator, case_ids in indicator_to_cases.items()
        if len(case_ids) >= 2
    }
    return shared


if __name__ == "__main__":
    import json
    from pathlib import Path
    from ingestion.eml_parser import parse_eml_file
    from ingestion.indicator_extractor import extract_indicators

    demo_dir = Path(__file__).parent.parent / "demo_data" / "emails"
    cases = []
    for eml_path in sorted(demo_dir.glob("*.eml")):
        parsed = parse_eml_file(str(eml_path))
        indicators = extract_indicators(parsed)
        cases.append(CaseIndicators(
            case_id=eml_path.stem,
            label=parsed.subject,
            indicators=indicators,
        ))

    print("=== Shared infrastructure across cases ===")
    shared = find_shared_infrastructure(cases)
    if not shared:
        print("No shared infrastructure found.")
    for indicator, case_ids in shared.items():
        print(f"  {indicator} -> shared by: {case_ids}")

    print("\n=== Graph summary ===")
    graph = build_threat_graph(cases)
    print(f"Nodes: {len(graph.nodes)}, Edges: {len(graph.edges)}")
    for n in graph.nodes:
        print(f"  [{n.type}] {n.id} ({n.label})")

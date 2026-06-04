import networkx as nx
from typing import Dict, List, Optional
import uuid

def build_entity_graph(
    root_entity: str,
    associated_domains: List[str] = [],
    associated_ips: List[str] = [],
    platform_presence: Dict[str, bool] = {},
    linked_entities: List[Dict] = [],
) -> Dict:
    """Build a network graph for an entity"""

    G = nx.DiGraph()
    nodes = []
    edges = []

    # Root node
    root_id = str(uuid.uuid4())[:8]
    G.add_node(root_id, label=root_entity, type="target", threat_score=0)
    nodes.append({
        "id": root_id,
        "label": root_entity[:30],
        "type": "target",
        "threat_score": 0,
        "platform": None,
    })

    # Domain nodes
    for domain in associated_domains[:8]:
        nid = str(uuid.uuid4())[:8]
        G.add_node(nid, label=domain, type="domain", threat_score=20)
        G.add_edge(root_id, nid, relationship="resolves_to")
        nodes.append({"id": nid, "label": domain[:30], "type": "domain", "threat_score": 20, "platform": None})
        edges.append({"source": root_id, "target": nid, "relationship": "resolves_to", "weight": 1.0})

    # IP nodes
    for ip in associated_ips[:5]:
        nid = str(uuid.uuid4())[:8]
        G.add_node(nid, label=ip, type="ip", threat_score=15)
        G.add_edge(root_id, nid, relationship="hosted_on")
        nodes.append({"id": nid, "label": ip, "type": "ip", "threat_score": 15, "platform": None})
        edges.append({"source": root_id, "target": nid, "relationship": "hosted_on", "weight": 0.8})

    # Platform presence
    for platform, present in platform_presence.items():
        if present:
            nid = str(uuid.uuid4())[:8]
            G.add_node(nid, label=f"@{root_entity} on {platform}", type="social", threat_score=10)
            G.add_edge(root_id, nid, relationship="present_on")
            nodes.append({"id": nid, "label": platform, "type": "social", "threat_score": 10, "platform": platform})
            edges.append({"source": root_id, "target": nid, "relationship": "present_on", "weight": 0.6})

    # Linked entities
    for entity in linked_entities[:10]:
        nid = str(uuid.uuid4())[:8]
        threat = entity.get("threat_score", 30)
        G.add_node(nid, label=entity.get("name", "unknown"), type=entity.get("type", "entity"), threat_score=threat)
        G.add_edge(root_id, nid, relationship=entity.get("relationship", "linked_to"))
        nodes.append({
            "id": nid,
            "label": entity.get("name", "unknown")[:30],
            "type": entity.get("type", "entity"),
            "threat_score": threat,
            "platform": entity.get("platform"),
        })
        edges.append({
            "source": root_id,
            "target": nid,
            "relationship": entity.get("relationship", "linked_to"),
            "weight": entity.get("weight", 1.0),
        })

    # Graph metrics
    metrics = {
        "node_count": G.number_of_nodes(),
        "edge_count": G.number_of_edges(),
        "density": round(nx.density(G), 4),
        "is_connected": nx.is_weakly_connected(G) if G.number_of_nodes() > 1 else True,
    }

    return {
        "nodes": nodes,
        "edges": edges,
        "metrics": metrics,
        "root_id": root_id,
    }


def detect_coordination_clusters(entities: List[Dict]) -> List[List[str]]:
    """Detect groups of coordinated entities"""
    G = nx.Graph()

    for entity in entities:
        G.add_node(entity["id"])

    # Connect entities that share IPs, domains, or posting patterns
    for i, e1 in enumerate(entities):
        for e2 in entities[i+1:]:
            shared = set(e1.get("ips", [])) & set(e2.get("ips", []))
            shared |= set(e1.get("domains", [])) & set(e2.get("domains", []))
            if shared:
                G.add_edge(e1["id"], e2["id"], weight=len(shared))

    # Find connected components (coordination clusters)
    clusters = [list(c) for c in nx.connected_components(G) if len(c) > 1]
    return clusters

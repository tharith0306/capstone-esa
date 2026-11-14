"""Export an incident's attack graph to Neo4j (Cypher script, or pushed directly if configured)."""

import json
import re

from app.core.config import Settings

_LABELS = {"ip": "IP", "host": "Host", "identity": "Identity", "key": "AccessKey", "resource": "Resource",
           "finding": "Finding"}


def _rel(relation: str) -> str:
    return re.sub(r"[^A-Z0-9_]", "_", relation.upper()) or "RELATED_TO"


def _props(d: dict) -> str:
    return "{" + ", ".join(f"{k}: {json.dumps(v)}" for k, v in d.items()) + "}"


def cypher_for_incident(incident_id: str, graph: dict) -> str:
    """Idempotent Cypher (MERGE) so re-exporting the same incident does not duplicate nodes."""
    lines = [f"// CloudShield incident {incident_id}",
             f"MERGE (i:Incident {{incident_id: {json.dumps(incident_id)}}});"]
    for n in graph["nodes"]:
        label = _LABELS.get(n["type"], "Entity")
        props = {"rank": n["rank"], "sensitivity": n.get("sensitivity", 0), "first_seen": n["first_seen"]}
        lines.append(f"MERGE (n:{label} {{key: {json.dumps(n['id'])}}}) SET n.label = {json.dumps(n['label'])}, "
                     f"n += {_props(props)};")
        lines.append(f"MATCH (i:Incident {{incident_id: {json.dumps(incident_id)}}}), (n {{key: {json.dumps(n['id'])}}}) "
                     f"MERGE (i)-[:INVOLVES {{rank: {n['rank']}}}]->(n);")
    for e in graph["edges"]:
        props = {"incident_id": incident_id, "count": e["count"], "suspicion": e["suspicion"], "bytes": e["bytes"],
                 "first_seen": e["first_seen"], "last_seen": e["last_seen"]}
        lines.append(f"MATCH (a {{key: {json.dumps(e['source'])}}}), (b {{key: {json.dumps(e['target'])}}}) "
                     f"MERGE (a)-[r:{_rel(e['relation'])} {{incident_id: {json.dumps(incident_id)}}}]->(b) "
                     f"SET r += {_props(props)};")
    return "\n".join(lines) + "\n"


def push_to_neo4j(settings: Settings, incident_id: str, graph: dict) -> dict:
    if not settings.neo4j_uri:
        raise RuntimeError("CLOUDSHIELD_NEO4J_URI is not configured")
    try:
        from neo4j import GraphDatabase
    except ImportError as exc:
        raise RuntimeError("neo4j driver not installed: pip install '.[graph]'") from exc
    statements = [s for s in cypher_for_incident(incident_id, graph).splitlines() if s and not s.startswith("//")]
    with GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password or "")) as driver:
        with driver.session() as session:
            for statement in statements:
                session.run(statement.rstrip(";"))
    return {"incident_id": incident_id, "statements": len(statements), "uri": settings.neo4j_uri}

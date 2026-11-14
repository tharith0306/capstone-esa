"""Forensic incident report as PDF (ReportLab)."""

import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

_styles = getSampleStyleSheet()
H1, H2, BODY = _styles["Title"], _styles["Heading2"], _styles["BodyText"]
SMALL = ParagraphStyle("small", parent=BODY, fontSize=7.5, leading=9)
MONO = ParagraphStyle("mono", parent=SMALL, fontName="Courier")
LEVEL_COLORS = {"CRITICAL": colors.HexColor("#be123c"), "HIGH": colors.HexColor("#ea580c"),
                "MEDIUM": colors.HexColor("#ca8a04"), "LOW": colors.HexColor("#0284c7"), "MINIMAL": colors.grey}


def _p(text, style=SMALL) -> Paragraph:
    return Paragraph(str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), style)


def _table(rows: list[list], widths: list[float], header: bool = True) -> Table:
    data = [[c if isinstance(c, Paragraph) else _p(c) for c in row] for row in rows]
    table = Table(data, colWidths=[w * mm for w in widths], repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP")]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")))
    table.setStyle(TableStyle(style))
    return table


def _fmt(ts: str | datetime | None) -> str:
    if ts is None:
        return "—"
    return (ts if isinstance(ts, str) else ts.isoformat()).replace("T", " ")[:19] + " UTC"


def build_incident_pdf(report: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm,
                            bottomMargin=14 * mm, title=f"CloudShield incident {report['incident_id']}")
    risk = report["risk"]
    story = [
        Paragraph("CloudShield forensic incident report", H1),
        _p(f"Generated {_fmt(report['generated_at'])} · incident {report['incident_id']} · model "
           f"{report['evidence_manifest'].get('model_version')}", BODY),
        Spacer(1, 4 * mm),
        Paragraph(report["title"], H2),
        _table([
            ["Risk", "Status", "Window", "Alerts / events", "Correlation"],
            [Paragraph(f'<font color="{LEVEL_COLORS.get(risk["level"], colors.black).hexval()}"><b>{risk["level"]} '
                       f'{risk["score"]}</b></font>', SMALL), report["status"],
             f"{_fmt(report['start'])} → {_fmt(report['end'])}", f"{report['alert_count']} / {report['event_count']}",
             f"{report['correlation_score']:.2f}"],
        ], [28, 24, 80, 28, 22]),
        Spacer(1, 3 * mm),
        Paragraph("Explainable risk score", H2),
        _p(risk["formula"], MONO),
        _table([["Term", "Meaning", "Value", "Weight", "Contribution"]] +
               [[c["symbol"], c["description"], f"{c['value']:.2f}", c["weight"], f"{c['contribution']:.1f}"]
                for c in risk["components"]], [12, 104, 20, 20, 26]),
        Paragraph("Why this is suspicious", H2),
    ]
    reasons = report["explanation"].get("reasons") or ["Rule-based incident (no ML window explanation)."]
    story += [_p(f"• {r}", BODY) for r in reasons]
    shap = (report["explanation"] or {}).get("shap")
    if shap:
        story += [Spacer(1, 2 * mm), _p(f"SHAP contributions for class '{shap['explained_class']}' (log-odds):", BODY),
                  _table([["Feature", "Value", "SHAP"]] + [[f["description"] or f["feature"], f"{f['value']:.3g}",
                                                             f"{f['shap']:+.3f}"] for f in shap["features"]],
                         [120, 30, 32])]
    story += [Paragraph("MITRE ATT&CK techniques", H2),
              _table([["Technique", "Name", "Tactic", "Count"]] +
                     [[m["id"], m["name"], m["tactic"], m.get("count", "")] for m in report["mitre"]] or [["—", "", "", ""]],
                     [24, 96, 40, 22]),
              Paragraph("Entities", H2),
              _table([["Identities", ", ".join(report["actors"]) or "—"],
                      ["Source IPs", ", ".join(report["source_ips"]) or "—"],
                      ["Access keys", ", ".join(report["access_keys"]) or "—"],
                      ["Resources", ", ".join(report["resources"][:15]) or "—"]], [30, 152], header=False),
              Paragraph("Most suspicious graph nodes", H2),
              _table([["Node", "Type", "Rank"]] + [[n["label"], n["type"], f"{n['rank']:.2f}"]
                                                  for n in report["graph"]["nodes"][:8]], [130, 28, 24])]

    story += [PageBreak(), Paragraph("Forensic timeline (attack-relevant events)", H2)]
    relevant = [t for t in report["timeline"] if t["stage"] != "NORMAL" or t["in_alert"]][:120]
    story.append(_table([["Time (UTC)", "Stage (HMM)", "Event", "MITRE"]] +
                        [[_fmt(t["timestamp"])[:19], t["stage"], t["description"],
                          (t["mitre"] or {}).get("id", "")] for t in relevant], [32, 34, 98, 18]))

    story += [Paragraph("Response actions", H2)]
    story.append(_table([["Action", "Status", "Decided by", "Execution"]] +
                        [[a["description"], a["status"], a.get("decided_by") or "—",
                          (a.get("execution") or {}).get("mode", "—")] for a in report["actions"]]
                        or [["No actions (risk below HIGH)", "", "", ""]], [100, 22, 30, 30]))

    ev = report["evidence_summary"]
    story += [Paragraph("Evidence integrity", H2),
              _p(f"{ev['verified']} of {ev['events']} raw records re-verified against their SHA-256 at report time "
                 f"({'all verified' if ev['all_verified'] else 'MISMATCH DETECTED'}).", BODY),
              _p(f"Evidence manifest SHA-256: {report['evidence_manifest']['manifest_sha256']}", MONO),
              Paragraph("Audit trail", H2),
              _table([["Time", "Actor", "Action", "Object"]] +
                     [[_fmt(a["timestamp"]), a["actor"], a["action"], a["object_id"]] for a in report["audit_trail"]]
                     or [["—", "", "", ""]], [42, 30, 36, 74])]
    doc.build(story)
    return buf.getvalue()

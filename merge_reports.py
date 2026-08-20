#!/usr/bin/env python3
"""Führt die Ergebnisse der drei Scanner zu einem konsolidierten Report zusammen.

Nimmt die drei JSON-Ergebnisse (jeweils `... --json`-Output) entgegen und
liefert einen einzigen, einheitlichen Report:

  * `--format json`  -> {"clean":bool, "summary":{...}, "findings":[...]}
  * `--format text`  -> menschenlesbare Zusammenfassung (Default)

Die Eingabedateien können beide erkannten Formate enthalten:
  * Objekt   {"clean": bool, "findings": [...]}   (Scanner 1 & 2)
  * Liste    [ {...}, ... ]                        (Scanner 3)

Einzelfunde werden aus allen Quellen gesammelt, nach (Seite, Schweregrad)
sortiert, dedupliziert und in ein einheitliches Schema gebracht.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, List, Dict


def _try_decode_block(text: str, start: int) -> Any:
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[start:])
        return obj
    except json.JSONDecodeError:
        return None


def load_findings(file_path: str) -> List[Dict[str, Any]]:
    """Extrahiert die Einzelbefunde aus einer Scanner-JSON-Datei.

    Unterstützt sowohl das Objekt- als auch das reine Listen-Format und
    sucht – wie im Log üblich – von hinten nach vorn nach gültigem JSON.
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    candidates = []
    scan_from = 0
    for ch, i in zip(text, range(len(text))):
        if ch in "[{":
            candidates.append(i)
            scan_from = i
    for i in reversed(candidates):
        obj = _try_decode_block(text, i)
        if obj is None:
            continue
        if isinstance(obj, dict):
            fs = obj.get("findings")
            if isinstance(fs, list):
                return [d for d in fs if isinstance(d, dict)]
        elif isinstance(obj, list):
            return [d for d in obj if isinstance(d, dict)]
    return []


def _sev_rank(sev: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get((sev or "low").lower(), 9)


def normalize(finding: Dict[str, Any], source: str) -> Dict[str, Any]:
    """Bringt ein Finding aller Scanner auf ein einheitliches Schema."""
    return {
        "page": finding.get("page", 0),
        "type": finding.get("type", "unknown"),
        "description": finding.get("description", ""),
        "content": finding.get("content", ""),
        "severity": (finding.get("severity") or "low").lower(),
        "source": source,
    }


def merge(sources: Dict[str, str]) -> Dict[str, Any]:
    """sources: {name: pfad_zur_json}; liefert konsolidierten Report."""
    all_findings: List[Dict[str, Any]] = []
    errors = []
    for name, path in sources.items():
        try:
            found = load_findings(path)
        except Exception as e:
            errors.append(f"{name}: {e}")
            continue
        for f in found:
            all_findings.append(normalize(f, name))

    # Deduplizierung (gleiche Seite + Typ + Inhalt)
    seen = set()
    unique = []
    for f in all_findings:
        key = (f["page"], f["type"], f["content"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    # Sortierung: Seite aufsteigend, dann nach Schweregrad
    unique.sort(key=lambda f: (f["page"], _sev_rank(f["severity"]), f["type"]))

    summary = {
        "total": len(unique),
        "high": sum(1 for f in unique if f["severity"] == "high"),
        "medium": sum(1 for f in unique if f["severity"] == "medium"),
        "low": sum(1 for f in unique if f["severity"] == "low"),
    }

    return {
        "clean": summary["total"] == 0,
        "summary": summary,
        "sources": list(sources.keys()),
        "errors": errors,
        "findings": unique,
    }


def render_text(report: Dict[str, Any]) -> str:
    s = report["summary"]
    lines = []
    lines.append("=" * 60)
    lines.append("KONSOLIDIERER SCAN-REPORT  (Scanner 1 + 2 + 3)")
    lines.append("=" * 60)
    if report["clean"]:
        lines.append("SAUBER - keine Auffaelligkeiten gefunden.")
    else:
        lines.append(
            f"{s['total']} Funde: "
            f"{s['high']} kritisch, {s['medium']} Warnung, {s['low']} Hinweis"
        )
        lines.append("-" * 60)
        for i, f in enumerate(report["findings"], 1):
            sev = f["severity"].upper()
            lines.append(f"[{i:>3}] {sev:<7} | Seite {f['page']:<3} | {f['type']:<20} | {f['source']}")
            preview = (f["content"] or "").strip().replace("\n", " ")
            lines.append(f"        {preview[:100]}{'...' if len(preview) > 100 else ''}")
    if report.get("errors"):
        lines.append("-" * 60)
        lines.append("Lese-Fehler bei Quellen:")
        for e in report["errors"]:
            lines.append(f"  - {e}")
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="Konsolidierter Report aus 3 Scanner-JSONs")
    p.add_argument("--text", help="JSON-Ergebnis von Scanner 1 (Text/Metadaten)")
    p.add_argument("--image", help="JSON-Ergebnis von Scanner 2 (Bild/OCR)")
    p.add_argument("--injection", help="JSON-Ergebnis von Scanner 3 (Tiefenscan)")
    p.add_argument("--format", choices=["json", "text"], default="json")
    args = p.parse_args()

    sources = {
        "text": args.text,
        "image": args.image,
        "injection": args.injection,
    }
    sources = {k: v for k, v in sources.items() if v}

    if not sources:
        sys.stderr.write("Keine Quellen angegeben. Nutzung: merge_reports.py --text X --image Y --injection Z\n")
        sys.exit(2)

    report = merge(sources)

    if args.format == "json":
        sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    else:
        sys.stdout.write(render_text(report) + "\n")

    # Exit-Code: 0 = sauber, 1 = Funde, 2 = Fehler
    if report["errors"] and not report["findings"]:
        sys.exit(2)
    sys.exit(0 if report["clean"] else 1)


if __name__ == "__main__":
    main()

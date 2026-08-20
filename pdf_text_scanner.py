import sys
import re
import json

import fitz  # PyMuPDF

from pdfscan_core import (
    MIN_TEXT_SIZE,
    is_light_or_white,
    luminance,
    find_matches_with_positions,
)

SEVERITY_LABELS = {"high": "KRITISCH", "medium": "WARNUNG", "low": "HINWEIS"}

# Verdächtige Link-Ziele: Script-Schema + Exfiltration-/Upload-Phrasen
JS_LINK_RE = re.compile(r"^\s*javascript\s*:", re.IGNORECASE)
EXFIL_LINK_RE = re.compile(
    r"(?:leak|exfil|upload|send|post|transmit)\S*\s*(?:to)?.*"
    r"(?:key|token|secret|credential|session|cookie|password)\b",
    re.IGNORECASE,
)


def _finding(page, finding_type, severity, content, description):
    return {
        "page": page,
        "type": finding_type,
        "description": description,
        "content": content,
        "severity": severity,
    }


def _scan_field(value, page, finding_type, findings):
    """Prüft einen String-Wert (Metadaten, XMP, Anhänge, JS) auf Injektionsmuster."""
    if not value or not isinstance(value, str):
        return
    value = value.strip()
    if len(value) < 2:
        return
    for label, matched, s, e in find_matches_with_positions(value):
        snippet = value[max(0, s - 30): min(len(value), e + 30)].strip()
        findings.append(_finding(
            page, finding_type, "high", value,
            f"Muster ({label}): …{snippet}…"))


def _scan_embedded_js(doc, findings, out):
    """Eingebettete JavaScript-Blöcke – jeder Block ist allein schon ein Risiko."""
    out("[*] Analysiere eingebettetes JavaScript...")
    try:
        js_list = list(doc.get_js() or [])
    except Exception:
        js_list = []

    for code in js_list:
        code = (code or "").strip()
        if not code:
            continue
        _scan_field(code, 0, "JavaScript-Prompt", findings)
        findings.append(_finding(
            0, "JavaScript-Code", "high", code[:400],
            "Eingebettetes JavaScript im PDF (mögliche Ausführung bei Load/Aktion)"))

    if not js_list:
        out("      Keine eingebettete JavaScript-Blöcke gefunden.")


def _scan_actions(doc, findings, out):
    """Dokumenten-/Objekt-Level Actions (Open, AA-Autostart) – verdächtige Auslöser."""
    out("[*] Analysiere dokumentweite Actions...")
    action_keys = ("OpenAction", "AA")
    checked = False
    try:
        xref_count = doc.xref_length()
    except Exception:
        return

    for xref in range(1, max(xref_count, 1)):
        for key in action_keys:
            try:
                kind, val = doc.xref_get_key(xref, key)
            except Exception:
                continue
            if kind not in ("null", "") and val:
                checked = True
                findings.append(_finding(
                    0, "Dokument-Action", "high",
                    f"xref {xref}: /{key} vorhanden",
                    "PDF definiert eine Auto-Execute-/Open-Action (kann JS/Aktion auslösen)"))

    if not checked:
        out("      Keine Open-/Auto-Execute-Actions gefunden.")


def _scan_links(doc, findings, out):
    """Seiten-Links: javascript:-Schema + Exfiltration-Ziele."""
    out("[*] Analysiere Seiten-Links...")
    for page_num in range(len(doc)):
        try:
            links = list(doc[page_num].get_links() or [])
        except Exception:
            links = []
        for link in links:
            uri = str(link.get("uri") or "")
            if not uri:
                continue
            if JS_LINK_RE.search(uri):
                findings.append(_finding(
                    page_num + 1, "Link-JavaScript", "high", uri[:300],
                    "Link führt ein javascript:-Schema aus"))
            elif EXFIL_LINK_RE.search(uri):
                findings.append(_finding(
                    page_num + 1, "Link-Exfiltration", "high", uri[:300],
                    "Link-Ziel enthält Exfiltrations-/Upload-Phrasen"))


def _scan_embedded_files(doc, findings, out):
    """Eingebettete Dateien (Anhänge) – Datei-Namen auf Injektionsmuster prüfen."""
    out("[*] Analysiere eingebettete Dateien (Anhang) und ihre Namen...")
    seen = set()
    for page_num in range(len(doc)):
        try:
            annots = list(doc[page_num].annots() or [])
        except Exception:
            annots = []
        for annot in annots:
            if getattr(annot, "type_name", "") not in ("FileAttachment", "TextAnnotation") and \
               getattr(annot, "file", None) is None:
                continue
            name = ""
            try:
                file_info = doc.extract_file(xref=annot.xref)
                name = file_info[0]
            except Exception:
                pass
            sig = (page_num, name)
            if sig in seen:
                continue
            seen.add(sig)
            _scan_field(name, page_num + 1, "Anhang-Prompt", findings)


def _scan_xmp(doc, findings, out):
    """Dokument-weites XMP-Blob auf Injektionsmuster prüfen."""
    out("[*] Analysiere Dokument-XMP...")
    try:
        xmp = doc.get_xml_metadata() or ""
    except Exception:
        xmp = ""
    if xmp:
        _scan_field(xmp, 0, "XMP-Prompt", findings)


def scan_text_and_metadata(pdf_path, verbose=True):
    def out(*args):
        if verbose:
            print(*args)

    try:
        doc = fitz.open(pdf_path)
    except Exception as e:
        out(f"[-] Fehler beim Öffnen der Datei: {e}")
        return None

    if doc.needs_pass:
        out("[-] Dokument ist passwortgeschützt; Text-Scan nicht möglich.")
        return None

    out(f"=== STRUKTUR- UND TEXTSCANNER: {pdf_path} ===")
    out(f"Seitenanzahl: {len(doc)}")
    out()
    findings = []

    # 1. JS, Actions, Links, Anhänge, Dokument-XMP (alle ohne Seitenbezug -> Seite 0)
    _scan_embedded_js(doc, findings, out)
    _scan_actions(doc, findings, out)
    _scan_links(doc, findings, out)
    _scan_embedded_files(doc, findings, out)
    _scan_xmp(doc, findings, out)

    # 2. Globale Dokumenten-Metadaten prüfen
    out("[*] Analysiere globale Dokumenten-Metadaten...")
    for key, value in doc.metadata.items():
        if value and isinstance(value, str):
            _scan_field(value, 0, "Metadaten-Prompt", findings)

    # 3. Seitenweise Textlayer-Analyse
    out("[*] Analysiere Textlayer auf Anomalien und Prompts...")
    for page_num in range(len(doc)):
        page = doc[page_num]
        w, h = page.rect.width, page.rect.height
        text_page = page.get_text("dict")

        for block in text_page.get("blocks", []):
            if block.get("type") != 0:  # nur Textblöcke
                continue
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    text = span.get("text", "").strip()
                    if not text:
                        continue

                    size = span.get("size", 0)
                    color_int = span.get("color", 0)
                    bbox = span.get("bbox", (0, 0, 0, 0))

                    lum = luminance(color_int)
                    is_white = is_light_or_white(color_int)
                    is_tiny = (size < MIN_TEXT_SIZE)
                    is_off_page = (bbox[0] < 0 or bbox[1] < 0 or bbox[2] > w or bbox[3] > h)

                    if is_white or is_tiny or is_off_page:
                        reasons = []
                        if is_white:
                            r = (color_int >> 16) & 255
                            g = (color_int >> 8) & 255
                            b = color_int & 255
                            reasons.append(f"Heller/weißer Text (Luminanz: {lum:.0f}, RGB: {r},{g},{b})")
                        if is_tiny:
                            reasons.append(f"Mikroschrift ({size:.2f} pt)")
                        if is_off_page:
                            reasons.append("Off-Page (Außerhalb des Rahmens)")
                        findings.append(_finding(
                            page_num + 1, "Text-Anomalie", "medium", text,
                            ", ".join(reasons)))

                    # Semantische Prüfung über die gemeinsame Signatur-DB
                    for label, matched, s, e in find_matches_with_positions(text):
                        snippet = text[max(0, s - 30): min(len(text), e + 30)].strip()
                        findings.append(_finding(
                            page_num + 1, "Textlayer-Prompt", "high", text,
                            f"Muster ({label}): …{snippet}…"))

    # Deduplizierung (gleiche Seite + Typ + Inhalt)
    dedup = []
    seen = set()
    for f in findings:
        key = (f["page"], f["type"], f["content"])
        if key in seen:
            continue
        seen.add(key)
        dedup.append(f)
    findings = dedup

    # Ausgabe
    out()
    out("=== SCAN-ERGEBNISSE (TEXT/METADATEN) ===")
    if not findings:
        out("[✓] Keine Text-Anomalien oder Prompt-Muster gefunden.")
        return findings, 0

    for idx, f in enumerate(findings, 1):
        out(f"[{idx}] {SEVERITY_LABELS[f['severity']]} | {f['type']} (Seite {f['page']}) | "
            f"{f['description']}")
        out(f"    Inhalt: \"{f['content']}\"")
        out()

    if any(f["severity"] == "high" for f in findings):
        return findings, 1
    # Anomalien (heller/weißer Text) sind kein bestätigter Injektionsbeweis,
    # aber ein deutliches Versteck-Indiz -> nicht "sauber".
    return findings, 2


def usage():
    print("Nutzung: python3 pdf_text_scanner.py [--json] <pfad_zur_pdf>")


def main():
    args = [a for a in sys.argv[1:] if a not in ("--help", "-h")]
    json_only = "--json" in args
    args = [a for a in args if a != "--json"]
    if not args:
        usage()
        sys.exit(2)

    findings, code = scan_text_and_metadata(args[0], verbose=not json_only)
    if findings is None:
        sys.exit(1)

    print(json.dumps({"clean": code == 0, "findings": findings},
                     ensure_ascii=False, indent=2))
    sys.exit(code)


if __name__ == "__main__":
    main()

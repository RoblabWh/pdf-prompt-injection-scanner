"""Scanner fuer .docx, .txt und .md – versteckte Prompt-Injektionen in Textdokumenten.

Nur Standardbibliothek (zipfile + xml.etree), daher ohne extra Abhaengigkeit.
Deckung:
  * .txt/.md  - Volltext + Metadaten-Heuristik (Frontmatter-Blöcke)
  * .docx     - Dokument-Text, Kopf-/Fußzeilen, Kern-/App-Metadaten, Kommentare,
                verborgene Zeichen (w:vanish / w:vanish-like), Weiß-auf-Weiß-Text
                und Injektionsmuster in der Dokument-XML.

Exit-Codes: 0 = sauber, 1 = kritisch (High), 2 = nur Auffälligkeit (Medium).
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

from pdfscan_core import find_matches_with_positions

SEVERITY_LABELS = {"high": "KRITISCH", "medium": "WARNUNG", "low": "HINWEIS"}

# DOCX-XML-Namespace
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def _finding(page, finding_type, severity, content, description):
    return {
        "page": page,
        "type": finding_type,
        "description": description,
        "content": content,
        "severity": severity,
    }


def _scan_text_field(text, page, finding_type, findings):
    """Prüft einen Text-String auf alle gemeinsamen Injektionsmuster."""
    if not text or not isinstance(text, str):
        return
    text = text.strip()
    if len(text) < 2:
        return
    for label, matched, s, e in find_matches_with_positions(text):
        snippet = text[max(0, s - 30): min(len(text), e + 30)].strip()
        findings.append(_finding(
            page, finding_type, "high", text,
            f"Muster ({label}): …{snippet}…"))


# ── TXT / MD ───────────────────────────────────────────────────────────────────
def _scan_plain_text(path, verbose):
    def out(*args):
        if verbose:
            print(*args)

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except Exception as e:
        out(f"[-] Fehler beim Lesen der Datei: {e}")
        return None

    ext = os.path.splitext(path)[1].lower()
    out(f"=== DOKUMENT-SCANNER ({ext.lstrip('.') or 'text'}): {path} ===")
    out(f"Laenge: {len(content)} Zeichen")
    out()

    findings = []

    # Metadaten-Heuristik fuer Markdown-Frontmatter (--- ... ---)
    if ext == ".md":
        fm = _extract_frontmatter(content)
        for key, value in fm.items():
            _scan_text_field(value, 0, "Frontmatter-Prompt", findings)

    # Kompletten Inhalt auf Signatur-Muster pruefen.
    _scan_text_field(content, 1, "Textlayer-Prompt", findings)

    # Dedup
    findings = _dedup(findings)
    return findings, _summarize(findings, out)


def _extract_frontmatter(content):
    """Zerlegt ein Markdown-Frontmatter-Block (--- ... ---) in Key/Value-Listen."""
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", content, re.DOTALL)
    if not m:
        return {}
    pairs = {}
    for line in m.group(1).splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        pairs[k.strip()] = v.strip()
    return pairs


# ── DOCX ────────────────────────────────────────────────────────────────────────
def _localname(tag):
    return tag.split("}")[-1] if "}" in tag else tag


def _scan_docx(path, verbose):
    def out(*args):
        if verbose:
            print(*args)

    try:
        zf = zipfile.ZipFile(path)
    except Exception as e:
        out(f"[-] Fehler beim Öffnen des DOCX-Archivs: {e}")
        return None

    out(f"=== DOKUMENT-SCANNER (docx): {path} ===")
    names = zf.namelist()
    out(f"ZIP-Eintraege: {len(names)}")
    out()

    findings = []

    # 1. Dokument-Text (Wort, Tabellen, Listen …) + Format-Anomalien
    if "word/document.xml" in names:
        _scan_docx_body(zf.read("word/document.xml"), findings, out)

    # 2. Kopf- und Fußzeilen
    for name in names:
        if re.match(r"word/header\d*\.xml$", name) or re.match(r"word/footer\d*\.xml$", name):
            _scan_docx_part(zf.read(name), 0, "Header/Footer-Prompt", findings, out)

    # 3. Kommentare
    if "word/comments.xml" in names:
        _scan_docx_part(zf.read("word/comments.xml"), 0, "Kommentar-Prompt", findings, out)

    # 4. Kern-/App-Metadaten
    for name, ftype in (("docProps/core.xml", "Metadaten-Prompt"),
                        ("docProps/app.xml", "Metadaten-Prompt")):
        if name in names:
            _scan_docx_part(zf.read(name), 0, ftype, findings, out)

    # 5. Eingebettete Objekte / Anhänge: nur die Dateinamen pruefen
    for name in names:
        if name.startswith("word/embeddings/") or name.startswith("word/media/"):
            _scan_text_field(os.path.basename(name), 0, "Anhang-Prompt", findings)

    # 6. Injektionsmuster in der rohen XML (z. B. versteckte w:vanish-Schreibweisen)
    _scan_docx_hidden_signals(zf.read("word/document.xml") if "word/document.xml" in names else b"",
                              findings, out)

    zf.close()

    findings = _dedup(findings)
    return findings, _summarize(findings, out)


def _scan_docx_body(xml_bytes, findings, out):
    """Extrahiert Absatz-Text aus word/document.xml inkl. Format-Anomalien.

    Word zerlegt Text oft in mehrere <w:r>-Lauf; daher werden alle <w:t>
    eines Absatzes (<w:p>) zusammengefuellt, bevor die Signatur-DB geprüft
    wird – so treffen auch mehrwörtige Muster.
    """
    out("[*] Analysiere Dokument-Text und -Formulierung...")
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        out(f"    [!] XML-Parsing document.xml fehlgeschlagen: {e}")
        return

    for el in root.iter():
        tag = _localname(el.tag)

        if tag == "p":  # Absatz: alle Textspans zusammenfuehren
            text = "".join((t.text or "") for t in el.iter()
                           if _localname(t.tag) == "t").strip()
            if text:
                _scan_text_field(text, 1, "Textlayer-Prompt", findings)

        elif tag == "rPr":  # Zeichenformatierung -> Versteck-Anomalien
            _check_run_props(el, findings, out)


def _check_run_props(rpr, findings, out):
    """Weiß-auf-Weiß-Text und 'verschollene' (vanished) Schrift als Auffaelligkeit."""
    # w:color -> Wert als hex (z. B. "FFFFFF")
    color_hex = None
    vanish = False
    for child in rpr.iter():
        ctag = _localname(child.tag)
        if ctag == "color":
            color_hex = (child.get(f"{{{W_NS}}}val") or "").strip().upper()
        elif ctag == "vanish":
            vanish = True

    # Nur melden, wenn ein Text dazugehoert – wir haetten hier nur das rPr;
    # die zugehoerigen <w:t>-Knoten liegen im selben <w:r>.
    # Wir bewerten die Anomalie allgemein als Medium (Versteck-Indiz).
    if vanish:
        findings.append(_finding(
            1, "Text-Anomalie", "medium", "[w:vanish]",
            "Versteckte Schrift (vanish) im Dokument"))
        return

    if color_hex and len(color_hex) == 6:
        try:
            color_int = int(color_hex, 16)
        except ValueError:
            return
        # Weißer/ sehr heller Text = Versteck-Indiz
        r = (color_int >> 16) & 255
        g = (color_int >> 8) & 255
        b = color_int & 255
        luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b
        if luminance >= 200:
            findings.append(_finding(
                1, "Text-Anomalie", "medium", f"color #{color_hex}",
                f"Heller/weißer Text (Luminanz: {luminance:.0f}, RGB: {r},{g},{b})"))


def _scan_docx_part(xml_bytes, page, finding_type, findings, out):
    """Prüft einen DOCX-Bestandteil (Header/Footer/Kommentar/Metadaten) auf Muster."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        # Metadaten-XML: alle Stringwerte sammeln
        _scan_xml_all_text(xml_bytes, page, finding_type, findings)
        return
    texts = [t for t in (el.text for el in root.iter() if el.text) if t and t.strip()]
    blob = "\n".join(t.strip() for t in texts if t.strip())
    if blob:
        _scan_text_field(blob, page, finding_type, findings)


def _scan_xml_all_text(xml_bytes, page, finding_type, findings):
    """Fallback: alle lesbaren Textfragmente aus einer XML auslesen und pruefen."""
    try:
        text = xml_bytes.decode("utf-8", errors="replace")
    except Exception:
        return
    texts = re.findall(r">([^<>]{3,})<", text)
    blob = "\n".join(t.strip() for t in texts if t.strip())
    if blob:
        _scan_text_field(blob, page, finding_type, findings)


def _scan_docx_hidden_signals(xml_bytes, findings, out):
    """Sucht in der rohen XML nach typischen Versteck-Signalen (vanish, size 0, white)."""
    try:
        raw = xml_bytes.decode("utf-8", errors="replace")
    except Exception:
        return
    # w:vanish
    if "<w:vanish" in raw:
        findings.append(_finding(
            1, "Text-Anomalie", "medium", "w:vanish",
            "Dokument verwendet versteckte Schrift (w:vanish)"))
    # Schriftgröße 0 (w:sz val="0")
    if re.search(r'w:sz\s+w:val="0"\s*/', raw) or re.search(r'w:sz val="0"', raw):
        findings.append(_finding(
            1, "Text-Anomalie", "medium", "w:sz val=0",
            "Dokument enthält Schriftgröße 0 (Mikroschrift/unsichtbar)"))


# ── Gemeinsame Abschluss-Helfer ──────────────────────────────────────────────────
def _dedup(findings):
    dedup = []
    seen = set()
    for f in findings:
        key = (f["page"], f["type"], f["content"])
        if key in seen:
            continue
        seen.add(key)
        dedup.append(f)
    return dedup


def _summarize(findings, out):
    """Gibt den Abschluss-Report und den Exit-Code (0/1/2) zurueck."""
    out()
    out("=== SCAN-ERGEBNISSE (DOKUMENT) ===")
    if not findings:
        out("[ok] Keine Prompt-Muster oder Anomalien gefunden.")
        return 0

    for idx, f in enumerate(findings, 1):
        out(f"[{idx}] {SEVERITY_LABELS[f['severity']]} | {f['type']} (Seite {f['page']}) | "
            f"{f['description']}")
        out(f"    Inhalt: \"{f['content']}\"")
        out()

    if any(f["severity"] == "high" for f in findings):
        return 1
    return 2


# ── Öffentliche API ───────────────────────────────────────────────────────────────
def scan_document(path, verbose=True):
    """Routet je Dateityp auf den passenden Pfad. Liefern (findings, code) oder None."""
    if not os.path.isfile(path):
        print(f"[-] Datei nicht gefunden: {path}")
        return None
    ext = os.path.splitext(path)[1].lower()
    if ext == ".docx":
        return _scan_docx(path, verbose)
    if ext in (".txt", ".md", ".markdown", ".rst", ".log", ".csv"):
        return _scan_plain_text(path, verbose)
    print(f"[-] Nicht unterstützter Dateityp fuer doc_scanner: {ext}")
    return None


def usage():
    print("Nutzung: python3 doc_scanner.py [--json] <pfad_zur_dokument>  (.docx/.txt/.md)")


def main():
    args = [a for a in sys.argv[1:] if a not in ("--help", "-h")]
    json_only = "--json" in args
    args = [a for a in args if a != "--json"]
    if not args:
        usage()
        sys.exit(2)

    res = scan_document(args[0], verbose=not json_only)
    if res is None:
        sys.exit(2)
    findings, code = res

    print(json.dumps({"clean": code == 0, "findings": findings},
                     ensure_ascii=False, indent=2))
    sys.exit(code)


if __name__ == "__main__":
    main()

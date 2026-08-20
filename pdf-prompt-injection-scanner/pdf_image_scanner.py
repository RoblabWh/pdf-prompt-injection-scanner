import sys
import re
import io
import json
import subprocess

import fitz  # PyMuPDF

try:
    import pytesseract
    from PIL import Image
    from PIL.ExifTags import TAGS
except ImportError:
    print("[-] Fehler: Bitte installieren Sie pymupdf, pytesseract und pillow.")
    sys.exit(1)

from pdfscan_core import (
    find_matches_with_positions,
)

SEVERITY_LABELS = {"high": "KRITISCH", "medium": "WARNUNG", "low": "HINWEIS"}


def _finding(page, img_index, finding_type, severity, content, description):
    return {
        "page": page,
        "type": finding_type,
        "description": f"{description} — Bild {img_index}",
        "content": content,
        "severity": severity,
    }


def _available_ocr_langs():
    """Fragt Tesseract ab, welche Sprachpakete installiert sind."""
    try:
        out = subprocess.check_output(
            ["tesseract", "--list-langs"], stderr=subprocess.STDOUT
        ).decode(errors="replace")
    except Exception:
        return set()
    langs = {line.strip() for line in out.splitlines()[2:]}
    return {l for l in langs if l}


def scan_image_metadata(img_object, page_num, img_index, findings, out):
    """Prüft EXIF- und XMP-Daten des Bildes auf Injektionsmuster."""
    # 1. EXIF
    try:
        exif_data = img_object.getexif()
        if exif_data:
            out("    [Metadaten] EXIF-Daten im Bild gefunden:")
            for tag_id in exif_data:
                tag = TAGS.get(tag_id, tag_id)
                data_str = str(exif_data.get(tag_id)).strip()
                if data_str:
                    out(f"      | {tag}: {data_str[:60]}")
                    for label, matched, s, e in find_matches_with_positions(data_str):
                        snippet = data_str[max(0, s - 30): min(len(data_str), e + 30)].strip()
                        out(f"      [ALERT] KRITISCH: Injection in EXIF '{tag}'! ({label})")
                        findings.append(_finding(
                            page_num, img_index, "Bild-EXIF", "high", data_str,
                            f"Injektion erkannt ({label}) — Feld: {tag}"))
    except Exception as e:
        out(f"    [Metadaten] Fehler beim EXIF-Parsing: {e}")

    # 2. XMP/Info-Blöcke
    try:
        if hasattr(img_object, "info") and img_object.info:
            out("    [Metadaten] Erweiterte Info/XMP-Blöcke im Bild gefunden:")
            for key, value in img_object.info.items():
                val_str = str(value).strip()
                if val_str:
                    out(f"      | {key}: {val_str[:60]}...")
                    for label, matched, s, e in find_matches_with_positions(val_str):
                        snippet = val_str[max(0, s - 30): min(len(val_str), e + 30)].strip()
                        out(f"      [ALERT] KRITISCH: Injection in Bild-Info '{key}'! ({label})")
                        findings.append(_finding(
                            page_num, img_index, "Bild-XMP", "high", val_str,
                            f"Injektion erkannt ({label}) — Block: {key}"))
    except Exception as e:
        out(f"    [Metadaten] Fehler beim XMP-Parsing: {e}")


def scan_pdf_images(pdf_path, verbose=True):
    def out(*args):
        if verbose:
            print(*args)

    try:
        doc = fitz.open(pdf_path)
    except Exception as e:
        out(f"[-] Fehler beim Öffnen der Datei: {e}")
        return None

    out(f"=== BILD- UND OCR-TIEFENSCANNER: {pdf_path} ===")
    out(f"Seitenanzahl: {len(doc)}")
    out()

    # OCR-Sprachen dynamisch bestimmen: deu+eng als Basis, chi_sim wenn vorhanden.
    available = _available_ocr_langs()
    wanted = []
    for l in ("deu", "eng", "chi_sim"):
        if l in available:
            wanted.append(l)
    ocr_lang = "+".join(wanted) if wanted else "eng"
    out(f"[OCR] Verfügbare Tesseract-Sprachen: {sorted(available) or '(none)'}")
    out(f"[OCR] Wähle: {ocr_lang}")
    out()

    findings = []
    total_images = 0

    for page_num in range(len(doc)):
        page = doc[page_num]
        image_list = page.get_images(full=True)
        if not image_list:
            continue

        out(f"--- Seite {page_num + 1} ({len(image_list)} Bild/er gefunden) ---")

        for img_index, img in enumerate(image_list):
            total_images += 1
            xref = img[0]
            base_image = doc.extract_image(xref)
            image_bytes = base_image.get("image", b"") or b""

            try:
                image = Image.open(io.BytesIO(image_bytes))
            except Exception as e:
                out(f"  [!] Fehler beim Laden von Bild {img_index + 1} (XREF {xref}): {e}")
                continue

            out(f"  -> Bild {img_index + 1} (XREF {xref}):")

            # Schritt A: Bild-Metadaten scannen
            scan_image_metadata(image, page_num + 1, img_index + 1, findings, out)

            # Schritt B: OCR-Texterkennung (DE+EN+ZU wenn möglich)
            try:
                ocr_text = pytesseract.image_to_string(image, lang=ocr_lang).strip()
                if ocr_text:
                    out(f"    [OCR] Vollständiger extrahierter Text:")
                    for line in ocr_text.splitlines():
                        out(f"      | {line}")
                    for label, matched, s, e in find_matches_with_positions(ocr_text):
                        snippet = ocr_text[max(0, s - 30): min(len(ocr_text), e + 30)].strip()
                        out(f"      [ALERT] KRITISCH: Injection im Bildtext! ({label})")
                        findings.append(_finding(
                            page_num + 1, img_index + 1, "Bild-OCR", "high", ocr_text,
                            f"Muster ({label}): …{snippet}…"))
                else:
                    out("    [OCR] Kein visueller Text im Bild erkannt.")
            except Exception as e:
                out(f"    [!] Tesseract OCR fehlgeschlagen: {e}")
            out()

    # Abschlussbericht
    out("==================================================")
    out("=== SCAN-ZUSAMMENFASSUNG (BILDER) ===")
    out(f"Gescannte Bilder insgesamt: {total_images}")
    out(f"Kritische Funde in Bildern: {len(findings)}")
    out("==================================================")

    # Dedup
    dedup = []
    seen = set()
    for f in findings:
        key = (f["page"], f["type"], f["content"])
        if key in seen:
            continue
        seen.add(key)
        dedup.append(f)
    findings = dedup

    if not findings:
        out("[✓] Alle Bilddaten und OCR-Texte sind sauber.")
        return findings, 0

    out()
    out("[!] GEFAHRENHERDE IN BILDERN GEFUNDEN:")
    out()
    for idx, f in enumerate(findings, 1):
        out(f"[{idx}] {SEVERITY_LABELS[f['severity']]} | {f['type']} (Seite {f['page']}) | "
            f"{f['description']}")
        out(f"    Inhalt: \"{f['content'][:200].strip()}\"")
        out()

    return findings, 1


def usage():
    print("Nutzung: python3 pdf_image_scanner.py [--json] <pfad_zur_pdf>")


def main():
    args = [a for a in sys.argv[1:] if a not in ("--help", "-h")]
    json_only = "--json" in args
    args = [a for a in args if a != "--json"]
    if not args:
        usage()
        sys.exit(2)

    findings, code = scan_pdf_images(args[0], verbose=not json_only)
    if findings is None:
        sys.exit(1)

    print(json.dumps({"clean": code == 0, "findings": findings},
                     ensure_ascii=False, indent=2))
    sys.exit(code)


if __name__ == "__main__":
    main()

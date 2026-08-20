# PDF Prompt-Injection Scanner

Eine lokal laufende Python-Suite zur Erkennung **versteckter Prompt-Injektionen**
in PDF-Dokumenten. Drei Scanner teilen sich eine gemeinsame Signatur-Datenbank
und liefern konsistente Ergebnisse für Text, Bilder/OCR und einen vertieften
Analysepfad – ohne Cloud, ohne Telemetrie.

## Warum?

LLM-basierte Tools verarbeiten PDFs häufig automatisch. Angreifer nutzen das aus:
Befehle wie „ignore all instructions" werden so eingebettet, dass sie für Menschen
unsichtbar bleiben, aber von der KI als Anweisung gelesen werden. Diese Suite
erkennt solche Techniken strukturell und signaturbasiert im Dokument.

## Was wird erkannt?

- **Weiß-auf-Weiß / sehr heller Text** (Luminanz-Schwelle nach ITU-R BT.709, Wert 200)
- **Mikroschrift** (Text unter 2,0 pt)
- **Off-Page-Text** (außerhalb der Seitenränder)
- **Dokumenten-Metadaten** (Titel, Autor, Betreff, XMP)
- **Eingebettetes JavaScript** und **Auto-Execute-Actions**
- **`javascript:`-Links** sowie **Exfiltrations-/Upload-URLs**
- **Anhänge** (Embedded Files)
- **Bilder**: EXIF/XMP-Metadaten und OCR-Text (Deutsch + Englisch, optional Chinesisch)

Signaturmuster liegen auf **Englisch, Deutsch und Chinesisch** vor
(98+ kompilierte Regex-Muster). Neue Muster an einer einzigen Stelle
(`prompt_patterns.py`) ergänzen.

## Voraussetzungen

- Python 3.10 oder neuer
- Tesseract-OCR (für den Bild-/OCR-Scanner)
- Linux (getestet auf Ubuntu/Debian); macOS entsprechend angepasst

## Installation

```bash
# 1) Systemabhängigkeiten (Ubuntu/Debian)
sudo apt update
sudo apt install tesseract-ocr tesseract-ocr-deu tesseract-ocr-eng

# Optional: Chinesisch-OCR
sudo apt install tesseract-ocr-chi-sim

# 2) Python-Umgebung
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Schnelleinstieg

```bash
./run_pdf_scanner.sh Pfad/zur/Datei.pdf
```

Die Pipeline führt alle drei Stufen aus und druckt einen konsolidierten
Report. Exit-Code `0` bedeutet „sauber", jeder andere Wert ist Alarm.

### Alle Optionen

```bash
./run_pdf_scanner.sh <pdf>                    # alle drei Stufen (Standard)
./run_pdf_scanner.sh --only text <pdf>        # nur Text/Struktur
./run_pdf_scanner.sh --only image <pdf>       # nur Bilder/OCR
./run_pdf_scanner.sh --only injection <pdf>   # nur Tiefenscan
./run_pdf_scanner.sh --batch <ordner>         # alle *.pdf im Ordner
./run_pdf_scanner.sh --format text <pdf>      # Text- statt JSON-Report
./run_pdf_scanner.sh -h                       # Hilfe
```

### Einzelne Scanner (ohne Pipeline)

```bash
python3 pdf_text_scanner.py  Datei.pdf --json
python3 pdf_image_scanner.py Datei.pdf --json
PYTHONPATH=pdf-injection-scanner python3 -m pdf_injection_scanner.scanner Datei.pdf --json
```

Die `--json`-Ausgabe lässt sich direkt in weitere Skripte oder Pipelines
einbinden.

## Architektur

| Stufe | Datei | Deckung |
|-------|-------|---------|
| 1 | `pdf_text_scanner.py` | Textlayer, Metadaten, XMP, JavaScript, Actions, Links, Anhänge, Layout-Anomalien |
| 2 | `pdf_image_scanner.py` | EXIF/XMP, OCR (deu+eng, optional chi_sim) |
| 3 | `pdf-injection-scanner/pdf_injection_scanner/scanner.py` | Weiß-/Mikro-/Off-Page-Text und Signatur-Treffer |
| Basis | `pdfscan_core.py` | Kompilierte Signatur-DB, Luminanz-Helfer, gemeinsame Schwellen |
| DB | `prompt_patterns.py` | CANONICAL-Muster (EN/DE/ZH) |
| CLI | `run_pdf_scanner.sh` | Kombinierte Pipeline (Batch, `--only`, `--format`) |
| Report | `merge_reports.py` | Konsolidierter Report aus den drei Scannern |

Alle drei Stufen importieren dieselbe Signatur-DB und dieselben
Layout-Schwellen aus `pdfscan_core` – neue Muster und Änderungen passieren
deshalb an genau einer Stelle.

### Muster ergänzen

```python
# prompt_patterns.py
PROMPT_PATTERNS = [
    r"(?i)ignore\s+all\s+instructions",
    r"(?i)execute\s+this\s+code",
]
```

```python
# pdfscan_core.py – mit Label für Rich-Report und Scanner 3
SUPPLEMENTARY_PATTERNS = [
    (r"(?i)execute\s+this\s+code", "Code execution command"),
]
```

## Exit-Codes

| Code | Bedeutung |
|------|-----------|
| 0 | sauber |
| 1 | kritische Injektion (High-Severity) |
| 2 | nur Auffälligkeit (Medium) oder Fehler (Datei fehlt, Passwort, Format) |

`run_pdf_scanner.sh` wertet jeden Exit-Code ungleich `0` als **ALARM** –
praktisch für CI/CD und Skripte.

## Tests

```bash
python3 -m pytest test_scanner_suite.py -v
```

7 Test-Cases decken die wichtigsten Erkennungs-Klassen ab: weißer Text,
Mikroschrift, Metadaten, `javascript:`-Link, Shared-DB-Konsistenz,
Negativ-Tests und die Luminanz-Logik.

## Hinweise

- Scans laufen **vollständig lokal**; es wird keine Datei auf einen Server übertragen.
- Das Tool ist ein **Frühwarn-Indikator**, kein Ersatz für eine vollständige
  Sicherheitsanalyse oder ein Sandboxing-Verfahren.
- Tesseract mit `chi_sim` ist optional; ohne das Paket fallen die
  Chinesisch-Tests bei Scanner 2 sanft zurück (kein Fehlschlag).

## Lizenz

MIT – siehe `pdf-injection-scanner/pyproject.toml`.

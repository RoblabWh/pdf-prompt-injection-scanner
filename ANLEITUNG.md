# PDF Prompt-Injection Scanner - Anleitung

## 1. Uebersicht

Diese Suite prüft PDF-Dokumente auf **versteckte Prompt-Injektionen** - also
Anweisungen, die für das Auge unsichtbar, aber für LLM-basierte Parser
(z. B. RAG-Pipelines) lesbar sind.

**Erkannte Verstecktechniken:**
- Weiß-auf-Weiß / sehr heller Text (BT.709-Luminanz)
- Mikroschrift (< 2,0 pt)
- Off-Page-Text (außerhalb der Seitenränder)
- Injektionen in globale PDF-Metadaten
- Injektionen in EXIF/XMP eingebetteter Bilder
- Prompts als Rasterbild (OCR-verschleiert)
- eingebettetes JavaScript, Auto-Execute-Actions, `javascript:`-Links, Exfiltrations-URLs
- Anhänge (Embedded Files)

---

## 2. Architektur - Die drei Scanner

| # | Scanner | Datei | Regex-Quelle | Deckung |
|---|---------|-------|-------------|---------|
| 1 | **Text & Struktur** | `pdf_text_scanner.py` | `pdfscan_core` (gemeinsam) | Textlayer, Metadaten, XMP, JS, Actions, Links, Anhänge, Layout-Anomalien |
| 2 | **Bilder & OCR** | `pdf_image_scanner.py` | `pdfscan_core` (gemeinsam) | EXIF/XMP, OCR-Text (deu+eng + optional chi_sim) |
| 3 | **Tiefenscan** | `pdf-injection-scanner/pdf_injection_scanner/scanner.py` | `pdfscan_core` (gemeinsam) | White/Tiny/Off-Page-Text + Signatur-Treffer |

**Wichtig:** Alle drei Scanner teilen sich **eine einzige** Signatur-DB in
`pdfscan_core.py` (aus `prompt_patterns.py` + `SUPPLEMENTARY_PATTERNS`
kompiliert). Neue Muster gehören **nur dort** hinein - das wirkt sich
sofort auf alle drei Scanner aus.

---

## 3. Installation

```bash
# Tesseract-OCR + Sprachpakete
sudo apt update
sudo apt install tesseract-ocr tesseract-ocr-deu tesseract-ocr-eng -y

# Python-Bibliotheken (einmal)
pip install -r requirements.txt
```

Für Chinesisch-OCR optional installieren:
```bash
sudo apt install tesseract-ocr-chi-sim
```
Ohne `chi_sim` fällt `pdf_image_scanner.py` automatisch auf `deu+eng` zurück.

---

## 4. Ausfuehrung

### 4.1 Alle drei Scanner mit einem Befehl (empfohlen)

```bash
./run_pdf_scanner.sh Pfad/zur/Datei.pdf
```

Optionen:
```bash
./run_pdf_scanner.sh --only text Datei.pdf        # nur Scanner 1
./run_pdf_scanner.sh --only image Datei.pdf       # nur Scanner 2
./run_pdf_scanner.sh --only injection Datei.pdf   # nur Scanner 3

./run_pdf_scanner.sh --batch <ordner>             # alle *.pdf im Ordner

./run_pdf_scanner.sh --format text Datei.pdf      # Text- statt JSON-Report
./run_pdf_scanner.sh --report-json Datei.pdf      # erzwinge JSON-Report
```

### 4.2 Einzelne Scanner manuell

```bash
python3 pdf_text_scanner.py  Datei.pdf          # Scanner 1
python3 pdf_image_scanner.py Datei.pdf          # Scanner 2
PYTHONPATH=pdf-injection-scanner python3 -m pdf_injection_scanner.scanner Datei.pdf  # Scanner 3
```

### 4.3 JSON-Ausgabe (maschinell lesbar)

```bash
python3 pdf_text_scanner.py  --json Datei.pdf   # Scanner 1 (JSON)
python3 pdf_image_scanner.py --json Datei.pdf   # Scanner 2 (JSON)
PYTHONPATH=pdf-injection-scanner python3 -m pdf_injection_scanner.scanner --json Datei.pdf  # Scanner 3 (JSON)
```

### 4.4 Konsolidierter Report (alle 3 Scanner)

```bash
# Laeuft automatisch, wenn --report-json oder --format json gesetzt ist:
./run_pdf_scanner.sh --report-json Pfad/zur/Datei.pdf
```

Alternativ manuell:
```bash
python3 pdf_text_scanner.py  --json Datei.pdf > /tmp/t.json
python3 pdf_image_scanner.py --json Datei.pdf > /tmp/i.json
PYTHONPATH=pdf-injection-scanner python3 -m pdf_injection_scanner.scanner --json Datei.pdf > /tmp/j.json

python3 merge_reports.py --text /tmp/t.json --image /tmp/i.json --injection /tmp/j.json
python3 merge_reports.py --text /tmp/t.json --image /tmp/i.json --injection /tmp/j.json --format text
```

---

## 5. Reguläre Ausdrücke - Wo liegen sie?

**Einziger Punkt:** `prompt_patterns.py` (CANONICAL-Muster), plus eine
kleine ergänzende Liste in `pdfscan_core.py` (`SUPPLEMENTARY_PATTERNS`).
Beides wird beim Import ein einziges Mal kompiliert zu:

```python
pdfscan_core.COMPILED_PATTERNS  # Liste von Pattern(regex, label)
```

### Neue Muster hinzufügen

Für **einzelne Regex-Phrasen** (EN/DE/ZH):

```python
# prompt_patterns.py
PROMPT_PATTERNS = [
    # ... bestehende Muster ...
    r"(?i)\bexecute\s+this\s+code\b",
    r"(?i)\bgeheimes\s+protokoll\s+:[A-Z]+\b",
]
```

Für **Muster mit Label** (klickbare Signatur-DB, auch in Scanner 3):

```python
# pdfscan_core.py  (SUPPLEMENTARY_PATTERNS)
SUPPLEMENTARY_PATTERNS = [
    (r"(?i)execute\s+this\s+code", "Code execution command"),
]
```

Das Flag `(?i)` = Case-Insensitive. Die Muster sind bewusst phrasenhaft
(kein einzelnes Wort), um False Positives in technischen PDFs zu vermeiden.

### Schwellen anpassen

```python
# pdfscan_core.py
MIN_TEXT_SIZE = 2.0          # Punkt; kleiner gilt als "Mikroschrift"
LIGHT_TEXT_LUMINANCE = 200   # BT.709-Luminanz 0-255; >= gilt als "heller/weißer Text"
```

---

## 6. Exit-Codes

| Code | Bedeutung (alle drei Scanner einheitlich) |
|------|-----------|
| `0` | sauber - keine Auffälligkeiten |
| `1` | High-Severity / kritische Injektion |
| `2` | Fehler (Datei fehlt, passwortgeschützt, falsches Format) |

`run_pdf_scanner.sh` fährt **alles != 0** als ALARM aus.

---

## 7. Diagramm: Gemeinsame Basis

```
 prompt_patterns.py           pdfscan_core.SUPPLEMENTARY_PATTERNS
        \                           /
         \                         /
          v                       v
      pdfscan_core.py  (COMPILED_PATTERNS)
          ^           ^           ^
          |           |           |
   pdf_text_scanner_ pdf_image_scanner_ pdf-injection-scanner/...
        py               py
```

Alle drei Scanner importieren dieselbe Liste und die gleichen
Schwellen. Eine Änderung wirkt sich auf alle drei gleichzeitig aus.

---

## 8. Tests

```bash
python3 -m pytest test_scanner_suite.py -v
```

7 Tests:
- weißer Text erkannt
- Mikroschrift erkannt
- Metadaten-Injektion erkannt
- `javascript:`-Link erkannt
- Shared-DB-Konsistenz zwischen Scanner 1 & 2
- sauberes Dokument bleibt "sauber"
- Luminanz-Logik konsistent

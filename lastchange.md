# Änderungen (2026-09-11)

11 Dateien geändert – 619 Zeilen ergänzt, 31 entfernt.

## pdfscan_core.py  (+170)
- **Anomalie-Detektor** `find_text_anomalies()`:
  - Zero-Width-Space, Bidi-Overrides, Steuerzeichen, lange Base64/Hex-Runs
  - `_visible_snippet()` – kennzeichnet unsichtbare Zeichen im Snippet
  - Schweregrade: ZWS/Bidi `high`, Steuerzeichen/Base64 `medium`
- **Sprach-Kontextsignal** (neu):
  - `language_finding()`: unerwartete Sprache (non EN/DE) → `medium`
    – in Kombination mit weißer/zu kleiner Schrift im selben Span → `high` (ALARM)
  - `detect_langs()`, `unexpected_langs()`, `lang_label()`
  - Whitelist: EN + DE (erwartete Dokument-Sprachen)
  - Konfidenz-Schwelle 0.5 + Mindestlänge 20 Zeichen → keine FP bei kurzen Tokens
  - Fallback: ohne `langdetect` schweigt die Funktion

## test_scanner_suite.py  (+180)
- `TestNewSignatureCoverage` – 11 Tests:
  Chat-Template-Tokens, PromptInject (nevermind/scream/spellcheck),
  Goodside, Encoding, URL-Injection, ZWS/Bidi/Base64-Anomalien,
  Negativ-Test (saubere Base64-Doku)
- `TestLanguageContext` – 7 Tests:
  FR (PDF/TXT) → medium, FR+weiß → high (exit 1), FR+Mikro → high,
  AR+Mikro → high, DE/EN sauber, Kurztext-Abbruch
- Gesamt: 40 Tests, alle grün

## prompt_patterns.py  (+63)
122 CANONICAL Signaturen (→ 133 kompiliert), zuvor 87. Neu:
- Chat-Template-Tokens (Llama/ChatML/Gemma: `<|im_start|>`, `<start_of_turn>`)
- PromptInject Goal-Hijacking (NEVERMIND / STOP EVERYTHING / just-say)
- PromptInject Spellcheck-Leak
- Goodside (garak probe)
- GCG adversarial suffix (`valid: I am`)
- Encoding/Obfuscation, URL-Indirekt-Injection
- DE-Leak patterns (Umlaut-tolerant: `[üu]`, `[äa]`)
- ZH-Äquivalente (指令覆盖, 暗号词, 行为指定, …)

## pdf_text_scanner.py  (+63)
- Anomalie-Checks in `_scan_field` + Span-Loop (ZWS, Bidi, Base64)
- Sprach-Kontext im Span: `visual_notes` (weiß/klein/off-page)
  durchgereicht → Eskalation auf `high`
- `JS_LINK_RE` erweitert: `vbscript:` und `script:` zusätzlich
- `DANGEROUS_DATA_URI_RE`: `data:text/…` und `data:application/…`
- Multi-Span-Combined-Matching: Fragmente über Spans hinweg werden
  am zusammengebauten Seitentext geprüft, `span_labels`-Dedup vermeidet Doppel-Funde

## pdf_image_scanner.py  (+20)
- `_add_anomalies()` für EXIF, XMP und OCR-Text

## doc_scanner.py  (+18)
- Anomalie-Checks in `_scan_text_field`
- Sprach-Kontext (medium; keine visuelle Eskalation, da DOCX keine
  Span-Farbe/-Größe liefert)
- Fuß-/Endnoten-Scan (`word/footnotes.xml`, `word/endnotes.xml`)

## pdf-injection-scanner/…/scanner.py  (Scanner 3, +13)
- Sprach-Kontext (medium) über `language_finding()` im `scan_page()` –
  weiße/Tiny-Schrift war dort bereits `high`

## run_pdf_scanner.sh  (+33)
- **JSON-Sanitizer** `sanitize_json`: entfernt Zeilen außerhalb des ersten
  bis letzten gültigen JSON-Blatts – fitz-Deprecation-Warnung auf stdout
  macht keinen Report mehr invalid; Exit-Codes bleiben korrekt
  (1 = ALARM/KRITISCH, 0 = SAUBER)
- **Interpreter-Auflösung** erweitert:
  `$PYTHON` → `venv/bin/python` → `.venv/bin/python` → `python3`
  Damit funktioniert die Pipeline automatisch mit `uv venv` (erzeugt `.venv`),
  ohne `PYTHON` manuell setzen zu müssen
- `_rc_label()` wiederhergestellt (bei vorherigerEdit versehentlich gelöscht)

## requirements.txt  (+1)
- `langdetect`

## README.md  (+52)
- „Was wird erkannt?": neue Techniken + Quellen
- **Installation**: Variante A = `uv pip install -r requirements.txt --system`
  (empfohlen), Variante B = `pip install -r requirements.txt`;
  uv-Install-Hinweis (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Muster-/Test-Zahlen aktualisiert

## ANLEITUNG.md  (+37)
- Erkannte Techniken + Quellen-Tabellen aktualisiert
- **Installation**: `uv` als Variante A, `pip` als Variante B

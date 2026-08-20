#!/bin/bash
# ============================================================================
# Dokument-Sicherheits-Pipeline  (Scanner 1 + 2 + 3 + 4)
#
#  Nutzung:
#    ./run_pdf_scanner.sh <datei>                   # passende Scanner (empfohlen)
#    ./run_pdf_scanner.sh --only text|image|injection|doc <datei>
#    ./run_pdf_scanner.sh --batch <ordner>          # *.pdf + *.docx + *.txt + *.md
#    ./run_pdf_scanner.sh --format text <datei>     # Text- statt JSON-Report
#    ./run_pdf_scanner.sh --report-json <datei>     # erzwinge JSON-Report
#
#  Dateitypen:
#    .pdf                       -> Scanner 1 (Text/Metadaten) + 2 (Bilder/OCR) + 3 (Tiefenscan)
#    .docx / .txt / .md         -> Scanner 4 (Textdokumente)
#
#  Exit-Codes: 0 = sauber, 1 = Funde, 2 = Fehler
# ============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Python-Interpreter auflösen: venv bevorzugen, sonst System-python3.
# venv/bin/python nutzt pyvenv.cfg und findet fitz/Pillow/pytest; System-python3
# hat die Abhängigkeiten in dieser Umgebung nicht.
PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
    if [ -x "$SCRIPT_DIR/venv/bin/python" ]; then
        PYTHON="$SCRIPT_DIR/venv/bin/python"
    elif command -v python3 >/dev/null 2>&1; then
        PYTHON="python3"
    fi
fi
if [ -z "$PYTHON" ]; then
    echo "[FEHLER] Kein Python-Interpreter gefunden." >&2; exit 2
fi

ONLY="all"
BATCH=""
FORMAT="json"
REPORT_JSON=0

# ── Argumente parsen ────────────────────────────────────────────────────────
PDF=""
while [ $# -gt 0 ]; do
    case "$1" in
        --only)         ONLY="$2"; shift 2 ;;
        --batch)        BATCH="$2"; shift 2 ;;
        --format)       FORMAT="$2"; shift 2 ;;
        --report-json)  REPORT_JSON=1; shift ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//' | awk '/^Python-Interpreter/{exit} {print}'
            exit 0 ;;
        -*)
            echo "[FEHLER] Unbekannte Option: $1" >&2; exit 2 ;;
        *)
            PDF="$1"; shift ;;
    esac
done

# gültige Werte für --only prüfen
case "$ONLY" in
    all|text|image|injection|doc) : ;;
    *) echo "[FEHLER] --only muss einer von all|text|image|injection|doc sein." >&2; exit 2 ;;
esac

# ── Dateityp bestimmen – bestimmt, welche Scanner relevant sind ────────────────
ext_of() {
    printf '%s' "${1##*.}" | tr '[:upper:]' '[:lower:]'
}

is_pdf_ext() {
    case "$(ext_of "$1")" in
        pdf) return 0 ;;
        *)   return 1 ;;
    esac
}

is_doc_ext() {
    case "$(ext_of "$1")" in
        docx|txt|md|markdown) return 0 ;;
        *)                    return 1 ;;
    esac
}

# ── Scanner-Funktion: führt EINEN Scanner aus und liefert sauberes JSON ──────
#    Exit-Code-Semantik der einzelnen Scanner (0/1/2) behalten wir bei.
#    Zusätzlicher Trenner: JSON-Datei muss valide sein, sonst ist es ein Fehler.
run_one() {
    local target="$1" which="$2" jsonfile="$3"
    local rc=0
    local py_err="2"   # Fallback-Code, falls Parser fehlschlaegt, ohne JSON
    case "$which" in
        text)
            $PYTHON pdf_text_scanner.py --json "$target" > "$jsonfile" 2>"$jsonfile.err"
            rc=$?
            ;;
        image)
            $PYTHON pdf_image_scanner.py --json "$target" > "$jsonfile" 2>"$jsonfile.err"
            rc=$?
            ;;
        injection)
            export PYTHONPATH="${SCRIPT_DIR}/pdf-injection-scanner${PYTHONPATH:+:$PYTHONPATH}"
            $PYTHON -m pdf_injection_scanner.scanner "$target" --json > "$jsonfile" 2>"$jsonfile.err"
            rc=$?
            ;;
        doc)
            $PYTHON doc_scanner.py --json "$target" > "$jsonfile" 2>"$jsonfile.err"
            rc=$?
            ;;
    esac
    # Fehler-Fall: Scanner lief nicht sauber DURCH.
    if [ ! -s "$jsonfile" ] || ! $PYTHON -c "import json,sys; json.load(open(sys.argv[1]))" "$jsonfile" >/dev/null 2>&1; then
        # Wenn ein Parser-Fehler oder ein fehlgeschlagener Launch vorlag: 2 zurück.
        return 2
    fi
    # Sonst den Scanner-Exit-Code (0/1/2) transparent weitergeben.
    return $rc
}

_rc_label() {
    case "$1" in
        0) echo "ok" ;;
        1) echo "KRITISCH" ;;
        2) echo "AUFFAELLIG" ;;
        *) echo "CODE=$1" ;;
    esac
}

# ── Eine Datei komplett scannen (routet je Dateityp) ──────────────────────
scan_file() {
    local target="$1"
    local name_clean
    name_clean=$(basename "$target")
    name_clean="${name_clean%.*}"

    # Typ: pdf|doc – bestimmt den Scanner-Plan
    local kind="pdf"
    if is_doc_ext "$target"; then
        kind="doc"
    fi

    echo "=============================================================="
    echo "SCAN: $name_clean  [${kind}]"
    echo "=============================================================="

    # ── Plan bestimmen (nur relevante Scanner ausführen) ─────────────────
    #   doc-Typ:  Scanner 4  (Text/DOCX)
    #   pdf-Typ:  Scanner 1+2+3 (oder --only-Untermenge)
    local want_text=0 want_image=0 want_injection=0 want_doc=0 stage=1
    case "$kind:$ONLY" in
        doc:all|doc:doc)      want_doc=1 ;;
        pdf:all)              want_text=1; want_image=1; want_injection=1; stage=3 ;;
        pdf:text)             want_text=1 ;;
        pdf:image)            want_image=1 ;;
        pdf:injection)        want_injection=1 ;;
        *)
            # Kombination aus --only und unpassendem Typ (z. B. --only text bei .txt).
            echo "  [!] Der gewaelte --only-Modus passt nicht zum Dateityp; wird trotzdem versucht."
            case "$ONLY" in
                text)      want_text=1 ;;
                image)     want_image=1 ;;
                injection) want_injection=1 ;;
                doc)       want_doc=1 ;;
            esac
            ;;
    esac

    local tmpdir
    tmpdir="$(mktemp -d)"
    local txt="$tmpdir/text.json" img="$tmpdir/image.json" inj="$tmpdir/inj.json" dco="$tmpdir/doc.json"

    local ran=()
    local rc_total=0 rc n=0
    [ "$want_text" -eq 1 ] && n=$((n+1))
    [ "$want_image" -eq 1 ] && n=$((n+1))
    [ "$want_injection" -eq 1 ] && n=$((n+1))
    [ "$want_doc" -eq 1 ] && n=$((n+1))
    local s=0

    if [ "$want_text" -eq 1 ]; then
        s=$((s+1)); echo -n "  [${s}/${n}] Text & Struktur ... "
        run_one "$target" text "$txt"; rc=$?
        echo " -> $(_rc_label $rc)"
        ran+=("text"); [ $rc -gt $rc_total ] && rc_total=$rc
    fi
    if [ "$want_image" -eq 1 ]; then
        s=$((s+1)); echo -n "  [${s}/${n}] Bilder & OCR ... "
        run_one "$target" image "$img"; rc=$?
        echo " -> $(_rc_label $rc)"
        ran+=("image"); [ $rc -gt $rc_total ] && rc_total=$rc
    fi
    if [ "$want_injection" -eq 1 ]; then
        s=$((s+1)); echo -n "  [${s}/${n}] Tiefenscan ... "
        run_one "$target" injection "$inj"; rc=$?
        echo " -> $(_rc_label $rc)"
        ran+=("injection"); [ $rc -gt $rc_total ] && rc_total=$rc
    fi
    if [ "$want_doc" -eq 1 ]; then
        s=$((s+1)); echo -n "  [${s}/${n}] Dokument (Text/DOCX) ... "
        run_one "$target" doc "$dco"; rc=$?
        echo " -> $(_rc_label $rc)"
        ran+=("doc"); [ $rc -gt $rc_total ] && rc_total=$rc
    fi

    # ── Konsolidierten Report aus den laufenden Quellen bauen ─────────────
    local src_args=()
    [[ "${ran[*]:-}" == *text* ]]      && [ -s "$txt" ] && src_args+=("--text" "$txt")
    [[ "${ran[*]:-}" == *image* ]]     && [ -s "$img" ] && src_args+=("--image" "$img")
    [[ "${ran[*]:-}" == *injection* ]] && [ -s "$inj" ] && src_args+=("--injection" "$inj")
    [[ "${ran[*]:-}" == *doc* ]]       && [ -s "$dco" ] && src_args+=("--doc" "$dco")

    if [ ${#src_args[@]} -gt 0 ]; then
        if [ "$FORMAT" = "json" ] || [ "$REPORT_JSON" -eq 1 ]; then
            echo
            echo "  --- Report (JSON) ---"
            $PYTHON merge_reports.py "${src_args[@]}" --format json
            echo
        else
            echo
            echo "  --- Report ---"
            $PYTHON merge_reports.py "${src_args[@]}" --format text
            echo
        fi
    fi

    rm -rf "$tmpdir" 2>/dev/null || true
    return $rc_total
}

# Kompatibilitaets-Alias (fruehere Funktionsbezeichnung)
scan_pdf() { scan_file "$@"; }

# ── Hauptlogik ─────────────────────────────────────────────────────────────
# Batch-Modus: alle unterstützten Erweiterungen (PDF + DOCX/TXT/MD)
if [ -n "$BATCH" ]; then
    if [ ! -d "$BATCH" ]; then echo "[FEHLER] Ordner nicht gefunden: $BATCH" >&2; exit 2; fi
    shopt -s nullglob nocaseglob
    files=(
        "$BATCH"/*.pdf
        "$BATCH"/*.docx
        "$BATCH"/*.txt
        "$BATCH"/*.md
        "$BATCH"/*.markdown
    )
    if [ ${#files[@]} -eq 0 ]; then
        echo "[WARNUNG] Keine PDF/DOCX/TXT/MD-Dateien in $BATCH" >&2; exit 2
    fi

    echo "=============================================================="
    echo "BATCH-MODUS: ${#files[@]} Datei(en) in $BATCH"
    echo "  (.pdf, .docx, .txt, .md, .markdown)"
    echo "=============================================================="

    worst=0
    for f in "${files[@]}"; do
        scan_file "$f"; rc=$?
        [ $rc -gt $worst ] && worst=$rc
        echo
    done
    echo "=============================================================="
    if [ $worst -eq 0 ]; then
        echo "GESAMTSTATUS: SAUBER"
    else
        echo "GESAMTSTATUS: ALARM (mindestens eine Datei mit Auffälligkeiten)"
    fi
    exit $worst
fi

# Einzeldatei-Modus
if [ -z "$PDF" ]; then
    echo "[FEHLER] Keine Datei angegeben. Nutzung: $0 <datei>  (.pdf/.docx/.txt/.md)" >&2
    exit 2
fi
if [ ! -f "$PDF" ]; then
    echo "[FEHLER] Die Datei '$PDF' wurde nicht gefunden." >&2
    exit 2
fi
if ! is_pdf_ext "$PDF" && ! is_doc_ext "$PDF"; then
    echo "[FEHLER] Nicht unterstützter Dateityp: '$(ext_of "$PDF")' (erlaubt: pdf, docx, txt, md, markdown)" >&2
    exit 2
fi

scan_file "$PDF"
RC=$?

echo "=============================================================="
if [ $RC -eq 0 ]; then
    echo "GESAMTSTATUS: SAUBER"
else
    echo "GESAMTSTATUS: ALARM / VORSICHT"
fi

exit $RC

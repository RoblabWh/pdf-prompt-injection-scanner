"""Gemeinsames Kern-Modul für alle PDF-Scanner.

Dies ist der EINZIGE Importpunkt, den Scanner 1 (Text/Metadaten),
Scanner 2 (Bild/OCR) und Scanner 3 (Tiefenscan) für Signatur-Muster und
Layout-Anomalie-Schwellen verwenden. Ziel: eine geteilte, versionierte
Signatur-DB und einheitliche Erkennungslogik, statt drei getrennten.

Inhalte:
  * MIN_TEXT_SIZE / LIGHT_TEXT_LUMINANCE  – einheitliche Layout-Schwellen
  * is_light_or_white()                   – einheitliche Helligkeitslogik (BT.709)
  * COMPILED_PATTERNS                     – (compiled_regex, label) für EN/DE/ZH
  * find_matches()                        – durchsucht einen Text nach allen Mustern
  * OCR_LANGS                             – verfügbare OCR-Sprachen (Graceful-Fallback)

Die CANONICAL-Muster stammen aus `prompt_patterns.py` (einfache Strings).
Zur Abdeckung wurden ergänzende (regex, label)-Tupel für Tag-Injektionen,
Modell-spezifische Prüfungen und erweiterte ZH-Gruppen hinzugefügt.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple

# ── Einheitliche Layout-Anomalie-Schwellen ───────────────────────────────────
# Diese zwei Werte gelten ALLEIN für Scanner 1 UND den Tiefenscan (früher:
# Scanner 1 = 2.5pt / Luminanz 200, Scanner 3 = 2.0pt / Kanal-Schwelle 0.9).
MIN_TEXT_SIZE = 2.0          # Punkt; kleiner gilt als "Mikroschrift"
LIGHT_TEXT_LUMINANCE = 200   # BT.709-Luminanz 0-255; ≥ gilt als "heller/weißer Text"


def is_light_or_white(color_int: int, threshold: int = LIGHT_TEXT_LUMINANCE) -> bool:
    """Wahrnehmungsnaher Helligkeitstest (ITU-R BT.709) für ein 24-Bit-RGB-Int.

    0xRRGGBB wird in R,G,B zerlegt; der gewichtete Luminanzwert bestimmt,
    ob der Text auf weißem Hintergrund (nahezu) unsichtbar ist.
    """
    r = (color_int >> 16) & 255
    g = (color_int >> 8) & 255
    b = color_int & 255
    luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b
    return luminance >= threshold


def luminance(color_int: int) -> int:
    r = (color_int >> 16) & 255
    g = (color_int >> 8) & 255
    b = color_int & 255
    return int(0.2126 * r + 0.7152 * g + 0.0722 * b)


def is_light_rgb_triple(rgb, threshold: int = LIGHT_TEXT_LUMINANCE) -> bool:
    """BT.709-Prüfung für 0-1-normierte RGB-Triples (pdfplumber-Format).

    `rgb` darf ein einzelner Float (Graustufen) oder ein (r,g,b)/
    (c,m,y,k)-Liste sein. CMYK wird nach sRGB approx. umgerechnet.
    """
    if rgb is None:
        return False
    if isinstance(rgb, (int, float)):
        lum01 = float(rgb)
    elif isinstance(rgb, (list, tuple)):
        if len(rgb) == 1:
            lum01 = float(rgb[0])
        elif len(rgb) == 3:
            lum01 = 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2]
        elif len(rgb) == 4:
            c, m, y, k = rgb
            r = (1 - c) * (1 - k)
            g = (1 - m) * (1 - k)
            b = (1 - y) * (1 - k)
            lum01 = 0.2126 * r + 0.7152 * g + 0.0722 * b
        else:
            return False
    else:
        return False
    return lum01 * 255 >= threshold


# ── Strukturanomalien: Versteck-/Evasions-Techniken (ohne Regex) ───────
# Techniken, die Signatur-Matches umgehen: unsichtbare Zeichen
# (cf. garak probes.badchars), Bidirectional-Overrides (Bidi-Attacken),
# Steuerzeichen und sehr lange Base64/Hex-artige Token-Läufe
# (cf. garak probes.encoding, OWASP LLM01-Invisible-Content).
INVISIBLE_CHAR_NAMES = {
    0x200B: "Zero-Width Space",
    0x200C: "Zero-Width Non-Joiner",
    0x200D: "Zero-Width Joiner",
    0x2060: "Word Joiner",
    0xFEFF: "BOM / Zero-Width No-Break Space",
    0x00AD: "Soft Hyphen",
    0x180E: "Mongolian Vowel Separator",
    0x034F: "Combining Grapheme Joiner",
    0x200E: "Left-to-Right Mark",
    0x200F: "Right-to-Left Mark",
}
BIDI_OVERRIDE_CHARS = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E}

# ── Sprach-Kontextsignal ──────────────────────────────────────────────────────
# Injizierte Anweisungen stehen i. d. R. auf Englisch (LLM-"Lingua franca")
# ODER in der Sprache des Dokuments (hier: Deutsch). Text in einer Unerwarteten
# Sprache (FR, AR, ZH, …) ist ein Hinweis auf versteckten Fremdttext – und in
# Kombination mit weißer/zu kleiner Schrift im selben Span ein starkes Zeichen
# aktiver Versteckung (deshalb Eskalation auf "high").
EXPECTED_LANGS = {"en", "de"}
MIN_LANG_TEXT_CHARS = 20    # isolierte Tokens / kurze Begriffe (z. B. "Projektstatus")
                             # liefern bei langdetect unsinnige Ergebnisse (lt/et);
                             # echte fremdsprachige Anweisungen sind immer Sätze.
_LANG_NAMES = {
    "en": "Englisch", "de": "Deutsch", "fr": "Französisch", "es": "Spanisch",
    "it": "Italienisch", "pt": "Portugiesisch", "nl": "Niederländisch",
    "ru": "Russisch", "zh-cn": "Chinesisch (Vereinfacht)",
    "zh-tw": "Chinesisch (Traditionell)", "ja": "Japanisch", "ko": "Koreanisch",
    "ar": "Arabisch", "tr": "Türkisch", "pl": "Polnisch", "sv": "Schwedisch",
    "da": "Dänisch", "no": "Norwegisch", "fi": "Finnisch", "hu": "Ungarisch",
    "ro": "Rumänisch", "cs": "Tschechisch", "el": "Griechisch",
    "he": "Hebräisch", "th": "Thailändisch", "vi": "Vietnamesisch",
    "id": "Indonesisch", "ms": "Malaiisch", "fa": "Persisch", "ur": "Urdu",
    "hi": "Hindi", "bn": "Bengalisch", "ta": "Tamilisch", "sw": "Swahili",
}


def detect_langs(text):
    """[(Code, Konfidenz)] der erkannten Sprachen, leere Liste bei
    Nicht-Erkennung, zu kurzem Input oder fehlender liblangdetect."""
    if len(text.strip()) < MIN_LANG_TEXT_CHARS:
        return []
    try:
        from langdetect import detect_langs as _dl
    except ImportError:
        return []
    try:
        info = _dl(text)
        items = [info] if isinstance(info, object) and not isinstance(info, (list, tuple)) else list(info)
        out = []
        for it in items:
            try:
                code = str(getattr(it, "lang") or getattr(it, "code") or it)
            except Exception:
                code = str(it)[:2]
            try:
                conf = float(getattr(it, "prob", 0.0) or 0.0)
            except Exception:
                conf = 0.0
            # Nur bei klarer Erkennung vertrauen (langdetect rät gern).
            if code and conf > 0.5:
                out.append((code, conf))
        return out
    except Exception:
        return []


def unexpected_langs(text):
    """Codes erkannter Sprachen, die nicht zu EN/DE gehören."""
    return [c for c, _ in detect_langs(text) if c not in EXPECTED_LANGS]


def lang_label(code):
    return _LANG_NAMES.get(code, code)


def language_finding(text, visual_note=""):
    """
    Sprach-Kontextsignal:
      - unerwartete Sprache (nicht EN/DE)          -> medium
      - PLUS weiße/zu kleine Schrift im selben Span -> high
    """
    codes = unexpected_langs(text)
    if not codes:
        return None
    desc = " + ".join(lang_label(c) for c in codes)
    if visual_note:
        return {
            "severity": "high",
            "description": ("Ausländischer Text ({d}) in Verbindung mit {v} "
                            "– starkes Versteckungs-Zeichen").format(d=desc, v=visual_note),
        }
    return {
        "severity": "medium",
        "description": ("Text in unerwarteter Sprache ({d}) "
                        "– erwartete Dokument-Sprachen sind EN/DE").format(d=desc),
    }


def _visible_snippet(text, idx, context=25):
    """Zeigt einen Text-Schnipsel mit gekennzeichneten unsichtbaren Zeichen."""
    lo = max(0, idx - context)
    hi = min(len(text), idx + context)
    out = []
    for ch in text[lo:hi]:
        cp = ord(ch)
        if cp in INVISIBLE_CHAR_NAMES:
            out.append("[" + INVISIBLE_CHAR_NAMES[cp] + "]")
        elif cp in BIDI_OVERRIDE_CHARS:
            out.append("[BIDI U+%04X]" % cp)
        elif cp < 32 and ch not in "\t\n\r":
            out.append("[CTL U+%04X]" % cp)
        else:
            out.append(ch)
    return "".join(out).strip()


def find_text_anomalies(text):
    """Erkennt Evasions-Techniken in einem Text (kein Regextreffer nötig).

    Liefert eine Liste von Dicts mit den Schlüsseln:
      type, severity ("high"/"medium"), description, snippet.
    """
    if not text:
        return []
    out = []
    seen = set()

    def add(severity, description, snippet):
        key = (description, snippet)
        if key in seen:
            return
        seen.add(key)
        out.append({
            "type": "Text-Anomalie",
            "severity": severity,
            "description": description,
            "snippet": snippet,
        })

    for idx, ch in enumerate(text):
        cp = ord(ch)
        if cp in INVISIBLE_CHAR_NAMES:
            add("high",
                "Invisible Character (Evasions-Technik, cf. garak badchars) – "
                + INVISIBLE_CHAR_NAMES[cp],
                _visible_snippet(text, idx))
        elif cp in BIDI_OVERRIDE_CHARS:
            add("high",
                "Bidirectional Override (visuelle Verschleierung von Code/URLs)",
                _visible_snippet(text, idx))
        elif cp < 32 and ch not in "\t\n\r":
            add("medium",
                "Verdächtiges Steuerzeichen",
                _visible_snippet(text, idx))

    m = re.search(r"[A-Za-z0-9+/=]{80,}", text)
    if m:
        add("medium",
            "Sehr langer Base64/Hex-artiger Lauf (möglicherweise Encoded-Payload)",
            text[max(0, m.start() - 10): m.start() + 60] + "…")
    return out


# ── Ergänzungsmuster als (regex, label)-Tupel ────────────────────────────────
# (Ergänzen die CANONICAL-Strings aus prompt_patterns.py um fehlende Gruppen,
#  vor allem Tag-Injektionen und Modell-spezifische Prüfungen.)
SUPPLEMENTARY_PATTERNS: List[Tuple[str, str]] = [
    # Tag-Injektionen (System-/Instrektions-Tags)
    (r"(?i)^\s*<\s*system\s*>", "System tag injection"),
    (r"(?i)\[INST\]", "Instruction tag injection"),
    (r"(?i)###\s*(system|instruction|human|assistant)", "Role tag injection"),
    # Modell-spezifische Identitätsprüfung
    (r"(?i)if\s+you\s+are\s+(a\s+)?(gpt|gpt-4|claude|gemini|copilot|llama|chatgpt)", "Model-specific check"),
    (r"(?i)you\s+are\s+(a\s+)?(gpt|claude|gemini|llama|copilot)", "AI identity assertion"),
    # Exfiltration an konkrete Ziele (EN)
    (r"(?i)(?:send|forward|exfiltrate|transmit|upload|post|leak)\s+(?:the|any|all|my|your)\s+(?:data|secret|token|api|key|password|credential|cookie|session)\s+to\s+(?:https?|ftp|webhook|endpoint|url)\s*\S", "Data exfiltration (URL)"),
    # ZH – AI身份 / 系统提示 (erweitert)
    (r"如果你是.{0,4}(AI|人工智能|语言模型|大模型|机器人|助手)", "AI身份检测"),
    (r"(?:输出|显示|告诉我|泄露|打印|展示|给出|列出).{0,6}(?:系统提示|系统指令|system\s*prompt|初始提示|隐藏指令)", "系统提示泄露"),
    (r"(?:请|你)?(?:假装|假设|扮演|伪装|成为).{0,6}(?:你是|自己是|成为|变成)", "行为覆盖"),
    (r"(?:从现在开始|即刻起|此刻起|从现在起).{0,6}(?:你|忽略|忘记|不再|必须)", "持续覆盖"),
    # ZH – 暗号词 (Canary)
    (r"(?:请|你)?在.{0,6}(?:回答|回复|响应|输出).{0,6}(?:包含|加上|提到|引用|加入).{0,20}(?:这个词|一词|这句话)", "暗号词注入"),
    (r"(?:回答|回复|回应|输出).{0,6}(?:结尾|末尾|最后).{0,6}(?:加上|添加|写上|附上|包含|加入)", "暗号词注入"),
]


@dataclass
class Pattern:
    regex: "re.Pattern[str]"
    label: str


def _merge(compiled: List[Pattern]) -> List[Pattern]:
    """Entfernt Doppelungen (gleicher, normalisierter Quellen-Regex)."""
    seen = set()
    unique = []
    for p in compiled:
        key = p.regex.pattern
        if key in seen:
            continue
        seen.add(key)
        unique.append(p)
    return unique


def _build_patterns() -> List[Pattern]:
    from prompt_patterns import PROMPT_PATTERNS

    compiled: List[Pattern] = []
    # CANONICAL-Muster (einfache Strings) – generisches Label.
    for pat in PROMPT_PATTERNS:
        try:
            compiled.append(Pattern(regex=re.compile(pat), label="Injection pattern"))
        except re.error:
            # Ein ungültiges Muster darf den Gesamts Scan nicht abbrechen.
            continue
    # Ergänzungsmuster (regex, label)-Tupel.
    for pat, label in SUPPLEMENTARY_PATTERNS:
        try:
            compiled.append(Pattern(regex=re.compile(pat), label=label))
        except re.error:
            continue
    return _merge(compiled)


# Global kompiliert (einmalig beim Import). Alle Scanner nutzen diese Liste.
COMPILED_PATTERNS: List[Pattern] = _build_patterns()


def find_matches(text: str) -> List[Tuple[str, str]]:
    """Gibt (label, matched_text) für jede Trefferstelle aller Muster zurück."""
    if not text:
        return []
    hits: List[Tuple[str, str]] = []
    for p in COMPILED_PATTERNS:
        for m in p.regex.finditer(text):
            hits.append((p.label, m.group(0)))
    return hits


def find_matches_with_positions(
    text: str, context: int = 40
) -> List[Tuple[str, str, int, int]]:
    """Gibt (label, matched_text, start, end) für jede Stelle zurück."""
    if not text:
        return []
    hits: List[Tuple[str, str, int, int]] = []
    for p in COMPILED_PATTERNS:
        for m in p.regex.finditer(text):
            hits.append((p.label, m.group(0), m.start(), m.end()))
    return sorted(hits, key=lambda h: h[2])


def count_matches(text: str) -> int:
    return len(find_matches(text))

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

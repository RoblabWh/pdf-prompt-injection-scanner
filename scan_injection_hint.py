import json
import re
import sys


def _try_decode(text, index):
    """Versucht, an `index` gültiges JSON zu parsen; nur Ergebnis-Blöcke."""
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[index:])
    except json.JSONDecodeError:
        return None
    if isinstance(obj, dict):
        fs = obj.get("findings")
        if isinstance(fs, list) and (not fs or all(isinstance(f, dict) for f in fs)):
            return fs
        return None
    if isinstance(obj, list) and (not obj or all(isinstance(f, dict) for f in obj)):
        return obj
    return None


def load_findings(stream):
    """Extrahiert das Ergebnis-JSON ({"clean":..,"findings":[..]} oder [..])
    aus einem Stream, der zusätzlich Konsolen-Output enthält.
    Von hinten nach vorne suchen, da der JSON-Block am Ende des Logs liegt."""
    text = stream.read()
    candidates = [m.start() for m in re.finditer(r"[\[{]", text)]
    for i in reversed(candidates):
        result = _try_decode(text, i)
        if result is not None:
            return result
    return []


SEVERITY_COLORS = {"high": "red", "medium": "yellow", "low": "blue"}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def render(findings, title="Result"):
    """Gibt die Treffer als Rich-Tabelle aus (wie der pdf_injection_scanner)."""
    try:
        from rich.console import Console
        from rich.markup import escape
        from rich.panel import Panel
        from rich.table import Table
    except ImportError:
        # Fallback, falls Rich fehlt: einfache Texttabelle.
        _render_plain(findings)
        return

    console = Console()
    high = sum(1 for f in findings if f.get("severity") == "high")
    med = sum(1 for f in findings if f.get("severity") == "medium")
    low = sum(1 for f in findings if f.get("severity") == "low")

    summary = f"[bold red]{len(findings)} potential injection(s)[/bold red]"
    if high:
        summary += f"  [red]({high} high)[/red]"
    if med:
        summary += f"  [yellow]({med} medium)[/yellow]"
    if low:
        summary += f"  [blue]({low} low)[/blue]"
    console.print(Panel(summary, title=title))

    table = Table(show_header=True, header_style="bold")
    table.add_column("#", width=3, justify="right")
    table.add_column("Page", width=5, justify="center")
    table.add_column("Severity", width=8, justify="center")
    table.add_column("Type", width=22)
    table.add_column("Content", max_width=60)

    ordered = sorted(
        findings,
        key=lambda f: (f.get("page", 0), SEVERITY_ORDER.get(f.get("severity"), 9)),
    )
    for i, f in enumerate(ordered, 1):
        sev = f.get("severity") or "low"
        color = SEVERITY_COLORS.get(sev, "white")
        content = f.get("content", "")
        preview = content[:100] + ("..." if len(content) > 100 else "")
        table.add_row(
            str(i),
            str(f.get("page", "?")),
            f"[{color}]{sev.upper()}[/{color}]",
            escape(f.get("type", "?")),
            escape(preview),
        )
    console.print(table)


def _render_plain(findings):
    """Einfache Texttabelle ohne Rich."""
    print(f"{'#':>3} | {'Page':>5} | {'Severity':<8} | {'Type':<22} | Content")
    print("-" * 78)
    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "?").upper()
        preview = f.get("content", "")[:60]
        print(f"{i:>3} | {f.get('page', '?'):>5} | {sev:<8} | {f.get('type', '?'):<22} | {preview}")


def main():
    title = "Result"
    argv = sys.argv[1:]
    if argv and argv[0] == "--title":
        title = argv[1]
        argv = argv[2:]

    findings = load_findings(sys.stdin)
    if not findings:
        return 0
    render(findings, title=title)
    return 2


if __name__ == "__main__":
    sys.exit(main())

"""
output/renderer.py - Rich TUI renderer for ArCHie Analyzer.

Handles:
  - Per-source results table (SOURCE | VERDICT | KEY FINDINGS)
  - Verdict box (always shown, lists agreeing sources + errors)
  - Bulk summary table
  - Startup banners (random ASCII art on each run)
"""

import random

from rich.console import Console
from rich.table   import Table
from rich.panel   import Panel
from rich.text    import Text
from rich         import box

console = Console(legacy_windows=False)

# --- Verdict colour + emoji mapping ------------------------------------------

_TUI_VERDICT = {
    "malicious":  "[!] MALICIOUS",
    "suspicious": "[~] SUSPICIOUS",
    "clean":      "[+] CLEAN",
    "not_found":  "[?] NOT FOUND",
    "skipped":    "[-] NO KEY",
    "info":       "[i] INFO",
    "error":      "[x] ERROR",
    "unknown":    "[?] UNKNOWN",
}

_VERDICT_COLOR = {
    "malicious":  "red1",
    "suspicious": "yellow1",
    "clean":      "bright_green",
    "not_found":  "cyan",
    "skipped":    "yellow1",
    "info":       "cyan",
    "error":      "red1",
    "unknown":    "dim",
}

# --- ASCII Banners (random on startup) ----------------------------------------

_ASCII_BANNERS = [
    # 1: Big letter A - clean slash-art
    r"""
      /\                 
     /  \           ArCHie  Analyzer
    / /\ \   -----------------------------
   / /  \ \   Threat Intelligence  *  v4.0
  /_/    \_\   IOC  |  Hash  |  IP  |  CVE""",

    # 2: Scan-line / matrix style
    r"""
  > INITIALIZING THREAT INTEL ENGINE...
  +--------------------------------------+
  |  A r C H i e   A n a l y z e r       |
  |  Threat Intelligence  CLI  v4.0      |
  |  IOC  .  Hash  .  Domain  .  CVE     |
  +--------------------------------------+
  > MODULES LOADED. READY.""",

    # 3: Big letter A - filled hash block
    r"""
       ###            ArCHie  Analyzer
      ####    ----------------------------------
     ##  ##
    #######     Threat Intelligence  *  v4.0
   ##     ##    IOC  .  Hash  .  Domain  .  CVE
  ##       ##""",
]


# --- Banner -------------------------------------------------------------------

def print_banner():
    art  = random.choice(_ASCII_BANNERS)
    text = Text()
    text.append(art, style="bold bright_white")
    text.append("\n  by Akshar  ", style="color(61)")
    text.append("v4.0", style="medium_purple1")
    text.append("  --  Threat Intel CLI", style="color(61)")
    console.print(text)
    console.print()
    console.print("  [color(61)]ArCHie Analyzer -- Made with [/color(61)][bold red]\u2764\ufe0f[/bold red][color(61)] by Akshar[/color(61)]\n")


# --- IOC Header ---------------------------------------------------------------

def print_ioc_header(ioc):
    console.print(f"  [bold white]IOC  [/bold white][dim]>>[/dim] [white]{ioc.value}[/white]")
    console.print(f"  [bold white]TYPE [/bold white][dim]>>[/dim] [white]{ioc.display_label}[/white]")
    console.print()


# --- Results Table ------------------------------------------------------------

_IOC_NOUN: dict[str, str] = {
    "ipv4":     "IP address",
    "domain":   "domain",
    "url":       "URL",
    "md5":      "file",
    "sha1":     "file",
    "sha256":   "file",
    "email":    "email address",
    "cve":      "CVE",
    "filepath": "file path",
}


def _is_url_value(v: str) -> bool:
    """Return True if a value is a plain URL."""
    return isinstance(v, str) and (v.startswith("http://") or v.startswith("https://"))


def _format_data(data: dict, ioc_type: str = "", verdict: str = "") -> str:
    """
    Flatten data dict into a readable pipe-separated string.

    Special handling for the 'detections' field (VirusTotal-style):
      "4/94"  â†’  "4/94 security vendors flagged this IP address as malicious"

    - Skips raw URL-only values (report links, screenshots, etc.)
    - Caps each individual value at 65 chars to prevent table overflow
    """
    if not data:
        return "-"

    parts: list[str] = []

    # VT-style detection count - must come first and be formatted specially
    detections = data.get("detections")
    if detections and isinstance(detections, str) and "/" in detections:
        noun = _IOC_NOUN.get(ioc_type, "indicator")
        parts.append(f"{detections} security vendors flagged this {noun} as malicious")

    for k, v in data.items():
        if k == "detections":
            continue          # already handled above
        sv = str(v)
        if not sv or sv == "-" or _is_url_value(sv):
            continue
        if len(sv) > 65:
            sv = sv[:62] + "..."
        parts.append(sv)

    return "  |  ".join(parts[:4]) if parts else "-"


def print_results_table(results: list, ioc_type: str = ""):
    table = Table(
        box=box.ROUNDED,
        border_style="color(54)",
        header_style="bold bright_white on grey11",
        show_lines=True,
    )
    table.add_column("SOURCE",       style="white",  no_wrap=True)
    table.add_column("VERDICT",      no_wrap=True)
    table.add_column("KEY FINDINGS", style="white",  max_width=80)

    for r in results:
        v        = r.get("verdict", "unknown")
        color    = _VERDICT_COLOR.get(v) or "white"
        label    = _TUI_VERDICT.get(v) or v.upper()
        findings = _format_data(r.get("data", {}), ioc_type=ioc_type, verdict=v)
        if r.get("error") and v == "error":
            findings = r["error"][:80]

        table.add_row(
            r.get("source", "?"),
            Text(label, style=f"bold {color}"),
            findings,
        )

    console.print(table)
    console.print()


# --- Verdict Box -------------------------------------------------------------

def _compute_verdict(results: list) -> dict:
    """
    Determine overall verdict from all results.

    Verdict rules (analyst-friendly):
      MALICIOUS  â†’ ANY source says malicious
      SUSPICIOUS â†’ ANY source says suspicious (and none say malicious)
      CLEAN      â†’ ALL actionable sources say clean / not_found
      UNKNOWN    â†’ No actionable sources returned data

    Sources with verdict "skipped", "error", "info", or "unknown" are NOT
    counted as actionable (they didn't contribute a threat signal).
    """
    malicious_sources  = []
    suspicious_sources = []
    clean_sources      = []
    error_parts        = []
    total_actionable   = 0

    for r in results:
        v   = r.get("verdict", "unknown")
        src = r.get("source", "?")
        err = r.get("error")

        if v == "skipped":
            error_parts.append(f"{src} (No API key)")
            continue
        if v == "error":
            reason = err or "Unknown error"
            error_parts.append(f"{src} ({reason[:40]})")
            continue
        if v == "info":
            continue
        if v == "unknown":
            continue

        total_actionable += 1

        if v == "malicious":
            malicious_sources.append(src)
        elif v == "suspicious":
            suspicious_sources.append(src)
        elif v in ("clean", "not_found"):
            clean_sources.append(src)

    # -- Verdict decision -----------------------------------------------------
    if malicious_sources:
        verdict = "malicious"
        agreed  = malicious_sources
        count   = f"{len(malicious_sources)} of {total_actionable}"

    elif suspicious_sources:
        verdict = "suspicious"
        agreed  = suspicious_sources
        count   = f"{len(suspicious_sources)} of {total_actionable}"

    elif total_actionable == 0:
        verdict = "unknown"
        agreed  = []
        count   = "0"

    else:
        verdict = "clean"
        agreed  = clean_sources
        count   = f"{len(agreed)} of {total_actionable}"

    return {
        "verdict": verdict,
        "agreed":  agreed,
        "count":   count,
        "errors":  error_parts,
    }


def print_verdict_box(results: list):
    info    = _compute_verdict(results)
    v       = info["verdict"]
    color   = _VERDICT_COLOR.get(v, "white")
    label   = _TUI_VERDICT.get(v, v.upper())

    lines = Text()

    # Line 1: VERDICT
    lines.append(f"  {label}   ", style=f"bold {color}")
    lines.append(f"({info['count']} sources agree)\n", style="white")

    # Line 2: Agreed / Flagged by
    if info["agreed"]:
        flag_word = "Flagged" if v in ("malicious", "suspicious") else "Agreed"
        lines.append(f"  {flag_word:8}: ", style="color(55)")
        lines.append(", ".join(info["agreed"]) + "\n", style=f"bold {color}")

    # Line 3+: Errors / skipped sources
    if info["errors"]:
        err_str = ", ".join(info["errors"])
        lines.append(f"  {'Errors':8}: ", style="color(55)")
        lines.append(err_str + "\n", style="yellow1")

    console.print(Panel(
        lines,
        border_style=color,
        title="[bold color(55)]// VERDICT[/bold color(55)]",
        title_align="left",
        box=box.ROUNDED,
        padding=(0, 1),
    ))
    console.print()

    return v  # returned for bulk summary


# --- Bulk Summary Table -------------------------------------------------------

def print_bulk_summary(rows: list):
    """
    rows: list of (index, ioc_value, ioc_type_label, verdict_str, top_hit)
    """
    console.print()
    table = Table(
        box=box.ROUNDED,
        border_style="color(54)",
        header_style="bold bright_white on grey11",
        show_lines=True,
    )
    table.add_column("#",        width=4,  style="dim white")
    table.add_column("IOC",      width=36, no_wrap=True, style="white")
    table.add_column("TYPE",     width=14, style="white")
    table.add_column("VERDICT",  width=18)
    table.add_column("TOP HIT",  width=20, style="dim white")

    counts = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}

    for idx, ioc_value, ioc_type, verdict, top_hit in rows:
        color  = _VERDICT_COLOR.get(verdict) or "white"
        label  = _TUI_VERDICT.get(verdict) or verdict.upper()
        counts[verdict] = counts.get(verdict, 0) + 1
        display_ioc = ioc_value if len(ioc_value) <= 36 else ioc_value[:33] + "..."
        table.add_row(
            str(idx),
            display_ioc,
            ioc_type,
            Text(label, style=f"bold {color}"),
            top_hit,
        )

    console.print(table)
    console.print(
        f"\n  [bold]Summary:[/bold]  "
        f"[red1]{counts.get('malicious', 0)} Malicious[/red1]  |  "
        f"[yellow1]{counts.get('suspicious', 0)} Suspicious[/yellow1]  |  "
        f"[bright_green]{counts.get('clean', 0)} Clean[/bright_green]  |  "
        f"[dim]{counts.get('unknown', 0)} Unknown[/dim]\n"
    )


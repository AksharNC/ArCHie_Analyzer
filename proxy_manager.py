"""
proxy_manager.py — Self-contained Java proxy lifecycle for ArCHie Analyzer.

On tool start  → compiles SimpleProxy.java (once), spawns java SimpleProxy on port 8888
On tool exit   → kills the java process automatically (via atexit)

Routes outbound HTTPS requests through a local Java tunnel, which can help
work around network-level URL restrictions in corporate environments.
Note: proxy effectiveness depends on the specific restrictions in place and
may not bypass all filtering systems.
"""

import atexit
import socket
import subprocess
import time
from pathlib import Path

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8888

_TOOL_DIR      = Path(__file__).parent
_PROXY_DIR     = _TOOL_DIR / "proxy"   # SimpleProxy.java/.class live here
_proxy_process = None


# ─── Private Helpers ──────────────────────────────────────────────────────────

def _port_open(timeout: float = 1.0) -> bool:
    """Return True if something is already listening on port 8888."""
    try:
        with socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=timeout):
            return True
    except (ConnectionRefusedError, OSError):
        return False


def _kill_proxy():
    """atexit handler — always kill the proxy on tool exit (clean or Ctrl+C)."""
    global _proxy_process
    if _proxy_process and _proxy_process.poll() is None:
        _proxy_process.terminate()
        try:
            _proxy_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _proxy_process.kill()
        _proxy_process = None


def _java_available() -> bool:
    """Check that java is on PATH."""
    try:
        r = subprocess.run(["java", "-version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _compile_if_needed(console) -> bool:
    """Compile SimpleProxy.java → SimpleProxy.class if not already compiled."""
    class_file = _PROXY_DIR / "SimpleProxy.class"
    java_file  = _PROXY_DIR / "SimpleProxy.java"

    if class_file.exists():
        return True

    console.print("[cyan]  [*] Compiling proxy (first run only)...[/cyan]")
    result = subprocess.run(
        ["javac", str(java_file)],
        cwd=str(_PROXY_DIR),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        console.print(f"[red]  [x] Compile failed:[/red] {result.stderr.strip()}")
        return False
    return True


# ─── Public API ───────────────────────────────────────────────────────────────

def start(console=None) -> dict:
    """
    Start the embedded Java proxy (if not already running).

    Args:
        console: rich Console instance for status output (optional)

    Returns:
        {
          "running": bool,
          "proxies": {"http": ..., "https": ...},
          "message": str
        }
    """
    global _proxy_process

    def log(msg):
        if console:
            console.print(msg)

    # 1. Java available?
    if not _java_available():
        log("[yellow]  [!] Java not found -- running without proxy. Some URLs may be restricted.[/yellow]")
        return {"running": False, "proxies": {}, "message": "Java not found"}

    # 2. Already running on port 8888?
    if _port_open():
        log(f"[green]  ✅ Proxy already live on port {PROXY_PORT}[/green]")
        return _success()

    # 3. Compile if needed
    if not _compile_if_needed(console):
        return {"running": False, "proxies": {}, "message": "Compile failed"}

    # 4. Launch
    log(f"[cyan]  🚀 Starting ArCHie proxy on port {PROXY_PORT}...[/cyan]")
    _proxy_process = subprocess.Popen(
        ["java", "SimpleProxy"],
        cwd=str(_PROXY_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    atexit.register(_kill_proxy)

    # 5. Wait up to 5s for it to bind
    for _ in range(10):
        time.sleep(0.5)
        if _port_open():
            log(f"[green]  ✅ Proxy live on port {PROXY_PORT}[/green]")
            return _success()

    log("[yellow]  [!] Proxy took too long to start -- running without it.[/yellow]")
    return {"running": False, "proxies": {}, "message": "Timeout"}


def stop():
    """Manually stop the proxy (also triggered automatically on exit)."""
    _kill_proxy()


def _success() -> dict:
    proxies = {
        "http":  f"http://{PROXY_HOST}:{PROXY_PORT}",
        "https": f"http://{PROXY_HOST}:{PROXY_PORT}",
    }
    return {"running": True, "proxies": proxies, "message": "OK"}

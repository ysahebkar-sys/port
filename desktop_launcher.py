#!/usr/bin/env python3
"""Desktop launcher for the local Config Port Tester.

Starts the existing FastAPI application on loopback only and opens it in a
native pywebview window. No VPN/proxy tunnel is created by this launcher.
"""
from __future__ import annotations

import os
import socket
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _app_dir() -> Path:
    # PyInstaller one-file extracts bundled files into _MEIPASS.
    if getattr(__import__("sys"), "frozen", False):
        return Path(getattr(__import__("sys"), "_MEIPASS"))
    return Path(__file__).resolve().parent


def main() -> None:
    os.chdir(_app_dir())
    os.environ.setdefault("MAX_TARGETS", "20000")
    os.environ.setdefault("MAX_CIDR_PREFIX", "16")
    os.environ.setdefault("CONNECT_TIMEOUT", "4")
    os.environ.setdefault("MAX_CONCURRENCY", "100")

    port = _find_free_port()
    os.environ["PORT"] = str(port)
    os.environ["HOST"] = "127.0.0.1"

    import main as server_app

    config = uvicorn.Config(
        server_app.app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}/"
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("Local application failed to start.")

    try:
        import webview
        window = webview.create_window(
            "Config Port Tester",
            url,
            width=1280,
            height=860,
            min_size=(900, 620),
            resizable=True,
        )
        webview.start(debug=False)
    except ImportError:
        # Development fallback only. Packaged builds include pywebview.
        webbrowser.open(url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    finally:
        server.should_exit = True


if __name__ == "__main__":
    main()

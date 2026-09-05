#!/bin/sh
set -eu
cd "$(dirname "$0")"
python3 -m pip install -r requirements-desktop.txt
python3 desktop_launcher.py

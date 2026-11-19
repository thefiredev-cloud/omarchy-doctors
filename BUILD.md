# Build guide: omarchy-doctors

## Requirements

- Python 3. Nothing to install.
- An Omarchy desktop for live runs. The tests need no session: they use fixtures and stubs.

## Run the tests

```bash
./scripts/test.sh
```

This runs `python3 -m unittest discover -s tests` inside each tool folder. Expected counts: display-doctor 23, input-doctor 42, bar-plugin-audit 15, qs-crash-digest 17.

## display-doctor

```bash
./display-doctor/display-doctor          # text report
./display-doctor/display-doctor --json   # machine readable
```

Reads:

1. `hyprctl monitors all -j`: current mode against the best `availableModes` entry (highest refresh at the native size), scale and VRR.
2. `hyprctl getoption`: animations, blur, shadow, `misc:vrr`.
3. `/sys/class/drm/card*/device/gpu_busy_percent` (3 samples) and the card that owns each monitor connector.
4. Directories in `$XDG_RUNTIME_DIR/hypr`. A directory is stale when its `.socket.sock` is missing or refuses a connection.

Findings are ranked by severity (high, medium, low, info) plus a small bonus for size. Exit code 0 means Hyprland answered. Exit code 1 means no live instance was found. The JSON still prints, with `errors`.

## input-doctor

```bash
./input-doctor/input-doctor                          # text table, fix hint under every non-pass row
./input-doctor/input-doctor --json                   # same checks as JSON, exit 0 once every check ran
./input-doctor/input-doctor --strict                 # exit 1 if any check fails
./input-doctor/input-doctor --expect-tilt-screenshot # require wheel-tilt screenshot binds
```

Checks: `hypr.signature`, `voxtype.service`, `voxtype.display`, `voxtype.hotkey`, `device.keyboard`, `device.mouse`, `binds.screenshot`, `binds.tilt`, `screenshot.scripts`, `tool.wtype`, `tool.ydotool`, `tool.ydotoold`, `clipboard.types`.

It never injects keys, never calls `hyprctl keyword`, `dispatch` or `reload`, and never restarts a service. `voxtype.display` compares the Voxtype daemon's own signature with the live one. A daemon started under an old compositor logs "Error reading events from display: Broken pipe". The bare Alt tap is a Lua raw-key handler, so `hyprctl binds -j` does not list it.

## bar-plugin-audit

```bash
python3 bar-plugin-audit/bar_plugin_audit.py [--json] [--all] [--no-crashes] [--no-qml]
```

Reads `~/.config/omarchy/plugins`, `~/.config/omarchy/shell.json`, stock manifests under `/usr/share/omarchy/shell/plugins` and `~/.cache/quickshell/crashes`. It never writes to them. The QML hazard scan checks every plugin that is in the bar layout or enabled for five patterns: unqualified `Color.popups` or `Color.notifications`, layer effects (crash on window scale change), unguarded `root.bar.foreground` theme reads (null during bar rebuilds), unguarded deferred `root.` calls, and `height: visible ? implicitHeight : 0` binding loops.

## qs-crash-digest

```bash
python3 qs-crash-digest/qs_crash_digest.py            # table, sorted by count
python3 qs-crash-digest/qs_crash_digest.py --json
python3 qs-crash-digest/qs_crash_digest.py --since 24 # reports from the last 24 hours
python3 qs-crash-digest/qs_crash_digest.py --dir PATH # default ~/.cache/quickshell/crashes
```

Input: every `<dir>/<run>/report.txt` plus a loose `<dir>/report.txt`, each with its `log.qslog.log`. Each crash gets a time (modification time of `report.txt`), a signal, a top frame (first symbolized frame that is not libc, libstdc++, jemalloc or libffi plumbing) and a last plugin (the id in the last `plugins/<id>/` path in the last 256 KB of the log; `(core)` marks stock plugins). Groups are keyed by signal, top frame and last plugin.

## Layout

```text
display-doctor/      display-doctor, display_doctor.py, tests/
input-doctor/        input-doctor, input_doctor.py, tests/
bar-plugin-audit/    bar_plugin_audit.py, tests/
qs-crash-digest/     qs_crash_digest.py, tests/ (two redacted real crash reports)
scripts/test.sh      runs all four test suites
docs/architecture.svg
```

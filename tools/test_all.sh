#!/bin/bash
# Runs the whole nornNET test suite and prints one line per result: host tests, then
# every apps/nn* in Espressif's QEMU and on an ESP32 board if its serial port exists.
# Exit code 1 if anything failed. SKIP (test_tap without a TAP interface) is not a
# failure.
#
#   NORNOS=../nornCore      the nornCore (kernel) checkout
#   APPS="nn01"             subset of test applications (default: all apps/nn*)
#   ESP_PORT=/dev/ttyUSB0   board serial port; skipped when absent. ESP_PORT= disables.
#                           Apps with NN_SLIP = BAUD in app.mk talk SLIP on that port
#                           through tools/slip_bridge.py and the TAP nn0 (SKIP without it);
#                           NN_MON_SECS overrides MON_SECS per app.
#   QEMU_ESP=~/dev/tools/qemu-esp
#   MON_SECS=12             seconds to watch the board or QEMU per test
set -u
cd "$(dirname "$0")/.."

NORNOS=${NORNOS:-$(realpath ../nornCore)}
APPS=${APPS:-$(ls -d apps/nn* | xargs -n1 basename)}
ESP_PORT=${ESP_PORT-/dev/ttyUSB0}
ESP_PYTHON=${ESP_PYTHON:-$HOME/dev/tools/esp-venv/bin/python}
QEMU_ESP=${QEMU_ESP:-$HOME/dev/tools/qemu-esp}
MON_SECS=${MON_SECS:-12}
export QEMU_NIC=${QEMU_NIC-user,model=open_eth,hostfwd=tcp:127.0.0.1:17009-:17009}
LOGS=build/test-logs
mkdir -p "$LOGS"

failures=0
total=0

report() {   # name result detail
    total=$((total + 1))
    printf '%-24s %-5s %s\n' "$1" "$2" "$3"
    case "$2" in PASS|SKIP) ;; *) failures=$((failures + 1));; esac
}

clean_log() { sed 's/\x1b\[[0-9;]*m//g' | tr -d '\r'; }

result_of() {   # app logfile
    local app=$1 log=$2 line
    line=$(grep -a -o "RESULT $app [A-Z]*" "$log" | tail -1)
    if [ -z "$line" ]; then
        echo "NONE no RESULT line (crash, hang or assertion); see $log"
    else
        echo "${line##* } $(grep -a 'CHECK FAILED' "$log" | head -1)"
    fi
}

nornos_make() {   # app args...
    local app=$1; shift
    make -C "$NORNOS" --no-print-directory APP="$app" APPDIR="$PWD/apps/$app" BOARD=esp32 "$@"
}

# ---- host tests
log=$LOGS/host.log
if make -s host-test > "$log" 2>&1; then
    report "host-test" PASS "$(grep -c 'RESULT .* PASS' "$log") passed, $(grep -c 'RESULT .* SKIP' "$log") skipped"
else
    report "host-test" FAIL "see $log"
fi

# ---- ESP32 in QEMU (apps marked NN_BOARD_ONLY in app.mk need a real serial line)
if [ -x "$QEMU_ESP/bin/qemu-system-xtensa" ]; then
    for app in $APPS; do
        grep -q '^NN_BOARD_ONLY' "apps/$app/app.mk" 2>/dev/null && continue
        extra="-DTC_TOLERANCE_PERMILLE=30"
        log=$LOGS/$app-esp32-qemu.log
        if ! nornos_make "$app" EXTRA_CFLAGS="$extra" image > "$log" 2>&1; then
            report "$app esp32 qemu" FAIL "build failed; see $log"; continue
        fi
        tools/with_servers.sh "apps/$app" make -C "$NORNOS" --no-print-directory APP="$app" APPDIR="$PWD/apps/$app" BOARD=esp32 \
            EXTRA_CFLAGS="$extra" QEMU_ESP="$QEMU_ESP" SIM_SECONDS="$MON_SECS" sim 2>&1 | clean_log > "$log"
        read -r res detail <<< "$(result_of "$app" "$log")"
        report "$app esp32 qemu" "$res" "$detail"
    done
else
    echo "esp32 qemu: $QEMU_ESP not present, skipped"
fi

# ---- ESP32 on the board (apps marked NN_QEMU_ONLY in app.mk need the emulated MAC)
if [ -n "$ESP_PORT" ] && [ -e "$ESP_PORT" ]; then
    for app in $APPS; do
        grep -q '^NN_QEMU_ONLY' "apps/$app/app.mk" 2>/dev/null && continue
        log=$LOGS/$app-esp32.log
        if ! nornos_make "$app" image > "$log" 2>&1; then
            report "$app esp32" FAIL "build failed; see $log"; continue
        fi
        slip=$(sed -n 's/^NN_SLIP *= *//p' "apps/$app/app.mk" 2>/dev/null)
        secs=$(sed -n 's/^NN_MON_SECS *= *//p' "apps/$app/app.mk" 2>/dev/null); secs=${secs:-$MON_SECS}
        if [ -n "$slip" ] && [ ! -e /sys/class/net/nn0 ]; then
            report "$app esp32" SKIP "needs the TAP nn0 (sudo tools/tap_setup.sh)"; continue
        fi
        if ! nornos_make "$app" PORT="$ESP_PORT" upload >> "$log" 2>&1; then
            report "$app esp32" FAIL "upload failed; see $log"; continue
        fi
        if [ -n "$slip" ]; then
            tools/with_servers.sh "apps/$app" "$ESP_PYTHON" tools/slip_bridge.py "$ESP_PORT" "$slip" "$secs" 10.0.77.3 nn0 2>&1 | clean_log > "$log"
        else
            "$ESP_PYTHON" "$NORNOS/tools/monitor.py" "$ESP_PORT" 115200 "$secs" 2>&1 | clean_log > "$log"
        fi
        read -r res detail <<< "$(result_of "$app" "$log")"
        report "$app esp32" "$res" "$detail"
    done
elif [ -n "$ESP_PORT" ]; then
    echo "esp32: $ESP_PORT not present, skipped"
fi

echo "$((total - failures)) of $total passed"
[ "$failures" -eq 0 ]

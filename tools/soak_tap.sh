#!/bin/bash
# Soak test over the TAP interface: runs test_tap for SECONDS (default 3600) while the
# Linux kernel pings it as fast as an unprivileged user may, and reports the result.
#
#   tools/soak_tap.sh [SECONDS]
set -u
cd "$(dirname "$0")/.."
SECS=${1:-3600}
make -s build/test_tap || exit 1
NN_SOAK_SECONDS=$SECS ASAN_OPTIONS=detect_stack_use_after_return=0 ./build/test_tap > build/soak_tap.log 2>&1 &
TEST=$!
sleep 3
# -i 0.002 is the fastest an unprivileged ping allows; -q prints only the summary.
ping -q -i 0.002 -w "$((SECS - 2))" 10.0.77.2 > build/soak_ping.log 2>&1
wait $TEST
rc=$?
grep -E "transmitted|rtt" build/soak_ping.log
tail -2 build/soak_tap.log
exit $rc

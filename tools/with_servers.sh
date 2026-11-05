#!/bin/bash
# with_servers.sh APPDIR command...  : runs the command; if APPDIR/app.mk sets
# NN_HOST_SERVERS, the UDP echo, DNS stub, TCP echo, TCP sink and HTTP servers run on the host
# meanwhile, bound to every address (QEMU's guest reaches them as 10.0.2.2, a board on
# the TAP as 10.0.77.1). NN_HOST_CLIENT = ADDR additionally starts tools/tcp_client.py
# after 5 s against ADDR:17009 for the passive open test (127.0.0.1 for QEMU, which
# forwards it to the guest through hostfwd; the board's address on the TAP otherwise).
set -u
appdir=$1; shift
pids=""
if grep -q '^NN_HOST_SERVERS' "$appdir/app.mk" 2>/dev/null; then
    python3 "$(dirname "$0")/udp_echo.py" 0.0.0.0 17007 & pids="$pids $!"
    python3 "$(dirname "$0")/dns_stub.py" 0.0.0.0 15353 & pids="$pids $!"
    python3 "$(dirname "$0")/tcp_echo.py" 0.0.0.0 17008 & pids="$pids $!"
    python3 "$(dirname "$0")/tcp_sink.py" 0.0.0.0 17010 & pids="$pids $!"
    python3 -m http.server --bind 0.0.0.0 --directory "$(dirname "$0")" 18080 > /dev/null 2>&1 & pids="$pids $!"
    sleep 0.3
fi
client=$(sed -n 's/^NN_HOST_CLIENT *= *//p' "$appdir/app.mk" 2>/dev/null)
if [ -n "$client" ]; then
    [ "$client" = 1 ] && client=127.0.0.1
    python3 "$(dirname "$0")/tcp_client.py" "$client" 17009 5 20000 > /dev/null & pids="$pids $!"
fi
"$@"
rc=$?
[ -n "$pids" ] && kill $pids 2>/dev/null
exit $rc

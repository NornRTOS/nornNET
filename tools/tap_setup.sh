#!/bin/sh
# Create (or remove) the persistent TAP interface the host tests use. Needs root once;
# afterwards the owning user opens it without privileges.
#
#   sudo tools/tap_setup.sh          create nn0, 10.0.77.1/24, owned by the invoking user
#   sudo tools/tap_setup.sh down     remove it
#   NN_TAP=name NN_TAP_ADDR=a.b.c.d/nn to change the defaults
set -e
TAP=${NN_TAP:-nn0}
ADDR=${NN_TAP_ADDR:-10.0.77.1/24}
USER_NAME=${SUDO_USER:-$(id -un)}

if [ "$(id -u)" != 0 ]; then
    echo "run with sudo" >&2
    exit 1
fi
if [ "${1:-up}" = down ]; then
    ip link del "$TAP" 2>/dev/null || true
    echo "$TAP removed"
    exit 0
fi
ip tuntap add mode tap user "$USER_NAME" name "$TAP" 2>/dev/null || true
ip addr replace "$ADDR" dev "$TAP"
ip link set "$TAP" up
echo "$TAP up at $ADDR, owned by $USER_NAME"

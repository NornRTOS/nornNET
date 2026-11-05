# nn03: DHCP, UDP echo and DNS against QEMU's user mode network plus two small servers on
# the host (tools/udp_echo.py, tools/dns_stub.py), which QEMU reaches as 10.0.2.2.
BOARD        = esp32
ONLY_BOARDS  = esp32
NN_QEMU_ONLY = 1
NN_HOST_SERVERS = 1
NORNNET_DIR  = $(abspath $(dir $(lastword $(MAKEFILE_LIST)))../..)
MODULES     += $(NORNNET_DIR)/nornnet.mk

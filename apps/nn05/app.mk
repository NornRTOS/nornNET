# nn05: the stack on the real ESP32 over SLIP on UART0 (921600 baud) with the Linux
# kernel as peer through tools/slip_bridge.py and the TAP nn0. The board is 10.0.77.3,
# Linux 10.0.77.1. Needs the host servers and the delayed client of with_servers.sh.
BOARD        = esp32
ONLY_BOARDS  = esp32
NN_BOARD_ONLY = 1
NN_SLIP      = 921600
NN_MON_SECS  = 40
NN_HOST_SERVERS = 1
NN_HOST_CLIENT = 10.0.77.3
NORNNET_DIR  = $(abspath $(dir $(lastword $(MAKEFILE_LIST)))../..)
MODULES     += $(NORNNET_DIR)/nornnet.mk

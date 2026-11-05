# nn02: ARP, IPv4 and ICMP against QEMU's user mode network through the open_eth MAC.
# QEMU only: the board has no Ethernet MAC the stack can drive.
BOARD        = esp32
ONLY_BOARDS  = esp32
NN_QEMU_ONLY = 1
NORNNET_DIR  = $(abspath $(dir $(lastword $(MAKEFILE_LIST)))../..)
MODULES     += $(NORNNET_DIR)/nornnet.mk

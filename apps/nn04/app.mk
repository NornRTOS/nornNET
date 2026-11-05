# nn04: TCP in QEMU against the host: echo, throughput, HTTP, a passive open through a
# hostfwd port and a refused connect. Needs the host servers of tools/with_servers.sh
# and its delayed client (NN_HOST_CLIENT), and the hostfwd rule in QEMU_NIC.
BOARD        = esp32
ONLY_BOARDS  = esp32
NN_QEMU_ONLY = 1
NN_HOST_SERVERS = 1
NN_HOST_CLIENT = 127.0.0.1
NORNNET_DIR  = $(abspath $(dir $(lastword $(MAKEFILE_LIST)))../..)
MODULES     += $(NORNNET_DIR)/nornnet.mk

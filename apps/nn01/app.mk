# nn01: nornNET foundation test on the ESP32 (loopback round trips, zero copy, timers).
BOARD       = esp32
ONLY_BOARDS = esp32
NORNNET_DIR = $(abspath $(dir $(lastword $(MAKEFILE_LIST)))../..)
MODULES    += $(NORNNET_DIR)/nornnet.mk

# nornNET: a small TCP/IP stack for nornOS.
#
#   make host-test             unit tests on the PC (POSIX layer and the nornOS host port)
#   make nn01                  build test application nn01 for the ESP32 (needs nornOS)
#   make nn01-sim              run it in Espressif's QEMU
#   make nn01-upload PORT=...  flash it;  make nn01-monitor
#   make nn05-slip             after nn05-upload: SLIP bridge to the TAP plus host servers
#   make test-all              everything, one line per result (tools/test_all.sh)
#   make lib BOARD=esp32 PROFILE=default
#                              the module library of the binary SDK, built against the
#                              nornRTOS profile (PROFILE_DIR, default ../../profiles/<profile>)
#
# NORNOS points at the nornCore checkout (default: next to this repository).

NORNOS  ?= $(abspath ../nornCore)
BUILD    = build
HOSTCC   = gcc

NN_SRC   = $(wildcard nn/*.c)
NN_INC   = -Inn -Ios -Idrv -Ihost

SANITIZE ?= -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer
WARN      = -Wall -Wextra -Wshadow -Wundef -Wstrict-prototypes -Wconversion
HOST_FLAGS = -std=c99 -pedantic $(WARN) -g -O0 $(SANITIZE) -DNN_CONFIG_H $(NN_INC)

# Tests on the POSIX layer: no kernel at all.
POSIX_SRC  = $(NN_SRC) os/nn_os_posix.c drv/nn_drv_loop.c drv/nn_drv_slip.c
# Tests on the nornOS host port: the real OS layer over the kernel's host build.
NORNOS_SRC = $(NN_SRC) os/nn_os_nornos.c drv/nn_drv_loop.c drv/nn_drv_tap.c host/nn_host.c \
             $(wildcard $(NORNOS)/kernel/*.c) $(wildcard $(NORNOS)/port/host/*.c)
NORNOS_INC = -I$(NORNOS)/kernel -I$(NORNOS)/port/host

HOST_TESTS = $(BUILD)/test_buf $(BUILD)/test_ip $(BUILD)/test_udp $(BUILD)/test_tcp $(BUILD)/test_slip $(BUILD)/test_fuzz $(BUILD)/test_net $(BUILD)/test_tap

.PHONY: all host-test test-all lib nn01 nn01-sim nn01-upload nn01-monitor clean

all: host-test

BOARD     ?= esp32
PROFILE   ?= default
NORN_RTOS ?= $(abspath ../..)
PROFILE_DIR ?= $(NORN_RTOS)/profiles/$(PROFILE)
lib:
	@test -f $(PROFILE_DIR)/nn_config.h || { echo "no nn_config.h in $(PROFILE_DIR)"; exit 1; }
	$(MAKE) --no-print-directory -C $(NORNOS) modlib MODULES=$(abspath nornnet.mk) MODNAME=nornNET \
	        MODDIR=$(abspath .) MOD_PROFILE_DIR=$(abspath $(PROFILE_DIR)) PROFILE_DIR=$(abspath $(PROFILE_DIR)) \
	        BOARD=$(BOARD) PROFILE=$(PROFILE)

$(BUILD)/test_buf $(BUILD)/test_ip $(BUILD)/test_udp $(BUILD)/test_tcp $(BUILD)/test_slip $(BUILD)/test_fuzz: $(BUILD)/test_%: test/test_%.c $(POSIX_SRC) $(wildcard nn/*.h os/*.h drv/*.h test/*.h test/*/nn_config.h)
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOST_FLAGS) -DNN_OS_POSIX -Itest/test_$* -Itest -o $@ $< $(POSIX_SRC) -lpthread

# A test with its own kernel configuration keeps it in test/<name>/rtos_config.h.
$(BUILD)/test_%: test/test_%.c $(NORNOS_SRC) $(wildcard nn/*.h os/*.h drv/*.h host/*.h test/*.h test/*/rtos_config.h)
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOST_FLAGS) -DNN_OS_NORNOS -DNN_HOST -Itest/test_$* -Itest $(NORNOS_INC) -o $@ $< $(NORNOS_SRC)

host-test: $(HOST_TESTS)
	@for t in $(HOST_TESTS); do echo "== $$t"; \
	    out=$$(ASAN_OPTIONS=detect_stack_use_after_return=0 $$t 2>&1); rc=$$?; \
	    echo "$$out" | grep -a "CHECK FAILED\|RESULT\|ERROR: \|runtime error" | tail -5; \
	    [ $$rc -eq 0 ] || exit 1; done

# ESP32 test applications are nornOS applications living in apps/; they are built by the
# nornOS Makefile with APPDIR pointing here.
NN_APPS = nn01 nn02 nn03 nn04 nn05
ESP_PYTHON ?= $(HOME)/dev/tools/esp-venv/bin/python
PORT ?= /dev/ttyUSB0
export QEMU_NIC ?= user,model=open_eth,hostfwd=tcp:127.0.0.1:17009-:17009
define APP_RULES
$(1):
	$$(MAKE) -C $$(NORNOS) --no-print-directory APP=$(1) APPDIR=$$(CURDIR)/apps/$(1) BOARD=esp32 $$(NORNOS_ARGS) image
$(1)-sim:
	tools/with_servers.sh apps/$(1) $$(MAKE) -C $$(NORNOS) --no-print-directory APP=$(1) APPDIR=$$(CURDIR)/apps/$(1) BOARD=esp32 $$(NORNOS_ARGS) sim
$(1)-upload:
	$$(MAKE) -C $$(NORNOS) --no-print-directory APP=$(1) APPDIR=$$(CURDIR)/apps/$(1) BOARD=esp32 $$(NORNOS_ARGS) upload
$(1)-monitor:
	$$(MAKE) -C $$(NORNOS) --no-print-directory APP=$(1) APPDIR=$$(CURDIR)/apps/$(1) BOARD=esp32 $$(NORNOS_ARGS) monitor
$(1)-slip:
	tools/with_servers.sh apps/$(1) $$(ESP_PYTHON) tools/slip_bridge.py $$(PORT) $$(shell sed -n 's/^NN_SLIP *= *//p' apps/$(1)/app.mk) $$(or $$(SECS),40) 10.0.77.3 nn0
endef
$(foreach a,$(NN_APPS),$(eval $(call APP_RULES,$(a))))

test-all:
	NORNOS=$(NORNOS) tools/test_all.sh

clean:
	rm -rf $(BUILD)
	@for a in $(NN_APPS); do rm -rf $(NORNOS)/build/$$a-esp32*; done

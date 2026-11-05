# nornNET as a module of a nornOS application. The application's app.mk says
#
#   NORNNET_DIR = $(abspath $(dir $(lastword $(MAKEFILE_LIST)))../..)   # or a fixed path
#   MODULES    += $(NORNNET_DIR)/nornnet.mk
#
# and the nornOS Makefile includes this file, which appends to MOD_SRC, MOD_INC and
# MOD_CFLAGS. An nn_config.h next to the application overrides the NN_CFG_* defaults.
NN_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

MOD_SRC    += $(wildcard $(NN_DIR)/nn/*.c) $(NN_DIR)/os/nn_os_nornos.c $(NN_DIR)/drv/nn_drv_loop.c $(NN_DIR)/drv/nn_drv_slip.c
MOD_INC    += -I$(NN_DIR)/nn -I$(NN_DIR)/os -I$(NN_DIR)/drv
MOD_CFLAGS += -DNN_OS_NORNOS
ifneq ($(wildcard $(APPDIR)/nn_config.h),)
  MOD_CFLAGS += -DNN_CONFIG_H
else ifneq ($(wildcard $(PROFILE_DIR)/nn_config.h),)
  MOD_CFLAGS += -DNN_CONFIG_H          # the nornRTOS profile's nn_config.h, on the include path
endif

# Board specific drivers.
ifeq ($(BOARD),esp32)
  MOD_SRC += $(NN_DIR)/drv/nn_drv_openeth.c
endif

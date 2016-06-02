include $(REP_DIR)/lib/import/import-toxcore.mk

TOXCORE_SRC_DIR = $(TOXCORE_PORT_DIR)/src/lib/toxcore

SRC_C := $(notdir $(wildcard $(TOXCORE_SRC_DIR)/toxcore/*.c))

LIBS := libc libsodium pthread lwip libc_lwip

vpath %.c   $(TOXCORE_SRC_DIR)/toxcore

SHARED_LIB = yes

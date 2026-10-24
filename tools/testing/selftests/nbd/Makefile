# SPDX-License-Identifier: GPL-2.0-only
CFLAGS += -O2 -Wall -Wextra $(KHDR_INCLUDES)
TEST_GEN_PROGS := nbd_pid_race nbd_multi_conn
LOCAL_HDRS += nbd_common.h

include ../lib.mk

$(TEST_GEN_PROGS): nbd_common.c

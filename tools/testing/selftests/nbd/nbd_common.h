/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 KylinSoft Co., Ltd. All rights reserved.
 */

#ifndef NBD_SELFTEST_COMMON_H
#define NBD_SELFTEST_COMMON_H

#include <stdbool.h>
#include <sys/types.h>

#define IO_TIMEOUT_MS 5000

struct options {
	int rounds;
	unsigned int spread_a;
	unsigned int spread_b;
	unsigned int seed;
};

struct result {
	pid_t pid;
	int error;
};

struct session {
	int index;
	int fd;
	int sockets[2][2];
	int go[2];
	int ready[2];
	int result[2];
	pid_t children[2];
	struct result results[2];
	int nr_children;
	int nr_results;
	bool owns_config;
};

long long nbd_now_ms(void);
int nbd_device_pid(int index);
int nbd_pick_device(int round);
int nbd_session_open(struct session *s, int index, int connections,
		     unsigned long flags);
int nbd_get_result(struct session *s, int timeout);
int nbd_launch(struct session *s, int children, struct options *o);
int nbd_session_close(struct session *s);
int nbd_wait_state(struct session *s);
int nbd_prime(int index, int connections, struct options *o);
void nbd_parse_options(int argc, char **argv, struct options *o);
int nbd_init_test(struct options *o);

#endif /* NBD_SELFTEST_COMMON_H */

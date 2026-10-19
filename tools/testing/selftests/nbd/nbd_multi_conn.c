// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 KylinSoft Co., Ltd. All rights reserved.
 *
 * Startup must revalidate CAN_MULTI_CONN after an unlocked queue update.
 */
#include <errno.h>
#include <linux/nbd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../kselftest.h"
#include "nbd_common.h"

struct stats {
	int rounds;
	int rejected;
	int missed;
	int hits;
	int errors;
};

/*
 * A byte cannot disappear from this UNIX socket unless a receiver reads it.
 * Only recv_work() reads the client endpoint. Keep the reply incomplete so
 * observing a second receiver does not depend on hardware queue counts or
 * inject a malformed NBD reply into request completion.
 */
static int second_receiver(struct session *s)
{
	long long end = nbd_now_ms() + 50;

	if (send(s->sockets[1][1], "x", 1, MSG_NOSIGNAL) != 1)
		return -errno;
	for (;;) {
		int pending;

		if (ioctl(s->sockets[1][0], FIONREAD, &pending))
			return -errno;
		if (!pending)
			return 1;
		if (pending != 1)
			return -EIO;
		if (nbd_now_ms() >= end)
			return 0;
		usleep(1000);
	}
}

static int multi_connection(int index, struct options *o, struct stats *st,
			    bool flags_only)
{
	struct session s;
	int ret, state = -1, cleanup;
	bool eligible = true;

	ret = nbd_prime(index, flags_only ? 1 : 2, o);
	if (ret)
		return ret;
	ret = nbd_session_open(&s, index, flags_only ? 2 : 1,
			       flags_only ? NBD_FLAG_CAN_MULTI_CONN : 0);
	if (!ret)
		ret = nbd_launch(&s, 1, o);
	if (!ret) {
		if (o->spread_b)
			usleep(rand_r(&o->seed) % o->spread_b);
		if (flags_only) {
			if (ioctl(s.fd, NBD_SET_FLAGS, 0))
				ret = -errno;
			/* A flags change after startup is a separate, older behavior. */
			state = nbd_device_pid(index);
			if (state < 0)
				ret = state;
			eligible = state == 0;
		} else if (ioctl(s.fd, NBD_SET_SOCK, s.sockets[1][0])) {
			if (errno == EBUSY)
				eligible = false;
			else
				ret = -errno;
		}
	}
	if (!ret) {
		state = nbd_wait_state(&s);
		st->rounds++;
		if (!state && s.results[0].error == EINVAL) {
			st->rejected++;
		} else if (state == 1) {
			int receiving = eligible ? second_receiver(&s) : 0;

			if (receiving < 0) {
				ret = receiving;
			} else if (receiving) {
				st->hits++;
				ksft_print_msg("nbd%d: invalid second receiver (%s)\n",
					       index,
					       flags_only ? "flags changed" : "socket added");
			} else {
				st->missed++;
			}
		} else {
			ret = state < 0 ? state : -EIO;
		}
	}
	cleanup = nbd_session_close(&s);
	if (!ret)
		ret = cleanup;
	if (!ret && state == 1 && (s.nr_results != 1 || s.results[0].error))
		ret = -EIO;
	return ret;
}

static void run_test(struct options *o, bool flags_only, const char *name)
{
	struct stats st = { 0 };
	int i;

	for (i = 0; i < o->rounds; i++) {
		int ret = multi_connection(nbd_pick_device(i), o, &st, flags_only);

		if (ret) {
			ksft_print_msg("%s round %d: %s (%d)\n", name, i + 1,
				       strerror(-ret), ret);
			st.errors++;
		}
		if (st.errors || st.hits)
			break;
	}
	ksft_test_result(!st.errors && !st.hits && st.rounds == o->rounds,
			 "%s: rounds=%d rejected=%d missed=%d regressions=%d errors=%d\n",
			 name, st.rounds, st.rejected, st.missed, st.hits, st.errors);
}

int main(int argc, char **argv)
{
	struct options o;

	nbd_parse_options(argc, argv, &o);
	ksft_print_header();
	nbd_init_test(&o);
	ksft_set_plan(2);
	run_test(&o, false, "socket-count retry rechecks CAN_MULTI_CONN");
	run_test(&o, true, "flags-only change rechecks CAN_MULTI_CONN");
	ksft_finished();
}

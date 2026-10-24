// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 KylinSoft Co., Ltd. All rights reserved.
 *
 * Concurrent NBD_DO_IT callers must preserve the successful starter's PID.
 */
#include <errno.h>
#include <linux/nbd.h>
#include <string.h>

#include "../kselftest.h"
#include "nbd_common.h"

struct stats {
	int rounds;
	int rejected;
	int hits;
	int errors;
};

static int duplicate_start(int index, struct options *o, struct stats *st)
{
	struct session s;
	struct result *loser;
	pid_t winner;
	int ret, cleanup, pid;

	ret = nbd_prime(index, 1, o);
	if (ret)
		return ret;
	ret = nbd_session_open(&s, index, 2, NBD_FLAG_CAN_MULTI_CONN);
	if (!ret)
		ret = nbd_launch(&s, 2, o);
	if (!ret)
		ret = nbd_get_result(&s, IO_TIMEOUT_MS);
	if (!ret) {
		loser = &s.results[0];
		pid = nbd_device_pid(index);
		winner = loser->pid == s.children[0] ? s.children[1] : s.children[0];
		st->rounds++;
		if (loser->error == EEXIST || pid == loser->pid) {
			st->hits++;
			ksft_print_msg("nbd%d: losing pid %d errno=%d, sysfs pid=%d\n",
				       index, loser->pid, loser->error, pid);
		} else if (loser->error == EBUSY && pid == winner) {
			st->rejected++;
		} else {
			ksft_print_msg("nbd%d: unexpected errno=%d or pid=%d (winner %d)\n",
				       index, loser->error, pid, winner);
			ret = -EIO;
		}
	}
	cleanup = nbd_session_close(&s);
	if (!ret)
		ret = cleanup;
	if (!ret && (s.nr_results != 2 || s.results[1].error))
		ret = -EIO;
	return ret;
}

int main(int argc, char **argv)
{
	struct stats st = { 0 };
	struct options o;
	int i;

	nbd_parse_options(argc, argv, &o);
	ksft_print_header();
	nbd_init_test(&o);
	ksft_set_plan(1);
	for (i = 0; i < o.rounds; i++) {
		int ret = duplicate_start(nbd_pick_device(i), &o, &st);

		if (ret) {
			ksft_print_msg("PID race round %d: %s (%d)\n", i + 1,
				       strerror(-ret), ret);
			st.errors++;
		}
		if (st.errors || st.hits)
			break;
	}
	ksft_test_result(!st.errors && !st.hits && st.rounds == o.rounds,
			 "concurrent NBD_DO_IT preserves the winning PID: rounds=%d EBUSY=%d regressions=%d errors=%d\n",
			 st.rounds, st.rejected, st.hits, st.errors);
	ksft_finished();
}

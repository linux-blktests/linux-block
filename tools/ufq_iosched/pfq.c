// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 * Copyright (c) 2026 Li Youhong <liyouhong@kylinos.cn>
 *
 * Userspace loader for the PFQ eBPF scheduler (UFQ struct_ops backend).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <ufq/common.h>
#include <ufq/pfq.bpf.h>
#include <ufq/pfq_stat.h>
#include <ufq/pfq_tunable.h>
#include <ufq/pfq_disk.h>
#include "pfq.bpf.skel.h"

const char help_fmt[] =
"PFQ eBPF scheduler for the UFQ iosched framework.\n"
"\n"
"Usage: %s [-v] [-d] [-t SEC] [-i NAME]... [-h]\n"
"\n"
"  -v            Print version\n"
"  -d            Print libbpf debug messages\n"
"  -t SEC        Stats print interval in seconds (default: 3)\n"
"  -i NAME       Prioritize an exact task comm (case-sensitive, 1-15 bytes)\n"
"                Repeat for up to 64 names; default: no interactive names\n"
"  -h            Display this help and exit\n";

#define PFQ_VERSION		"0.1.0"
#define TIME_INTERVAL		3

static bool verbose;
static volatile sig_atomic_t exit_req;
static unsigned int time_interval = TIME_INTERVAL;
static __u64 old_stats[PFQ_STAT_MAX];
static struct pfq_comm_key interactive_comms[PFQ_INTERACTIVE_MAX];
static unsigned int nr_interactive_comms;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			    va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int sig)
{
	(void)sig;
	exit_req = 1;
}

static int add_interactive_comm(const char *name)
{
	size_t len = strlen(name);
	unsigned int i;

	if (!len || len >= PFQ_COMM_LEN) {
		fprintf(stderr, "pfq: -i requires a task name of 1-%d bytes\n",
			PFQ_COMM_LEN - 1);
		return -1;
	}
	for (i = 0; i < nr_interactive_comms; i++) {
		if (!strcmp(interactive_comms[i].name, name))
			return 0;
	}
	if (nr_interactive_comms == PFQ_INTERACTIVE_MAX) {
		fprintf(stderr, "pfq: at most %d distinct task names are supported\n",
			PFQ_INTERACTIVE_MAX);
		return -1;
	}

	/* Static storage keeps the rest of each fixed-size map key zeroed. */
	memcpy(interactive_comms[nr_interactive_comms++].name, name, len);
	return 0;
}

static int init_interactive_comms(struct pfq *skel)
{
	int fd = bpf_map__fd(skel->maps.pfq_interactive_comms);
	__u8 enabled = 1;
	unsigned int i;

	for (i = 0; i < nr_interactive_comms; i++) {
		if (bpf_map_update_elem(fd, &interactive_comms[i],
					&enabled, BPF_ANY) < 0) {
			fprintf(stderr, "pfq: cannot configure task '%s': %s\n",
				interactive_comms[i].name, strerror(errno));
			return -1;
		}
	}
	return 0;
}

static void init_tunables(struct pfq *skel)
{
	int fd = bpf_map__fd(skel->maps.pfq_tunables);
	__u32 key = PFQ_TUNABLE_KEY;
	struct pfq_tunables tun = {
		.weight_base = PFQ_WEIGHT_BASE_DEFAULT,
		.idle_delay_min_ms = PFQ_IDLE_DELAY_MIN_MS_DEFAULT,
		.idle_delay_max_ms = PFQ_IDLE_DELAY_MAX_MS_DEFAULT,
		.batch_read = PFQ_BATCH_READ_DEFAULT,
		.batch_sync_write = PFQ_BATCH_SYNC_WRITE_DEFAULT,
		.batch_write = PFQ_BATCH_WRITE_DEFAULT,
	};

	if (bpf_map_update_elem(fd, &key, &tun, BPF_ANY) < 0)
		fprintf(stderr, "pfq: failed to seed tunables map\n");
}

/* Sum CPUs within each disk, then sum the independent disk totals. */
static int read_stats(struct pfq *skel, __u64 *stats)
{
	__u64 total[PFQ_STAT_MAX] = {}, disk[PFQ_STAT_MAX];
	__s32 key, next_key, seen[PFQ_DISK_MAP_MAX];
	int nr_cpus = libbpf_num_possible_cpus();
	int fd = bpf_map__fd(skel->maps.pfq_stats_map);
	int cpu, idx, ret = -1, nr_seen = 0;
	struct pfq_stats *values;

	if (nr_cpus <= 0)
		return -1;
	values = calloc(nr_cpus, sizeof(*values));
	if (!values)
		return -1;

	while (!bpf_map_get_next_key(fd, nr_seen ? &key : NULL, &next_key)) {
		/*
		 * A deletion can restart iteration. Skip this sample to avoid
		 * double-counting a disk or looping during disk churn.
		 */
		if (nr_seen == PFQ_DISK_MAP_MAX)
			goto out;
		for (idx = 0; idx < nr_seen; idx++)
			if (seen[idx] == next_key)
				goto out;
		seen[nr_seen++] = next_key;
		key = next_key;
		if (bpf_map_lookup_elem(fd, &key, values)) {
			if (errno == ENOENT)
				continue;
			goto out;
		}

		memset(disk, 0, sizeof(disk));
		for (cpu = 0; cpu < nr_cpus; cpu++)
			for (idx = 0; idx < PFQ_STAT_MAX; idx++)
				disk[idx] += values[cpu].counters[idx];
		/*
		 * Saturate each disk separately: a skewed sample on one disk
		 * must not deduct inserts from another disk.
		 */
		disk[PFQ_STAT_INSERT_CNT] =
			disk[PFQ_STAT_INSERT_CNT] >= disk[PFQ_STAT_RQMERGE_CNT] ?
			disk[PFQ_STAT_INSERT_CNT] - disk[PFQ_STAT_RQMERGE_CNT] : 0;
		disk[PFQ_STAT_INSERT_SIZE] =
			disk[PFQ_STAT_INSERT_SIZE] >= disk[PFQ_STAT_RQMERGE_SIZE] ?
			disk[PFQ_STAT_INSERT_SIZE] - disk[PFQ_STAT_RQMERGE_SIZE] : 0;
		for (idx = 0; idx < PFQ_STAT_MAX; idx++)
			total[idx] += disk[idx];
	}
	if (errno == ENOENT) {
		memcpy(stats, total, sizeof(total));
		ret = 0;
	}
out:
	free(values);
	return ret;
}

/* Removing/reinitializing a disk can reduce the aggregate counters. */
static __u64 stat_delta(__u64 current, __u64 previous)
{
	return current >= previous ? current - previous : 0;
}

/* Sum live per-disk queue state from pfq_map. */
static void read_disk_state(struct pfq *skel, __u32 *nr_queued_total,
			    __u32 *nr_active)
{
	int map_fd = bpf_map__fd(skel->maps.pfq_map);
	__u32 vsize = bpf_map__value_size(skel->maps.pfq_map);
	__u32 queued = 0, active = 0;
	__s32 key = 0, next_key;
	bool first = true;
	void *buf;

	if (vsize < sizeof(struct pfq_disk_data_user)) {
		fprintf(stderr, "pfq: pfq_map value smaller than expected\n");
		return;
	}

	buf = malloc(vsize);
	if (!buf)
		return;

	while (!bpf_map_get_next_key(map_fd, first ? NULL : &key, &next_key)) {
		struct pfq_disk_data_user *dd = buf;

		if (!bpf_map_lookup_elem(map_fd, &next_key, buf)) {
			queued += dd->nr_queued_total;
			active += dd->nr_active;
		}
		key = next_key;
		first = false;
	}
	free(buf);
	if (nr_queued_total)
		*nr_queued_total = queued;
	if (nr_active)
		*nr_active = active;
}

static void print_stats(struct pfq *skel)
{
	__u32 nr_queued_total = 0, nr_active = 0;
	__u64 stats[PFQ_STAT_MAX];

	if (read_stats(skel, stats)) {
		fprintf(stderr, "pfq: cannot read per-CPU statistics\n");
		return;
	}
	read_disk_state(skel, &nr_queued_total, &nr_active);

	printf("bps:%lluk  iops:%llu\n",
	       stat_delta(stats[PFQ_STAT_FINISH_SIZE],
			  old_stats[PFQ_STAT_FINISH_SIZE]) / 1024 / time_interval,
	       stat_delta(stats[PFQ_STAT_FINISH_CNT],
			  old_stats[PFQ_STAT_FINISH_CNT]) / time_interval);
	printf("(insert:   cnt=%llu size=%llu err=%llu) (interactive: %llu)\n",
	       stats[PFQ_STAT_INSERT_CNT], stats[PFQ_STAT_INSERT_SIZE],
	       stats[PFQ_STAT_INSERT_ERR],
	       stats[PFQ_STAT_INTERACTIVE]);
	printf("(at_head:  cnt=%llu size=%llu)\n",
	       stats[PFQ_STAT_AT_HEAD_CNT], stats[PFQ_STAT_AT_HEAD_SIZE]);
	printf("(rqmerge:  cnt=%llu size=%llu) (biomerge: cnt=%llu size=%llu)\n",
	       stats[PFQ_STAT_RQMERGE_CNT], stats[PFQ_STAT_RQMERGE_SIZE],
	       stats[PFQ_STAT_BIOMERGE_CNT], stats[PFQ_STAT_BIOMERGE_SIZE]);
	printf("(dispatch: cnt=%llu size=%llu) (at_head_disp: cnt=%llu size=%llu)\n",
	       stats[PFQ_STAT_DISPATCH_CNT], stats[PFQ_STAT_DISPATCH_SIZE],
	       stats[PFQ_STAT_DISPATCH_AT_HEAD_CNT],
	       stats[PFQ_STAT_DISPATCH_AT_HEAD_SIZE]);
	printf("(finish:   cnt=%llu size=%llu)\n",
	       stats[PFQ_STAT_FINISH_CNT], stats[PFQ_STAT_FINISH_SIZE]);
	printf("(nr_queued_total: %u) (nr_active: %u) (idle_hold: %llu)\n",
	       nr_queued_total, nr_active, stats[PFQ_STAT_IDLE_HOLD]);
	memcpy(old_stats, stats, sizeof(old_stats));
}

int main(int argc, char **argv)
{
	struct bpf_link *link;
	struct pfq *skel;
	int opt;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	skel = UFQ_OPS_OPEN(pfq_ops, pfq);

	while ((opt = getopt(argc, argv, "vdht:i:")) != -1) {
		switch (opt) {
		case 'v':
			printf("pfq version: %s\n", PFQ_VERSION);
			pfq__destroy(skel);
			return 0;
		case 'd':
			verbose = true;
			break;
		case 'i':
			if (add_interactive_comm(optarg)) {
				pfq__destroy(skel);
				return 1;
			}
			break;
		case 't': {
			char *end;
			unsigned long v = strtoul(optarg, &end, 10);

			if (*end || v == 0) {
				fprintf(stderr, "pfq: invalid -t value\n");
				pfq__destroy(skel);
				return 1;
			}
			time_interval = v;
			break;
		}
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			pfq__destroy(skel);
			return opt != 'h';
		}
	}

	if (optind != argc) {
		fprintf(stderr, "pfq: unexpected argument '%s' (use -i NAME)\n",
			argv[optind]);
		pfq__destroy(skel);
		return 1;
	}

	UFQ_OPS_LOAD(skel, pfq_ops, pfq);
	if (init_interactive_comms(skel)) {
		pfq__destroy(skel);
		return 1;
	}
	init_tunables(skel);
	link = UFQ_OPS_ATTACH(skel, pfq_ops, pfq);

	printf("PFQ eBPF scheduler v%s attached (struct_ops)\n", PFQ_VERSION);

	while (!exit_req) {
		sleep(time_interval);
		print_stats(skel);
	}

	bpf_link__destroy(link);
	pfq__destroy(skel);
	return 0;
}

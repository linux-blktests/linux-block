/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 * Copyright (c) 2026 Li Youhong <liyouhong@kylinos.cn>
 *
 * Per-disk, per-CPU PFQ event counters. Disk exit removes the counters;
 * initialization reuses an existing entry without resetting it.
 */
#ifndef __PFQ_STAT_H
#define __PFQ_STAT_H

enum pfq_stat_idx {
	PFQ_STAT_INSERT_CNT = 0,
	PFQ_STAT_INSERT_SIZE,
	PFQ_STAT_INSERT_ERR,
	PFQ_STAT_AT_HEAD_CNT,
	PFQ_STAT_AT_HEAD_SIZE,
	PFQ_STAT_INTERACTIVE,
	PFQ_STAT_RQMERGE_CNT,
	PFQ_STAT_RQMERGE_SIZE,
	PFQ_STAT_BIOMERGE_CNT,
	PFQ_STAT_BIOMERGE_SIZE,
	PFQ_STAT_DISPATCH_CNT,
	PFQ_STAT_DISPATCH_SIZE,
	PFQ_STAT_DISPATCH_AT_HEAD_CNT,
	PFQ_STAT_DISPATCH_AT_HEAD_SIZE,
	PFQ_STAT_FINISH_CNT,
	PFQ_STAT_FINISH_SIZE,
	PFQ_STAT_IDLE_HOLD,
	PFQ_STAT_MAX,
};

/*
 * INSERT counters count successful normal inserts before merge deductions.
 * RQMERGE counters count queued candidates removed by merge_req, before the
 * kernel attempts the merge. A rejected candidate is counted again on insert.
 * For each disk, sum all CPUs before subtracting RQMERGE counters.
 */
struct pfq_stats {
	__u64 counters[PFQ_STAT_MAX];
};

#endif /* __PFQ_STAT_H */

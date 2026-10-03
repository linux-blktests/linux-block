/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 * Copyright (c) 2026 Li Youhong <liyouhong@kylinos.cn>
 *
 * Userspace prefix of struct pfq_disk_data through nr_queued_total.
 * Keep field types and order in sync with pfq.bpf.c.
 *
 * Lookup must use a buffer of bpf_map__value_size(); this prefix is safe
 * to interpret when the map value is at least sizeof(*this).
 */
#ifndef __PFQ_DISK_H
#define __PFQ_DISK_H

#include <linux/bpf.h>
#include <stdint.h>
#include <ufq/pfq.bpf.h>

typedef int32_t s32;
typedef uint32_t u32;
typedef uint64_t u64;

struct pfq_disk_data_user {
	struct bpf_spin_lock lock;
	struct bpf_list_head dispatch;
	struct bpf_rb_root service_tree;
	struct bpf_rb_root rq_trees[PFQ_RQ_TREES];
	struct bpf_rb_root fifo_trees[PFQ_RQ_TREES];
	s32 disk_id;
	u64 vtime;
	u64 min_vtime;
	u64 last_sector;
	u32 nr_active;
	u32 nr_queued_total;
};

#endif /* __PFQ_DISK_H */

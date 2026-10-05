/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 * Copyright (c) 2026 Li Youhong <liyouhong@kylinos.cn>
 *
 * PFQ eBPF scheduler constants shared by pfq.bpf.c and pfq.c.
 */
#ifndef __PFQ_BPF_H
#define __PFQ_BPF_H

/* Task comm includes the terminating NUL, matching TASK_COMM_LEN. */
#define PFQ_COMM_LEN			16
#define PFQ_INTERACTIVE_MAX		64

enum pfq_init_state {
	PFQ_UNINITIALIZED,
	PFQ_INITIALIZING,
	PFQ_INITIALIZED,
};

struct pfq_comm_key {
	char name[PFQ_COMM_LEN];
};

#define PFQ_PRIO_LEVELS			8
#define PFQ_IOCLASS_NUM			4
#define PFQ_QUEUE_TYPES			3
#define PFQ_TOTAL_QUEUES \
	(PFQ_IOCLASS_NUM * PFQ_PRIO_LEVELS * PFQ_QUEUE_TYPES)

/*
 * Share request and FIFO roots by I/O type to stay within BTF_FIELDS_MAX.
 * Each tree groups logical queues by qid, then orders requests by sector
 * or FIFO deadline.
 */
#define PFQ_RQ_TREES			PFQ_QUEUE_TYPES

#define PFQ_QUEUE_MAP_MAX \
	(PFQ_DISK_MAP_MAX * PFQ_TOTAL_QUEUES)

#define PFQ_INDEX(class, prio, type) \
	(((class) * PFQ_PRIO_LEVELS * PFQ_QUEUE_TYPES) + \
	 ((prio) * PFQ_QUEUE_TYPES) + (type))

#define PFQ_GET_CLASS(index) \
	((index) / (PFQ_PRIO_LEVELS * PFQ_QUEUE_TYPES))
#define PFQ_GET_PRIO(index) \
	(((index) % (PFQ_PRIO_LEVELS * PFQ_QUEUE_TYPES)) / PFQ_QUEUE_TYPES)
#define PFQ_GET_TYPE(index) \
	((index) % PFQ_QUEUE_TYPES)

#define PFQ_QID_TREE_INDEX(qid)		PFQ_GET_TYPE(qid)

#define PFQ_DEFAULT_QUEUE_INDEX(type) \
	PFQ_INDEX(2 /* PFQ_BE_CLASS */, 4 /* IOPRIO_BE_NORM */, (type))

#define PFQ_WEIGHT_MULT_SPECIAL		400
#define PFQ_PRIO_LEVEL_COEFF_SP_READ	200
#define PFQ_PRIO_LEVEL_COEFF_READ	100
#define PFQ_PRIO_LEVEL_COEFF_WRITE	5

#define PFQ_VTIME_SHIFT			10

#define PFQ_WEIGHT_BASE_DEFAULT		100
#define PFQ_BATCH_READ_DEFAULT		8
#define PFQ_BATCH_SYNC_WRITE_DEFAULT	4
#define PFQ_BATCH_WRITE_DEFAULT		2
#define PFQ_IDLE_DELAY_MIN_MS_DEFAULT	8
#define PFQ_IDLE_DELAY_MAX_MS_DEFAULT	20

#define PFQ_READ_EXPIRE_NS		(500000000ULL)
#define PFQ_SYNC_WRITE_EXPIRE_NS	(2000000000ULL)
#define PFQ_WRITE_EXPIRE_NS		(5000000000ULL)

#define PFQ_LOOP_MAX			128
#define PFQ_RB_HEIGHT_MAX		24	/* verifier search bound */
#define PFQ_DISK_MAP_MAX		32
#define PFQ_QID_NONE			0xffffffffU

#define PFQ_IOPRIO_CLASS_SHIFT		13

#define PFQ_IOPRIO_CLASS_NONE		0
#define PFQ_IOPRIO_CLASS_RT		1
#define PFQ_IOPRIO_CLASS_BE		2
#define PFQ_IOPRIO_CLASS_IDLE		3
#define PFQ_IOPRIO_BE_NORM		4

#define PFQ_SPECIAL_CLASS		0
#define PFQ_RT_CLASS			1
#define PFQ_BE_CLASS			2
#define PFQ_IDLE_CLASS			3

#define PFQ_READ			0
#define PFQ_WRITE			1
#define PFQ_SYNC_WRITE			2

#define BLK_MQ_INSERT_AT_HEAD		0x01
#define REQ_OP_MASK			((1 << 8) - 1)
#define SECTOR_SHIFT			9

/* BPF-only masks: derive bit positions from the generated kernel enums. */
#ifdef __VMLINUX_H__
#define PFQ_REQ_SYNC			(1ULL << __REQ_SYNC)
#define PFQ_REQ_META			(1ULL << __REQ_META)
#define PFQ_REQ_OP_FLUSH			REQ_OP_FLUSH
#define PFQ_REQ_OP_ZONE_APPEND		REQ_OP_ZONE_APPEND
#define PFQ_REQ_OP_WRITE_ZEROES		REQ_OP_WRITE_ZEROES
#define PFQ_REQ_OP_DRV_IN		REQ_OP_DRV_IN
#define PFQ_REQ_OP_DRV_OUT		REQ_OP_DRV_OUT

#define PFQ_REQ_NOMERGE			(1ULL << __REQ_NOMERGE)
#define PFQ_REQ_FUA			(1ULL << __REQ_FUA)
#define PFQ_REQ_PREFLUSH			(1ULL << __REQ_PREFLUSH)
#define PFQ_REQ_NOMERGE_FLAGS \
	(PFQ_REQ_NOMERGE | PFQ_REQ_PREFLUSH | PFQ_REQ_FUA)

#define PFQ_RQF_STARTED			(1U << __RQF_STARTED)
#define PFQ_RQF_FLUSH_SEQ		(1U << __RQF_FLUSH_SEQ)
#define PFQ_RQF_SPECIAL_PAYLOAD		(1U << __RQF_SPECIAL_PAYLOAD)
#define PFQ_RQF_NOMERGE_FLAGS \
	(PFQ_RQF_STARTED | PFQ_RQF_FLUSH_SEQ | PFQ_RQF_SPECIAL_PAYLOAD)
#endif /* __VMLINUX_H__ */

#endif /* __PFQ_BPF_H */

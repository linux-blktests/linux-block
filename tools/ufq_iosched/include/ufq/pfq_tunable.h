/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 * Copyright (c) 2026 Li Youhong <liyouhong@kylinos.cn>
 */
#ifndef __PFQ_TUNABLE_H
#define __PFQ_TUNABLE_H

#include <ufq/pfq.bpf.h>

#define PFQ_TUNABLE_KEY	0

struct pfq_tunables {
	__u32 weight_base;
	__u32 idle_delay_min_ms;
	__u32 idle_delay_max_ms;
	__u32 batch_read;
	__u32 batch_sync_write;
	__u32 batch_write;
};

#endif /* __PFQ_TUNABLE_H */

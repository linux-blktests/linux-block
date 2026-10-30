// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 * Copyright (c) 2026 Li Youhong <liyouhong@kylinos.cn>
 *
 * PFQ (Priority Fair Queue) eBPF scheduler for the UFQ iosched framework.
 *
 * Each disk has 96 logical queues sharing request and FIFO indexes by I/O
 * type. The service tree orders queues by virtual time; dispatch serves
 * bounded batches with FIFO expiry taking precedence over seek distance.
 * Head inserts bypass fair queueing.
 *
 * dd->lock protects graph roots and mutable scheduling state. Map lookups,
 * allocation and request acquisition run outside the lock. Detached and
 * temporary owning references are released after unlocking.
 *
 * Empty SPECIAL+READ queues can retain their service slot until a later
 * callback checks the idle deadline. UFQ provides no timer for this hold.
 */
#include <ufq/common.bpf.h>
#include <ufq/pfq.bpf.h>
#include <ufq/pfq_stat.h>
#include <ufq/pfq_tunable.h>

char _license[] SEC("license") = "GPL";

/* Unlocked qid reads are prefetch hints, revalidated under dd->lock. */
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, value) (*(volatile typeof(x) *)&(x) = (value))

/*
 * The request and FIFO trees each own a reference to the same wrapper.
 * The wrapper owns one request reference, independent of its tree references.
 */
struct pfq_rq_core {
	struct bpf_refcount ref;
	struct bpf_rb_node rb_node;	/* request-tree link */
	struct bpf_rb_node fifo_rb_node; /* FIFO-tree link */
	struct request __kptr *req;	/* owned request (bpf_request_acquire) */
	u64 fifo_deadline_ns;		/* boot-time FIFO deadline */
	u64 sector;			/* cached req->__sector for rq_less */
	u32 qid;			/* logical queue index */
	bool is_meta;			/* cached REQ_META for seek choose */
};

/*
 * Urgent dispatch entry: BLK_MQ_INSERT_AT_HEAD bypasses fair queueing and is
 * drained from dd->dispatch before the service tree.
 */
struct pfq_dispatch_node {
	struct bpf_list_node node;
	struct request __kptr *req;
};

/*
 * The queue map owns each logical queue for the disk lifetime. The service
 * tree owns another reference while the queue is active or held idle.
 * Mutable scheduling fields are protected by dd->lock.
 */
struct pfq_queue_data {
	struct bpf_refcount ref;
	struct bpf_rb_node svc_rb_node;	/* link in dd->service_tree */
	u64 vtime;			/* virtual time charged on dispatch */
	u64 weight;			/* virtual-time divisor */
	u32 nr_queued;			/* requests in this logical queue */
	bool in_tree;			/* in dd->service_tree; dd->lock only */
	u32 qid;			/* index 0..95; tree tie-break */
	u8 pq_class;			/* PFQ_*_CLASS */
	u8 priority;			/* 0..7 from IOPRIO_PRIO_LEVEL */
	u8 io_type;			/* PFQ_READ / WRITE / SYNC_WRITE */
};

/* Prefetch queue unlocked; detach at most one expired hold under dd->lock. */
struct pfq_idle_cleanup {
	struct pfq_queue_data *queue;
	struct pfq_queue_data *service;
};

static void pfq_idle_cleanup(struct pfq_idle_cleanup *cleanup)
{
	if (cleanup->service)
		bpf_obj_drop(cleanup->service);
	if (cleanup->queue)
		bpf_obj_drop(cleanup->queue);
}

/* Detached dispatch references for release after unlocking dd->lock. */
struct pfq_dispatch_cleanup {
	struct pfq_queue_data *empty_service;
	struct pfq_queue_data *old_service;
	struct pfq_rq_core *fifo_node;
	struct pfq_rq_core *rq_node;
	struct pfq_stats *stats;
};

/*
 * dd->lock also protects mutable fields in the referenced queue objects.
 */
struct pfq_disk_data {
	struct bpf_spin_lock lock;	/* sole lock for all scheduler state */
	struct bpf_list_head dispatch __contains(pfq_dispatch_node, node);
	struct bpf_rb_root service_tree __contains(pfq_queue_data, svc_rb_node);
	struct bpf_rb_root rq_trees[PFQ_RQ_TREES]
		__contains(pfq_rq_core, rb_node);
	struct bpf_rb_root fifo_trees[PFQ_RQ_TREES]
		__contains(pfq_rq_core, fifo_rb_node);
	s32 disk_id;			/* request_queue::id */
	u64 vtime;			/* global virtual time floor */
	u64 min_vtime;			/* cached service-tree minimum */
	u64 last_sector;		/* end sector of last fair dispatch */
	u32 nr_active;			/* active or idle-held queues */
	u32 nr_queued_total;		/* pending rq in fair queues */
	u32 in_service_dispatched;	/* dispatches in current batch */
	u32 in_service_qid;		/* queue being batch-dispatched */
	u64 idle_deadline_ns;		/* checked by later callbacks */
	u32 idle_queue_qid;		/* reserved service slot */
	bool waiting_idle;		/* SPECIAL+READ idle hold active */
	u64 fifo_expire_ns[3];		/* FIFO windows by I/O type */
	u32 max_batch[3];		/* batch limit per io_type */
	u32 weight_base;		/* base weight from tunables */
	u32 idle_delay_min_ms;		/* SPECIAL+READ idle hold lower bound */
	u32 idle_delay_max_ms;		/* SPECIAL+READ idle hold upper bound */
	int init_state;			/* enum pfq_init_state; atomic access */
};

struct pfq_queue_handle {
	struct pfq_queue_data __kptr *queue;
};

struct pfq_queue_key {
	s32 disk_id;
	u32 qid;
};

/* Exact, case-sensitive task names configured before struct_ops attach. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PFQ_INTERACTIVE_MAX);
	__type(key, struct pfq_comm_key);
	__type(value, u8);
} pfq_interactive_comms SEC(".maps");

/*
 * Per-disk state: key = request_queue::id; value = pfq_disk_data.
 * Dynamic hash elements run their BTF field destructor after deletion,
 * releasing graph roots and node-owned kptrs; reused IDs get fresh elements.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, PFQ_DISK_MAP_MAX);
	__type(key, s32);
	__type(value, struct pfq_disk_data);
} pfq_map SEC(".maps");

/* Per-logical-queue kptr: key = (disk_id, qid). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PFQ_QUEUE_MAP_MAX);
	__type(key, struct pfq_queue_key);
	__type(value, struct pfq_queue_handle);
} pfq_queue_map SEC(".maps");

/*
 * Initialization tunables (single entry, key 0).  Userspace writes them
 * before attach; pfq_do_init_sched snapshots them for each disk.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct pfq_tunables);
} pfq_tunables SEC(".maps");

/*
 * Keep the disk template off the limited BPF stack. Per-CPU storage
 * separates concurrent initializers running on different CPUs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct pfq_disk_data);
} pfq_disk_scratch SEC(".maps");

/* One independent set of CPU counters per pfq_map disk entry. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, PFQ_DISK_MAP_MAX);
	__type(key, s32);
	__type(value, struct pfq_stats);
} pfq_stats_map SEC(".maps");

/* Lookup before taking dd->lock; map helpers are forbidden while locked. */
static __always_inline struct pfq_stats *pfq_stats_lookup(int disk_id)
{
	return bpf_map_lookup_elem(&pfq_stats_map, &disk_id);
}

/* A pre-fetched per-CPU pointer is usable with or without dd->lock. */
static __always_inline void pfq_stat_add(struct pfq_stats *stats, u32 idx,
					 u64 val)
{
	if (stats && idx < PFQ_STAT_MAX)
		/* Also protect against same-CPU interrupt/reentrant writers. */
		__sync_fetch_and_add(&stats->counters[idx], val);
}

/* Boot time, including suspend, for FIFO and idle deadlines. */
static __always_inline u64 pfq_now_ns(void)
{
	return bpf_ktime_get_boot_ns();
}

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000ULL
#endif
#ifndef CONFIG_HZ
#define CONFIG_HZ 1000
#endif
#define PFQ_NS_PER_JIFFY (NSEC_PER_SEC / CONFIG_HZ)

static __always_inline u64 pfq_jiffies_to_deadline_ns(unsigned long jdeadline,
						      u64 now_ns)
{
	u64 jnow = bpf_jiffies64();
	u64 delta_j = (u64)jdeadline > jnow ? (u64)jdeadline - jnow : 0;

	return now_ns + delta_j * PFQ_NS_PER_JIFFY;
}

static __always_inline bool pfq_qid_valid(u32 qid)
{
	return qid < PFQ_TOTAL_QUEUES;
}

/* Return a non-owning queue pointer; caller must not hold dd->lock. */
static __always_inline struct pfq_queue_data *
pfq_queue_lookup(s32 disk_id, u32 qid)
{
	struct pfq_queue_key key = {};
	struct pfq_queue_handle *hp;

	if (!pfq_qid_valid(qid))
		return NULL;

	key.disk_id = disk_id;
	key.qid = qid;
	hp = bpf_map_lookup_elem(&pfq_queue_map, &key);
	if (!hp || !hp->queue)
		return NULL;
	return hp->queue;
}

/*
 * Initialization-only lookup: drop dd->lock for the map helper and return
 * with it held. The INITIALIZING owner keeps queue entries alive across
 * this unlocked interval. The returned pointer is non-owning.
 */
static __always_inline struct pfq_queue_data *
pfq_queue_scalar(struct pfq_disk_data *dd, u32 qid)
{
	struct pfq_queue_data *queue;
	s32 disk_id;

	if (!dd || !pfq_qid_valid(qid))
		return NULL;

	disk_id = dd->disk_id;
	bpf_spin_unlock(&dd->lock);
	queue = pfq_queue_lookup(disk_id, qid);
	bpf_spin_lock(&dd->lock);
	return queue;
}

/* Map lookup + owning ref. Caller must not hold dd->lock. */
static __always_inline struct pfq_queue_data *
pfq_queue_acquire(s32 disk_id, u32 qid)
{
	struct pfq_queue_data *queue = NULL;
	struct pfq_queue_key key = {};
	struct pfq_queue_handle *hp;

	if (!pfq_qid_valid(qid))
		return NULL;

	key.disk_id = disk_id;
	key.qid = qid;
	hp = bpf_map_lookup_elem(&pfq_queue_map, &key);
	if (hp && hp->queue)
		queue = bpf_refcount_acquire(hp->queue);
	return queue;
}

/*
 * Select roots at constant offsets: graph kfuncs reject a root pointer at
 * a variable offset into the map value. Caller holds dd->lock.
 */
static __always_inline struct bpf_rb_root *
pfq_rq_tree(struct pfq_disk_data *dd, u32 qid)
{
	u8 ty;

	if (!pfq_qid_valid(qid))
		return NULL;
	ty = PFQ_GET_TYPE(qid);
	if (ty == PFQ_READ)
		return &dd->rq_trees[PFQ_READ];
	if (ty == PFQ_WRITE)
		return &dd->rq_trees[PFQ_WRITE];
	if (ty == PFQ_SYNC_WRITE)
		return &dd->rq_trees[PFQ_SYNC_WRITE];
	return NULL;
}

static __always_inline struct bpf_rb_root *
pfq_fifo_tree(struct pfq_disk_data *dd, u32 qid)
{
	u8 ty;

	if (!pfq_qid_valid(qid))
		return NULL;
	ty = PFQ_GET_TYPE(qid);
	if (ty == PFQ_READ)
		return &dd->fifo_trees[PFQ_READ];
	if (ty == PFQ_WRITE)
		return &dd->fifo_trees[PFQ_WRITE];
	if (ty == PFQ_SYNC_WRITE)
		return &dd->fifo_trees[PFQ_SYNC_WRITE];
	return NULL;
}

/*
 * Lock-held detach helpers: bpf_rbtree_remove returns owning refs that must
 * be bpf_obj_drop'd only after releasing bpf_spin_lock.
 */
static __always_inline struct pfq_rq_core *
pfq_rq_tree_remove_take(struct bpf_rb_root *root, struct bpf_rb_node *node)
{
	struct bpf_rb_node *rb;

	if (!root || !node)
		return NULL;
	rb = bpf_rbtree_remove(root, node);
	if (!rb)
		return NULL;
	return container_of(rb, struct pfq_rq_core, rb_node);
}

static __always_inline struct pfq_rq_core *
pfq_fifo_tree_remove_take(struct bpf_rb_root *root, struct bpf_rb_node *node)
{
	struct bpf_rb_node *rb;

	if (!root || !node)
		return NULL;
	rb = bpf_rbtree_remove(root, node);
	if (!rb)
		return NULL;
	return container_of(rb, struct pfq_rq_core, fifo_rb_node);
}

/**
 * pfq_dispatch_push_dn - Append an urgent dispatch node
 * @dispatch: urgent dispatch list protected by the disk lock
 * @dn: node whose owning reference is transferred to the list
 *
 * bpf_list_push_back consumes the node reference even on failure. The
 * caller must not drop dn or restore dn->req after a failed push.
 *
 * Context: Caller holds the disk lock.
 *
 * Return: 0 on success, or -EINVAL for invalid arguments or a failed push.
 */
static __noinline int
pfq_dispatch_push_dn(struct bpf_list_head *dispatch,
		     struct pfq_dispatch_node *dn)
{
	if (!dispatch || !dn)
		return -EINVAL;

	if (bpf_list_push_back(dispatch, &dn->node))
		return -EINVAL;

	return 0;
}

/*
 * Return the displaced request reference for release after unlocking.
 * If core is NULL, return req so the caller retains ownership.
 */
static __always_inline struct request *
pfq_core_put_req_stash(struct pfq_rq_core *core, struct request *req)
{
	if (!req)
		return NULL;
	if (!core)
		return req;
	return bpf_kptr_xchg(&core->req, req);
}

/*
 * Map updates skip kptr fields, so transfer the queue reference with
 * bpf_kptr_xchg. On success the map owns it; on failure the caller does.
 */
static int pfq_queue_map_insert(s32 disk_id, u32 qid,
				struct pfq_queue_data *queue)
{
	struct pfq_queue_handle handle = {}, *hp;
	struct pfq_queue_key key = {};
	struct pfq_queue_data *old;
	int ret;

	key.disk_id = disk_id;
	key.qid = qid;
	ret = bpf_map_update_elem(&pfq_queue_map, &key, &handle, BPF_NOEXIST);
	if (ret)
		return ret;

	hp = bpf_map_lookup_elem(&pfq_queue_map, &key);
	if (!hp)
		return -ENOENT;

	old = bpf_kptr_xchg(&hp->queue, queue);
	if (old)
		bpf_obj_drop(old);
	return 0;
}

static void pfq_queues_destroy(s32 disk_id)
{
	struct pfq_queue_key key = {};
	struct pfq_queue_handle *hp;
	struct pfq_queue_data __kptr *queue;
	u32 i;

	key.disk_id = disk_id;
	for (i = 0; i < PFQ_TOTAL_QUEUES; i++) {
		key.qid = i;
		hp = bpf_map_lookup_elem(&pfq_queue_map, &key);
		if (hp) {
			queue = bpf_kptr_xchg(&hp->queue, NULL);
			bpf_map_delete_elem(&pfq_queue_map, &key);
			if (queue)
				bpf_obj_drop(queue);
		} else {
			bpf_map_delete_elem(&pfq_queue_map, &key);
		}
	}
}

/**
 * pfq_ioprio_to_class - Map kernel I/O priority class to PFQ class
 * @ioprio: encoded I/O priority, including class and level
 *
 * Unspecified or invalid I/O priority classes use best-effort service.
 * Task-name overrides are applied separately by pfq_class_from_*().
 *
 * Return: PFQ class; unspecified or invalid classes use PFQ_BE_CLASS.
 */
static __always_inline u8 pfq_ioprio_to_class(u16 ioprio)
{
	u8 iclass = (ioprio >> PFQ_IOPRIO_CLASS_SHIFT) & 0x7;

	if (iclass <= PFQ_IOPRIO_CLASS_IDLE) {
		switch (iclass) {
		case PFQ_IOPRIO_CLASS_RT:
			return PFQ_RT_CLASS;
		case PFQ_IOPRIO_CLASS_BE:
			return PFQ_BE_CLASS;
		case PFQ_IOPRIO_CLASS_IDLE:
			return PFQ_IDLE_CLASS;
		default:
			return PFQ_BE_CLASS;
		}
	}
	return PFQ_BE_CLASS;
}

/*
 * Match the current thread's comm before taking dd->lock. Worker-submitted
 * I/O is classified by the worker name, not the original userspace submitter.
 */
static __always_inline bool pfq_current_is_interactive(void)
{
	struct pfq_comm_key key = {};
	u8 *enabled;

	if (bpf_get_current_comm(key.name, sizeof(key.name)))
		return false;
	enabled = bpf_map_lookup_elem(&pfq_interactive_comms, &key);
	return enabled && *enabled;
}

/**
 * pfq_class_from_ioprio - Resolve the request priority class
 * @ioprio: encoded request I/O priority
 * @interactive: whether the current thread matches a configured comm
 *
 * Return: PFQ_SPECIAL_CLASS for an interactive thread, otherwise the I/O
 * class.
 */
static __always_inline u8 pfq_class_from_ioprio(u16 ioprio, bool interactive)
{
	if (interactive)
		return PFQ_SPECIAL_CLASS;
	return pfq_ioprio_to_class(ioprio);
}

/**
 * pfq_class_from_bio - Resolve the bio priority class
 * @bio: bio supplying the I/O priority
 * @interactive: whether the current thread matches a configured comm
 *
 * Return: PFQ_SPECIAL_CLASS for an interactive thread, otherwise the I/O
 * class.
 */
static __always_inline u8 pfq_class_from_bio(struct bio *bio, bool interactive)
{
	if (interactive)
		return PFQ_SPECIAL_CLASS;
	return pfq_ioprio_to_class(bio->bi_ioprio);
}

static __always_inline u8 pfq_ioprio_level(u16 ioprio)
{
	return ioprio & 0x7;
}

/**
 * pfq_rq_io_type - Classify request direction and synchrony
 * @rq: request supplying the operation and REQ_SYNC flag
 *
 * Match rq_data_dir(): odd opcodes use write queues, with REQ_SYNC
 * selecting the synchronous-write queue.
 *
 * Return: PFQ_READ, PFQ_WRITE or PFQ_SYNC_WRITE.
 */
static __always_inline u8 pfq_rq_io_type(struct request *rq)
{
	if ((rq->cmd_flags & REQ_OP_MASK) & 1)
		return ((rq->cmd_flags & PFQ_REQ_SYNC) ? PFQ_SYNC_WRITE : PFQ_WRITE);
	return PFQ_READ;
}

static __always_inline u8 pfq_bio_io_type(struct bio *bio)
{
	if ((bio->bi_opf & REQ_OP_MASK) & 1)
		return ((bio->bi_opf & PFQ_REQ_SYNC) ? PFQ_SYNC_WRITE : PFQ_WRITE);
	return PFQ_READ;
}

/*
 * Index fifo_expire_ns / max_batch with constant offsets only.
 * Even a clamped variable index is rejected on PTR_TO_BTF_ID.
 */
static __always_inline u64 pfq_fifo_expire_ns(struct pfq_disk_data *dd, u8 io_type)
{
	if (io_type == PFQ_READ)
		return dd->fifo_expire_ns[PFQ_READ];
	if (io_type == PFQ_SYNC_WRITE)
		return dd->fifo_expire_ns[PFQ_SYNC_WRITE];
	return dd->fifo_expire_ns[PFQ_WRITE];
}

static __always_inline u32 pfq_max_batch(struct pfq_disk_data *dd, u8 io_type)
{
	if (io_type == PFQ_READ)
		return dd->max_batch[PFQ_READ];
	if (io_type == PFQ_SYNC_WRITE)
		return dd->max_batch[PFQ_SYNC_WRITE];
	return dd->max_batch[PFQ_WRITE];
}

/**
 * pfq_queue_index - Compute the logical queue index
 * @pq_class: PFQ priority class
 * @level: priority level; invalid levels use IOPRIO_BE_NORM
 * @io_type: PFQ_READ, PFQ_WRITE or PFQ_SYNC_WRITE
 *
 * Return: Flat index for the class, priority level and I/O type.
 */
static __always_inline u32 pfq_queue_index(u8 pq_class, u8 level, u8 io_type)
{
	if (level >= PFQ_PRIO_LEVELS)
		level = PFQ_IOPRIO_BE_NORM;
	return PFQ_INDEX(pq_class, level, io_type);
}

/**
 * pfq_rq_ioprio - Read request priority with a best-effort fallback
 * @rq: request whose first bio supplies the I/O priority
 *
 * Internal requests without a bio use normal best-effort priority.
 *
 * Return: Encoded bio priority, or normal best-effort priority without a
 * bio.
 */
static __always_inline u16 pfq_rq_ioprio(struct request *rq)
{
	if (rq->bio)
		return rq->bio->bi_ioprio;
	return (PFQ_IOPRIO_CLASS_BE << PFQ_IOPRIO_CLASS_SHIFT) | PFQ_IOPRIO_BE_NORM;
}

static __always_inline u32 pfq_rq_qid(struct request *rq, bool interactive)
{
	u16 ioprio = pfq_rq_ioprio(rq);

	return pfq_queue_index(pfq_class_from_ioprio(ioprio, interactive),
			       pfq_ioprio_level(ioprio),
			       pfq_rq_io_type(rq));
}

static __always_inline u32 pfq_bio_qid(struct bio *bio, bool interactive)
{
	return pfq_queue_index(pfq_class_from_bio(bio, interactive),
			       pfq_ioprio_level(bio->bi_ioprio),
			       pfq_bio_io_type(bio));
}

/**
 * pfq_prio_coeff - Choose the per-level weight increment
 * @queue: queue supplying the priority class and I/O type
 *
 * Return: Read or write coefficient, with a larger value for SPECIAL
 * reads.
 */
static __always_inline u32 pfq_prio_coeff(struct pfq_queue_data *queue)
{
	if (queue->pq_class == PFQ_SPECIAL_CLASS && queue->io_type == PFQ_READ)
		return PFQ_PRIO_LEVEL_COEFF_SP_READ;
	if (queue->io_type == PFQ_READ)
		return PFQ_PRIO_LEVEL_COEFF_READ;
	return PFQ_PRIO_LEVEL_COEFF_WRITE;
}

/**
 * pfq_calc_weight - Calculate the virtual-time weight
 * @dd: disk state supplying the configured base weight
 * @queue: queue supplying class, priority level and I/O type
 *
 * Higher weights slow virtual-time growth and give more service.
 * SPECIAL reads receive an additional percentage multiplier.
 *
 * Context: Caller holds @dd->lock.
 *
 * Return: Queue weight, with a minimum of one.
 */
static __always_inline u64 pfq_calc_weight(struct pfq_disk_data *dd,
					   struct pfq_queue_data *queue)
{
	u64 base = dd->weight_base, final;

	base += (PFQ_PRIO_LEVELS - 1 - queue->priority) * pfq_prio_coeff(queue);
	final = base;
	if (queue->pq_class == PFQ_SPECIAL_CLASS && queue->io_type == PFQ_READ)
		final = base * PFQ_WEIGHT_MULT_SPECIAL / 100;
	return final ? final : 1;
}

/**
 * pfq_apply_tunables - Apply a prefetched disk configuration
 * @dd: disk being configured
 * @tun: snapshot read from pfq_tunables before taking the lock
 *
 * Zero tunables select defaults. Apply the prefetched snapshot under
 * dd->lock before initializing queue weights.
 *
 * Context: Caller holds @dd->lock.
 */
static void pfq_apply_tunables(struct pfq_disk_data *dd,
			       const struct pfq_tunables *tun)
{
	if (tun->weight_base)
		dd->weight_base = tun->weight_base;
	else
		dd->weight_base = PFQ_WEIGHT_BASE_DEFAULT;

	if (tun->idle_delay_min_ms)
		dd->idle_delay_min_ms = tun->idle_delay_min_ms;
	else
		dd->idle_delay_min_ms = PFQ_IDLE_DELAY_MIN_MS_DEFAULT;

	if (tun->idle_delay_max_ms)
		dd->idle_delay_max_ms = tun->idle_delay_max_ms;
	else
		dd->idle_delay_max_ms = PFQ_IDLE_DELAY_MAX_MS_DEFAULT;

	if (tun->batch_read)
		dd->max_batch[PFQ_READ] = tun->batch_read;
	else
		dd->max_batch[PFQ_READ] = PFQ_BATCH_READ_DEFAULT;

	if (tun->batch_sync_write)
		dd->max_batch[PFQ_SYNC_WRITE] = tun->batch_sync_write;
	else
		dd->max_batch[PFQ_SYNC_WRITE] = PFQ_BATCH_SYNC_WRITE_DEFAULT;

	if (tun->batch_write)
		dd->max_batch[PFQ_WRITE] = tun->batch_write;
	else
		dd->max_batch[PFQ_WRITE] = PFQ_BATCH_WRITE_DEFAULT;
}

static __always_inline u64 pfq_distance(sector_t pos, u64 last_sector)
{
	if (pos >= last_sector)
		return pos - last_sector;
	return last_sector - pos;
}

/* Service tree ordering: lowest vtime first, tie-break by qid. */
static bool svc_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct pfq_queue_data *qa, *qb;

	qa = container_of(a, struct pfq_queue_data, svc_rb_node);
	qb = container_of(b, struct pfq_queue_data, svc_rb_node);
	if (qa->vtime != qb->vtime)
		return qa->vtime < qb->vtime;
	return qa->qid < qb->qid;
}

/*
 * Order by (qid, sector) using cached fields. Avoid request kptr exchanges
 * in the comparator; request release is not KF_SPINLOCK_SAFE.
 */
static bool rq_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct pfq_rq_core *na, *nb;

	na = container_of(a, struct pfq_rq_core, rb_node);
	nb = container_of(b, struct pfq_rq_core, rb_node);
	if (na->qid != nb->qid)
		return na->qid < nb->qid;
	return na->sector < nb->sector;
}

/* io_type FIFO tree: (qid, deadline, sector). */
static bool fifo_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct pfq_rq_core *na, *nb;

	na = container_of(a, struct pfq_rq_core, fifo_rb_node);
	nb = container_of(b, struct pfq_rq_core, fifo_rb_node);
	if (na->qid != nb->qid)
		return na->qid < nb->qid;
	if (na->fifo_deadline_ns != nb->fifo_deadline_ns)
		return na->fifo_deadline_ns < nb->fifo_deadline_ns;
	return na->sector < nb->sector;
}

/* Tag bit in request->elv.priv[1] after dispatch (see pfq_rq_bind_qid). */
#define PFQ_RQ_QID_TAG	0x80000000U

/*
 * UFQ owns elv.priv[0]. PFQ uses priv[1] for a non-owning core address while
 * queued, then a tagged qid after dispatch. BPF cannot write the slot
 * directly, so stores use the KF_SPINLOCK_SAFE kfunc.
 */
static __always_inline void pfq_rq_set_core(struct request *rq,
					    struct pfq_rq_core *core)
{
	__u64 addr = 0;

	/*
	 * Pass address as scalar: do not hand a ref-tracked MEM_ALLOC pointer
	 * into priv (non-owning cache only).
	 */
	bpf_probe_read_kernel(&addr, sizeof(addr), &core);
	bpf_request_set_elv_priv1(rq, addr);
}

static __always_inline void pfq_rq_clear_node(struct request *rq)
{
	bpf_request_set_elv_priv1(rq, 0);
}

/*
 * Keep the dispatched queue identity for finish_req after the wrapper is
 * dropped. pfq_rq_bound_qid() checks both the tag and the encoded qid range.
 */
static __always_inline void pfq_rq_bind_qid(struct request *rq, u32 qid)
{
	bpf_request_set_elv_priv1(rq, (u64)(qid | PFQ_RQ_QID_TAG));
}

/* Must run before dd->lock: bpf_core_read() calls a probe-read helper. */
static __always_inline u32 pfq_rq_bound_qid(struct request *rq)
{
	u64 tag = 0;

	/* A C cast would retain the verifier pointer type. */
	if (bpf_core_read(&tag, sizeof(tag), &rq->elv.priv[1]))
		return PFQ_QID_NONE;

	/* Only accept encoded qids, never a live pfq_rq_core pointer. */
	if (!(tag & PFQ_RQ_QID_TAG) ||
	    (tag & ~(u64)PFQ_RQ_QID_TAG) >= PFQ_TOTAL_QUEUES)
		return PFQ_QID_NONE;
	return (u32)tag & ~PFQ_RQ_QID_TAG;
}

/*
 * Graph nodes are opaque and there is no parent-access kfunc. Find sector
 * neighbors by searching from the root using the available child kfuncs.
 */

/* Earliest FIFO deadline within qid. Caller holds dd->lock. */
static struct pfq_rq_core *
pfq_fifo_first_qid(struct bpf_rb_root *root, u32 qid)
{
	struct pfq_rq_core *c, *best = NULL;
	struct bpf_rb_node *node;
	int i;

	if (!root)
		return NULL;

	node = bpf_rbtree_root(root);
	for (i = 0; node && i < PFQ_RB_HEIGHT_MAX; i++) {
		c = container_of(node, struct pfq_rq_core, fifo_rb_node);
		if (c->qid < qid) {
			node = bpf_rbtree_right(root, node);
		} else {
			best = c;
			node = bpf_rbtree_left(root, node);
		}
	}
	if (!best || best->qid != qid)
		return NULL;
	return best;
}

/* Nearest sector >= @sector within this qid; tree ordered by (qid, sector). */
static struct pfq_rq_core *pfq_rq_tree_next(struct pfq_disk_data *dd,
					 struct pfq_queue_data *queue,
					 u64 sector)
{
	struct bpf_rb_root *root = pfq_rq_tree(dd, queue->qid);
	struct pfq_rq_core *core, *best = NULL;
	struct bpf_rb_node *node;
	int i;

	if (!root)
		return NULL;
	node = bpf_rbtree_root(root);
	for (i = 0; node && i < PFQ_RB_HEIGHT_MAX; i++) {
		core = container_of(node, struct pfq_rq_core, rb_node);
		if (core->qid < queue->qid ||
		    (core->qid == queue->qid && core->sector < sector)) {
			node = bpf_rbtree_right(root, node);
		} else {
			if (core->qid == queue->qid)
				best = core;
			node = bpf_rbtree_left(root, node);
		}
	}
	return best;
}

/* Nearest sector < @sector within this qid. */
static struct pfq_rq_core *pfq_rq_tree_prev(struct pfq_disk_data *dd,
					 struct pfq_queue_data *queue,
					 u64 sector)
{
	struct bpf_rb_root *root = pfq_rq_tree(dd, queue->qid);
	struct pfq_rq_core *core, *best = NULL;
	struct bpf_rb_node *node;
	int i;

	if (!root)
		return NULL;
	node = bpf_rbtree_root(root);
	for (i = 0; node && i < PFQ_RB_HEIGHT_MAX; i++) {
		core = container_of(node, struct pfq_rq_core, rb_node);
		if (core->qid > queue->qid ||
		    (core->qid == queue->qid && core->sector >= sector)) {
			node = bpf_rbtree_left(root, node);
		} else {
			if (core->qid == queue->qid)
				best = core;
			node = bpf_rbtree_right(root, node);
		}
	}
	return best;
}

/*
 * BPF v3 cannot directly encode acquire loads or release stores. A no-op CAS
 * reads the state with a full barrier (stronger than acquire); release XCHG
 * publishes preceding queue initialization or failure cleanup. Use these for
 * all accesses to a published disk header, including accesses under dd->lock.
 */
static __always_inline int pfq_init_state_load(struct pfq_disk_data *dd)
{
	return __sync_val_compare_and_swap(&dd->init_state,
					   PFQ_UNINITIALIZED,
					   PFQ_UNINITIALIZED);
}

static __always_inline void pfq_init_state_store(struct pfq_disk_data *dd,
					       int state)
{
	(void)__atomic_exchange_n(&dd->init_state, state, __ATOMIC_RELEASE);
}

/**
 * pfq_disk_lookup - Look up an initialized disk
 * @disk_id: request_queue::id used as the map key
 *
 * Acquire initialization before exposing a ready disk to callbacks.
 * UFQ must quiesce callbacks before exit_sched: the state check does not pin
 * the disk or its queue entries against teardown.
 *
 * Context: Caller must not hold a BPF spin lock.
 *
 * Return: Map-value pointer, or NULL if the disk is absent or not
 * initialized.
 */
static __always_inline struct pfq_disk_data *pfq_disk_lookup(int disk_id)
{
	struct pfq_disk_data *dd;

	dd = bpf_map_lookup_elem(&pfq_map, &disk_id);
	if (!dd || pfq_init_state_load(dd) != PFQ_INITIALIZED)
		return NULL;
	return dd;
}

/* Raw map lookup (init/exit only); ignores init_state. */
static __always_inline struct pfq_disk_data *pfq_disk_lookup_raw(int disk_id)
{
	return bpf_map_lookup_elem(&pfq_map, &disk_id);
}

/*
 * Reset special BTF fields with empty compound literals; a bulk memset
 * would generate accesses the verifier rejects.
 *
 * Keep this inlinable: noinline + compound-literal temps can leave a stack
 * address in R0 at subprog exit (verifier: cannot return stack pointer).
 */
static void pfq_disk_scratch_reset(struct pfq_disk_data *d)
{
	u32 i;

	d->lock = (struct bpf_spin_lock){};
	d->dispatch = (struct bpf_list_head){};
	d->service_tree = (struct bpf_rb_root){};
	for (i = 0; i < PFQ_RQ_TREES; i++) {
		d->rq_trees[i] = (struct bpf_rb_root){};
		d->fifo_trees[i] = (struct bpf_rb_root){};
	}
	d->disk_id = 0;
	d->vtime = 0;
	d->min_vtime = 0;
	d->last_sector = 0;
	d->nr_active = 0;
	d->nr_queued_total = 0;
	d->in_service_qid = PFQ_QID_NONE;
	d->in_service_dispatched = 0;
	d->waiting_idle = false;
	d->idle_queue_qid = PFQ_QID_NONE;
	d->idle_deadline_ns = 0;
	d->fifo_expire_ns[PFQ_READ] = 0;
	d->fifo_expire_ns[PFQ_WRITE] = 0;
	d->fifo_expire_ns[PFQ_SYNC_WRITE] = 0;
	d->max_batch[PFQ_READ] = 0;
	d->max_batch[PFQ_WRITE] = 0;
	d->max_batch[PFQ_SYNC_WRITE] = 0;
	d->weight_base = 0;
	d->idle_delay_min_ms = 0;
	d->idle_delay_max_ms = 0;
	d->init_state = PFQ_UNINITIALIZED;
}

/*
 * Publish an UNINITIALIZED disk header. BPF_NOEXIST prevents replacement of
 * an existing header; callers then claim initialization under that dd->lock.
 * Keep the header on init failure so concurrent callers share the same lock
 * and state until exit_sched.
 */
static int pfq_disk_create(int disk_id)
{
	struct pfq_disk_data *scratch;
	u32 zero = 0;

	scratch = bpf_map_lookup_elem(&pfq_disk_scratch, &zero);
	if (!scratch)
		return -ENOMEM;

	pfq_disk_scratch_reset(scratch);
	scratch->disk_id = disk_id;
	return bpf_map_update_elem(&pfq_map, &disk_id, scratch, BPF_NOEXIST);
}

/*
 * Only the INITIALIZING owner may create or unwind queue entries. Return 1
 * when this attempt created the stats entry, 0 when it reused an existing one.
 */
static int pfq_disk_create_queues(int disk_id)
{
	struct pfq_stats empty_stats = {};
	struct pfq_queue_data *queue;
	bool stats_created = false;
	int ret;
	u32 i;

	ret = bpf_map_update_elem(&pfq_stats_map, &disk_id, &empty_stats,
				  BPF_NOEXIST);
	if (ret == -EEXIST) {
		if (!pfq_stats_lookup(disk_id))
			return -ENOENT;
	} else if (ret) {
		return ret;
	} else {
		stats_created = true;
	}

	for (i = 0; i < PFQ_TOTAL_QUEUES; i++) {
		queue = bpf_obj_new(typeof(*queue));
		if (!queue) {
			ret = -ENOMEM;
			goto err_queues;
		}

		ret = pfq_queue_map_insert(disk_id, i, queue);
		if (ret) {
			bpf_obj_drop(queue);
			goto err_queues;
		}
	}

	return stats_created ? 1 : 0;

err_queues:
	pfq_queues_destroy(disk_id);
	if (stats_created)
		bpf_map_delete_elem(&pfq_stats_map, &disk_id);
	return ret;
}

/*
 * Keep map-value and queue-object loads in separate unoptimized subprograms.
 * Merging them can make the verifier reject one instruction used with
 * different pointer types.
 */
static __attribute__((noinline, optnone)) void
pfq_min_vtime_from_dd(struct pfq_disk_data *dd)
{
	dd->min_vtime = dd->vtime;
}

static __attribute__((noinline, optnone)) void
pfq_min_vtime_from_queue(struct pfq_disk_data *dd,
			 struct pfq_queue_data *queue)
{
	dd->min_vtime = queue->vtime;
}

static __noinline void pfq_refresh_min_vtime(struct pfq_disk_data *dd)
{
	struct pfq_queue_data *queue;
	struct bpf_rb_node *node;

	node = bpf_rbtree_first(&dd->service_tree);
	if (!node) {
		pfq_min_vtime_from_dd(dd);
		return;
	}
	queue = container_of(node, struct pfq_queue_data, svc_rb_node);
	pfq_min_vtime_from_queue(dd, queue);
}

/**
 * pfq_insert_queue_to_service_tree - Insert a queue at its current vtime
 * @dd: disk whose service tree receives the queue
 * @queue: queue for which the caller retains an owning reference
 *
 * Acquire a second owning reference for the service tree without consuming
 * the caller's @queue reference. bpf_rbtree_add() consumes tree_q on both
 * success and failure, so do not drop tree_q again on insertion failure.
 *
 * Context: Caller holds @dd->lock.
 *
 * Return: true if inserted, or false if reference acquisition or insertion
 * fails.
 */
static bool pfq_insert_queue_to_service_tree(struct pfq_disk_data *dd,
					     struct pfq_queue_data *queue)
{
	struct pfq_queue_data *tree_q;
	int ret;

	tree_q = bpf_refcount_acquire(queue);
	if (!tree_q)
		return false;

	ret = bpf_rbtree_add(&dd->service_tree, &tree_q->svc_rb_node, svc_less);
	if (ret)
		return false;
	pfq_refresh_min_vtime(dd);
	return true;
}

static void pfq_deactivate_queue(struct pfq_disk_data *dd,
				 struct pfq_queue_data *queue)
{
	if (!queue->in_tree)
		return;
	queue->in_tree = false;
	if (dd->nr_active > 0)
		dd->nr_active--;
}

/*
 * Detach and deactivate atomically. Return the tree's owning ref for the
 * caller to drop outside dd->lock; never unlock inside this helper.
 */
static struct pfq_queue_data *
pfq_remove_queue_from_service_tree_locked(struct pfq_disk_data *dd,
					 struct pfq_queue_data *queue)
{
	struct bpf_rb_node *removed;

	if (!queue->in_tree)
		return NULL;
	removed = bpf_rbtree_remove(&dd->service_tree, &queue->svc_rb_node);
	if (!removed)
		return NULL;

	pfq_deactivate_queue(dd, queue);
	pfq_refresh_min_vtime(dd);
	return container_of(removed, struct pfq_queue_data, svc_rb_node);
}

/* Retain the tree reference and active count while updating its position. */
static void pfq_requeue_in_service_tree(struct pfq_disk_data *dd,
					struct pfq_queue_data *queue)
{
	struct pfq_queue_data *owned;
	struct bpf_rb_node *removed;
	int ret;

	if (!queue->in_tree)
		return;

	removed = bpf_rbtree_remove(&dd->service_tree, &queue->svc_rb_node);
	if (!removed)
		goto deactivate;

	owned = container_of(removed, struct pfq_queue_data, svc_rb_node);
	ret = bpf_rbtree_add(&dd->service_tree, &owned->svc_rb_node, svc_less);
	if (ret)
		goto deactivate;

	pfq_refresh_min_vtime(dd);
	return;

deactivate:
	pfq_deactivate_queue(dd, queue);
}

/**
 * pfq_activate_queue - Activate a queue at the virtual-time floor
 * @dd: per-disk scheduler state
 * @queue: queue receiving its first queued request
 *
 * Publish tree membership and active accounting together under dd->lock.
 * A newly active queue starts no earlier than the disk's virtual-time floor.
 *
 * Context: Caller holds @dd->lock.
 *
 * Return: true if already active or successfully activated, otherwise
 * false.
 */
static bool pfq_activate_queue(struct pfq_disk_data *dd,
			       struct pfq_queue_data *queue)
{
	if (queue->in_tree)
		return true;

	if (queue->vtime < dd->vtime)
		queue->vtime = dd->vtime;

	if (!pfq_insert_queue_to_service_tree(dd, queue))
		return false;

	queue->in_tree = true;
	dd->nr_active++;
	return true;
}

/**
 * pfq_queue_snap - Snapshot queue scheduling fields
 * @queue: logical queue being operated on
 * @nq: output request count
 * @in_tree: output service-tree membership flag
 *
 * Caller holds dd->lock when reading queue scheduling fields.
 *
 * Context: Caller holds the disk lock.
 */
static __always_inline void pfq_queue_snap(struct pfq_queue_data *queue,
					   u32 *nq, bool *in_tree)
{
	*nq = queue->nr_queued;
	*in_tree = queue->in_tree;
}

/**
 * pfq_queue_nq_get - Read the queued request count
 * @queue: queue whose pending requests are counted
 *
 * Context: Caller holds the disk lock.
 *
 * Return: Number of requests queued in the logical queue.
 */
static __always_inline u32 pfq_queue_nq_get(struct pfq_queue_data *queue)
{
	bool in_tree;
	u32 nq;

	pfq_queue_snap(queue, &nq, &in_tree);
	return nq;
}

/* Clear SPECIAL+READ idle-hold state without removing queue from tree. */
static void pfq_clear_idle_hold(struct pfq_disk_data *dd)
{
	dd->waiting_idle = false;
	WRITE_ONCE(dd->idle_queue_qid, PFQ_QID_NONE);
	dd->idle_deadline_ns = 0;
}

/*
 * Clang may merge adjacent u32 stores into u64; verifier rejects that as
 * access beyond BTF member bounds (e.g. nr_active).
 */
static __always_inline void pfq_compiler_barrier(void)
{
	asm volatile("" ::: "memory");
}

static void pfq_disk_reset_counters(struct pfq_disk_data *dd)
{
	dd->nr_active = 0;
	pfq_compiler_barrier();
	dd->nr_queued_total = 0;
	pfq_compiler_barrier();
	WRITE_ONCE(dd->in_service_qid, PFQ_QID_NONE);
	pfq_compiler_barrier();
	dd->in_service_dispatched = 0;
}

/* Cancel the reservation when its queue receives new work. */
static void pfq_stop_idle_hold(struct pfq_disk_data *dd,
			       struct pfq_queue_data *queue)
{
	if (dd->waiting_idle && dd->idle_queue_qid == queue->qid)
		pfq_clear_idle_hold(dd);
}

/**
 * pfq_expire_idle_hold - Expire a SPECIAL read reservation
 * @dd: per-disk scheduler state
 * @now: boot time sampled before taking the disk lock
 * @cleanup: prefetched queue and output detached service reference
 *
 * Caller holds dd->lock and has prefetched cleanup->queue. Revalidate the
 * queue and current deadline; a stale or missing prefetch defers expiry.
 * cleanup->service must be NULL on entry. Detached and prefetched references
 * are released after the caller's final unlock.
 *
 * Context: Caller holds @dd->lock.
 */
static void pfq_expire_idle_hold(struct pfq_disk_data *dd, u64 now,
				 struct pfq_idle_cleanup *cleanup)
{
	struct pfq_queue_data *queue = cleanup->queue;
	u32 qid;

	if (!queue || !dd->waiting_idle ||
	    dd->idle_queue_qid != queue->qid || now < dd->idle_deadline_ns)
		return;

	qid = queue->qid;
	pfq_clear_idle_hold(dd);
	if (dd->in_service_qid == qid)
		WRITE_ONCE(dd->in_service_qid, PFQ_QID_NONE);
	if (!queue->nr_queued)
		cleanup->service =
			pfq_remove_queue_from_service_tree_locked(dd, queue);
}

/**
 * pfq_choose_core - Choose between cached dispatch candidates
 * @c1: first candidate, possibly NULL
 * @c2: second candidate, possibly NULL
 * @last_sector: end sector of the last fair-queue dispatch
 *
 * Prefer metadata, then smaller seek distance, then the lower sector.
 *
 * Context: Caller holds the disk lock.
 *
 * Return: Preferred non-owning candidate, or NULL if both candidates are
 * NULL.
 */
static __always_inline struct pfq_rq_core *
pfq_choose_core(struct pfq_rq_core *c1, struct pfq_rq_core *c2,
		u64 last_sector)
{
	u64 d1, d2, s1, s2;

	if (!c1 || c1 == c2)
		return c2;
	if (!c2)
		return c1;

	if (c1->is_meta && !c2->is_meta)
		return c1;
	if (!c1->is_meta && c2->is_meta)
		return c2;

	s1 = c1->sector;
	s2 = c2->sector;
	d1 = pfq_distance(s1, last_sector);
	d2 = pfq_distance(s2, last_sector);
	if (d1 < d2)
		return c1;
	if (d2 < d1)
		return c2;
	return s1 <= s2 ? c1 : c2;
}

/**
 * pfq_check_fifo_impl - Check the earliest FIFO deadline
 * @dd: per-disk scheduler state
 * @queue: queue whose FIFO deadline is checked
 * @last: node to reject if it is the earliest node, possibly NULL
 * @now: boot time used to check the deadline
 *
 * Return the queue's earliest node if expired and different from last.
 * The result is non-owning and valid only while dd->lock is held.
 *
 * Context: Caller holds @dd->lock.
 *
 * Return: Non-owning expired node, or NULL if absent, unexpired or equal
 * to @last.
 */
static __noinline struct pfq_rq_core *
pfq_check_fifo_impl(struct pfq_disk_data *dd, struct pfq_queue_data *queue,
		    struct pfq_rq_core *last, u64 now)
{
	struct bpf_rb_root *fifo;
	struct pfq_rq_core *core;

	fifo = pfq_fifo_tree(dd, queue->qid);
	if (!fifo)
		return NULL;

	core = pfq_fifo_first_qid(fifo, queue->qid);
	if (!core || core == last || now < core->fifo_deadline_ns)
		return NULL;

	return core;
}

/**
 * pfq_check_fifo - Check for an expired FIFO request
 * @dd: per-disk scheduler state
 * @queue: queue whose FIFO deadline is checked
 * @last: node to reject if it is the earliest node, possibly NULL
 * @now: boot time used to check the deadline
 *
 * Context: Caller holds @dd->lock.
 *
 * Return: Non-owning expired node, or NULL if absent, unexpired or equal
 * to @last.
 */
static struct pfq_rq_core *pfq_check_fifo(struct pfq_disk_data *dd,
					  struct pfq_queue_data *queue,
					  struct pfq_rq_core *last, u64 now)
{
	return pfq_check_fifo_impl(dd, queue, last, now);
}

/* FIFO expiry wins; otherwise compare candidates on either side of the head. */
static struct pfq_rq_core *pfq_update_next_rq(struct pfq_disk_data *dd,
					    struct pfq_queue_data *queue,
					    u64 now)
{
	struct pfq_rq_core *next_rn, *prev_rn, *fifo_rn;

	fifo_rn = pfq_check_fifo(dd, queue, NULL, now);
	if (fifo_rn)
		return fifo_rn;

	next_rn = pfq_rq_tree_next(dd, queue, dd->last_sector);
	prev_rn = pfq_rq_tree_prev(dd, queue, dd->last_sector);
	return pfq_choose_core(next_rn, prev_rn, dd->last_sector);
}

/**
 * pfq_reposition_rq_in_tree - Reposition a request after a front merge
 * @dd: per-disk scheduler state
 * @queue: queue containing the merged request
 * @rn: non-owning wrapper whose cached sector has been updated
 *
 * Reposition after a front merge; caller has updated rn->sector and holds
 * dd->lock. Preserve the FIFO deadline and FIFO-tree reference. If re-add
 * fails, the FIFO tree keeps rn alive and dequeue must handle that alone.
 *
 * Context: Caller holds @dd->lock.
 *
 * Return: true if reinserted, otherwise false.
 */
static bool pfq_reposition_rq_in_tree(struct pfq_disk_data *dd,
				      struct pfq_queue_data *queue,
				      struct pfq_rq_core *rn)
{
	struct bpf_rb_root *rq_root = pfq_rq_tree(dd, queue->qid);
	struct pfq_rq_core *tree_core;

	if (!rq_root)
		return false;

	tree_core = pfq_rq_tree_remove_take(rq_root, &rn->rb_node);
	if (!tree_core)
		return false;

	if (bpf_rbtree_add(rq_root, &tree_core->rb_node, rq_less))
		return false;
	return true;
}

/*
 * Caller holds dd->lock. A NULL queue adjusts only the disk total.
 */
static __always_inline void pfq_account_inc(struct pfq_disk_data *dd,
					    struct pfq_queue_data *queue)
{
	if (queue)
		queue->nr_queued++;
	dd->nr_queued_total++;
}

static __always_inline void pfq_account_dec(struct pfq_disk_data *dd,
					    struct pfq_queue_data *queue)
{
	if (queue)
		queue->nr_queued--;
	dd->nr_queued_total--;
}

/* Owning insert references retained until the callback's unlocked exit. */
struct pfq_insert_cleanup {
	struct pfq_dispatch_node *dn;
	struct pfq_queue_data *queue;
	struct pfq_rq_core *list_ref;
	struct pfq_rq_core *extra;
	struct pfq_rq_core *core;
	struct request *stale;
	struct request *req;
	struct pfq_stats *stats;
};

/*
 * Release each owning reference separately, even when both refer to the
 * same wrapper. list_n is the FIFO-tree reference, despite its name.
 */
static __noinline void pfq_drop_rq_container_refs(struct pfq_rq_core *list_n,
						  struct pfq_rq_core *tree_n)
{
	if (list_n)
		bpf_obj_drop(list_n);
	if (tree_n)
		bpf_obj_drop(tree_n);
}

/* Caller has completed all state updates and released dd->lock. */
static void pfq_insert_cleanup(struct pfq_insert_cleanup *cleanup)
{
	if (cleanup->req)
		bpf_request_release(cleanup->req);
	if (cleanup->stale)
		bpf_request_release(cleanup->stale);
	pfq_drop_rq_container_refs(cleanup->list_ref, cleanup->core);
	if (cleanup->extra)
		bpf_obj_drop(cleanup->extra);
	if (cleanup->dn)
		bpf_obj_drop(cleanup->dn);
	if (cleanup->queue)
		bpf_obj_drop(cleanup->queue);
}

/**
 * pfq_finish_front_bio_merge - Update the front-merge survivor index
 * @dd: per-disk scheduler state
 * @queue: queue containing the surviving request
 * @rn: non-owning wrapper of the surviving request
 * @new_sector: request start sector after the bio merge
 *
 * Update the survivor's cached sector before repositioning under dd->lock.
 *
 * Context: Caller holds @dd->lock.
 */
static void pfq_finish_front_bio_merge(struct pfq_disk_data *dd,
				       struct pfq_queue_data *queue,
				       struct pfq_rq_core *rn,
				       u64 new_sector)
{
	rn->sector = new_sector;
	(void)pfq_reposition_rq_in_tree(dd, queue, rn);
}

/**
 * pfq_dequeue_rq_core_locked - Detach a request from both indexes
 * @dd: per-disk scheduler state
 * @queue: queue containing the request
 * @rn: non-NULL, non-owning request wrapper
 * @cleanup: output tree references to release after unlocking
 *
 * Detach rn and transfer its request reference without unlocking dd->lock.
 * A failed reposition may have left only the FIFO-tree reference. Transfer
 * each removed reference to cleanup for release after unlocking.
 *
 * Context: Caller holds @dd->lock.
 *
 * Return: Owning request reference, or NULL if no request can be taken.
 */
static __noinline struct request *
pfq_dequeue_rq_core_locked(struct pfq_disk_data *dd,
			   struct pfq_queue_data *queue,
			   struct pfq_rq_core *rn,
			   struct pfq_dispatch_cleanup *cleanup)
{
	struct bpf_rb_root *rq_root = pfq_rq_tree(dd, queue->qid);
	struct bpf_rb_root *fifo_root = pfq_fifo_tree(dd, queue->qid);
	struct pfq_rq_core *list_n, *tree_n;
	bool unlinked = false;
	struct request *rq;

	tree_n = pfq_rq_tree_remove_take(rq_root, &rn->rb_node);
	if (tree_n)
		list_n = pfq_fifo_tree_remove_take(fifo_root,
						   &tree_n->fifo_rb_node);
	else
		list_n = pfq_fifo_tree_remove_take(fifo_root, &rn->fifo_rb_node);

	if (tree_n) {
		rq = bpf_kptr_xchg(&tree_n->req, NULL);
		unlinked = true;
	} else if (list_n) {
		rq = bpf_kptr_xchg(&list_n->req, NULL);
		unlinked = true;
	} else {
		rq = NULL;
	}

	if (unlinked)
		pfq_account_dec(dd, queue);
	cleanup->rq_node = tree_n;
	cleanup->fifo_node = list_n;
	return rq;
}

/**
 * pfq_undo_insert_activate_fail - Roll back a failed queue activation
 * @dd: per-disk scheduler state
 * @queue: queue whose activation failed
 * @held: owning wrapper reference transferred to cleanup
 * @rq: request whose non-owning private cache must be cleared
 * @cleanup: output references to release at the callback exit
 *
 * Roll back failed activation under dd->lock. Consume held and transfer
 * all owning references to cleanup for release at the callback's exit.
 *
 * Context: Caller holds @dd->lock.
 *
 * Return: -ENOMEM.
 */
static __noinline int
pfq_undo_insert_activate_fail(struct pfq_disk_data *dd,
			      struct pfq_queue_data *queue,
			      struct pfq_rq_core *held,
			      struct request *rq,
			      struct pfq_insert_cleanup *cleanup)
{
	struct bpf_rb_root *rq_root = pfq_rq_tree(dd, queue->qid);
	struct bpf_rb_root *fifo_root = pfq_fifo_tree(dd, queue->qid);
	struct pfq_rq_core *list_n, *tree_n;
	struct request *old;
	bool unlinked = false;

	pfq_rq_clear_node(rq);

	/*
	 * Match pfq_dequeue_rq_core_locked control flow so clang does not emit
	 * pointer |= pointer for (tree_n || list_n).
	 */
	tree_n = pfq_rq_tree_remove_take(rq_root, &held->rb_node);
	if (tree_n)
		list_n = pfq_fifo_tree_remove_take(fifo_root,
						   &tree_n->fifo_rb_node);
	else
		list_n = pfq_fifo_tree_remove_take(fifo_root,
						   &held->fifo_rb_node);

	if (tree_n) {
		old = bpf_kptr_xchg(&tree_n->req, NULL);
		unlinked = true;
	} else if (list_n) {
		old = bpf_kptr_xchg(&list_n->req, NULL);
		unlinked = true;
	} else {
		old = bpf_kptr_xchg(&held->req, NULL);
	}

	if (unlinked)
		pfq_account_dec(dd, queue);
	cleanup->req = old;
	cleanup->list_ref = list_n;
	cleanup->core = tree_n;
	cleanup->extra = held;
	return -ENOMEM;
}

/**
 * pfq_insert_core_locked - Insert a request into both indexes
 * @dd: per-disk scheduler state
 * @queue: target logical queue
 * @core: owning wrapper reference consumed by insertion or cleanup
 * @rq: incoming request with its non-owning private cache set
 * @cleanup: output temporary or detached references for cleanup
 *
 * Each request index consumes one owning reference. Keep dd->lock held
 * through insertion and activation; return temporary or detached references
 * through cleanup on either success or failure.
 *
 * Context: Caller holds @dd->lock.
 *
 * Return: 0 on success, or a negative errno after preparing deferred
 * cleanup.
 */
static __noinline int
pfq_insert_core_locked(struct pfq_disk_data *dd,
		       struct pfq_queue_data *queue,
		       struct pfq_rq_core *core,
		       struct request *rq,
		       struct pfq_insert_cleanup *cleanup)
{
	struct pfq_rq_core *list_ref, *list_n, *tree_n, *held = NULL;
	struct bpf_rb_root *rq_root = pfq_rq_tree(dd, queue->qid);
	struct bpf_rb_root *fifo_root = pfq_fifo_tree(dd, queue->qid);
	struct request *old;

	list_ref = bpf_refcount_acquire(core);
	if (!list_ref) {
		old = bpf_kptr_xchg(&core->req, NULL);
		pfq_rq_clear_node(rq);
		cleanup->req = old;
		cleanup->core = core;
		return -ENOMEM;
	}

	if (!rq_root || bpf_rbtree_add(rq_root, &core->rb_node, rq_less)) {
		old = bpf_kptr_xchg(&list_ref->req, NULL);
		pfq_rq_clear_node(rq);
		cleanup->req = old;
		/* Failed rbtree_add consumes core; a missing root does not. */
		if (!rq_root)
			cleanup->core = core;
		cleanup->list_ref = list_ref;
		return -EINVAL;
	}
	if (!fifo_root ||
	    bpf_rbtree_add(fifo_root, &list_ref->fifo_rb_node, fifo_less)) {
		pfq_rq_clear_node(rq);
		tree_n = pfq_rq_tree_remove_take(rq_root, &core->rb_node);
		old = tree_n ? bpf_kptr_xchg(&tree_n->req, NULL) : NULL;
		cleanup->req = old;
		cleanup->core = tree_n;
		/* A failed add consumes list_ref; a missing root does not. */
		if (!fifo_root)
			cleanup->list_ref = list_ref;
		return -EINVAL;
	}

	/*
	 * Keep an owning reference for activation rollback or final cleanup.
	 * Successful insertion retains both tree references independently.
	 */
	held = bpf_refcount_acquire(core);
	if (!held) {
		pfq_rq_clear_node(rq);
		tree_n = pfq_rq_tree_remove_take(rq_root, &core->rb_node);
		list_n = tree_n ?
			pfq_fifo_tree_remove_take(fifo_root,
						  &tree_n->fifo_rb_node) :
			NULL;
		old = tree_n ? bpf_kptr_xchg(&tree_n->req, NULL) : NULL;
		cleanup->req = old;
		cleanup->list_ref = list_n;
		cleanup->core = tree_n;
		return -ENOMEM;
	}

	pfq_account_inc(dd, queue);

	if (queue->in_tree) {
		pfq_stop_idle_hold(dd, queue);
		goto success_defer_held;
	}
	if (pfq_activate_queue(dd, queue))
		goto success_defer_held;

	return pfq_undo_insert_activate_fail(dd, queue, held, rq, cleanup);

success_defer_held:
	cleanup->extra = held;
	return 0;
}

/**
 * pfq_update_queue_vtime - Charge virtual time for a dispatch
 * @dd: disk supplying the virtual-time floor
 * @queue: queue whose virtual time is charged
 * @sectors: number of sectors dispatched
 *
 * Context: Caller holds @dd->lock.
 */
static void pfq_update_queue_vtime(struct pfq_disk_data *dd,
				   struct pfq_queue_data *queue,
				   u32 sectors)
{
	u64 delta;

	if (queue->vtime < dd->vtime)
		queue->vtime = dd->vtime;
	delta = ((u64)sectors << PFQ_VTIME_SHIFT) / queue->weight;
	/* Integer truncation must not give small requests free service. */
	if (sectors && !delta)
		delta = 1;
	queue->vtime += delta;
}

/* Begin a new in-service batch on queue @qid. */
static void pfq_set_in_service(struct pfq_disk_data *dd, u32 qid)
{
	WRITE_ONCE(dd->in_service_qid, qid);
	dd->in_service_dispatched = 0;
}

/*
 * Keep an empty SPECIAL+READ queue selected until its deadline.
 * @random and @now are sampled before dd->lock; never drop the lock between
 * checking idle eligibility and publishing the hold.
 */
static void pfq_start_idle_hold(struct pfq_disk_data *dd,
			       struct pfq_queue_data *queue, u64 now, u32 random,
			       struct pfq_stats *stats)
{
	u64 range, extra = 0;

	if (!queue->in_tree || queue->nr_queued ||
	    dd->in_service_qid != queue->qid || dd->waiting_idle)
		return;

	/* Use u64 so the inclusive range cannot wrap for UINT_MAX tunables. */
	if (dd->idle_delay_max_ms >= dd->idle_delay_min_ms) {
		range = (u64)dd->idle_delay_max_ms - dd->idle_delay_min_ms + 1;
		extra = random % range;
	}

	WRITE_ONCE(dd->idle_queue_qid, queue->qid);
	dd->waiting_idle = true;
	dd->idle_deadline_ns = now +
		((u64)dd->idle_delay_min_ms + extra) * 1000000ULL;
	pfq_stat_add(stats, PFQ_STAT_IDLE_HOLD, 1);
}

/*
 * Return an owning queue reference under dd->lock. Revalidate the prefetched
 * current queue and use the latest batch state, including a new batch on
 * the same qid. A stale prefetch returns NULL without dequeuing. Transfer
 * removed service references to cleanup for release after unlocking.
 */
static struct pfq_queue_data *
pfq_select_next_queue_locked(struct pfq_disk_data *dd,
			     struct pfq_queue_data *current,
			     u64 now, u32 random,
			     struct pfq_dispatch_cleanup *cleanup)
{
	struct pfq_queue_data *queue;
	struct bpf_rb_node *node;

	if (current) {
		if (dd->in_service_qid != current->qid)
			return NULL;
	} else if (pfq_qid_valid(dd->in_service_qid)) {
		return NULL;
	}
	if (!dd->nr_active)
		return NULL;

	if (current) {
		if (current->nr_queued > 0) {
			if (dd->in_service_dispatched <
			    pfq_max_batch(dd, current->io_type))
				return bpf_refcount_acquire(current);
			if (current->in_tree)
				pfq_requeue_in_service_tree(dd, current);
		} else {
			if (current->pq_class == PFQ_SPECIAL_CLASS &&
			    current->io_type == PFQ_READ)
				pfq_start_idle_hold(dd, current, now, random,
						    cleanup->stats);
			if (dd->waiting_idle &&
			    dd->idle_queue_qid == current->qid)
				return bpf_refcount_acquire(current);
			cleanup->old_service =
				pfq_remove_queue_from_service_tree_locked(dd, current);
		}
		WRITE_ONCE(dd->in_service_qid, PFQ_QID_NONE);
	}

	node = bpf_rbtree_first(&dd->service_tree);
	if (!node)
		return NULL;
	queue = container_of(node, struct pfq_queue_data, svc_rb_node);
	pfq_set_in_service(dd, queue->qid);
	return bpf_refcount_acquire(queue);
}

/* Only the INITIALIZING owner may initialize queue fields. */
static int pfq_init_queue_fields(struct pfq_disk_data *dd, u32 idx)
{
	struct pfq_queue_data *queue = pfq_queue_scalar(dd, idx);

	if (!queue)
		return -ENOENT;

	queue->qid = idx;
	queue->pq_class = PFQ_GET_CLASS(idx);
	queue->priority = PFQ_GET_PRIO(idx);
	queue->io_type = PFQ_GET_TYPE(idx);
	queue->nr_queued = 0;
	queue->vtime = 0;
	queue->weight = pfq_calc_weight(dd, queue);
	queue->in_tree = false;
	return 0;
}

/**
 * pfq_disk_init - Reset disk scheduling state
 * @dd: unpublished disk state with tunables already applied
 *
 * Reset scheduling state under dd->lock before publishing initialized queues.
 * Tunables have already been applied; event counters are managed separately.
 *
 * Context: Caller holds @dd->lock.
 */
static void pfq_disk_init(struct pfq_disk_data *dd)
{
	dd->vtime = 0;
	dd->min_vtime = 0;
	dd->last_sector = 0;
	pfq_disk_reset_counters(dd);
	dd->waiting_idle = false;
	WRITE_ONCE(dd->idle_queue_qid, PFQ_QID_NONE);
	dd->idle_deadline_ns = 0;
	dd->fifo_expire_ns[PFQ_READ] = PFQ_READ_EXPIRE_NS;
	dd->fifo_expire_ns[PFQ_SYNC_WRITE] = PFQ_SYNC_WRITE_EXPIRE_NS;
	dd->fifo_expire_ns[PFQ_WRITE] = PFQ_WRITE_EXPIRE_NS;
}

/**
 * pfq_do_init_sched - Initialize disk state and logical queues
 * @q: request queue being initialized
 *
 * Initialize at elevator setup or lazily at insert after BPF attach.
 *
 * Claim UNINITIALIZED -> INITIALIZING under dd->lock before creating queues.
 * The owner stays INITIALIZING across unlocks, including failure cleanup.
 * Concurrent callers return -EAGAIN while initialization or cleanup is in
 * progress. Publish INITIALIZED on success or UNINITIALIZED after cleanup.
 *
 * Context: Caller must not hold a BPF spin lock.
 *
 * Return: 0 if ready, -EAGAIN if initialization is in progress, or another
 * negative errno on failure.
 */
static int pfq_do_init_sched(struct request_queue *q)
{
	struct pfq_tunables tun = {}, *map_tun;
	u32 tun_key = PFQ_TUNABLE_KEY, i;
	int id = q->id, ret, state;
	struct pfq_disk_data *dd;
	bool stats_created;

	dd = pfq_disk_lookup_raw(id);
	if (!dd) {
		ret = pfq_disk_create(id);
		if (ret && ret != -EEXIST)
			return ret;
		dd = pfq_disk_lookup_raw(id);
		if (!dd)
			return -ENOENT;
	}

	bpf_spin_lock(&dd->lock);
	state = pfq_init_state_load(dd);
	if (state != PFQ_UNINITIALIZED) {
		ret = state == PFQ_INITIALIZED ? 0 : -EAGAIN;
		bpf_spin_unlock(&dd->lock);
		return ret;
	}
	pfq_init_state_store(dd, PFQ_INITIALIZING);
	bpf_spin_unlock(&dd->lock);

	ret = pfq_disk_create_queues(id);
	if (ret < 0)
		goto reset_state;
	stats_created = ret > 0;

	map_tun = bpf_map_lookup_elem(&pfq_tunables, &tun_key);
	if (map_tun)
		tun = *map_tun;

	bpf_spin_lock(&dd->lock);
	pfq_apply_tunables(dd, &tun);
	pfq_disk_init(dd);
	for (i = 0; i < PFQ_TOTAL_QUEUES; i++) {
		ret = pfq_init_queue_fields(dd, i);
		if (ret)
			goto err_queues;
	}
	pfq_init_state_store(dd, PFQ_INITIALIZED);
	bpf_spin_unlock(&dd->lock);

	return 0;

err_queues:
	bpf_spin_unlock(&dd->lock);
	pfq_queues_destroy(id);
	if (stats_created)
		bpf_map_delete_elem(&pfq_stats_map, &id);
reset_state:
	/* Complete cleanup before another caller can claim initialization. */
	pfq_init_state_store(dd, PFQ_UNINITIALIZED);
	return ret;
}

/*
 * pfq_init_sched - Initialize a disk using the attached policy
 * @q: request queue switching to UFQ
 *
 * Return: 0 on success, or a negative errno.
 */
int BPF_STRUCT_OPS(pfq_init_sched, struct request_queue *q)
{
	return pfq_do_init_sched(q);
}

/* UFQ must quiesce this disk's callbacks before removing its state. */
int BPF_STRUCT_OPS(pfq_exit_sched, struct request_queue *q)
{
	struct pfq_disk_data *dd;
	int id = q->id;

	dd = pfq_disk_lookup_raw(id);
	if (dd) {
		pfq_init_state_store(dd, PFQ_UNINITIALIZED);
		pfq_queues_destroy(id);
	}

	bpf_map_delete_elem(&pfq_stats_map, &id);
	/* The value destructor releases graph nodes and request kptrs. */
	bpf_map_delete_elem(&pfq_map, &id);
	return 0;
}

/*
 * pfq_has_req - Report requests awaiting dispatch
 * @q: request queue being queried
 * @rqs_count: UFQ pending request count used if disk state is unavailable
 *
 * Report queued work, excluding empty idle reservations. If disk state is
 * unavailable, fall back to UFQ's count of requests awaiting dispatch.
 * Idle expiry is checked here; UFQ does not arrange an idle-expiry timer.
 *
 * Return: true if requests await dispatch, otherwise false.
 */
bool BPF_STRUCT_OPS(pfq_has_req, struct request_queue *q, int rqs_count)
{
	struct pfq_idle_cleanup idle_cleanup = {};
	struct pfq_disk_data *dd;
	bool has = false;
	int id = q->id;
	u64 now;

	dd = pfq_disk_lookup(id);
	if (!dd)
		return rqs_count > 0;

	now = pfq_now_ns();
	idle_cleanup.queue = pfq_queue_acquire(id, READ_ONCE(dd->idle_queue_qid));
	bpf_spin_lock(&dd->lock);
	pfq_expire_idle_hold(dd, now, &idle_cleanup);
	has = !bpf_list_empty(&dd->dispatch) || dd->nr_queued_total > 0;
	bpf_spin_unlock(&dd->lock);
	pfq_idle_cleanup(&idle_cleanup);
	return has;
}

/**
 * pfq_insert_normal - Insert a request into a fair queue
 * @dd: per-disk scheduler state
 * @rq: incoming request
 * @qid: queue index resolved before taking the disk lock
 * @now: boot time sampled before taking the disk lock
 * @cleanup: prefetched statistics and output references for cleanup
 *
 * Enter and leave unlocked. Prepare references before taking dd->lock, then
 * hold it through tree insertion, activation and accounting. Return all
 * temporary or detached references in cleanup for the callback's exit.
 *
 * Context: Caller must not hold @dd->lock.
 *
 * Return: 0 on success, or a negative errno.
 */
static int pfq_insert_normal(struct pfq_disk_data *dd, struct request *rq,
			       u32 qid, u64 now, struct pfq_insert_cleanup *cleanup)
{
	struct pfq_queue_data *queue;
	struct pfq_rq_core *core;
	struct request *acquired;
	int link_ret;

	queue = pfq_queue_acquire(dd->disk_id, qid);
	if (!queue)
		return -EINVAL;
	cleanup->queue = queue;

	core = bpf_obj_new(typeof(*core));
	if (!core)
		return -ENOMEM;

	acquired = bpf_request_acquire(rq);
	if (!acquired) {
		cleanup->core = core;
		return -EPERM;
	}

	/* The probe-read helper requires an unlocked context. */
	pfq_rq_set_core(rq, core);

	/* jiffies helpers forbidden under bpf_spin_lock. */
	unsigned long jnow = (unsigned long)bpf_jiffies64();
	unsigned long ft = (unsigned long)rq->fifo_time;
	u64 fifo_deadline_ns;

	if (ft > jnow)
		fifo_deadline_ns = pfq_jiffies_to_deadline_ns(ft, now);
	else
		/* dd->fifo_expire_ns read unlocked; stable after disk_init. */
		fifo_deadline_ns = now + pfq_fifo_expire_ns(dd, queue->io_type);

	bpf_spin_lock(&dd->lock);

	cleanup->stale = bpf_kptr_xchg(&core->req, acquired);

	core->qid = queue->qid;
	core->sector = rq->__sector;
	core->is_meta = !!(rq->cmd_flags & PFQ_REQ_META);
	core->fifo_deadline_ns = fifo_deadline_ns;

	link_ret = pfq_insert_core_locked(dd, queue, core, rq, cleanup);
	if (!link_ret) {
		pfq_stat_add(cleanup->stats, PFQ_STAT_INSERT_CNT, 1);
		pfq_stat_add(cleanup->stats, PFQ_STAT_INSERT_SIZE, rq->__data_len);
	}
	bpf_spin_unlock(&dd->lock);
	return link_ret;
}

/*
 * pfq_insert_req - Insert a request using the UFQ policy
 * @q: request queue receiving the request
 * @rq: incoming request
 * @flags: insertion flags; BLK_MQ_INSERT_AT_HEAD selects urgent dispatch
 *
 * Head inserts use the urgent dispatch list; other inserts use fair queues.
 * Retain idle-expiration references until the final callback cleanup.
 *
 * Return: 0 on success, or a negative errno for UFQ insert-error handling.
 */
int BPF_STRUCT_OPS(pfq_insert_req, struct request_queue *q,
		   struct request *rq, blk_insert_t flags)
{
	struct pfq_idle_cleanup idle_cleanup = {};
	struct pfq_insert_cleanup cleanup = {};
	struct pfq_dispatch_node *dn;
	struct pfq_disk_data *dd;
	struct request *acquired;
	struct pfq_stats *stats;
	int id = q->id, ret = 0;
	bool interactive;
	u32 qid = 0;
	u64 now;

	dd = pfq_disk_lookup(id);
	if (!dd) {
		/* Initialize after attach or retry an earlier failure. */
		ret = pfq_do_init_sched(q);
		if (ret)
			return ret;
		dd = pfq_disk_lookup(id);
		if (!dd)
			return -EINVAL;
	}

	interactive = pfq_current_is_interactive();
	if (!(flags & BLK_MQ_INSERT_AT_HEAD))
		qid = pfq_rq_qid(rq, interactive);
	now = pfq_now_ns();
	stats = pfq_stats_lookup(dd->disk_id);
	cleanup.stats = stats;
	idle_cleanup.queue = pfq_queue_acquire(id, READ_ONCE(dd->idle_queue_qid));
	bpf_spin_lock(&dd->lock);
	pfq_expire_idle_hold(dd, now, &idle_cleanup);
	bpf_spin_unlock(&dd->lock);

	if (flags & BLK_MQ_INSERT_AT_HEAD) {
		dn = bpf_obj_new(typeof(*dn));
		if (!dn) {
			ret = -ENOMEM;
			goto out;
		}
		acquired = bpf_request_acquire(rq);
		if (!acquired) {
			cleanup.dn = dn;
			ret = -EPERM;
			goto out;
		}
		bpf_spin_lock(&dd->lock);
		cleanup.stale = bpf_kptr_xchg(&dn->req, acquired);
		ret = pfq_dispatch_push_dn(&dd->dispatch, dn);
		if (!ret) {
			pfq_stat_add(stats, PFQ_STAT_AT_HEAD_CNT, 1);
			pfq_stat_add(stats, PFQ_STAT_AT_HEAD_SIZE, rq->__data_len);
		}
		bpf_spin_unlock(&dd->lock);
	} else {
		ret = pfq_insert_normal(dd, rq, qid, now, &cleanup);
		if (!ret && interactive)
			pfq_stat_add(stats, PFQ_STAT_INTERACTIVE, 1);
	}
out:
	if (ret)
		pfq_stat_add(stats, PFQ_STAT_INSERT_ERR, 1);
	pfq_idle_cleanup(&idle_cleanup);
	pfq_insert_cleanup(&cleanup);
	return ret;
}

/*
 * Commit post-dispatch service state without unlocking. Return any removed
 * service-tree ref for deferred release by the dispatch caller.
 */
static __always_inline struct pfq_queue_data *
pfq_reposition_after_dispatch_locked(struct pfq_disk_data *dd,
				     struct pfq_queue_data *queue,
				     bool force_requeue,
				     u64 now, u32 random,
				     struct pfq_stats *stats)
{
	struct pfq_queue_data *removed;

	if (queue->nr_queued > 0) {
		if (force_requeue)
			pfq_requeue_in_service_tree(dd, queue);
		return NULL;
	}
	if (queue->pq_class == PFQ_SPECIAL_CLASS && queue->io_type == PFQ_READ &&
	    dd->in_service_qid == queue->qid && queue->in_tree) {
		pfq_requeue_in_service_tree(dd, queue);
		pfq_start_idle_hold(dd, queue, now, random, stats);
		if (dd->waiting_idle && dd->idle_queue_qid == queue->qid)
			return NULL;
	}
	removed = pfq_remove_queue_from_service_tree_locked(dd, queue);
	if (dd->in_service_qid == queue->qid)
		WRITE_ONCE(dd->in_service_qid, PFQ_QID_NONE);
	return removed;
}

/**
 * pfq_dispatch_rq_from_queue_locked - Dequeue and charge a selected request
 * @dd: per-disk scheduler state
 * @queue: selected logical queue
 * @now: boot time used for FIFO expiry
 * @cleanup: output detached tree references for deferred release
 *
 * Pick, dequeue and charge virtual time with dd->lock held throughout.
 *
 * Context: Caller holds @dd->lock.
 *
 * Return: Owning request reference, or NULL if no request can be
 * dispatched.
 */
static struct request *
pfq_dispatch_rq_from_queue_locked(struct pfq_disk_data *dd,
				 struct pfq_queue_data *queue, u64 now,
				 struct pfq_dispatch_cleanup *cleanup)
{
	struct pfq_rq_core *rn;
	struct request *rq;
	u32 sectors;

	rn = pfq_update_next_rq(dd, queue, now);
	if (!rn)
		return NULL;

	rq = pfq_dequeue_rq_core_locked(dd, queue, rn, cleanup);
	if (!rq)
		return NULL;

	pfq_rq_bind_qid(rq, queue->qid);

	sectors = rq->__data_len >> SECTOR_SHIFT;
	dd->last_sector = rq->__sector + sectors;
	pfq_update_queue_vtime(dd, queue, sectors);

	return rq;
}

/*
 * pfq_dispatch_req - Dispatch the next UFQ request
 * @q: request queue being dispatched
 *
 * Prefetch the current queue and acquire newly selected queues from the
 * service tree. Idle expiry, selection, dequeue and accounting share one
 * lock hold; release detached and temporary references after unlocking.
 *
 * Return: Owning request reference, or NULL if no request is selected.
 */
struct request *BPF_STRUCT_OPS(pfq_dispatch_req, struct request_queue *q)
{
	struct pfq_queue_data *current, *queue = NULL;
	struct pfq_idle_cleanup idle_cleanup = {};
	struct pfq_dispatch_cleanup cleanup = {};
	struct pfq_dispatch_node *dn = NULL;
	bool at_head = false, more_batch;
	struct request *rq = NULL;
	struct pfq_disk_data *dd;
	struct bpf_list_node *ln;
	struct pfq_stats *stats;
	int id = q->id;
	u32 random, qid;
	u64 now;

	dd = pfq_disk_lookup(id);
	if (!dd)
		return NULL;

	now = pfq_now_ns();
	random = bpf_get_prandom_u32();
	stats = pfq_stats_lookup(dd->disk_id);
	qid = READ_ONCE(dd->in_service_qid);
	current = pfq_queue_acquire(id, qid);
	/* The idle hold belongs to current; share its prefetched reference. */
	idle_cleanup.queue = current;

	bpf_spin_lock(&dd->lock);
	pfq_expire_idle_hold(dd, now, &idle_cleanup);
	ln = bpf_list_pop_front(&dd->dispatch);
	if (ln) {
		dn = container_of(ln, struct pfq_dispatch_node, node);
		rq = bpf_kptr_xchg(&dn->req, NULL);
		at_head = true;
		goto out;
	}

	cleanup.stats = stats;
	/* Expiration may have cleared the current slot. */
	queue = pfq_select_next_queue_locked(dd,
			dd->in_service_qid == PFQ_QID_NONE ? NULL : current,
			now, random, &cleanup);
	if (!queue)
		goto out;

	rq = pfq_dispatch_rq_from_queue_locked(dd, queue, now, &cleanup);
	if (!rq)
		goto out;

	dd->in_service_dispatched++;
	/* Keep the queue in service until its batch budget is exhausted. */
	more_batch = pfq_queue_nq_get(queue) > 0 &&
		     dd->in_service_dispatched <
		     pfq_max_batch(dd, queue->io_type);
	cleanup.empty_service =
		pfq_reposition_after_dispatch_locked(dd, queue, !more_batch,
						    now, random, stats);

	/* Advance global vtime floor to lagging active queues. */
	if (dd->nr_active > 0 && dd->vtime != dd->min_vtime)
		dd->vtime = dd->min_vtime;

out:
	if (rq) {
		if (at_head) {
			pfq_stat_add(stats, PFQ_STAT_DISPATCH_AT_HEAD_CNT, 1);
			pfq_stat_add(stats, PFQ_STAT_DISPATCH_AT_HEAD_SIZE,
				     rq->__data_len);
		} else {
			pfq_stat_add(stats, PFQ_STAT_DISPATCH_CNT, 1);
			pfq_stat_add(stats, PFQ_STAT_DISPATCH_SIZE, rq->__data_len);
		}
	}
	bpf_spin_unlock(&dd->lock);
	pfq_idle_cleanup(&idle_cleanup);
	pfq_drop_rq_container_refs(cleanup.fifo_node, cleanup.rq_node);
	if (cleanup.old_service)
		bpf_obj_drop(cleanup.old_service);
	if (cleanup.empty_service)
		bpf_obj_drop(cleanup.empty_service);
	if (queue)
		bpf_obj_drop(queue);
	if (dn)
		bpf_obj_drop(dn);
	return rq;
}

/*
 * pfq_finish_req - Account completion and consider idle hold
 * @rq: completed request carrying its dispatched queue identity
 *
 * Account completions for initialized disks. The qid bound at dispatch
 * identifies whether an empty SPECIAL+READ queue still owns the service
 * slot and may start an idle hold.
 */
void BPF_STRUCT_OPS(pfq_finish_req, struct request *rq)
{
	struct pfq_queue_data *queue = NULL;
	struct pfq_disk_data *dd;
	struct pfq_stats *stats;
	u32 rq_qid, random;
	u64 now;
	int id;

	if (!rq || !rq->q)
		return;

	id = rq->q->id;
	dd = pfq_disk_lookup(id);
	if (!dd)
		return;

	rq_qid = pfq_rq_bound_qid(rq);
	now = pfq_now_ns();
	random = bpf_get_prandom_u32();
	stats = pfq_stats_lookup(dd->disk_id);
	queue = pfq_queue_acquire(id, rq_qid);
	bpf_spin_lock(&dd->lock);

	pfq_stat_add(stats, PFQ_STAT_FINISH_CNT, 1);
	pfq_stat_add(stats, PFQ_STAT_FINISH_SIZE,
		     (u64)rq->stats_sectors << SECTOR_SHIFT);

	/* The service slot may have changed while acquiring the bound queue. */
	if (!queue || rq_qid != dd->in_service_qid)
		goto out;

	{
		bool may_idle = false;

		if (queue->pq_class == PFQ_SPECIAL_CLASS &&
		    queue->io_type == PFQ_READ &&
		    queue->in_tree && !queue->nr_queued)
			may_idle = true;
		if (may_idle && !dd->waiting_idle)
			pfq_start_idle_hold(dd, queue, now, random, stats);
	}

out:
	pfq_rq_clear_node(rq);
	bpf_spin_unlock(&dd->lock);
	if (queue)
		bpf_obj_drop(queue);
}

/* Group arguments to stay within the BPF subprogram limit of five. */
struct pfq_adj_find_ctl {
	sector_t probe_start;
	sector_t probe_end;
	struct pfq_rq_core **out_rn;
	struct request **out_stale;
	struct request **out_req;
};

/**
 * pfq_rq_tree_find_adjacent - Find a queued sector-adjacent request
 * @dd: per-disk scheduler state
 * @queue: logical queue to search
 * @ctl: probe sector range and output wrapper/request references
 *
 * Find an adjacent request within queue's qid with dd->lock held. Return
 * its owning request reference in ctl->out_req and a non-owning wrapper in
 * ctl->out_rn. The caller must restore the request or commit the merge
 * before unlocking. Unexpected displaced references go to ctl->out_stale
 * for release after unlocking.
 *
 * Context: Caller holds @dd->lock.
 *
 * Return: ELEVATOR_FRONT_MERGE, ELEVATOR_BACK_MERGE or ELEVATOR_NO_MERGE.
 */
static enum elv_merge
pfq_rq_tree_find_adjacent(struct pfq_disk_data *dd,
			  struct pfq_queue_data *queue,
			  struct pfq_adj_find_ctl *ctl)
{
	struct bpf_rb_root *rq_root = pfq_rq_tree(dd, queue->qid);
	sector_t probe_start, probe_end, cand_start, cand_end;
	enum elv_merge mt = ELEVATOR_NO_MERGE;
	struct request *req, *stale = NULL;
	struct bpf_rb_node *node;
	struct pfq_rq_core *rn;
	int count = 0;

	if (!ctl)
		return ELEVATOR_NO_MERGE;

	probe_start = ctl->probe_start;
	probe_end = ctl->probe_end;
	*ctl->out_rn = NULL;
	*ctl->out_req = NULL;
	*ctl->out_stale = NULL;

	if (!rq_root)
		return ELEVATOR_NO_MERGE;

	node = bpf_rbtree_root(rq_root);
	while (node && count++ < PFQ_LOOP_MAX) {
		rn = container_of(node, struct pfq_rq_core, rb_node);
		if (rn->qid < queue->qid) {
			node = bpf_rbtree_right(rq_root, node);
			continue;
		}
		if (rn->qid > queue->qid) {
			node = bpf_rbtree_left(rq_root, node);
			continue;
		}

		req = bpf_kptr_xchg(&rn->req, NULL);
		if (!req)
			break;

		cand_start = req->__sector;
		cand_end = cand_start + (req->__data_len >> SECTOR_SHIFT);

		if (probe_end < cand_start) {
			node = bpf_rbtree_left(rq_root, node);
		} else if (probe_start > cand_end) {
			node = bpf_rbtree_right(rq_root, node);
		} else if (cand_start == probe_end) {
			*ctl->out_rn = rn;
			*ctl->out_req = req;
			mt = ELEVATOR_FRONT_MERGE;
			break;
		} else if (cand_end == probe_start) {
			*ctl->out_rn = rn;
			*ctl->out_req = req;
			mt = ELEVATOR_BACK_MERGE;
			break;
		} else {
			stale = bpf_kptr_xchg(&rn->req, req);
			break;
		}

		stale = bpf_kptr_xchg(&rn->req, req);
		if (stale)
			break;
	}

	if (stale) {
		*ctl->out_stale = stale;
		return ELEVATOR_NO_MERGE;
	}
	return mt;
}

/*
 * Reject clearly unmergeable requests before unlinking a candidate.
 * The kernel performs the remaining merge checks after the callback returns.
 */
static __always_inline bool pfq_rq_mergeable_one(struct request *rq)
{
	u32 op = rq->cmd_flags & REQ_OP_MASK;

	if (op == PFQ_REQ_OP_DRV_IN || op == PFQ_REQ_OP_DRV_OUT)
		return false;
	if (op == PFQ_REQ_OP_FLUSH || op == PFQ_REQ_OP_WRITE_ZEROES ||
	    op == PFQ_REQ_OP_ZONE_APPEND)
		return false;
	if (rq->cmd_flags & PFQ_REQ_NOMERGE_FLAGS)
		return false;
	if (rq->rq_flags & PFQ_RQF_NOMERGE_FLAGS)
		return false;
	return true;
}

/**
 * pfq_rq_merge_attrs_ok - Precheck request merge attributes
 * @a: first merge candidate
 * @b: second merge candidate
 *
 * Check a subset of attempt_merge() attributes before unlinking. The caller
 * checks mq_ctx and mq_hctx; the kernel still validates the full merge.
 *
 * Context: Caller holds the disk lock.
 *
 * Return: true if the checked attributes match, otherwise false.
 */
static __always_inline bool pfq_rq_merge_attrs_ok(struct request *a,
						  struct request *b)
{
	u32 opa, opb;

	if (!pfq_rq_mergeable_one(a) || !pfq_rq_mergeable_one(b))
		return false;

	opa = a->cmd_flags & REQ_OP_MASK;
	opb = b->cmd_flags & REQ_OP_MASK;
	if (opa != opb)
		return false;
	/* data direction: LSB of op (same as rq_data_dir). */
	if ((opa & 1) != (opb & 1))
		return false;
	if (!a->bio || !b->bio)
		return false;
	if (a->bio->bi_write_hint != b->bio->bi_write_hint)
		return false;
	if (a->bio->bi_ioprio != b->bio->bi_ioprio)
		return false;
	return true;
}

/*
 * pfq_merge_req - Detach an adjacent request for merging
 * @q: request queue containing the candidates
 * @rq: incoming request to merge
 * @type: output merge type; ELEVATOR_NO_MERGE when no candidate is
 *        returned
 *
 * Return an owning reference to an adjacent candidate and set the merge type.
 *
 * Unlink the candidate from PFQ; UFQ attempts the merge and reinserts the
 * candidate if it fails. For a back merge, incoming rq is absorbed into the
 * candidate; for a front merge, the candidate is absorbed into rq.
 *
 * Return: Owning reference to the detached candidate, or NULL.
 */
struct request *BPF_STRUCT_OPS(pfq_merge_req, struct request_queue *q,
			       struct request *rq, int *type)
{
	struct pfq_rq_core *tree_core, *list_n, *rn;
	struct request *stale = NULL, *targ = NULL;
	enum elv_merge mt = ELEVATOR_NO_MERGE;
	struct pfq_queue_data *queue;
	sector_t rq_start, rq_end;
	struct pfq_disk_data *dd;
	struct pfq_stats *stats;
	bool interactive;
	u32 qid;

	*type = ELEVATOR_NO_MERGE;
	if (!pfq_rq_mergeable_one(rq))
		return NULL;

	dd = pfq_disk_lookup(q->id);
	if (!dd)
		return NULL;

	interactive = pfq_current_is_interactive();
	qid = pfq_rq_qid(rq, interactive);
	rq_start = rq->__sector;
	rq_end = rq_start + (rq->__data_len >> SECTOR_SHIFT);

	stats = pfq_stats_lookup(dd->disk_id);
	queue = pfq_queue_acquire(dd->disk_id, qid);
	if (!queue)
		return NULL;
	bpf_spin_lock(&dd->lock);
	{
		struct pfq_adj_find_ctl ctl = {
			.probe_start = rq_start,
			.probe_end = rq_end,
			.out_rn = &rn,
			.out_req = &targ,
			.out_stale = &stale,
		};

		mt = pfq_rq_tree_find_adjacent(dd, queue, &ctl);
	}
	if (mt == ELEVATOR_NO_MERGE)
		goto out;

	if (rq->mq_ctx != targ->mq_ctx || rq->mq_hctx != targ->mq_hctx ||
	    !pfq_rq_merge_attrs_ok(rq, targ)) {
		stale = pfq_core_put_req_stash(rn, targ);
		targ = NULL;
		goto out;
	}

	tree_core = pfq_rq_tree_remove_take(pfq_rq_tree(dd, queue->qid),
					    &rn->rb_node);
	list_n = tree_core ?
		pfq_fifo_tree_remove_take(pfq_fifo_tree(dd, queue->qid),
					  &tree_core->fifo_rb_node) :
		NULL;

	/* fifo_time inheritance is done by ufq-iosched.c after merge_req. */
	pfq_account_dec(dd, queue);
	pfq_rq_clear_node(targ);
	pfq_stat_add(stats, PFQ_STAT_RQMERGE_CNT, 1);
	pfq_stat_add(stats, PFQ_STAT_RQMERGE_SIZE, targ->__data_len);
	bpf_spin_unlock(&dd->lock);
	bpf_obj_drop(queue);
	pfq_drop_rq_container_refs(list_n, tree_core);
	*type = mt;
	return targ;

out:
	bpf_spin_unlock(&dd->lock);
	if (stale)
		bpf_request_release(stale);
	bpf_obj_drop(queue);
	return NULL;
}

/*
 * pfq_merge_bio - Merge a bio into a queued request
 * @q: request queue receiving the bio
 * @bio: incoming bio
 * @nr_segs: segment count passed to the merge kfunc
 * @merged: set true when the bio is absorbed
 *
 * Merge within the bio's logical queue, including the current task-name
 * classification. Set merged on success and keep the survivor queued;
 * this callback does not coalesce neighboring requests.
 *
 * The merge kfunc uses spin_trylock() on ctx->lock to avoid blocking on a
 * nested lock while dd->lock is held.
 *
 * Return: NULL; the surviving request stays queued.
 */
struct request *BPF_STRUCT_OPS(pfq_merge_bio, struct request_queue *q,
			       struct bio *bio, unsigned int nr_segs,
			       bool *merged)
{
	struct request *cand = NULL, *stale = NULL;
	struct pfq_queue_data *queue;
	struct pfq_disk_data *dd;
	struct pfq_stats *stats;
	struct pfq_rq_core *rn;
	sector_t start, end;
	enum elv_merge mt;
	bool interactive;
	u32 qid;

	if (!merged)
		return NULL;

	dd = pfq_disk_lookup(q->id);
	if (!dd)
		return NULL;

	interactive = pfq_current_is_interactive();
	qid = pfq_bio_qid(bio, interactive);
	start = bio->bi_iter.bi_sector;
	end = start + (bio->bi_iter.bi_size >> SECTOR_SHIFT);

	stats = pfq_stats_lookup(dd->disk_id);
	queue = pfq_queue_acquire(dd->disk_id, qid);
	if (!queue)
		return NULL;
	bpf_spin_lock(&dd->lock);
	{
		struct pfq_adj_find_ctl ctl = {
			.probe_start = start,
			.probe_end = end,
			.out_rn = &rn,
			.out_req = &cand,
			.out_stale = &stale,
		};

		mt = pfq_rq_tree_find_adjacent(dd, queue, &ctl);
	}
	if (mt == ELEVATOR_NO_MERGE)
		goto out;

	if (!bpf_request_bio_try_merge(cand, bio, nr_segs)) {
		stale = pfq_core_put_req_stash(rn, cand);
		goto out;
	}
	*merged = true;
	stale = pfq_core_put_req_stash(rn, cand);
	if (mt == ELEVATOR_FRONT_MERGE)
		pfq_finish_front_bio_merge(dd, queue, rn,
					   bio->bi_iter.bi_sector);
	pfq_stat_add(stats, PFQ_STAT_BIOMERGE_CNT, 1);
	pfq_stat_add(stats, PFQ_STAT_BIOMERGE_SIZE, bio->bi_iter.bi_size);

out:
	bpf_spin_unlock(&dd->lock);
	if (stale)
		bpf_request_release(stale);
	bpf_obj_drop(queue);
	return NULL;
}

UFQ_OPS_DEFINE(pfq_ops,
	.init_sched	= (void *)pfq_init_sched,
	.exit_sched	= (void *)pfq_exit_sched,
	.insert_req	= (void *)pfq_insert_req,
	.dispatch_req	= (void *)pfq_dispatch_req,
	.has_req	= (void *)pfq_has_req,
	.finish_req	= (void *)pfq_finish_req,
	.merge_req	= (void *)pfq_merge_req,
	.merge_bio	= (void *)pfq_merge_bio,
	.name		= "pfq_ebpf");

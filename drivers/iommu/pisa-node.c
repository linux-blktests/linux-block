// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * PISA per-NUMA-node state: PISA page reservoir and background work.
 * See Documentation/core-api/pisa.rst for the architecture overview.
 */

#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/pisa.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/nodemask.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/topology.h>
#include <linux/workqueue.h>

#include "pisa-priv.h"

/* Parameters are pisa.<name> at boot and in /sys/module/pisa/parameters/. */
#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "pisa."

/*
 * Per-NUMA-node reservoir of pre-allocated, pre-zeroed, and pre-decrypted
 * PISA pages (pisa.reservoir_max, default 16, 0 = disabled). Refilled and
 * trimmed by each node's work item on system_dfl_wq, which also scrubs
 * allocators on that node.
 */
unsigned int pisa_reservoir_max __read_mostly = 16;

/* Scrub the allocators whose home node (@pa->nid) is this one. */
#define PISA_NODE_SCRUB	0

static int pisa_reservoir_max_set(const char *val, const struct kernel_param *kp)
{
	int ret = param_set_uint(val, kp);

	/* Schedule per-node workers to refill or trim once pisa_meta_init() has run. */
	if (!ret && static_branch_unlikely(&pisa_key))
		pisa_schedule_reservoir();
	return ret;
}

static const struct kernel_param_ops pisa_reservoir_max_ops = {
	.set = pisa_reservoir_max_set,
	.get = param_get_uint,
};
module_param_cb(reservoir_max, &pisa_reservoir_max_ops, &pisa_reservoir_max, 0644);

/* Apply GFP_NOFS/GFP_NOIO scope around internal GFP_KERNEL allocations. */
static unsigned int pisa_memalloc_save(gfp_t gfp)
{
	unsigned int flags = 0;

	if (!(gfp & __GFP_FS))
		flags |= PF_MEMALLOC_NOFS;
	if (!(gfp & __GFP_IO))
		flags |= PF_MEMALLOC_NOIO;
	return memalloc_flags_save(flags);
}

/* Allocate a PISA page from the buddy allocator and initialize its metadata. */
static struct pisa_meta *__pisa_page_alloc(gfp_t gfp, int nid, bool can_block,
					   bool decrypt, bool *clean)
{
	struct pisa_meta *meta;
	unsigned int memflags;
	struct page *page;

	if (unlikely(!static_branch_unlikely(&pisa_key))) {
		if (!can_block || (gfp & (__GFP_FS | __GFP_IO)) != (__GFP_FS | __GFP_IO) ||
		    pisa_meta_init())
			return ERR_PTR(-EAGAIN);
	}

	/* Racy check against global ceiling across allocators and reservoirs. */
	if (atomic_long_read(&pisa_nr_pages) >= READ_ONCE(pisa_max_pages))
		return ERR_PTR(-ENOSPC);

	/*
	 * Long-lived active pages must be unmovable, lowmem, non-compound, and
	 * must not dip into emergency reserves or trigger OOM/warnings.
	 */
	gfp &= ~(__GFP_COMP | __GFP_HIGHMEM | __GFP_MOVABLE);
	if (decrypt)
		gfp &= ~__GFP_ZERO;
	gfp |= __GFP_NOWARN | __GFP_NOMEMALLOC | (can_block ? __GFP_RETRY_MAYFAIL : __GFP_NORETRY);

	if (can_block)
		memflags = pisa_memalloc_save(gfp);
	page = alloc_pages_node(nid, gfp, PISA_ORDER);
	if (!page) {
		if (can_block)
			memalloc_flags_restore(memflags);
		return ERR_PTR(-ENOMEM);
	}

	/* Ensure the metadata chunk for this PFN is populated. */
	if (unlikely(pisa_meta_ensure_pfn(page_to_pfn(page), can_block))) {
		if (can_block)
			memalloc_flags_restore(memflags);
		__free_pages(page, PISA_ORDER);
		return ERR_PTR(-ERANGE);
	}

	meta = pisa_meta_of_pfn(page_to_pfn(page));
	memset(meta, 0, sizeof(*meta));

	atomic_long_inc(&pisa_nr_pages);
	/* On decrypt failure the page is leaked and stays charged to budget. */
	if (decrypt && pisa_page_prepare(page, meta)) {
		if (can_block)
			memalloc_flags_restore(memflags);
		return ERR_PTR(-EIO);
	}
	if (can_block)
		memalloc_flags_restore(memflags);
	*clean = (gfp & __GFP_ZERO) || (meta->flags & PISA_DECRYPTED) ||
		 want_init_on_alloc(0) || want_init_on_free();

	return meta;
}


/* Refill node @nid's reservoir up to pisa_reservoir_max pre-zeroed PISA pages. */
static void pisa_reservoir_refill_node(int nid)
{
	struct pisa_node *res = &pisa_nodes[nid];

	while (res->nr_pages < READ_ONCE(pisa_reservoir_max)) {
		struct pisa_meta *meta;
		unsigned long flags;
		bool clean;

		meta = __pisa_page_alloc(GFP_KERNEL | __GFP_THISNODE, nid, true,
					 pisa_want_decrypt(), &clean);
		if (IS_ERR(meta)) {
			pisa_stat_inc(res->stats.refill_err);
			break;
		}

		/* Decrypted and init_on_alloc/init_on_free pages are already zeroed. */
		if (!clean)
			memset(page_address(pfn_to_page(pisa_meta_to_pfn(meta))), 0, PISA_SIZE);

		spin_lock_irqsave(&res->lock, flags);
		list_add(&meta->list, &res->pages);
		res->nr_pages++;
		pisa_stat_inc(res->stats.refill);
		spin_unlock_irqrestore(&res->lock, flags);

		cond_resched();
	}
}

/* Release PISA pages in node @nid's reservoir above @max. */
static void pisa_reservoir_trim_node(int nid, unsigned int max)
{
	struct pisa_node *res = &pisa_nodes[nid];

	while (res->nr_pages > max && res->nr_pages > READ_ONCE(pisa_reservoir_max)) {
		struct pisa_meta *meta;
		unsigned long flags;

		spin_lock_irqsave(&res->lock, flags);
		meta = list_first_entry_or_null(&res->pages, struct pisa_meta, list);
		if (meta) {
			list_del_init(&meta->list);
			res->nr_pages--;
			pisa_stat_inc(res->stats.trim);
		}
		spin_unlock_irqrestore(&res->lock, flags);
		if (!meta)
			break;

		pisa_release_page(meta);
		cond_resched();
	}
}

/* Schedule node @nid's work item to scrub allocators homed on @nid. */
void pisa_schedule_scrub(int nid)
{
	struct pisa_node *node;

	if (!READ_ONCE(pisa_scrub_max) && !READ_ONCE(pisa_scrub_migrate))
		return;

	node = &pisa_nodes[nid];
	set_bit(PISA_NODE_SCRUB, &node->flags);
	/* Pairs with the clearing of PENDING before the work runs. */
	smp_mb__after_atomic();
	if (!work_pending(&node->work))
		queue_work_node(nid, system_dfl_wq, &node->work);
}

void pisa_schedule_scrub_all(void)
{
	int nid;

	for_each_node_state(nid, N_MEMORY)
		pisa_schedule_scrub(nid);
}

/* Per-node worker: trim/refill the reservoir, then scrub allocators homed on @nid. */
static void pisa_node_work_fn(struct work_struct *work)
{
	struct pisa_node *node = container_of(work, struct pisa_node, work);
	int nid = node - pisa_nodes;

	pisa_reservoir_trim_node(nid, READ_ONCE(pisa_reservoir_max));
	if (READ_ONCE(pisa_reservoir_max) && static_branch_unlikely(&pisa_key))
		pisa_reservoir_refill_node(nid);

	if (test_and_clear_bit(PISA_NODE_SCRUB, &node->flags) && pisa_scrub_node(nid))
		pisa_schedule_scrub(nid);
}

/* Queue node @nid's work if its reservoir is below or above the target. */
static void pisa_schedule_reservoir_node(int nid)
{
	struct pisa_node *res = &pisa_nodes[nid];

	if (node_state(nid, N_MEMORY) &&
	    READ_ONCE(res->nr_pages) != READ_ONCE(pisa_reservoir_max) &&
	    !work_pending(&res->work))
		queue_work_node(nid, system_dfl_wq, &res->work);
}

void pisa_schedule_reservoir(void)
{
	int nid;

	for_each_node_state(nid, N_MEMORY)
		pisa_schedule_reservoir_node(nid);
}

/* Pop one pre-prepared PISA page from node @nid's reservoir under @res->lock. */
static struct pisa_meta *pisa_reservoir_pop_node(int nid, unsigned int max, bool decrypt)
{
	struct pisa_node *res = &pisa_nodes[nid];
	struct pisa_meta *meta;
	unsigned long flags;
	bool refill = false;

	if (!READ_ONCE(res->nr_pages))
		return NULL;

	spin_lock_irqsave(&res->lock, flags);
	meta = list_first_entry_or_null(&res->pages, struct pisa_meta, list);
	if (meta && !!(meta->flags & PISA_DECRYPTED) == decrypt) {
		list_del_init(&meta->list);
		res->nr_pages--;
		pisa_stat_inc(res->stats.hit);
		refill = res->nr_pages <= max / 2;
	} else {
		meta = NULL;
	}
	spin_unlock_irqrestore(&res->lock, flags);

	if (refill)
		pisa_schedule_reservoir_node(nid);

	return meta;
}

/*
 * Pop a pre-prepared PISA page from @nid's reservoir (scheduling an async
 * refill when <= half full or empty), or allocate one inline on miss.
 */
struct pisa_meta *pisa_reservoir_pop(int nid, gfp_t gfp, bool decrypt, bool *clean)
{
	bool can_block = gfpflags_allow_blocking(gfp);
	unsigned int max = READ_ONCE(pisa_reservoir_max);
	struct pisa_meta *meta;

	nid = pisa_sanitize_nid(nid);
	if (max) {
		meta = pisa_reservoir_pop_node(nid, max, decrypt);
		if (meta) {
			*clean = true;
			return meta;
		}
		pisa_stat_atomic_inc(pisa_nodes[nid].stats.miss);
		/* Empty: pop_node() only schedules after a successful pop. */
		pisa_schedule_reservoir_node(nid);
	}

	/* Back off briefly on GFP_ATOMIC if previous allocation on @nid failed. */
	if (!can_block && time_before(jiffies, READ_ONCE(pisa_nodes[nid].next_alloc)))
		return ERR_PTR(-EAGAIN);
	/* Page decryption may sleep; atomic callers must rely on the reservoir. */
	if (decrypt && !can_block)
		return ERR_PTR(-EAGAIN);

	meta = __pisa_page_alloc(gfp, nid, can_block, decrypt, clean);
	if (IS_ERR(meta))
		pisa_alloc_backoff(nid, can_block);
	return meta;
}

/* Number of PISA pages held in all the reservoirs. */
unsigned long pisa_reservoir_count(void)
{
	unsigned long nr = 0;
	int nid;

	for_each_node_state(nid, N_MEMORY)
		nr += READ_ONCE(pisa_nodes[nid].nr_pages);
	return nr;
}

/* Detach up to @nr_to_scan base pages from reservoirs onto @release_list. */
unsigned long pisa_reservoir_shrink(struct list_head *release_list, unsigned long nr_to_scan)
{
	unsigned long freed = 0;
	int nid;

	for_each_node_state(nid, N_MEMORY) {
		struct pisa_node *res = &pisa_nodes[nid];

		if (!READ_ONCE(res->nr_pages))
			continue;
		freed += pisa_shrink_list(&res->lock, &res->pages, &res->nr_pages,
					  release_list, nr_to_scan - freed);
		if (freed >= nr_to_scan)
			break;
	}
	return freed;
}

void __init pisa_node_init(void)
{
	int nid;

	for (nid = 0; nid < MAX_NUMNODES; nid++) {
		spin_lock_init(&pisa_nodes[nid].lock);
		INIT_LIST_HEAD(&pisa_nodes[nid].pages);
		INIT_WORK(&pisa_nodes[nid].work, pisa_node_work_fn);
	}
}

/* Print the reservoir of each node that has seen any activity. */
void pisa_reservoir_show(struct seq_file *s)
{
	bool header = false;
	int nid;

	for_each_node_state(nid, N_MEMORY) {
		struct pisa_node *res = &pisa_nodes[nid];
		unsigned int nr = READ_ONCE(res->nr_pages);
		s64 refill = pisa_stat_read(res->stats.refill);
		s64 refill_err = pisa_stat_read(res->stats.refill_err);
		s64 miss = pisa_stat_atomic_read(res->stats.miss);
		char title[16];

		/* Pages served or trimmed were refilled first. */
		if (!nr && !refill && !refill_err && !miss)
			continue;
		if (!header) {
			seq_puts(s, "reservoir\n");
			header = true;
		}
		snprintf(title, sizeof(title), "node_%d", nid);
		pisa_seq_kv(s, title, { pisa_pages_2m, nr },
			    { "hit", pisa_stat_read(res->stats.hit) },
			    { "miss", miss });
		pisa_seq_kv(s, title, { "refill", refill },
			    { "refill_err", refill_err },
			    { "trim", pisa_stat_read(res->stats.trim) });
	}
}

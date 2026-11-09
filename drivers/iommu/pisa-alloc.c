// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * PISA streaming page allocator, async page reclaim, shrinker, and debugfs.
 * See Documentation/core-api/pisa.rst for the architecture overview.
 */

#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/dma-mapping.h>
#include <linux/pisa.h>
#include <linux/export.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include "pisa-priv.h"

/* Parameters are pisa.<name> at boot and in /sys/module/pisa/parameters/. */
#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "pisa."

/* Idle PISA pages over the allocator watermark queued locklessly for release. */
static LLIST_HEAD(pisa_free_list);

/* Dedicated WQ_MEM_RECLAIM workqueue, can run without allocations. */
static struct workqueue_struct *pisa_wq __ro_after_init;

/* Max completely idle PISA pages kept per allocator before async release. */
static unsigned int pisa_max_idle __read_mostly = 1;
module_param_named(max_idle, pisa_max_idle, uint, 0644);

/* Grace period in ms before releasing idle PISA pages above @pisa_max_idle (0 = immediate). */
static unsigned int pisa_idle_ms __read_mostly = 200;
module_param_named(idle_ms, pisa_idle_ms, uint, 0644);

/* All live allocators, protected by pisa_allocs_lock. */
static LIST_HEAD(pisa_allocs);
static DEFINE_RWLOCK(pisa_allocs_lock);

/* Per-NUMA-node PISA state (ring/TX/user allocators, reservoir). */
struct pisa_node pisa_nodes[MAX_NUMNODES] = {
	[0 ... MAX_NUMNODES - 1] = {
		.next_alloc = INITIAL_JIFFIES,
		.lock = __SPIN_LOCK_UNLOCKED(pisa_nodes.lock),
	},
};

static void pisa_schedule_reclaim(void);

/*
 * Idle PISA page release proceeds in three stages:
 * 1. Detach onto lockless pisa_free_list and schedule pisa_reclaim_work.
 * 2. In process context (pisa_release_page()), unmap from all IOMMU domains,
 *    clear PISA_ACTIVE, and queue pisa_release_page_rcu() via call_rcu().
 * 3. After an RCU grace period, pisa_release_page_rcu() unfreezes all blocks
 *    and returns them to the buddy allocator.
 */

/* RCU callback: unfreeze and return a retired PISA page's blocks to the buddy allocator. */
static void pisa_release_page_rcu(struct rcu_head *head)
{
	/* Read @meta before freeing blocks; the frame can be reused immediately. */
	struct pisa_meta *meta = container_of(head, struct pisa_meta, rcu);
	struct page *block, *page = pfn_to_page(pisa_meta_to_pfn(meta));
	unsigned int i, order = meta->pa->order;

	WRITE_ONCE(meta->pa, NULL);

	for (i = 0; i < PISA_BLOCKS(order); i++) {
		block = page + (i << order);
		page_ref_unfreeze(block, 1);
		__free_pages(block, order);
	}
}

/* Unmap a retired PISA page, clear PISA_ACTIVE, and queue RCU release. */
void pisa_release_page(struct pisa_meta *meta)
{
	if (!meta->pa) {
		__free_pages(pfn_to_page(pisa_meta_to_pfn(meta)), PISA_ORDER);
		return;
	}

	/* pisa_unmap_all(meta) will be called here once IOMMU mappings are added. */

	/* Clear PISA_ACTIVE before the RCU grace period so new readers stop entering. */
	WRITE_ONCE(meta->flags, meta->flags & ~PISA_ACTIVE);
	call_rcu(&meta->rcu, pisa_release_page_rcu);
}

/* Value of @meta->on_list. 0 is "not on an allocator list", as for a zeroed @meta. */
enum pisa_meta_list {
	PISA_LIST_NONE,
	PISA_LIST_FULL,
	PISA_LIST_IDLE_CLEAN,		/* head of @idle */
	PISA_LIST_IDLE_DIRTY,		/* tail of @idle */
	PISA_LIST_PARTIAL_CLEAN_DENSE,	/* head of @partial */
	PISA_LIST_PARTIAL_CLEAN_SPARSE,	/* tail of @partial */
	PISA_LIST_PARTIAL_DIRTY_DENSE,	/* head of @partial_dirty */
	PISA_LIST_PARTIAL_DIRTY_SPARSE,	/* tail of @partial_dirty */
};

static void pisa_reclaim_work_fn(struct work_struct *work);

/* Asynchronous reclaim worker for pisa_free_list and expired idle pages. */
static DECLARE_DELAYED_WORK(pisa_reclaim_work, pisa_reclaim_work_fn);

static void pisa_reclaim_work_fn(struct work_struct *work)
{
	unsigned long grace = msecs_to_jiffies(READ_ONCE(pisa_idle_ms));
	unsigned long next_delay = MAX_JIFFY_OFFSET;
	struct pisa_meta *meta, *tmp;
	struct llist_node *node;
	struct pisa_alloc *pa;

	read_lock(&pisa_allocs_lock);
	list_for_each_entry(pa, &pisa_allocs, node) {
		unsigned long expire = READ_ONCE(pa->idle_jiffies) + grace;
		unsigned long now = jiffies, flags;

		if (READ_ONCE(pa->num_idle_pages) <= pa->max_idle_pages)
			continue;
		if (grace && time_before(now, expire)) {
			next_delay = min(next_delay, expire - now);
			continue;
		}
		spin_lock_irqsave(&pa->lock, flags);
		while (pa->num_idle_pages > pa->max_idle_pages && !list_empty(&pa->idle)) {
			meta = list_last_entry(&pa->idle, struct pisa_meta, list);
			list_del_init(&meta->list);
			WRITE_ONCE(meta->on_list, PISA_LIST_NONE);
			llist_add(&meta->llnode, &pisa_free_list);
			pa->num_idle_pages--;
		}
		spin_unlock_irqrestore(&pa->lock, flags);
	}
	read_unlock(&pisa_allocs_lock);

	node = llist_del_all(&pisa_free_list);
	llist_for_each_entry_safe(meta, tmp, node, llnode)
		pisa_release_page(meta);

	if (next_delay != MAX_JIFFY_OFFSET)
		queue_delayed_work(pisa_wq ?: system_wq, &pisa_reclaim_work, next_delay);
}

static void pisa_schedule_reclaim(void)
{
	struct workqueue_struct *wq = pisa_wq ?: system_wq;
	unsigned int idle_ms = READ_ONCE(pisa_idle_ms);

	if (!llist_empty(&pisa_free_list) || !idle_ms)
		mod_delayed_work(wq, &pisa_reclaim_work, 0);
	else
		queue_delayed_work(wq, &pisa_reclaim_work, msecs_to_jiffies(idle_ms));
}
/*
 * Update @meta's position on @pa's lists under @pa->lock. When all blocks
 * become available (avail == bpp), either queues @meta to @pisa_free_list (and
 * returns true so the caller schedules reclaim) or moves it to @pa->idle.
 */
static bool pisa_place_meta(struct pisa_meta *meta)
{
	struct pisa_alloc *pa = meta->pa;
	unsigned int avail = pisa_meta_avail(meta), bpp = PISA_BLOCKS(pa->order);
	u8 on_list;

	lockdep_assert_held(&pa->lock);

	if (avail == bpp) {
		if (pa->num_idle_pages >= pa->max_idle_pages && !READ_ONCE(pisa_idle_ms)) {
			list_del_init(&meta->list);
			WRITE_ONCE(meta->on_list, PISA_LIST_NONE);
			llist_add(&meta->llnode, &pisa_free_list);
			return true;
		}
		if (pa->num_idle_pages >= pa->max_idle_pages)
			WRITE_ONCE(pa->idle_jiffies, jiffies);
		pa->num_idle_pages++;
		on_list = meta->nr_dirty ? PISA_LIST_IDLE_DIRTY : PISA_LIST_IDLE_CLEAN;
	} else if (!avail) {
		on_list = PISA_LIST_FULL;
	} else {
		bool sparse;

		if (avail >= bpp - (bpp >> 2))
			sparse = true;
		else if (avail <= (bpp >> 1))
			sparse = false;
		else
			sparse = meta->on_list == PISA_LIST_PARTIAL_CLEAN_SPARSE ||
				 meta->on_list == PISA_LIST_PARTIAL_DIRTY_SPARSE;

		if (meta->nr_clean)
			on_list = sparse ? PISA_LIST_PARTIAL_CLEAN_SPARSE :
					   PISA_LIST_PARTIAL_CLEAN_DENSE;
		else
			on_list = sparse ? PISA_LIST_PARTIAL_DIRTY_SPARSE :
					   PISA_LIST_PARTIAL_DIRTY_DENSE;
	}

	if (on_list == meta->on_list)
		return avail == bpp && pa->num_idle_pages > pa->max_idle_pages;
	WRITE_ONCE(meta->on_list, on_list);

	switch (on_list) {
	case PISA_LIST_FULL:
		list_move(&meta->list, &pa->full);
		break;
	case PISA_LIST_IDLE_CLEAN:
		list_move(&meta->list, &pa->idle);
		break;
	case PISA_LIST_IDLE_DIRTY:
		list_move_tail(&meta->list, &pa->idle);
		break;
	case PISA_LIST_PARTIAL_CLEAN_DENSE:
		list_move(&meta->list, &pa->partial);
		break;
	case PISA_LIST_PARTIAL_CLEAN_SPARSE:
		list_move_tail(&meta->list, &pa->partial);
		break;
	case PISA_LIST_PARTIAL_DIRTY_DENSE:
		list_move(&meta->list, &pa->partial_dirty);
		break;
	default:
		list_move_tail(&meta->list, &pa->partial_dirty);
	}
	return avail == bpp && pa->num_idle_pages > pa->max_idle_pages;
}

/* Check for hwpoisoned block; if poisoned, warn once and leak it to keep @pa intact. */
static bool pisa_block_poisoned(struct pisa_alloc *pa, struct page *block)
{
	unsigned int i, nr = 1U << pa->order;

	for (i = 0; i < nr; i++) {
		if (unlikely(PageHWPoison(block + i))) {
			pr_err_once("pisa: poisoned block at pfn %lu, leaking it to keep allocator %p intact\n",
				    page_to_pfn(block), pa);
			return true;
		}
	}
	return false;
}

/**
 * pisa_create - Create a PISA page allocator
 * @nid: Home NUMA node for this allocator
 * @order: Block order to dispense (<= PISA_ORDER)
 * @dir: Supported DMA direction (DMA_BIDIRECTIONAL, DMA_TO_DEVICE, or
 *	DMA_FROM_DEVICE); other mappings fall back to per-buffer IOMMU mappings
 *
 * Return: Pointer to the created allocator, or NULL on failure.
 */
struct pisa_alloc *pisa_create(int nid, unsigned int order, enum dma_data_direction dir)
{
	struct pisa_alloc *pa;

	if (order > PISA_ORDER || !valid_dma_direction(dir))
		return NULL;

	pa = kzalloc(sizeof(*pa), GFP_KERNEL);
	if (!pa)
		return NULL;

	spin_lock_init(&pa->lock);
	pa->order = order;
	pa->nid = pisa_sanitize_nid(nid);
	pa->max_idle_pages = READ_ONCE(pisa_max_idle) ? : 1;
	pisa_set_name(pa, "%ps", (void *)_RET_IP_);
	INIT_LIST_HEAD(&pa->partial);
	INIT_LIST_HEAD(&pa->partial_dirty);
	INIT_LIST_HEAD(&pa->idle);
	INIT_LIST_HEAD(&pa->full);

	write_lock(&pisa_allocs_lock);
	list_add_tail(&pa->node, &pisa_allocs);
	write_unlock(&pisa_allocs_lock);

	return pa;
}

/**
 * pisa_set_name - Name a PISA allocator for debugfs
 * @pa: Allocator to name (may be NULL)
 * @fmt: printf-style format, truncated to fit @pa->name
 */
void pisa_set_name(struct pisa_alloc *pa, const char *fmt, ...)
{
	va_list args;

	if (!pa)
		return;
	va_start(args, fmt);
	vsnprintf(pa->name, sizeof(pa->name), fmt, args);
	va_end(args);
}

/* Return freed @block (at refcount 0) to @pa's bitmaps under @pa->lock. */
static void pisa_return_block_locked(struct pisa_alloc *pa, struct page *block, bool *release)
{
	unsigned long pfn = page_to_pfn(block);
	struct pisa_meta *meta = pisa_meta_of_pfn(pfn);
	unsigned int idx = (pfn & (PISA_BLOCKS(0) - 1)) >> pa->order;

	lockdep_assert_held(&pa->lock);

	if (WARN_ON_ONCE(test_bit(idx, meta->clean_bitmap) || test_bit(idx, meta->dirty_bitmap)))
		return;

	/* __pisa_free_page() zeroed it if init_on_free is set. */
	if (want_init_on_free()) {
		__set_bit(idx, meta->clean_bitmap);
		meta->nr_clean++;
	} else {
		__set_bit(idx, meta->dirty_bitmap);
		meta->nr_dirty++;
	}
	*release |= pisa_place_meta(meta);
}

/**
 * __pisa_free_page - Recycle a freed block back into its PISA allocator
 * @page: Block being freed (called from __free_pages_prepare() under RCU)
 *
 * Return: true if the page belonged to a PISA allocator and was recycled.
 */
bool __pisa_free_page(struct page *page)
{
	bool should_release = false;
	unsigned long pfn = page_to_pfn(page), flags;
	struct pisa_meta *meta = pisa_meta_of_pfn(pfn);
	struct pisa_alloc *pa = meta->pa;
	unsigned int idx = (pfn & (PISA_BLOCKS(0) - 1)) >> pa->order;

	/* Reject double frees, mismatched orders, or unaligned blocks. */
	if (WARN_ON_ONCE(!IS_ALIGNED(pfn, 1UL << pa->order) ||
			 compound_order(page) != pa->order ||
			 test_bit(idx, meta->clean_bitmap) || test_bit(idx, meta->dirty_bitmap)))
		return true;

	/* Never reuse or return a hwpoisoned block to the buddy allocator. */
	if (pisa_block_poisoned(pa, page))
		return true;

	/* Checks skipped by the early return in __free_pages_prepare(). */
	if (unlikely(!free_page_prepare_pisa(page, pa->order)))
		return true;

	/* KASAN/KMSAN/pgalloc_tag_sub run when pisa_release_page_rcu() frees to buddy. */
	if (want_init_on_free())
		memset(page_address(page), 0, PAGE_SIZE << pa->order);

	spin_lock_irqsave(&pa->lock, flags);
	pisa_return_block_locked(pa, page, &should_release);
	spin_unlock_irqrestore(&pa->lock, flags);

	if (should_release)
		pisa_schedule_reclaim();

	return true;
}

static int __init pisa_init(void)
{
	pisa_node_init();

	/* Dedicated WQ_MEM_RECLAIM workqueue so reclaim never blocks behind system_wq. */
	pisa_wq = alloc_workqueue("pisa", WQ_MEM_RECLAIM, 0);
	if (!pisa_wq)
		pr_warn("pisa: no reclaim workqueue, falling back to system_wq\n");

	return 0;
}
subsys_initcall(pisa_init);

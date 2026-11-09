// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * PISA streaming page allocator, async page reclaim, shrinker, and debugfs.
 * See Documentation/core-api/pisa.rst for the architecture overview.
 */

#include <kunit/visibility.h>
#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/cc_platform.h>
#include <linux/cpuhotplug.h>
#include <linux/device.h>
#include <linux/dma-direct.h>
#include <linux/dma-map-ops.h>
#include <linux/dma-mapping.h>
#include <linux/pisa.h>
#include <linux/export.h>
#include <linux/gfp.h>
#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/page_owner.h>
#include <linux/percpu.h>
#include <linux/pgalloc_tag.h>
#include <linux/rcupdate.h>
#include <linux/sched/clock.h>
#include <linux/sched/mm.h>
#include <linux/set_memory.h>
#include <linux/shrinker.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <net/hotdata.h>
#include <net/sock.h>

#include "dma-iommu.h"
#include "pisa-priv.h"

/* Parameters are pisa.<name> at boot and in /sys/module/pisa/parameters/. */
#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "pisa."

/* Idle PISA pages over the allocator watermark queued locklessly for release. */
static LLIST_HEAD(pisa_free_list);

/* Dedicated WQ_MEM_RECLAIM workqueue, can run without allocations. */
static struct workqueue_struct *pisa_wq __ro_after_init;

/* Mark active PISA pages decrypted for DMA (auto-enabled on CoCo guests). */
static bool pisa_decrypt __read_mostly;
module_param_named(decrypt, pisa_decrypt, bool, 0444);

/* Global count and ceiling on PISA pages across all allocators and reservoirs (0 = 1/8 RAM). */
atomic_long_t pisa_nr_pages __cacheline_aligned_in_smp;
unsigned long pisa_max_pages __read_mostly;
module_param_named(max_pages, pisa_max_pages, ulong, 0644);

/* Max completely idle PISA pages kept per allocator before async release. */
static unsigned int pisa_max_idle __read_mostly = 1;
module_param_named(max_idle, pisa_max_idle, uint, 0644);

/* Grace period in ms before releasing idle PISA pages above @pisa_max_idle (0 = immediate). */
static unsigned int pisa_idle_ms __read_mostly = 200;
module_param_named(idle_ms, pisa_idle_ms, uint, 0644);

/* Stop recycling partial-page blocks when free blocks exceed @pisa_compact PISA pages. */
static unsigned int pisa_compact __read_mostly;
module_param_named(compact, pisa_compact, uint, 0644);

/* Stop recycling partial pages older than @pisa_old_ms when wasted blocks > @pisa_wasted_pct%. */
unsigned int pisa_wasted_pct __read_mostly;
module_param_named(wasted_pct, pisa_wasted_pct, uint, 0644);

unsigned int pisa_old_ms __read_mostly;
module_param_named(old_ms, pisa_old_ms, uint, 0644);

/* Max pages zeroed in each scrubber run (0 = disabled, capped at PISA_SCRUB_MAX_LIMIT). */
unsigned int pisa_scrub_max __read_mostly;
#define PISA_SCRUB_MAX_LIMIT	65536U

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

static int pisa_scrub_set(const char *val, const struct kernel_param *kp)
{
	int ret = param_set_uint(val, kp);

	if (ret)
		return ret;
	WRITE_ONCE(pisa_scrub_max, min(pisa_scrub_max, PISA_SCRUB_MAX_LIMIT));
	/* Serve demand accumulated while the scrubber was off (once initialized). */
	if (pisa_scrub_max && static_branch_unlikely(&pisa_key))
		pisa_schedule_scrub_all();
	return 0;
}

static const struct kernel_param_ops pisa_scrub_ops = {
	.set = pisa_scrub_set,
	.get = param_get_uint,
};
module_param_cb(scrub_max, &pisa_scrub_ops, &pisa_scrub_max, 0644);
/* Return true if a new PISA page should be decrypted. */
bool pisa_want_decrypt(void)
{
	if (!pisa_decrypt)
		return false;

	/* Explicit page decryption is for CoCo guests, not bare-metal SME hosts. */
	return !WARN_ON_ONCE(cc_platform_has(CC_ATTR_HOST_MEM_ENCRYPT));
}

/* Decrypt and zero a new PISA page. Must be called from sleepable context. */
int pisa_page_prepare(struct page *page, struct pisa_meta *meta)
{
	void *vaddr = page_address(page);
	int ret;

	ret = set_memory_decrypted((unsigned long)vaddr, 1 << PISA_ORDER);
	if (ret) {
		/* Leak partially shared page rather than returning it to the buddy allocator. */
		pr_warn_ratelimited("pisa: leaking PISA page that could not be decrypted\n");
		return ret;
	}
	/* Initialize cleartext cachelines after flipping encryption state. */
	memset(vaddr, 0, PISA_SIZE);
	meta->flags |= PISA_DECRYPTED;
	return 0;
}

/* Undo pisa_page_prepare(). */
int pisa_page_unprepare(struct pisa_meta *meta)
{
	struct page *page;

	if (!(meta->flags & PISA_DECRYPTED))
		return 0;
	page = pfn_to_page(pisa_meta_to_pfn(meta));
	if (set_memory_encrypted((unsigned long)page_address(page), 1 << PISA_ORDER)) {
		pr_warn_ratelimited("pisa: leaking PISA page that could not be re-encrypted\n");
		return -EIO;
	}
	WRITE_ONCE(meta->flags, meta->flags & ~PISA_DECRYPTED);
	return 0;
}


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
	unsigned int i, order = meta->pa->order, slot = meta->slot;
	unsigned long flags;

	spin_lock_irqsave(&meta->pa->lock, flags);
	meta->pa->stats.page_free_cnt++;
	spin_unlock_irqrestore(&meta->pa->lock, flags);
	WRITE_ONCE(meta->pa, NULL);

	/* The page has been unmapped from every domain by pisa_release_page() */
	if (!(meta->flags & PISA_QUARANTINED))
		pisa_slot_free(slot);

	/* Still shared with the host, or possibly still mapped by a device. */
	if (meta->flags & (PISA_DECRYPTED | PISA_QUARANTINED))
		return;
	atomic_long_dec(&pisa_nr_pages);
	for (i = 0; i < PISA_BLOCKS(order); i++) {
		block = page + (i << order);
		page_ref_unfreeze(block, 1);
		__free_pages(block, order);
	}
}

/* Unmap a retired PISA page, clear PISA_ACTIVE, and queue RCU release. */
void pisa_release_page(struct pisa_meta *meta)
{
	u8 flags;

	if (!meta->pa) {
		/* Unbound (reservoir) page: leaked if re-encryption fails. */
		if (pisa_page_unprepare(meta))
			return;
		__free_pages(pfn_to_page(pisa_meta_to_pfn(meta)), PISA_ORDER);
		atomic_long_dec(&pisa_nr_pages);
		return;
	}

	/* Quarantined on unmap failure and leaked in pisa_release_page_rcu(). */
	pisa_unmap_all(meta);
	flags = meta->flags & ~PISA_ACTIVE;

	/* Clear PISA_ACTIVE before the RCU grace period so new readers stop entering. */
	WRITE_ONCE(meta->flags, flags);
	if ((flags & (PISA_DECRYPTED | PISA_QUARANTINED)) == PISA_DECRYPTED) {
		synchronize_rcu();
		pisa_page_unprepare(meta);
	}

	call_rcu(&meta->rcu, pisa_release_page_rcu);
}

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

void pisa_schedule_reclaim(void)
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
bool pisa_place_meta(struct pisa_meta *meta)
{
	struct pisa_alloc *pa = meta->pa;
	unsigned int avail = pisa_meta_avail(meta), bpp = PISA_BLOCKS(pa->order);
	u8 on_list;

	lockdep_assert_held(&pa->lock);

	if (avail == bpp) {
		if ((meta->flags & PISA_QUARANTINED) ||
		    (pa->num_idle_pages >= pa->max_idle_pages && !READ_ONCE(pisa_idle_ms))) {
			list_del_init(&meta->list);
			WRITE_ONCE(meta->on_list, PISA_LIST_NONE);
			llist_add(&meta->llnode, &pisa_free_list);
			return true;
		}
		if (pa->num_idle_pages >= pa->max_idle_pages)
			WRITE_ONCE(pa->idle_jiffies, jiffies);
		pa->num_idle_pages++;
		on_list = meta->nr_dirty ? PISA_LIST_IDLE_DIRTY : PISA_LIST_IDLE_CLEAN;
	} else if (!avail || unlikely(meta->flags & PISA_QUARANTINED)) {
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

/*
 * Background page scrubber: pre-zeroes dirty blocks in @pa->nid's work item
 * to match inline-zeroed demand (@pa->scrub_demand) when scrub_max > 0.
 */
static struct pisa_meta *pisa_pick_dirty_meta(struct pisa_alloc *pa)
{
	struct pisa_meta *meta;

	meta = list_first_entry_or_null(&pa->partial_dirty, struct pisa_meta, list);
	if (meta)
		return meta;

	list_for_each_entry(meta, &pa->partial, list) {
		if (meta->nr_dirty)
			return meta;
	}

	if (!list_empty(&pa->idle)) {
		meta = list_last_entry(&pa->idle, struct pisa_meta, list);
		if (meta->nr_dirty) {
			pa->num_idle_pages--;
			WRITE_ONCE(meta->alloc_jiffies, jiffies);
			return meta;
		}
	}

	return NULL;
}

/* Dirty blocks per allocator, inline-zeroed since the last run, that queue a run. */
#define PISA_SCRUB_TRIGGER	32U
/* Cap on @pa->scrub_demand, so a long-off scrubber does not owe too much. */
#define PISA_SCRUB_DEMAND_MAX	4096U
/* Bytes zeroed per batch: a few microseconds of memset(). */
/* XXX assumes PAGE_SIZE <= SZ_128K (32 * 4KB pages). */
#define PISA_SCRUB_BYTES	SZ_128K
#define PISA_SCRUB_BATCH	(PISA_SCRUB_BYTES >> PAGE_SHIFT)
/* Time after which a run stops and requeues. */
#define PISA_SCRUB_RUN_NS	(50 * NSEC_PER_USEC)

/*
 * Scrub one batch of dirty blocks in @pa outside @pa->lock.
 * Returns the number of PAGE_SIZE pages taken off the dirty bitmap.
 */
static unsigned long pisa_scrub_alloc(struct pisa_alloc *pa)
{
	unsigned int bpp, order, idx, count = 0, used = 0, want;
	u16 idxs[PISA_SCRUB_BATCH];
	unsigned long base_pfn, flags;
	bool should_release;
	struct pisa_meta *meta;

	spin_lock_irqsave(&pa->lock, flags);
	if (!pa->scrub_demand) {
		spin_unlock_irqrestore(&pa->lock, flags);
		return 0;
	}

	meta = pisa_pick_dirty_meta(pa);
	if (!meta) {
		pa->scrub_demand = 0;
		spin_unlock_irqrestore(&pa->lock, flags);
		return 0;
	}

	order = pa->order;
	bpp = PISA_BLOCKS(order);
	base_pfn = pisa_meta_to_pfn(meta);
	want = min(max(PISA_SCRUB_BATCH >> order, 1U), pa->scrub_demand);

	for_each_set_bit(idx, meta->dirty_bitmap, bpp) {
		struct page *block = pfn_to_page(base_pfn + (idx << order));

		__clear_bit(idx, meta->dirty_bitmap);
		used++;
		if (!pisa_block_poisoned(pa, block))
			idxs[count++] = idx;
		if (used == meta->nr_dirty || count == want)
			break;
	}
	meta->nr_dirty -= used;
	pa->blocks_in_use += used - count;
	pisa_place_meta(meta);
	spin_unlock_irqrestore(&pa->lock, flags);

	if (unlikely(!count))
		return (unsigned long)used << order;

	for (idx = 0; idx < count; idx++) {
		struct page *block = pfn_to_page(base_pfn + (idxs[idx] << order));

		memset(page_address(block), 0, PAGE_SIZE << order);
	}

	spin_lock_irqsave(&pa->lock, flags);
	for (idx = 0; idx < count; idx++)
		__set_bit(idxs[idx], meta->clean_bitmap);
	meta->nr_clean += count;
	pa->scrub_demand -= min(count, pa->scrub_demand);
	should_release = pisa_place_meta(meta);
	spin_unlock_irqrestore(&pa->lock, flags);

	if (should_release)
		pisa_schedule_reclaim();

	return (unsigned long)used << order;
}

/*
 * Scrub dirty blocks for allocators homed on @nid up to @pisa_scrub_max pages or
 * PISA_SCRUB_RUN_NS. Returns true if stopped early with demand remaining.
 */
bool pisa_scrub_node(int nid)
{
	unsigned long budget = READ_ONCE(pisa_scrub_max), done = 0, n;
	u64 deadline = local_clock() + PISA_SCRUB_RUN_NS;
	struct pisa_alloc *pa;
	bool more = false;

	if (!budget)
		goto migrate;

	read_lock(&pisa_allocs_lock);
	list_for_each_entry(pa, &pisa_allocs, node) {
		if (pa->nid != nid || !READ_ONCE(pa->scrub_demand))
			continue;
		read_unlock(&pisa_allocs_lock);

		while ((n = pisa_scrub_alloc(pa))) {
			done += n;
			if (done >= budget || local_clock() >= deadline) {
				more = true;
				break;
			}
			cond_resched();
		}

		read_lock(&pisa_allocs_lock);
		if (more)
			break;
	}
	read_unlock(&pisa_allocs_lock);

migrate:
	if (READ_ONCE(pisa_scrub_migrate)) {
		unsigned long rem = !budget ? 512 : (budget > done ? budget - done : 0);

		if (rem && local_clock() < deadline)
			more |= pisa_user_scrub_node(nid, rem, deadline);
		else
			more = true;
	}

	return more;
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
	pa->prot = (dir != DMA_FROM_DEVICE ? IOMMU_READ : 0) |
		     (dir != DMA_TO_DEVICE ? IOMMU_WRITE : 0);
	pa->max_idle_pages = READ_ONCE(pisa_max_idle) ? : 1;
	pisa_set_name(pa, "%ps", (void *)_RET_IP_);
	pa->nid = pisa_sanitize_nid(nid);
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
	pa->blocks_in_use--;
	*release |= pisa_place_meta(meta);
}

/**
 * pisa_page_can_recycle - Check if a block can stay cached in a caller pool
 * @page: Block head page
 *
 * Called on the recycle fast path (per-CPU cache, TX page_frag).
 * Fast-path cost is a static-key branch plus a READ_ONCE() of module parameters
 * (~1-2 ns when compaction is off); when enabled, it does a lockless RCU +
 * metadata array lookup (~5-10 ns).
 *
 * Return: true if @page can be recycled in place, false if it should be
 * released back to its allocator so sparse 2MB pages can drain.
 */
bool pisa_page_can_recycle(const struct page *page)
{
	unsigned int compact, wasted_pct, old_ms;
	unsigned long bpp, in_use, free_blocks;
	const struct pisa_meta *meta;
	const struct pisa_alloc *pa;
	unsigned long pfn;
	bool ret = true;
	u8 on_list;
	long held;

	if (!static_branch_unlikely(&pisa_key))
		return true;

	compact = READ_ONCE(pisa_compact);
	wasted_pct = READ_ONCE(pisa_wasted_pct);
	old_ms = READ_ONCE(pisa_old_ms);
	if (!compact && (!wasted_pct || !old_ms))
		return true;

	pfn = page_to_pfn(page);
	rcu_read_lock();
	if (!is_pisa_pfn(pfn))
		goto out;

	meta = pisa_meta_of_pfn(pfn);
	on_list = READ_ONCE(meta->on_list);
	if (on_list == PISA_LIST_FULL || on_list == PISA_LIST_NONE)
		goto out;

	if (!compact) {
		unsigned long max_age = msecs_to_jiffies(min(old_ms, PISA_OLD_MS_MAX));

		if (!time_after(jiffies, READ_ONCE(meta->alloc_jiffies) + max_age))
			goto out;
	}

	pa = meta->pa;
	if (!pa)
		goto out;

	/* Do not drain the partial page currently being filled at list head. */
	if (READ_ONCE(pa->partial_dirty.next) == &meta->list ||
	    READ_ONCE(pa->partial.next) == &meta->list)
		goto out;

	bpp = PISA_BLOCKS(pa->order);
	/* Do not drain dense pages that still have more than half their blocks in use. */
	if (READ_ONCE(meta->nr_clean) + READ_ONCE(meta->nr_dirty) < (bpp >> 1))
		goto out;

	held = pisa_alloc_held_pages(pa);
	in_use = READ_ONCE(pa->blocks_in_use);
	free_blocks = held > 0 && (unsigned long)held * bpp > in_use ?
		      (unsigned long)held * bpp - in_use : 0;

	if (compact && free_blocks > (unsigned long)compact * bpp) {
		ret = false;
		goto out;
	}
	if (wasted_pct && old_ms && held > 0 &&
	    free_blocks * 100 > (unsigned long)held * bpp * wasted_pct) {
		unsigned long max_age = msecs_to_jiffies(min(old_ms, PISA_OLD_MS_MAX));

		ret = !time_after(jiffies, READ_ONCE(meta->alloc_jiffies) + max_age);
	}
out:
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(pisa_page_can_recycle);

/* Return @n freed blocks to @pa under a single acquisition of @pa->lock. */
static void pisa_free_bulk(struct pisa_alloc *pa, struct page **blocks, unsigned int n)
{
	bool release = false;
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&pa->lock, flags);
	for (i = 0; i < n; i++) {
		if (likely(!pisa_block_poisoned(pa, blocks[i])))
			pisa_return_block_locked(pa, blocks[i], &release);
	}
	spin_unlock_irqrestore(&pa->lock, flags);

	if (release)
		pisa_schedule_reclaim();
}

/*
 * Per-CPU block cache: each CPU caches up to PISA_PCP_HIGH free blocks
 * (refcount 0, not in bitmaps), refilling and flushing in PISA_PCP_BATCH
 * batches. Drained by the shrinker and CPU hotplug.
 */

/* Max blocks moved per per-CPU cache refill or flush (1..PISA_PCP_BATCH). */
static unsigned int pisa_pcp_batch __read_mostly = PISA_PCP_BATCH;

static int pisa_pcp_batch_set(const char *val, const struct kernel_param *kp)
{
	return param_set_uint_minmax(val, kp, 1, PISA_PCP_BATCH);
}

static const struct kernel_param_ops pisa_pcp_batch_ops = {
	.set = pisa_pcp_batch_set,
	.get = param_get_uint,
};
module_param_cb(pcp_batch, &pisa_pcp_batch_ops, &pisa_pcp_batch, 0644);

/* Cache @n blocks at refcount 0 on this CPU, @n <= PISA_PCP_BATCH. */
static void pisa_pcp_push(struct pisa_alloc *pa, struct page **blocks, unsigned int n)
{
	unsigned int i, batch = READ_ONCE(pisa_pcp_batch);
	struct pisa_pcp *pcp;
	unsigned long flags;

	local_irq_save(flags);
	pcp = this_cpu_ptr(pa->pcp);
	spin_lock(&pcp->lock);
	for (i = 0; i < n; i++) {
		if (pcp->count == PISA_PCP_HIGH) {
			/* Keep the most recently freed, likely still in cache. */
			pisa_free_bulk(pa, pcp->blocks, batch);
			pcp->count -= batch;
			memmove(pcp->blocks, pcp->blocks + batch,
				pcp->count * sizeof(*pcp->blocks));
		}
		pcp->blocks[pcp->count++] = blocks[i];
	}
	spin_unlock(&pcp->lock);
	local_irq_restore(flags);
}

/* Take up to @nr blocks, at refcount 0, from this CPU's cache. */
static unsigned int pisa_pcp_pop(struct pisa_alloc *pa, unsigned int nr, struct page **out)
{
	struct pisa_pcp *pcp;
	unsigned int got = 0;
	unsigned long flags;

	local_irq_save(flags);
	pcp = this_cpu_ptr(pa->pcp);
	spin_lock(&pcp->lock);
	while (got < nr && pcp->count)
		out[got++] = pcp->blocks[--pcp->count];
	spin_unlock(&pcp->lock);
	local_irq_restore(flags);

	return got;
}

/* Return the blocks @cpu caches for @pa. Process context. */
static void pisa_pcp_drain_cpu(struct pisa_alloc *pa, int cpu)
{
	struct pisa_pcp *pcp = per_cpu_ptr(pa->pcp, cpu);
	unsigned long flags;

	spin_lock_irqsave(&pcp->lock, flags);
	if (pcp->count) {
		pisa_free_bulk(pa, pcp->blocks, pcp->count);
		pcp->count = 0;
	}
	spin_unlock_irqrestore(&pcp->lock, flags);
}

/* Drain every non-empty CPU cache of @pa. */
void pisa_pcp_drain(struct pisa_alloc *pa)
{
	int cpu;

	/* Pairs with smp_store_release() in pisa_enable_pcp(). */
	if (!smp_load_acquire(&pa->pcp))
		return;
	for_each_possible_cpu(cpu) {
		if (!READ_ONCE(per_cpu_ptr(pa->pcp, cpu)->count))
			continue;
		pisa_pcp_drain_cpu(pa, cpu);
	}
}

/* Blocks in @pa's caches, for shrinker and debugfs. */
static unsigned long pisa_pcp_count(struct pisa_alloc *pa)
{
	unsigned long n = 0;
	int cpu;

	if (!pa->pcp)
		return 0;
	for_each_possible_cpu(cpu) {
		/* A racy sum is good enough for reclaim and statistics. */
		n += data_race(per_cpu_ptr(pa->pcp, cpu)->count);
	}
	return n;
}

/**
 * pisa_enable_pcp - Put per-CPU block caches in front of an allocator
 * @pa: Allocator to cache
 *
 * Return: 0, or -ENOMEM; @pa works without the cache.
 */
int pisa_enable_pcp(struct pisa_alloc *pa)
{
	struct pisa_pcp __percpu *pcp;
	int cpu;

	if (!pa || pa->pcp)
		return 0;
	pcp = alloc_percpu(struct pisa_pcp);
	if (!pcp)
		return -ENOMEM;
	for_each_possible_cpu(cpu)
		spin_lock_init(&per_cpu_ptr(pcp, cpu)->lock);
	/* Publish initialized locks; readers depend on the pointer. */
	if (cmpxchg_release(&pa->pcp, NULL, pcp))
		free_percpu(pcp);
	return 0;
}

/*
 * Return the predefined per-node allocator for (@nid, @order, @ro), or NULL.
 */
struct pisa_alloc *pisa_node_pa(int nid, unsigned int order, bool ro)
{
	if (order > PISA_ORDER)
		return NULL;
	nid = pisa_sanitize_nid(nid);

	return pisa_nodes[nid].pa[ro][order];
}

/**
 * pisa_alloc_pages_bulk - Allocate pages from a per-node __GFP_PISA_* allocator
 * @gfp: GFP flags (must have __GFP_PISA_RW or __GFP_PISA_RO set)
 * @order: Page order
 * @preferred_nid: Preferred NUMA node (or NUMA_NO_NODE)
 * @nodemask: Allowed NUMA nodemask (declined if non-NULL)
 * @nr_pages: Total entries in @page_array
 * @page_array: Output array of page pointers (populated entries are skipped)
 * @frozen: Leave allocated pages frozen at refcount 0 if true
 *
 * Return: Number of populated entries at the start of @page_array.
 */
unsigned long pisa_alloc_pages_bulk(gfp_t gfp, unsigned int order, int preferred_nid,
				    nodemask_t *nodemask, int nr_pages,
				    struct page **page_array, bool frozen)
{
	struct pisa_alloc *pa = NULL;

	if (unlikely(nr_pages <= 0))
		return 0;
	if (likely(!nodemask) && (!order || (gfp & __GFP_COMP)))
		pa = pisa_node_pa(preferred_nid, order, !(gfp & __GFP_WRITE));
	return pisa_alloc_bulk(pa, gfp & ~__GFP_PISA_RW, nr_pages, page_array, frozen);
}

/**
 * pisa_alloc_folio - Allocate a frozen folio for SLUB (SLAB_CACHE_PISA_RO)
 * @gfp: GFP flags (must have __GFP_PISA_RW or __GFP_PISA_RO set)
 * @order: Folio order
 * @nid: Target NUMA node (or NUMA_NO_NODE)
 *
 * Drops __GFP_THISNODE before calling the per-node allocator and verifies
 * node placement afterwards.
 *
 * Return: Frozen folio of @order, or NULL.
 */
struct folio *pisa_alloc_folio(gfp_t gfp, unsigned int order, int nid)
{
	struct page *page;

	page = pisa_alloc_pages(gfp & ~__GFP_THISNODE, order, nid, NULL);
	if (!page)
		return NULL;
	if (unlikely((gfp & __GFP_THISNODE) && nid != NUMA_NO_NODE &&
		     page_to_nid(page) != nid)) {
		page_ref_unfreeze(page, 1);
		__free_pages(page, order);
		return NULL;
	}
	return page_folio(page);
}

/**
 * pisa_has_free_blocks_rx - Check if @dev has free PISA RX blocks of @order on @nid
 * @dev: Device to check
 * @order: Block order
 * @nid: Target NUMA node (or NUMA_NO_NODE)
 *
 * Return: true if @dev->pisa_rx_bufs is enabled and the per-node allocator
 * has a free block available.
 */
bool pisa_has_free_blocks_rx(const struct device *dev, unsigned int order, int nid)
{
	struct pisa_alloc *pa;

	if (!dev || !READ_ONCE(dev->pisa_rx_bufs))
		return false;
	pa = pisa_node_pa(nid, order, false);
	return pa &&
	       /* Pairs with cmpxchg_release() in pisa_enable_pcp(). */
	       ((smp_load_acquire(&pa->pcp) && raw_cpu_read(pa->pcp->count)) ||
		!list_empty_careful(&pa->partial) ||
		!list_empty_careful(&pa->partial_dirty) ||
		!list_empty_careful(&pa->idle));
}
EXPORT_SYMBOL(pisa_has_free_blocks_rx);

#ifdef CONFIG_NET
/* Enabled while at least one device has pisa_tx_bufs set. */
DEFINE_STATIC_KEY_FALSE(net_pisa_tx_bufs_key);
EXPORT_SYMBOL(net_pisa_tx_bufs_key);

int net_pisa_tx_bufs_set(struct device *dev, bool val)
{
	static DEFINE_MUTEX(lock);

	mutex_lock(&lock);
	if (dev->pisa_tx_bufs != val) {
		WRITE_ONCE(dev->pisa_tx_bufs, val);
		if (val)
			static_branch_inc(&net_pisa_tx_bufs_key);
		else
			static_branch_dec(&net_pisa_tx_bufs_key);
	}
	mutex_unlock(&lock);
	return 0;
}

/*
 * dev->pisa_tx_skb_heads: when set on an egress device, small TX skb heads
 * (__GFP_PISA_RO) come from a copy of skbuff_small_head whose slab pages are
 * PISA blocks. The linear part of most transmitted skbs is then mapped
 * through the PISA window without per-driver bounce buffers. Several heads
 * share a slab page and each one ends with its skb_shared_info, so:
 * - the allocators are TX-only (DMA_TO_DEVICE): their PISA pages are mapped device
 *   read-only, and a DMA mapping that wants device writes gets a per-buffer
 *   IOMMU mapping, as for any kmalloc() buffer;
 * - slab pages are zeroed when taken from the allocator, so the device can read
 *   skb heads (live or freed) but never older contents of the page.
 * Heads are freed with kfree() whichever cache they came from, so the key
 * can be toggled at any time. The cache and allocators are created on the first
 * write and never destroyed.
 */
DEFINE_STATIC_KEY_FALSE(net_pisa_tx_skb_heads_key);
EXPORT_SYMBOL(net_pisa_tx_skb_heads_key);

static struct kmem_cache *pisa_skb_small_head_cache __read_mostly;

/* Lazily initialize skbuff_small_head_pisa on first enable. */
static int pisa_skb_head_init(void)
{
	unsigned int size = kmem_cache_size(net_hotdata.skb_small_head_cache);
	struct kmem_cache_args args = {
		/* As skbuff_small_head, see skb_init(). */
		.useroffset	= 0,
		.usersize	= SKB_WITH_OVERHEAD(size),
		.sheaf_capacity	= 32,
	};
	static DEFINE_MUTEX(mutex);
	struct kmem_cache *s;
	int ret = 0;

	mutex_lock(&mutex);
	if (pisa_skb_small_head_cache)
		goto out;

	/* No slab is allocated before the cache is published below. */
	s = kmem_cache_create("skbuff_small_head_pisa", size, &args,
			      SLAB_HWCACHE_ALIGN | SLAB_NO_MERGE | SLAB_CACHE_PISA_RO);
	if (!s) {
		ret = -ENOMEM;
		goto out;
	}
	WRITE_ONCE(pisa_skb_small_head_cache, s);
out:
	mutex_unlock(&mutex);
	return ret;
}

int net_pisa_tx_skb_heads_set(struct device *dev, bool val)
{
	static DEFINE_MUTEX(lock);

	if (val) {
		int ret = pisa_skb_head_init();

		if (ret)
			return ret;
	}

	mutex_lock(&lock);
	if (dev->pisa_tx_skb_heads != val) {
		WRITE_ONCE(dev->pisa_tx_skb_heads, val);
		if (val)
			static_branch_inc(&net_pisa_tx_skb_heads_key);
		else
			static_branch_dec(&net_pisa_tx_skb_heads_key);
	}
	mutex_unlock(&lock);
	return 0;
}

void *pisa_skb_head_alloc_node(gfp_t flags, int node)
{
	if (!static_branch_unlikely(&net_pisa_tx_skb_heads_key))
		return NULL;
	return kmem_cache_alloc_node(pisa_skb_small_head_cache,
				     flags | __GFP_NOMEMALLOC | __GFP_NOWARN, node);
}

/*
 * The sysfs attributes pisa_tx_bufs and pisa_tx_skb_heads live on the
 * physical DMA parent (dev->dev.parent), whereas a socket route (dst->dev)
 * may point to an upper virtual net_device (bond, VLAN, ipvlan, etc.).
 * Walking lower devices via netdev_walk_all_lower_dev_rcu() on every TX
 * allocation would be too expensive, so dev->pisa_tx_stamp caches the walk
 * result on the net_device and refreshes it at most once every 256 jiffies:
 *   bit 0 (PISA_TX_STAMP_BUFS):       pisa_tx_bufs enabled on lower device(s)
 *   bit 1 (PISA_TX_STAMP_HEADS):      pisa_tx_skb_heads enabled on lower device(s)
 *   bits 31..8 (PISA_TX_STAMP_MASK):  upper 24 bits of (u32)jiffies
 */
static u32 netdev_pisa_tx_flags(const struct net_device *dev)
{
	struct device *parent = dev->dev.parent;
	u32 flags = 0;

	if (parent) {
		if (READ_ONCE(parent->pisa_tx_bufs))
			flags |= PISA_TX_STAMP_BUFS;
		if (READ_ONCE(parent->pisa_tx_skb_heads))
			flags |= PISA_TX_STAMP_HEADS;
	}
	return flags;
}

static int netdev_pisa_tx_walk(struct net_device *dev, struct netdev_nested_priv *priv)
{
	priv->data = (void *)((uintptr_t)priv->data | netdev_pisa_tx_flags(dev));
	return 0;
}

/* Slow path of __netdev_tx_pisa_ok(): refresh dev->pisa_tx_stamp. */
u32 netdev_tx_pisa_refresh(struct net_device *dev, u32 now)
{
	if (dev->dev.parent) {
		now |= netdev_pisa_tx_flags(dev);
	} else {
		struct netdev_nested_priv priv = {};

		rcu_read_lock();
		netdev_walk_all_lower_dev_rcu(dev, netdev_pisa_tx_walk, &priv);
		rcu_read_unlock();
		now |= (uintptr_t)priv.data;
	}
	WRITE_ONCE(dev->pisa_tx_stamp, now);
	return now;
}
EXPORT_SYMBOL(netdev_tx_pisa_refresh);
#endif /* CONFIG_NET */

/*
 * Split a non-compound page of @old_order into 1 << (@old_order - @new_order)
 * pages of @new_order (compound if @new_order > 0), all frozen at refcount 0.
 * Fails with -EBUSY if a speculative PFN walker holds a reference to @page.
 */
static int split_page_compound(struct page *page, unsigned int old_order, unsigned int new_order)
{
	unsigned int i;

	if (WARN_ON_ONCE(PageCompound(page) || !page_count(page) ||
			 new_order > old_order ||
			 folio_memcg_charged(page_folio(page))))
		return -EINVAL;

	/* Freeze @page[0] (1 -> 0) so all resulting pieces start at refcount 0. */
	if (!page_ref_freeze(page, 1))
		return -EBUSY;

	if (new_order < old_order) {
		split_page_owner(page, old_order, new_order);
		pgalloc_tag_split(page_folio(page), old_order, new_order);
	}

	/* Subpages of non-compound pages are already initialized as order 0. */
	if (new_order == 0)
		return 0;

	for (i = 0; i < (1U << old_order); i += (1U << new_order))
		prep_compound_page(page + i, new_order);

	return 0;
}

/* Obtain and split a new PISA page on @nid into blocks of @order. */
static struct pisa_meta *pisa_alloc_split_page(unsigned int order, gfp_t gfp, int nid)
{
	bool can_block = gfpflags_allow_blocking(gfp), clean;
	unsigned int bpp = PISA_BLOCKS(order);
	struct pisa_meta *meta;
	struct page *page;
	int ret;

	/* __GFP_DMA/__GFP_DMA32 were already declined by pisa_alloc_bulk(). */
	meta = pisa_reservoir_pop(nid, gfp & ~__GFP_ZERO, pisa_want_decrypt(), &clean);
	if (IS_ERR(meta))
		return meta;

	if (unlikely(pisa_slot_alloc(meta))) {
		ret = -ENOSPC;
		goto err_free;
	}

	page = pfn_to_page(pisa_meta_to_pfn(meta));

	/* Fails with -EBUSY if a concurrent PFN walker holds a speculative ref. */
	if (split_page_compound(page, PISA_ORDER, order)) {
		pisa_slot_free(meta->slot);
		pisa_alloc_backoff(nid, can_block);
		ret = -EBUSY;
		goto err_free;
	}

	INIT_LIST_HEAD(&meta->list);

	if (clean) {
		bitmap_set(meta->clean_bitmap, 0, bpp);
		meta->nr_clean = bpp;
	} else {
		bitmap_set(meta->dirty_bitmap, 0, bpp);
		meta->nr_dirty = bpp;
	}

	return meta;

err_free:
	if (!can_block && (meta->flags & PISA_DECRYPTED)) {
		/* set_memory_encrypted() may sleep; defer to reclaim worker. */
		llist_add(&meta->llnode, &pisa_free_list);
		pisa_schedule_reclaim();
	} else {
		pisa_release_page(meta);
	}
	return ERR_PTR(ret);
}

/* Reset fields normally cleared by prep_new_page()/post_alloc_hook(). */
static void pisa_block_prep(struct page *block)
{
	set_page_private(block, 0);
	clear_page_pfmemalloc(block);
}

/*
 * Collect up to @want blocks from @meta's dirty or clean bitmap. With
 * @unfreeze they get refcount 1; otherwise they stay at refcount 0.
 */
static unsigned int pisa_scan_bitmap(struct pisa_meta *meta, bool dirty,
				     unsigned int want, struct page **out, bool unfreeze)
{
	unsigned long *bitmap = dirty ? meta->dirty_bitmap : meta->clean_bitmap;
	u16 *countp = dirty ? &meta->nr_dirty : &meta->nr_clean;
	struct pisa_alloc *pa = meta->pa;
	unsigned int idx, got = 0, used = 0;
	unsigned long base_pfn;

	if (!*countp || !want)
		return 0;

	base_pfn = pisa_meta_to_pfn(meta);
	for_each_set_bit(idx, bitmap, PISA_BLOCKS(pa->order)) {
		struct page *block = pfn_to_page(base_pfn + (idx << pa->order));

		__clear_bit(idx, bitmap);
		used++;
		if (!pisa_block_poisoned(pa, block)) {
			pisa_block_prep(block);
			if (unfreeze)
				page_ref_unfreeze(block, 1);
			out[got++] = block;
		}

		if (used == *countp || got == want)
			break;
	}
	*countp -= used;
	pa->blocks_in_use += used;
	return got;
}

/* @zero: prefer PISA pages with blocks in @meta->clean_bitmap. */
static struct pisa_meta *pisa_pick_meta(struct pisa_alloc *pa, bool zero)
{
	struct pisa_meta *m_dirty, *m_clean, *meta;

	if (zero) {
		/* Clean blocks first: the head of @partial, then of @idle. */
		if (!list_empty(&pa->partial))
			return list_first_entry(&pa->partial, struct pisa_meta, list);
		meta = list_first_entry_or_null(&pa->idle, struct pisa_meta, list);
		if (meta && meta->nr_clean) {
			pa->num_idle_pages--;
			WRITE_ONCE(meta->alloc_jiffies, jiffies);
			WRITE_ONCE(pa->idle_jiffies, jiffies);
			return meta;
		}
	}

	m_dirty = list_first_entry_or_null(&pa->partial_dirty, struct pisa_meta, list);
	m_clean = list_first_entry_or_null(&pa->partial, struct pisa_meta, list);
	if (m_dirty && m_clean) {
		bool dirty_dense = m_dirty->on_list == PISA_LIST_PARTIAL_DIRTY_DENSE;
		bool clean_dense = m_clean->on_list == PISA_LIST_PARTIAL_CLEAN_DENSE;

		if (dirty_dense != clean_dense)
			return dirty_dense ? m_dirty : m_clean;
		return pisa_meta_avail(m_dirty) <= pisa_meta_avail(m_clean) ?
		       m_dirty : m_clean;
	}
	if (m_dirty)
		return m_dirty;
	if (m_clean)
		return m_clean;
	if (!list_empty(&pa->idle)) {
		meta = list_last_entry(&pa->idle, struct pisa_meta, list);
		pa->num_idle_pages--;
		WRITE_ONCE(meta->alloc_jiffies, jiffies);
		WRITE_ONCE(pa->idle_jiffies, jiffies);
		return meta;
	}
	return NULL;
}

/* Extract up to @want blocks from @meta under @pa->lock. */
static unsigned int take_blocks(struct pisa_meta *meta, unsigned int want,
				struct page **out, bool zero, bool frozen)
{
	unsigned int avail_before = pisa_meta_avail(meta), got = 0, used;
	struct pisa_alloc *pa = meta->pa;

	lockdep_assert_held(&pa->lock);

	if (zero) {
		unsigned int dirty, i;

		/* First choice are clean blocks, followed by dirty */
		got += pisa_scan_bitmap(meta, false, want, out, !frozen);
		dirty = pisa_scan_bitmap(meta, true, want - got, out + got, false);
		for (i = got; i < got + dirty; i++)
			set_page_private(out[i], 1);
		got += dirty;
		pa->scrub_demand = min(pa->scrub_demand + dirty, PISA_SCRUB_DEMAND_MAX);
	} else {
		/* First choice are dirty blocks, followed by clean */
		got += pisa_scan_bitmap(meta, true, want, out, !frozen);
		got += pisa_scan_bitmap(meta, false, want - got, out + got, !frozen);
	}

	used = avail_before - pisa_meta_avail(meta);
	/* If counts disagreed with bitmaps, zero them so @meta moves to @pa->full. */
	if (WARN_ON_ONCE(!used)) {
		meta->nr_clean = 0;
		meta->nr_dirty = 0;
	}
	pisa_place_meta(meta);

	return got;
}

/* Allocate @nr_pages blocks from @pa. */
static unsigned long __pisa_alloc_bulk(struct pisa_alloc *pa, gfp_t gfp, unsigned long nr_pages,
				       struct page **pages, bool zero, bool frozen)
{
	bool should_scrub = false;
	unsigned long n, flags, i;
	struct pisa_meta *meta;
	unsigned int want;

	/* Held across bitmap scans; dropped around slow-path pisa_alloc_split_page(). */
	spin_lock_irqsave(&pa->lock, flags);
	for (n = 0; n < nr_pages; n += take_blocks(meta, want, &pages[n], zero, frozen)) {
		want = min_t(unsigned long, nr_pages - n, PISA_BLOCKS(pa->order));
		meta = pisa_pick_meta(pa, zero);
		if (meta)
			continue;

		/* Fallback to a new allocation */
		should_scrub |= pa->scrub_demand >= PISA_SCRUB_TRIGGER;
		spin_unlock_irqrestore(&pa->lock, flags);
		/* With @zero, fresh dirty blocks are zeroed below. */
		meta = pisa_alloc_split_page(pa->order, gfp, pa->nid);
		if (IS_ERR(meta))
			goto out;
		spin_lock_irqsave(&pa->lock, flags);
		meta->pa = pa;
		meta->prot = pa->prot;
		WRITE_ONCE(meta->alloc_jiffies, jiffies);
		/* Set PISA_ACTIVE after @meta is fully set up. */
		WRITE_ONCE(meta->flags, meta->flags | PISA_ACTIVE);
		pa->stats.page_alloc_cnt++;
	}
	/* Queue the scrubber when the inline zeroing crosses the trigger. */
	should_scrub |= pa->scrub_demand >= PISA_SCRUB_TRIGGER;
	spin_unlock_irqrestore(&pa->lock, flags);

out:
	for (i = 0; zero && i < n; i++) {
		/* Dirty blocks for a zeroing caller were marked with page_private = 1. */
		if (!page_private(pages[i]))
			continue;
		set_page_private(pages[i], 0);
		memset(page_address(pages[i]), 0, PAGE_SIZE << pa->order);
		if (frozen) /* Order zeroing before caller publishes the page. */
			smp_wmb();
		else
			page_ref_unfreeze(pages[i], 1);
	}
	if (should_scrub)
		pisa_schedule_scrub(pa->nid);
	return n;
}

/* Allocate @nr_pages blocks through this CPU's cache, refilling in batches on miss. */
static unsigned long pisa_pcp_alloc(struct pisa_alloc *pa, gfp_t gfp, unsigned long nr_pages,
				    struct page **page_array, bool frozen)
{
	unsigned int pcp_batch = READ_ONCE(pisa_pcp_batch);
	unsigned long got, n, i, j;

	got = pisa_pcp_pop(pa, nr_pages, page_array);
	if (got < nr_pages) {
		if (nr_pages - got >= pcp_batch) {
			got += __pisa_alloc_bulk(pa, gfp, nr_pages - got,
						 page_array + got, false, true);
		} else {
			struct page *batch[PISA_PCP_BATCH];

			n = __pisa_alloc_bulk(pa, gfp, pcp_batch, batch, false, true);
			for (i = 0; i < n && got < nr_pages; i++)
				page_array[got++] = batch[i];
			if (i < n)
				pisa_pcp_push(pa, batch + i, n - i);
		}
	}

	for (i = j = 0; i < got; i++) {
		struct page *block = page_array[i];

		page_array[i] = NULL;
		/* Poisoned while cached: leak it, as pisa_scan_bitmap() does. */
		if (pisa_block_poisoned(pa, block))
			continue;
		pisa_block_prep(block);
		if (want_init_on_alloc(gfp)) {
			memset(page_address(block), 0, PAGE_SIZE << pa->order);
			if (frozen) /* Order zeroing before caller publishes the page. */
				smp_wmb();
		}
		if (!frozen)
			page_ref_unfreeze(block, 1);
		page_array[j++] = block;
	}
	return j;
}

/**
 * pisa_alloc_bulk - Allocate up to @nr_pages blocks from @pa
 * @pa: Allocator to allocate from
 * @gfp: GFP flags (requests with __GFP_THISNODE, __GFP_DMA, __GFP_DMA32, or
 *	__GFP_ACCOUNT are declined)
 * @nr_pages: Number of entries in @page_array (populated entries are skipped)
 * @page_array: Output array of page pointers
 * @frozen: Leave allocated pages frozen at refcount 0 if true
 *
 * Return: Number of populated entries at the start of @page_array.
 */
unsigned long pisa_alloc_bulk(struct pisa_alloc *pa, gfp_t gfp,
			      unsigned long nr_pages, struct page **page_array, bool frozen)
{
	unsigned long i = 0, n, got;

	if (unlikely(!pa ||
		     (gfp & (__GFP_DMA | __GFP_DMA32 | __GFP_THISNODE | __GFP_ACCOUNT))))
		goto skip;

	while (i < nr_pages) {
		if (page_array[i]) {
			i++;
			continue;
		}

		/* Fill the run of @n NULL entries at @i. */
		for (n = 1; i + n < nr_pages && !page_array[i + n]; n++)
			;
		/* Pairs with smp_store_release() in pisa_enable_pcp(). */
		if (smp_load_acquire(&pa->pcp))
			got = pisa_pcp_alloc(pa, gfp, n, page_array + i, frozen);
		else
			got = __pisa_alloc_bulk(pa, gfp, n, page_array + i,
						want_init_on_alloc(gfp), frozen);
		i += got;
		if (got < n)
			break;
	}
	return i;

skip:
	/* Declined: report the populated prefix, as alloc_pages_bulk_node() does. */
	while (i < nr_pages && page_array[i])
		i++;
	return i;
}

/* Find and reserve @nblocks aligned contiguous blocks in @meta under @pa->lock. */
static struct page *pisa_take_contig(struct pisa_meta *meta, unsigned int nblocks,
				     unsigned long align_mask)
{
	DECLARE_BITMAP(busy, PISA_MAX_BLOCKS);
	struct pisa_alloc *pa = meta->pa;
	unsigned int bpp = PISA_BLOCKS(0), i, dirty = 0;
	bool poisoned = false;
	unsigned long off;
	struct page *page;

	if (pisa_meta_avail(meta) < nblocks)
		return NULL;

	bitmap_or(busy, meta->clean_bitmap, meta->dirty_bitmap, bpp);
	bitmap_complement(busy, busy, bpp);

	off = 0;
	for (;;) {
		off = bitmap_find_next_zero_area(busy, bpp, off, nblocks, align_mask);
		if (off >= bpp) {
			if (poisoned) {
				if (meta->on_list == PISA_LIST_IDLE_CLEAN ||
				    meta->on_list == PISA_LIST_IDLE_DIRTY)
					pa->num_idle_pages--;
				pisa_place_meta(meta);
			}
			return NULL;
		}

		page = pfn_to_page(pisa_meta_to_pfn(meta) + off);
		for (i = 0; i < nblocks; i++) {
			if (!pisa_block_poisoned(pa, page + i))
				continue;
			if (__test_and_clear_bit(off + i, meta->clean_bitmap)) {
				meta->nr_clean--;
				pa->blocks_in_use++;
			} else if (__test_and_clear_bit(off + i, meta->dirty_bitmap)) {
				meta->nr_dirty--;
				pa->blocks_in_use++;
			}
			__set_bit(off + i, busy);
			poisoned = true;
			off += i + 1;
			break;
		}
		if (i == nblocks)
			break;
	}

	if (meta->on_list == PISA_LIST_IDLE_CLEAN ||
	    meta->on_list == PISA_LIST_IDLE_DIRTY) {
		pa->num_idle_pages--;
		WRITE_ONCE(meta->alloc_jiffies, jiffies);
	}

	for (i = 0; i < nblocks; i++) {
		if (__test_and_clear_bit(off + i, meta->clean_bitmap)) {
			meta->nr_clean--;
		} else {
			__clear_bit(off + i, meta->dirty_bitmap);
			meta->nr_dirty--;
			dirty++;
		}
		pisa_block_prep(page + i);
		page_ref_unfreeze(page + i, 1);
	}
	pa->blocks_in_use += nblocks;
	pa->scrub_demand = min(pa->scrub_demand + dirty, PISA_SCRUB_DEMAND_MAX);
	pisa_place_meta(meta);
	return page;
}

/*
 * Specialized memory provider for iommu_dma_alloc() and dma_direct_alloc():
 * allocate a zeroed, naturally aligned contiguous range of order-0 pages for
 * @size bytes (<= PISA_SIZE) from @dev's per-node coherent allocator into
 * *@pagep and return its kernel virtual address, or NULL.
 */
void *pisa_alloc_coherent(struct page **pagep, struct device *dev,
			  struct iommu_domain *domain, size_t size,
			  gfp_t gfp, unsigned long attrs)
{
	bool should_scrub = false, should_release = false;
	struct list_head *lists[3];
	unsigned long align_mask, flags;
	unsigned int nblocks, i;
	struct pisa_meta *meta;
	struct pisa_alloc *pa;
	struct page *page = NULL;

	size = PAGE_ALIGN(size);
	if (!pagep || !dev || !READ_ONCE(dev->pisa_coherent) ||
	    !dev_is_dma_coherent(dev) || !size || size > PISA_SIZE)
		return NULL;
	if (min_not_zero(dev->coherent_dma_mask, dev->bus_dma_limit) <= DMA_BIT_MASK(32))
		return NULL;
	if ((current_gfp_context(gfp) & ~(__GFP_ZERO | __GFP_NOWARN)) != GFP_KERNEL ||
	    (attrs & ~DMA_ATTR_NO_WARN))
		return NULL;

	if (domain) {
		struct pisa_window *win = pisa_dma_window(domain);

		if (!win || pisa_window_declined(win) || !(domain->pgsize_bitmap & PISA_SIZE))
			return NULL;
	} else if (is_swiotlb_for_alloc(dev) ||
		   (force_dma_unencrypted(dev) && !pisa_want_decrypt()) ||
		   !dma_coherent_ok(dev, PFN_PHYS(max_pfn) - 1, 1)) {
		return NULL;
	}

	pa = pisa_node_pa(dev_to_node(dev), 0, false);
	if (!pa)
		return NULL;
	pisa_pcp_drain(pa);

	nblocks = size >> PAGE_SHIFT;
	align_mask = (1UL << get_order(size)) - 1;
	lists[0] = &pa->partial;
	lists[1] = &pa->partial_dirty;
	lists[2] = &pa->idle;

	spin_lock_irqsave(&pa->lock, flags);
	for (i = 0; i < ARRAY_SIZE(lists) && !page; i++) {
		list_for_each_entry(meta, lists[i], list) {
			page = pisa_take_contig(meta, nblocks, align_mask);
			if (page)
				break;
		}
	}
	if (!page) {
		should_scrub |= pa->scrub_demand >= PISA_SCRUB_TRIGGER;
		spin_unlock_irqrestore(&pa->lock, flags);
		meta = pisa_alloc_split_page(0, gfp, pa->nid);
		if (IS_ERR(meta)) {
			if (should_scrub)
				pisa_schedule_scrub(pa->nid);
			return NULL;
		}
		spin_lock_irqsave(&pa->lock, flags);
		meta->pa = pa;
		meta->prot = pa->prot;
		WRITE_ONCE(meta->alloc_jiffies, jiffies);
		WRITE_ONCE(meta->flags, meta->flags | PISA_ACTIVE);
		pa->stats.page_alloc_cnt++;
		page = pisa_take_contig(meta, nblocks, align_mask);
		if (unlikely(!page))
			should_release = pisa_place_meta(meta);
	}
	should_scrub |= pa->scrub_demand >= PISA_SCRUB_TRIGGER;
	spin_unlock_irqrestore(&pa->lock, flags);

	if (should_release)
		pisa_schedule_reclaim();
	if (should_scrub)
		pisa_schedule_scrub(pa->nid);
	if (!page)
		return NULL;
	*pagep = page;
	return memset(page_address(page), 0, size);
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

	/* Pairs with cmpxchg_release() in pisa_enable_pcp(). */
	if (smp_load_acquire(&pa->pcp) && pa->nid == numa_mem_id() &&
	    page_to_nid(page) == numa_mem_id()) {
		if (pisa_page_can_recycle(page)) {
			pisa_pcp_push(pa, &page, 1);
			return true;
		}
		if (this_cpu_read(pa->pcp->count))
			pisa_pcp_drain_cpu(pa, raw_smp_processor_id());
	}

	spin_lock_irqsave(&pa->lock, flags);
	pisa_return_block_locked(pa, page, &should_release);
	spin_unlock_irqrestore(&pa->lock, flags);

	if (should_release)
		pisa_schedule_reclaim();

	return true;
}

/* Shrinker: releases reservoir pages first, then idle allocator pages. */
static unsigned long pisa_shrink_count(struct shrinker *shrink, struct shrink_control *sc)
{
	unsigned long nr = pisa_reservoir_count() << PISA_ORDER;
	struct pisa_alloc *pa;

	read_lock(&pisa_allocs_lock);
	list_for_each_entry(pa, &pisa_allocs, node) {
		nr += (unsigned long)READ_ONCE(pa->num_idle_pages) << PISA_ORDER;
		nr += pisa_pcp_count(pa) << pa->order;
	}
	read_unlock(&pisa_allocs_lock);

	return nr;
}

/* Detach PISA pages from @list onto @release_list up to @nr_to_scan base pages. */
unsigned long pisa_shrink_list(spinlock_t *lock, struct list_head *list,
			       unsigned int *nr, struct list_head *release_list,
			       unsigned long nr_to_scan)
{
	unsigned long freed = 0, flags;

	spin_lock_irqsave(lock, flags);
	while (freed < nr_to_scan && !list_empty(list)) {
		list_move(list->next, release_list);
		(*nr)--;
		freed += 1UL << PISA_ORDER;
	}
	spin_unlock_irqrestore(lock, flags);

	return freed;
}

VISIBLE_IF_KUNIT unsigned long pisa_shrink_scan(struct shrinker *shrink, struct shrink_control *sc)
{
	struct pisa_meta *meta, *tmp;
	struct pisa_alloc *pa;
	unsigned long freed;
	LIST_HEAD(release_list);

	freed = pisa_reservoir_shrink(&release_list, sc->nr_to_scan);

	if (freed < sc->nr_to_scan) {
		read_lock(&pisa_allocs_lock);
		list_for_each_entry(pa, &pisa_allocs, node) {
			/* Cached blocks keep PISA pages from going idle. */
			pisa_pcp_drain(pa);
			freed += pisa_shrink_list(&pa->lock, &pa->idle,
						  &pa->num_idle_pages, &release_list,
						  sc->nr_to_scan - freed);

			if (freed >= sc->nr_to_scan)
				break;
		}
		read_unlock(&pisa_allocs_lock);
	}

	/* Unmap outside locks; defer decrypted pages to workqueue outside fs_reclaim. */
	list_for_each_entry_safe(meta, tmp, &release_list, list) {
		list_del_init(&meta->list);
		if (meta->flags & PISA_DECRYPTED) {
			llist_add(&meta->llnode, &pisa_free_list);
			pisa_schedule_reclaim();
		} else {
			pisa_release_page(meta);
		}
	}

	/* Charge do_shrink_slab() for the full PISA pages reclaimed. */
	sc->nr_scanned = freed;

	return freed ?: SHRINK_STOP;
}

/* Return the blocks a dead CPU cached, which nothing else would. */
static int pisa_cpu_dead(unsigned int cpu)
{
	struct pisa_alloc *pa;

	read_lock(&pisa_allocs_lock);
	list_for_each_entry(pa, &pisa_allocs, node)
		/* Pairs with smp_store_release() in pisa_enable_pcp(). */
		if (smp_load_acquire(&pa->pcp))
			pisa_pcp_drain_cpu(pa, cpu);
	read_unlock(&pisa_allocs_lock);
	return 0;
}

static int __init pisa_init(void)
{
	const struct {
		u8 order;
		bool ro;
		bool pcp;
	} cfg[] = {
		{ 0, false, true },
		{ 2, true, false },
		{ SKB_FRAG_PAGE_ORDER, true, true },
	};
	struct shrinker *shrink;
	int nid, i;

	pisa_node_init();

	/* Default ceiling is 1/8th of RAM (floor of 16 PISA pages). */
	if (!pisa_max_pages)
		pisa_max_pages = max(totalram_pages() >> (PISA_ORDER + 3), 16UL);

	pisa_slots_init();

	/*
	 * CoCo guests require decrypted pages and cannot decrypt in atomic
	 * context, so ensure the per-node reservoir is enabled to serve them.
	 */
	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT)) {
		pisa_decrypt = true;
		if (!pisa_reservoir_max)
			pisa_reservoir_max = 16;
	}

	/* Preallocate the supported per-node allocators. */
	for_each_node_state(nid, N_MEMORY) {
		for (i = 0; i < ARRAY_SIZE(cfg); i++) {
			unsigned int order = cfg[i].order;
			bool ro = cfg[i].ro;
			struct pisa_alloc *pa;

			if (order > PISA_ORDER || pisa_nodes[nid].pa[ro][order])
				continue;
			pa = pisa_create(nid, order, ro ? DMA_TO_DEVICE : DMA_BIDIRECTIONAL);
			if (!pa)
				continue;
			pisa_set_name(pa, "pisa%s_o%u_n%d", ro ? "_ro" : "", order, nid);
			if (cfg[i].pcp)
				pisa_enable_pcp(pa);
			pisa_nodes[nid].pa[ro][order] = pa;
		}
	}

	pisa_user_boot_enable();

	/* Dedicated WQ_MEM_RECLAIM workqueue so reclaim never blocks behind system_wq. */
	pisa_wq = alloc_workqueue("pisa", WQ_MEM_RECLAIM, 0);
	if (!pisa_wq)
		pr_warn("pisa: no reclaim workqueue, falling back to system_wq\n");

	if (cpuhp_setup_state_nocalls(CPUHP_BP_PREPARE_DYN, "iommu/pisa:dead", NULL,
				      pisa_cpu_dead) < 0)
		pr_warn("pisa: no CPU hotplug callback, offline CPUs keep cached blocks\n");

	shrink = shrinker_alloc(0, "pisa");
	if (!shrink) {
		pr_warn("pisa: shrinker registration failed\n");
		return 0;
	}

	shrink->count_objects = pisa_shrink_count;
	shrink->scan_objects = pisa_shrink_scan;
	shrink->seeks = DEFAULT_SEEKS;
	shrinker_register(shrink);

	return 0;
}
subsys_initcall(pisa_init);

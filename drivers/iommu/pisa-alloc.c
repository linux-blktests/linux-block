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
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/page_owner.h>
#include <linux/pgalloc_tag.h>
#include <linux/rcupdate.h>
#include <linux/sched/mm.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <net/sock.h>

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

	/* __GFP_DMA/__GFP_DMA32 were already declined by pisa_alloc_bulk(). */
	meta = pisa_reservoir_pop(nid, gfp & ~__GFP_ZERO, &clean);
	if (IS_ERR(meta))
		return meta;

	page = pfn_to_page(pisa_meta_to_pfn(meta));

	/* Fails with -EBUSY if a concurrent PFN walker holds a speculative ref. */
	if (split_page_compound(page, PISA_ORDER, order)) {
		pisa_release_page(meta);
		pisa_alloc_backoff(nid, can_block);
		return ERR_PTR(-EBUSY);
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
		spin_unlock_irqrestore(&pa->lock, flags);
		/* With @zero, fresh dirty blocks are zeroed below. */
		meta = pisa_alloc_split_page(pa->order, gfp, pa->nid);
		if (IS_ERR(meta))
			goto out;
		spin_lock_irqsave(&pa->lock, flags);
		meta->pa = pa;
		/* Set PISA_ACTIVE after @meta is fully set up. */
		WRITE_ONCE(meta->flags, meta->flags | PISA_ACTIVE);
	}
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
	return n;
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
	const struct {
		u8 order;
		bool ro;
	} cfg[] = {
		{ 0, false },
		{ 2, true },
		{ SKB_FRAG_PAGE_ORDER, true },
	};
	int nid, i;

	pisa_node_init();

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
			pisa_nodes[nid].pa[ro][order] = pa;
		}
	}

	/* Dedicated WQ_MEM_RECLAIM workqueue so reclaim never blocks behind system_wq. */
	pisa_wq = alloc_workqueue("pisa", WQ_MEM_RECLAIM, 0);
	if (!pisa_wq)
		pr_warn("pisa: no reclaim workqueue, falling back to system_wq\n");

	return 0;
}
subsys_initcall(pisa_init);

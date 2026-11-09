/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _DRIVERS_IOMMU_PISA_PRIV_H
#define _DRIVERS_IOMMU_PISA_PRIV_H

#include <linux/dma-direction.h>
#include <linux/pisa.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/nodemask.h>
#include <linux/spinlock.h>
#include <linux/topology.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#ifdef CONFIG_PISA

#define PISA_MAX_BLOCKS		512U

#define PISA_BLOCKS(order)	(1U << (PISA_ORDER - (order)))

/*
 * Lock hierarchy:
 * - pisa_allocs_lock (rwlock): outermost; protects pisa_allocs list.
 * - pisa_meta_mutex (mutex): serializes pisa_meta_init() and page-table alloc.
 * - pa->lock (spinlock, irqsave): per-allocator lists, bitmaps, and stats.
 */

/**
 * struct pisa_meta - Metadata for a single PISA page in @pisa_meta_array
 * @flags:	PISA_ACTIVE while this page is owned by a pisa_alloc
 * @nr_clean:	Zeroed available blocks in @clean_bitmap
 * @nr_dirty:	Dirty available blocks in @dirty_bitmap
 * @on_list:	Current placement in @pa (enum pisa_meta_list)
 * @pa:		Owning pisa_alloc (NULL for reservoir pages)
 * @list:	Node in @pa lists or per-node reservoir (pisa_node.pages)
 * @llnode:	Node in lockless pisa_free_list for async release to the buddy allocator
 * @rcu:	RCU head used to defer release to the buddy allocator
 * @clean_bitmap: Bitmap of zeroed available block indices
 * @dirty_bitmap: Bitmap of dirty available block indices
 */
struct pisa_meta {
	u8 flags;
	u16 nr_clean;
	u16 nr_dirty;
	u8 on_list;
	struct pisa_alloc *pa;
	struct list_head list;

	union {
		struct llist_node llnode;
		struct rcu_head rcu;
	};

	DECLARE_BITMAP(clean_bitmap, PISA_MAX_BLOCKS) ____cacheline_aligned;
	DECLARE_BITMAP(dirty_bitmap, PISA_MAX_BLOCKS) ____cacheline_aligned;
} __aligned(PISA_META_SIZE);

static_assert(offsetof(struct pisa_meta, flags) == 0);
static_assert(sizeof(struct pisa_meta) == PISA_META_SIZE);

static inline unsigned int pisa_meta_avail(const struct pisa_meta *meta)
{
	return meta->nr_clean + meta->nr_dirty;
}

/**
 * struct pisa_alloc - Allocator managing 2MB-backed blocks of a fixed order
 * @lock:	Spinlock protecting lists and block bitmaps
 * @order:	Block order managed by this allocator (<= PISA_ORDER)
 * @partial:	Partially used PISA pages with @nr_clean > 0
 * @partial_dirty: Partially used PISA pages with @nr_clean == 0 and @nr_dirty > 0
 * @idle:	Completely free PISA pages (reclaimable under pressure)
 * @full:	List of PISA pages with 0 free blocks
 * @num_idle_pages: Length of @idle
 * @max_idle_pages: High watermark of @idle before async release to the buddy allocator
 * @idle_jiffies: Timestamp (jiffies) when @idle last exceeded @max_idle_pages
 * @nid:	NUMA node id
 * @node:	Node in the global pisa_allocs list
 * @name:	Debug name (defaults to caller of pisa_create())
 */
struct pisa_alloc {
	/* First cacheline: hot fields touched on block alloc and free. */
	spinlock_t		lock;
	u8			order;
	struct list_head	partial;
	struct list_head	partial_dirty;
	struct list_head	idle;
	struct list_head	full;
	unsigned int		num_idle_pages;
	unsigned int		max_idle_pages;
	unsigned long		idle_jiffies;

	/* Cold. */
	int			nid;
	struct list_head	node;
	char			name[48];
} ____cacheline_aligned;

/* Per-NUMA-node PISA state. */
struct pisa_node {
	unsigned long		next_alloc;	/* atomic alloc backoff jiffies */
	struct pisa_alloc	*pa[2][PISA_ORDER + 1]; /* [0]=RW, [1]=RO by order */

	spinlock_t		lock;		/* protects @pages and @nr_pages */
	struct list_head	pages;		/* reservoir */
	unsigned int		nr_pages;
	struct work_struct	work;		/* refill/trim, on this node */
} ____cacheline_aligned_in_smp;

/* Per-NUMA-node PISA state (ring/TX/user allocators, reservoir). */
extern struct pisa_node pisa_nodes[MAX_NUMNODES];

int pisa_meta_ensure_pfn(unsigned long pfn, bool can_block);
struct pisa_meta *pisa_meta_of_pfn(unsigned long pfn);
unsigned long pisa_meta_to_pfn(const struct pisa_meta *meta);

struct shrink_control;
struct shrinker;
#if IS_ENABLED(CONFIG_KUNIT)
unsigned long pisa_shrink_scan(struct shrinker *shrink, struct shrink_control *sc);
#endif

/* Global PISA page budget across all allocators and per-node reservoirs. */
extern atomic_long_t pisa_nr_pages;
extern unsigned long pisa_max_pages;

static inline int pisa_sanitize_nid(int nid)
{
	if ((unsigned int)nid >= MAX_NUMNODES || !node_state(nid, N_MEMORY))
		nid = numa_mem_id();
	if (!node_state(nid, N_MEMORY))
		nid = first_memory_node;
	return nid;
}

static inline void pisa_alloc_backoff(int nid, bool can_block)
{
	nid = pisa_sanitize_nid(nid);
	if (!can_block)
		WRITE_ONCE(pisa_nodes[nid].next_alloc, jiffies + DIV_ROUND_UP(HZ, 100));
}

/* pisa-alloc.c, also used by the per-node code in pisa-node.c */
struct pisa_alloc *pisa_create(int nid, unsigned int order, enum dma_data_direction dir);
struct pisa_alloc *pisa_node_pa(int nid, unsigned int order, bool ro);
__printf(2, 3)
void pisa_set_name(struct pisa_alloc *pa, const char *fmt, ...);
void pisa_release_page(struct pisa_meta *meta);
unsigned long pisa_alloc_bulk(struct pisa_alloc *pa, gfp_t gfp,
			      unsigned long nr_pages, struct page **page_array, bool frozen);

static inline struct page *pisa_alloc(struct pisa_alloc *pa, gfp_t gfp)
{
	struct page *page = NULL;

	if (pa)
		pisa_alloc_bulk(pa, gfp, 1, &page, false);
	return page;
}

unsigned long pisa_shrink_list(spinlock_t *lock, struct list_head *list,
			       unsigned int *nr, struct list_head *release_list,
			       unsigned long nr_to_scan);

/* pisa-node.c: per-NUMA-node PISA page reservoir and work item */
extern unsigned int pisa_reservoir_max;
void pisa_node_init(void);
void pisa_schedule_reservoir(void);
struct pisa_meta *pisa_reservoir_pop(int nid, gfp_t gfp, bool *clean);
unsigned long pisa_reservoir_count(void);
unsigned long pisa_reservoir_shrink(struct list_head *release_list, unsigned long nr_to_scan);

#endif /* CONFIG_PISA */
#endif /* _DRIVERS_IOMMU_PISA_PRIV_H */

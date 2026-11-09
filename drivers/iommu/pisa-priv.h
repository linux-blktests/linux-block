/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _DRIVERS_IOMMU_PISA_PRIV_H
#define _DRIVERS_IOMMU_PISA_PRIV_H

#include <linux/dma-mapping.h>
#include <linux/pisa.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/mem_encrypt.h>
#include <linux/nodemask.h>
#include <linux/spinlock.h>
#include <linux/topology.h>
#include <linux/types.h>
#include <linux/workqueue.h>

struct device;
struct iommu_domain;
struct iommu_iotlb_gather;

/**
 * struct pisa_window - A domain's IOVA window reserved for PISA pages
 * @base: Window base IOVA (PISA_SIZE aligned), or 0 if unassigned
 * @domain_idx: Dense index + PISA_IDX_FIRST, or PISA_IDX_* sentinel while @base == 0
 * @idx_gen: Value of pisa_idx_gen when @domain_idx was set to NOIDX
 *
 * Lives in iommu_dma_cookie. Active PISA pages map at @base + slot * PISA_SIZE.
 */
struct pisa_window {
	dma_addr_t base;
	u16 domain_idx;
	u32 idx_gen;
};

#ifdef CONFIG_PISA

#define PISA_MAX_BLOCKS		512U

#define PISA_BLOCKS(order)	(1U << (PISA_ORDER - (order)))

/* Max simultaneous PISA IOMMU domains (bit index in pisa_meta.domains_mapped). */
#define PISA_MAX_DOMAINS		128

/* Sentinel values of pisa_window.domain_idx below PISA_IDX_FIRST. */
enum {
	PISA_IDX_NONE,	/* not attempted yet */
	PISA_IDX_NOHUGE,	/* @domain can never use PISA */
	PISA_IDX_NOWINDOW,	/* no IOVA range for the window */
	PISA_IDX_NOIDX,	/* all domain indices were in use */
	PISA_IDX_FIRST,	/* first valid domain index */
};

/*
 * Lock hierarchy:
 * - pisa_allocs_lock (rwlock): outermost; protects pisa_allocs list.
 * - pisa_meta_mutex (mutex): serializes pisa_meta_init() and page-table alloc.
 * - pcp->lock (spinlock, irqsave): per-CPU block cache.
 * - pa->lock (spinlock, irqsave): per-allocator lists, bitmaps, and stats.
 * - pisa_domains[].map_lock (spinlock, irqsave): first-time iommu_map() in __pisa_map_phys().
 * - pisa_domains_lock (spinlock, irqsave): leaf lock over pisa_domains[]/windows.
 * - pisa_srcu: protects pisa_domains[] readers against pisa_domain_release().
 */

/**
 * struct pisa_meta - Metadata for a single PISA page in @pisa_meta_array
 * @flags:	PISA_ACTIVE / PISA_QUARANTINED / PISA_DECRYPTED
 * @prot:	Owning allocator's IOMMU_READ/WRITE protection bits
 * @nr_clean:	Zeroed available blocks in @clean_bitmap
 * @nr_dirty:	Dirty available blocks in @dirty_bitmap
 * @on_list:	Current placement in @pa (enum pisa_meta_list)
 * @slot:	Dense IOVA slot index in every domain's window
 * @domains_mapped: Bitmap of domain indices holding this page's leaf PTE
 * @pa:		Owning pisa_alloc (NULL for reservoir pages)
 * @list:	Node in @pa lists or per-node reservoir (pisa_node.pages)
 * @llnode:	Node in lockless pisa_free_list for async release to the buddy allocator
 * @rcu:	RCU head used to defer release to the buddy allocator
 * @clean_bitmap: Bitmap of zeroed available block indices
 * @dirty_bitmap: Bitmap of dirty available block indices
 */
struct pisa_meta {
	u8 flags;
	u8 prot;
	u16 nr_clean;
	u16 nr_dirty;
	u8 on_list;
	u32 slot;

	DECLARE_BITMAP(domains_mapped, PISA_MAX_DOMAINS);

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

/* Physical address for IOMMU PTE of @meta at @phys (shared alias if decrypted). */
static inline phys_addr_t pisa_pte_phys(const struct pisa_meta *meta, phys_addr_t phys)
{
	if (meta->flags & PISA_DECRYPTED)
		return dma_addr_unencrypted(phys);
	return phys;
}

static inline unsigned int pisa_meta_avail(const struct pisa_meta *meta)
{
	return meta->nr_clean + meta->nr_dirty;
}

/* Per-CPU front cache of free blocks at refcount 0, see pisa_enable_pcp(). */
#define PISA_PCP_HIGH	64U	/* blocks cached per CPU at most */
#define PISA_PCP_BATCH	32U	/* blocks moved per refill or flush */

struct pisa_pcp {
	spinlock_t	lock;	/* by this CPU, or by a drain from any CPU */
	unsigned int	count;
	struct page	*blocks[PISA_PCP_HIGH];
};

/* Per-allocator statistics, see pisa_allocs_show(). */
struct pisa_alloc_stats {
	u64		page_alloc_cnt;
	u64		page_free_cnt;
};

/**
 * struct pisa_alloc - Allocator managing 2MB-backed blocks of a fixed order
 * @lock:	Spinlock protecting lists, block bitmaps, and u64 @stats
 * @order:	Block order managed by this allocator (<= PISA_ORDER)
 * @prot:	IOMMU_READ and/or IOMMU_WRITE from @dir passed to pisa_create()
 * @pcp:	Per-CPU block caches, or NULL (see pisa_enable_pcp())
 * @partial:	Partially used PISA pages with @nr_clean > 0
 * @partial_dirty: Partially used PISA pages with @nr_clean == 0 and @nr_dirty > 0
 * @idle:	Completely free PISA pages (reclaimable under pressure)
 * @full:	List of PISA pages with 0 free blocks
 * @num_idle_pages: Length of @idle
 * @max_idle_pages: High watermark of @idle before async release to the buddy allocator
 * @idle_jiffies: Timestamp (jiffies) when @idle last exceeded @max_idle_pages
 * @blocks_in_use: Blocks handed out and not yet freed
 * @nid:	NUMA node id
 * @node:	Node in the global pisa_allocs list
 * @name:	Debug name (defaults to caller of pisa_create())
 * @stats:	Per-allocator statistics
 */
struct pisa_alloc {
	/* First cacheline: hot fields touched on block alloc and free. */
	spinlock_t		lock;
	u8			order;
	u8			prot;
	struct pisa_pcp __percpu *pcp;
	struct list_head	partial;
	struct list_head	partial_dirty;
	struct list_head	idle;
	struct list_head	full;
	unsigned int		num_idle_pages;
	unsigned int		max_idle_pages;
	unsigned long		idle_jiffies;
	unsigned long		blocks_in_use;
	/* Cold. */
	int			nid;
	struct list_head	node;
	char			name[48];
	struct pisa_alloc_stats	stats;
} ____cacheline_aligned;

/* Active non-idle PISA pages held by @pa, for soft compaction checks. */
static inline long pisa_alloc_held_pages(const struct pisa_alloc *pa)
{
	return (long)(READ_ONCE(pa->stats.page_alloc_cnt) -
		      READ_ONCE(pa->stats.page_free_cnt)) -
	       READ_ONCE(pa->num_idle_pages);
}

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

/* IOVA of @phys inside active RAM page @meta in @win. */
static inline dma_addr_t pisa_phys_to_iova(const struct pisa_window *win,
					  const struct pisa_meta *meta, phys_addr_t phys)
{
	return win->base + ((dma_addr_t)meta->slot << PISA_SHIFT) +
	       (phys & (PISA_SIZE - 1));
}

/* Offset of @meta from the start of a domain's window. */
static inline dma_addr_t pisa_meta_win_offset(const struct pisa_meta *meta)
{
	return (dma_addr_t)meta->slot << PISA_SHIFT;
}

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
bool pisa_want_decrypt(void);
int pisa_page_prepare(struct page *page, struct pisa_meta *meta);
int pisa_page_unprepare(struct pisa_meta *meta);

/* pisa-alloc.c, also used by the per-node code in pisa-node.c */
struct pisa_alloc *pisa_create(int nid, unsigned int order, enum dma_data_direction dir);
struct pisa_alloc *pisa_node_pa(int nid, unsigned int order, bool ro);
__printf(2, 3)
void pisa_set_name(struct pisa_alloc *pa, const char *fmt, ...);
int pisa_enable_pcp(struct pisa_alloc *pa);
void pisa_pcp_drain(struct pisa_alloc *pa);
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
struct pisa_meta *pisa_reservoir_pop(int nid, gfp_t gfp, bool decrypt, bool *clean);
unsigned long pisa_reservoir_count(void);
unsigned long pisa_reservoir_shrink(struct list_head *release_list, unsigned long nr_to_scan);

#endif /* CONFIG_PISA */

#if defined(CONFIG_PISA) && defined(CONFIG_IOMMU_DMA)

/* Size in bytes of every domain's PISA IOVA window, fixed at boot. */
extern u64 pisa_window_size;
/* Bumped under pisa_domains_lock whenever a domain index is released. */
extern unsigned int pisa_idx_gen;
extern unsigned int pisa_nr_slots;

void pisa_slots_init(void);
int pisa_slot_alloc(struct pisa_meta *meta);
void pisa_slot_free(unsigned int slot);
int pisa_unmap_all(struct pisa_meta *meta);
int pisa_window_assign(struct device *dev, struct iommu_domain *domain, struct pisa_window *win);
int __pisa_map_phys(dma_addr_t *iova, struct device *dev,
		    struct iommu_domain *domain, phys_addr_t phys,
		    size_t size, int prot);

static inline int pisa_map_phys(dma_addr_t *iova, struct device *dev,
				struct iommu_domain *domain, phys_addr_t phys,
				size_t size, int prot)
{
	return is_pisa_phys(phys) ?
	       __pisa_map_phys(iova, dev, domain, phys, size, prot) : -EINVAL;
}

/* Return negative errno if @win's domain was permanently/currently declined, or 0. */
static inline int pisa_window_declined(const struct pisa_window *win)
{
	switch (READ_ONCE(win->domain_idx)) {
	case PISA_IDX_NOHUGE:
		return -EOPNOTSUPP;
	case PISA_IDX_NOWINDOW:
		return -ENOSPC;
	case PISA_IDX_NOIDX:
		return READ_ONCE(win->idx_gen) == READ_ONCE(pisa_idx_gen) ?
		       -EBUSY : 0;
	default:
		return 0;
	}
}

/* Return true if @dma falls within @win's reserved PISA IOVA window. */
static inline bool is_pisa_iova(const struct pisa_window *win, dma_addr_t dma)
{
	/* Acquire pairs with the release of @base in pisa_window_assign(). */
	dma_addr_t base = smp_load_acquire(&win->base);

	return base && dma - base < pisa_window_size;
}

void pisa_domain_release(struct iommu_domain *domain);
void pisa_domain_quiesce(struct iommu_domain *domain);

#else /* !CONFIG_PISA || !CONFIG_IOMMU_DMA */

#define pisa_nr_slots 0U
static inline void pisa_slots_init(void) {}
static inline int pisa_slot_alloc(struct pisa_meta *meta) { return 0; }
static inline void pisa_slot_free(unsigned int slot) {}
static inline int pisa_unmap_all(struct pisa_meta *meta) { return 0; }

static inline int pisa_map_phys(dma_addr_t *iova, struct device *dev,
				struct iommu_domain *domain, phys_addr_t phys,
				size_t size, int prot)
{
	return -EOPNOTSUPP;
}

static inline int pisa_window_declined(const struct pisa_window *win)
{
	return -EOPNOTSUPP;
}

static inline bool is_pisa_iova(const struct pisa_window *win, dma_addr_t dma)
{
	return false;
}

static inline void pisa_domain_release(struct iommu_domain *domain)
{
}

static inline void pisa_domain_quiesce(struct iommu_domain *domain)
{
}

#endif /* CONFIG_PISA && CONFIG_IOMMU_DMA */
#endif /* _DRIVERS_IOMMU_PISA_PRIV_H */

/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _DRIVERS_IOMMU_PISA_PRIV_H
#define _DRIVERS_IOMMU_PISA_PRIV_H

#include <linux/dma-mapping.h>
#include <linux/pisa.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/mem_encrypt.h>
#include <linux/spinlock.h>
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
 * @alloc_jiffies: Timestamp (jiffies) when the page entered or re-entered use
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
	unsigned long alloc_jiffies;

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
	u64		alloc_cnt;
	u64		miss_cnt;
	u64		free_cnt;
	u64		alloc_ks;
	u64		alloc_as;
	struct page	*blocks[PISA_PCP_HIGH];
};

#define pisa_stat_add(var, val)		((var) += (val))
#define pisa_stat_inc(var)		pisa_stat_add(var, 1)
#define pisa_stat_dec(var)		pisa_stat_add(var, -1)
#define pisa_stat_read(var)		READ_ONCE(var)

#define pisa_stat_atomic_add(var, val)	atomic64_add(val, &(var))
#define pisa_stat_atomic_inc(var)	atomic64_inc(&(var))
#define pisa_stat_atomic_read(var)	atomic64_read(&(var))

/**
 * struct pisa_alloc_stats - Per-allocator statistics, see pisa_allocs_show()
 * @page_alloc_cnt:	PISA pages allocated for this allocator
 * @page_free_cnt:	PISA pages released back to the buddy allocator
 * @block_alloc_cnt:	Block allocations satisfied
 * @block_free_cnt:	Block frees recycled into allocator
 * @block_scrub_cnt:	Dirty blocks zeroed by background scrubber
 * @numa_mismatch_cnt:	Block allocations satisfied from a non-target NUMA node
 * @alloc_kd:		Sleepable non-zeroing block allocations
 * @alloc_kc:		Sleepable zeroing block allocations served from clean_bitmap
 * @alloc_ks:		Sleepable zeroing block allocations zeroed inline
 * @alloc_ad:		Atomic non-zeroing block allocations
 * @alloc_ac:		Atomic zeroing block allocations served from clean_bitmap
 * @alloc_as:		Atomic zeroing block allocations zeroed inline
 * @fail_backoff:	PISA page acquisitions skipped due to atomic backoff
 * @fail_budget:	PISA page acquisitions refused by global pisa_max_pages
 * @fail_nomem:		PISA page acquisitions that ran out of memory
 * @fail_split:		split_page_compound() rejections
 * @block_alloc_fail:	PISA page acquisitions that failed on empty allocator
 * @fail_gfp:		pisa_alloc() calls declined due to unsupported GFP
 * @page_map_cnt:	PISA page mappings established across all domains
 * @fallback_nowindow:	Buffers mapped individually due to no usable IOVA window
 * @fallback_noidx:	Buffers mapped individually due to exhausted domain indices
 * @fallback_nohuge:	Buffers mapped individually because domain cannot use PISA
 * @fallback_maperr:	Buffers mapped individually because PISA mapping failed
 * @fallback_prot:	Buffers mapped individually due to protection mismatch
 */
struct pisa_alloc_stats {
	/* Updated under @pa->lock. */
	u64		page_alloc_cnt;
	u64		page_free_cnt;
	u64		block_alloc_cnt;
	u64		block_free_cnt;
	u64		block_scrub_cnt;
	u64		numa_mismatch_cnt;
	u64		alloc_kd;
	u64		alloc_kc;
	u64		alloc_ks;
	u64		alloc_ad;
	u64		alloc_ac;
	u64		alloc_as;

	/* Updated without @pa->lock (e.g. pisa_alloc_split_page() and map path). */
	atomic64_t	fail_backoff;
	atomic64_t	fail_budget;
	atomic64_t	fail_nomem;
	atomic64_t	fail_split;
	atomic64_t	block_alloc_fail;
	atomic64_t	fail_gfp;
	atomic64_t	page_map_cnt;
	atomic64_t	fallback_nowindow;
	atomic64_t	fallback_noidx;
	atomic64_t	fallback_nohuge;
	atomic64_t	fallback_maperr;
	atomic64_t	fallback_prot;
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
 * @scrub_demand: Dirty blocks zeroed inline since the scrubber last ran
 * @blocks_in_use: Blocks handed out and not yet freed
 * @nid:	NUMA node whose worker scrubs this allocator
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
	unsigned int		scrub_demand;
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

/* Reservoir statistics, in PISA pages, see pisa_reservoir_show(). */
struct pisa_reservoir_stats {
	/* Updated under @res->lock or by the per-node singleton @res->work. */
	u64		hit;		/* requests for this node it served */
	u64		refill;		/* PISA pages added by the refill */
	u64		refill_err;	/* refill allocations that failed */
	u64		trim;		/* PISA pages released by the trim */

	/* Updated without @res->lock when the reservoir is empty. */
	atomic64_t	miss;		/* requests for this node found it empty */
};

/* Per-NUMA-node PISA state. */
struct pisa_node {
	unsigned long		next_alloc;	/* atomic alloc backoff jiffies */
	struct pisa_alloc	*pa[2][PISA_ORDER + 1]; /* [0]=RW, [1]=RO by order */
	struct pisa_alloc	*user_pa[3];	/* user/page-cache allocators by dir */

	spinlock_t		lock;		/* protects @pages and @nr_pages */
	struct list_head	pages;		/* reservoir */
	unsigned int		nr_pages;
	unsigned long		flags;		/* PISA_NODE_* requests */
	struct work_struct	work;		/* refill/trim/scrub, on this node */
	struct pisa_reservoir_stats stats;
} ____cacheline_aligned_in_smp;

/* Global reclaim and shrinker statistics, see pisa_allocs_show(). */
struct pisa_reclaim_stats {
	/* Updated by singleton pisa_reclaim_work. */
	u64		reclaim_run;	/* pisa_reclaim_work_fn() runs */
	u64		reclaim_pages;	/* PISA pages it released */

	/* Updated locklessly. */
	atomic64_t	shrink_scan;	/* pisa_shrink_scan() calls */
	atomic64_t	pte_pages_res;	/* 4KB pages taken from the reservoirs */
	atomic64_t	pte_pages_idle;	/* 4KB pages taken from idle allocators */
	atomic64_t	unmap_fail;	/* PISA page unmaps that failed */
};

extern struct pisa_reclaim_stats pisa_reclaim_stats;

extern char pisa_pages_2m[16];
extern char pisa_pages_4k[16];
extern char pisa_no_pages_2m[16];

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
bool pisa_place_meta(struct pisa_meta *meta);
void pisa_schedule_reclaim(void);
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

#define PISA_OLD_MS_MAX		100000U
extern unsigned int pisa_wasted_pct;
extern unsigned int pisa_old_ms;
extern unsigned int pisa_scrub_migrate;
unsigned long pisa_shrink_list(spinlock_t *lock, struct list_head *list,
			       unsigned int *nr, struct list_head *release_list,
			       unsigned long nr_to_scan);
extern unsigned int pisa_scrub_max;
bool pisa_scrub_node(int nid);
bool pisa_user_scrub_node(int nid, unsigned long budget, u64 deadline);

/* pisa-node.c: per-NUMA-node PISA page reservoir and work item */
extern unsigned int pisa_reservoir_max;
void pisa_node_init(void);
void pisa_schedule_reservoir(void);
void pisa_schedule_scrub(int nid);
void pisa_schedule_scrub_all(void);
struct pisa_meta *pisa_reservoir_pop(int nid, gfp_t gfp, bool decrypt, bool *clean);
unsigned long pisa_reservoir_count(void);
unsigned long pisa_reservoir_shrink(struct list_head *release_list, unsigned long nr_to_scan);

struct seq_file;
void pisa_reservoir_show(struct seq_file *s);
void pisa_user_show(struct seq_file *s);
void pisa_user_boot_enable(void);

/* One name/value pair of a debugfs statistics line. */
struct pisa_kv {
	const char *name;
	s64 val;
};

void __pisa_seq_kv(struct seq_file *s, const char *title, const struct pisa_kv *st, unsigned int n);

/* Print @title and fixed-width name/value pairs to debugfs seq_file @s. */
#define pisa_seq_kv(s, title, ...)				\
do {									\
	const struct pisa_kv __st[] = { __VA_ARGS__ };		\
									\
	__pisa_seq_kv(s, title, __st, ARRAY_SIZE(__st));		\
} while (0)

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
void pisa_domains_show(struct seq_file *s);
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
static inline void pisa_domains_show(struct seq_file *s) {}

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

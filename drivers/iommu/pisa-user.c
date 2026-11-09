// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * PISA user and page-cache folios: allocate or migrate order-0 folios into
 * per-node PISA allocators so zero-copy TX and block I/O use 2MB IOMMU mappings.
 * Disabled on CoCo guests (user PTEs map pages encrypted).
 */
#include <linux/blkdev.h>
#include <linux/cc_platform.h>
#include <linux/device.h>
#include <linux/pisa.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/iommu.h>
#include <linux/jiffies.h>
#include <linux/migrate.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/nodemask.h>
#include <linux/pagemap.h>
#include <linux/pagewalk.h>
#include <linux/folio_batch.h>
#include <linux/sched/clock.h>
#include <linux/swap.h>

#include "pisa-priv.h"

#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "pisa."

/* Soft cap on 4KB user pages held in PISA blocks (0 = disabled). */
static unsigned long pisa_user_max_4k_pages __read_mostly;
DEFINE_STATIC_KEY_FALSE(pisa_user_key);

static bool pisa_user_init(void);

static int pisa_user_max_set(const char *val, const struct kernel_param *kp)
{
	unsigned long max_pages;
	int ret;

	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		return -EOPNOTSUPP;
	ret = kstrtoul(val, 0, &max_pages);
	if (ret)
		return ret;
	WRITE_ONCE(pisa_user_max_4k_pages, max_pages);
	if (max_pages) {
		if (!pisa_nodes[first_memory_node].pa[0][0])
			return 0;
		if (!pisa_user_init())
			return -ENOMEM;
		static_branch_enable(&pisa_user_key);
	} else {
		static_branch_disable(&pisa_user_key);
	}
	return 0;
}

static const struct kernel_param_ops pisa_user_max_ops = {
	.set = pisa_user_max_set,
	.get = param_get_ulong,
};
module_param_cb(user_max_4K_pages, &pisa_user_max_ops, &pisa_user_max_4k_pages, 0644);

/*
 * Scrub-time migration of old sparse user_pa PISA pages when waste exceeds
 * pisa.wasted_pct (0 = off, 1 = compact in allocator, 2 = demote to the buddy allocator).
 */
unsigned int pisa_scrub_migrate __read_mostly;

static int pisa_scrub_migrate_set(const char *val, const struct kernel_param *kp)
{
	int ret = param_set_uint(val, kp);

	if (!ret && pisa_scrub_migrate && static_branch_unlikely(&pisa_key))
		pisa_schedule_scrub_all();
	return ret;
}

static const struct kernel_param_ops pisa_scrub_migrate_ops = {
	.set = pisa_scrub_migrate_set,
	.get = param_get_uint,
};
module_param_cb(scrub_migrate, &pisa_scrub_migrate_ops, &pisa_scrub_migrate, 0644);

/* True once per-node user allocators have been allocated, serialized by pisa_user_lock. */
static bool pisa_user_ready __read_mostly;
static DEFINE_MUTEX(pisa_user_lock);

/* Lazily create per-node user allocators on first use (process context). */
static bool pisa_user_init(void)
{
	static const char * const dir_names[3] = { "bi", "tx", "rx" };
	int nid;

	if (!READ_ONCE(pisa_user_max_4k_pages) || cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		return false;
	/* Pairs with smp_store_release() below: the allocators are visible. */
	if (smp_load_acquire(&pisa_user_ready))
		return true;
	if (pisa_meta_init())
		return false;
	mutex_lock(&pisa_user_lock);
	for_each_node_state(nid, N_MEMORY) {
		unsigned int dir;

		for (dir = 0; dir < ARRAY_SIZE(pisa_nodes[nid].user_pa); dir++) {
			struct pisa_alloc *pa = pisa_nodes[nid].user_pa[dir];

			if (!pa) {
				pa = pisa_create(nid, 0, dir);
				if (!pa)
					goto out;	/* retried on the next call */
				pisa_set_name(pa, "user_%s_n%d", dir_names[dir], nid);
				pisa_enable_pcp(pa);
				pisa_nodes[nid].user_pa[dir] = pa;
			}
		}
	}
	/* Publish pisa_nodes[].user_pa to lockless readers. */
	smp_store_release(&pisa_user_ready, true);
out:
	mutex_unlock(&pisa_user_lock);
	return pisa_user_ready;
}

void pisa_user_boot_enable(void)
{
	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT)) {
		WRITE_ONCE(pisa_user_max_4k_pages, 0);
		return;
	}
	if (READ_ONCE(pisa_user_max_4k_pages) && pisa_user_init())
		static_branch_enable(&pisa_user_key);
}

/* User pages currently held in PISA blocks. */
static unsigned long pisa_user_in_use(void)
{
	unsigned long used = 0;
	int nid;

	for_each_node_state(nid, N_MEMORY) {
		unsigned int dir;

		for (dir = 0; dir < ARRAY_SIZE(pisa_nodes[nid].user_pa); dir++) {
			const struct pisa_alloc *pa = pisa_nodes[nid].user_pa[dir];

			used += pa ? READ_ONCE(pa->blocks_in_use) : 0;
		}
	}
	return used;
}

/* Pages that can still be moved in before reaching pisa.user_max_4K_pages. */
static long pisa_user_budget(void)
{
	return (long)(READ_ONCE(pisa_user_max_4k_pages) - pisa_user_in_use());
}

/*
 * Return true if @folio should be migrated into (@to_pisa) or out of PISA
 * memory, promoting existing PISA folios to DMA_BIDIRECTIONAL when needed.
 */
static bool pisa_user_want_dir(struct folio *folio, bool to_pisa,
			       enum dma_data_direction dir, bool allow_file)
{
	unsigned long pfn = folio_pfn(folio);

	if (is_zero_folio(folio) || folio_is_zone_device(folio) ||
	    folio_test_ksm(folio) || folio_test_large(folio))
		return false;
	if (folio_test_anon(folio)) {
		if (folio_maybe_mapped_shared(folio))
			return false;
	} else if (!allow_file || !folio_mapping(folio) ||
		   folio_test_locked(folio) || folio_test_writeback(folio)) {
		return false;
	}

	if (!to_pisa)
		return is_pisa_pfn(pfn);
	if (!is_pisa_pfn(pfn))
		return true;

	if (dir == DMA_TO_DEVICE || dir == DMA_FROM_DEVICE) {
		int need = (dir == DMA_FROM_DEVICE) ? IOMMU_WRITE : IOMMU_READ;
		const struct pisa_meta *meta;
		bool promote;

		rcu_read_lock();
		meta = is_pisa_pfn(pfn) ? pisa_meta_of_pfn(pfn) : NULL;
		promote = meta && (meta->prot & need) != need;
		rcu_read_unlock();
		return promote;
	}
	return false;
}

/* Return true if @folio has references beyond its mappings, swap cache, and @extra. */
static bool pisa_user_busy(struct folio *folio, int extra)
{
	return folio_ref_count(folio) > folio_expected_ref_count(folio) + extra;
}

struct pisa_user_mtc {
	gfp_t			gfp;
	long			budget;
	enum dma_data_direction	dir;
	bool			same_alloc;
};

/* new_folio_t for migration into PISA memory. */
static struct folio *pisa_user_new_folio(struct folio *src, unsigned long private)
{
	struct pisa_user_mtc *mtc = (void *)private;
	bool already_pisa = is_pisa_pfn(folio_pfn(src));
	enum dma_data_direction dir = mtc->dir;
	int nid = folio_nid(src);
	struct page *page;

	if (!already_pisa && mtc->budget <= 0)
		return NULL;
	if (already_pisa && !mtc->same_alloc)
		dir = DMA_BIDIRECTIONAL;
	page = pisa_alloc(pisa_nodes[nid].user_pa[dir], mtc->gfp);
	if (!page)
		return NULL;
	if (pisa_meta_of_pfn(page_to_pfn(page))->flags & PISA_DECRYPTED) {
		put_page(page);
		mtc->budget = 0;
		return NULL;
	}
	if (!already_pisa)
		mtc->budget--;
	return page_folio(page);
}

/* new_folio_t for migration out of PISA memory: allocators never serve these. */
static struct folio *pisa_user_old_folio(struct folio *src, unsigned long private)
{
	return __folio_alloc_node(GFP_HIGHUSER_MOVABLE | __GFP_NOWARN, 0, folio_nid(src));
}

/* Migrate the isolated folios on @list; failures are put back. */
static unsigned int pisa_user_migrate_dir(struct list_head *list, bool to_pisa,
					  enum dma_data_direction dir,
					  bool same_alloc, gfp_t gfp)
{
	struct pisa_user_mtc mtc = {
		.gfp = gfp,
		.budget = LONG_MAX,
		.dir = dir,
		.same_alloc = same_alloc,
	};
	enum migrate_mode mode = MIGRATE_SYNC;
	unsigned int done = 0;

	if (list_empty(list))
		return 0;
	if (to_pisa) {
		mtc.budget = pisa_user_budget();
		if (!gfpflags_allow_blocking(gfp))
			mode = MIGRATE_ASYNC;
	}
	if (migrate_pages(list, to_pisa ? pisa_user_new_folio : pisa_user_old_folio,
			  NULL, (unsigned long)&mtc, mode, MR_SYSCALL, &done))
		putback_movable_pages(list);
	return done;
}

/**
 * pisa_upgrade_user_pages - Try to move user pages into PISA for @dir
 * @pages: Pages from iov_iter_get_pages2() or iov_iter_extract_pages()
 * @nr: Number of entries in @pages
 * @dir: I/O direction (DMA_TO_DEVICE or DMA_FROM_DEVICE)
 * @pinned: true if @pages are FOLL_PIN-pinned, false if refcounted (+1)
 *
 * Return: true if references/pins were dropped and the caller must re-lookup.
 */
bool pisa_upgrade_user_pages(struct page **pages, unsigned int nr,
			     enum dma_data_direction dir, bool pinned)
{
	int extra = pinned ? GUP_PIN_COUNTING_BIAS : 1;
	bool drained = false;
	LIST_HEAD(list);
	unsigned int i, want = 0, need_budget = 0;

	if (!pisa_user_init())
		return false;
	/* Common case: all pages already in PISA with matching prot. */
	for (i = 0; i < nr; i++) {
		struct folio *folio = page_folio(pages[i]);

		if (pisa_user_want_dir(folio, true, dir, false)) {
			want++;
			need_budget += !is_pisa_pfn(folio_pfn(folio));
		}
	}
	if (!want)
		return false;
	if (need_budget && pisa_user_budget() <= 0)
		return false;
	for (i = 0; i < nr; i++) {
		struct folio *folio = page_folio(pages[i]);

		if (!pisa_user_want_dir(folio, true, dir, false))
			continue;
		/* A freshly faulted page may still sit in a per-CPU LRU batch. */
		if (!drained && !folio_test_lru(folio)) {
			lru_add_drain();
			drained = true;
		}
		if (pisa_user_busy(folio, extra))
			continue;
		isolate_folio_to_list(folio, &list);
	}
	if (list_empty(&list))
		return false;
	/* Migration fails on pages with references or pins it does not expect. */
	if (pinned) {
		unpin_user_pages(pages, nr);
	} else {
		for (i = 0; i < nr; i++)
			put_page(pages[i]);
	}
	pisa_user_migrate_dir(&list, true, dir, false,
			      GFP_NOWAIT | __GFP_HARDWALL | __GFP_NOWARN);
	return true;
}

/**
 * __pisa_filemap_alloc - Allocate an order-0 page-cache folio from a PISA user allocator
 * @mapping: Page-cache address_space
 * @gfp: GFP flags
 * @is_write: True when allocating on the buffered write path
 *
 * Return: Newly allocated order-0 folio, or NULL on failure.
 */
struct folio *__pisa_filemap_alloc(const struct address_space *mapping,
				   gfp_t gfp, bool is_write)
{
	enum dma_data_direction dir = is_write ? DMA_TO_DEVICE : DMA_FROM_DEVICE;
	struct page *page;
	int nid;

	if (!__pisa_mapping_enabled(mapping, dir))
		return NULL;
	if (is_write && __pisa_mapping_enabled(mapping, DMA_FROM_DEVICE))
		dir = DMA_BIDIRECTIONAL;
	/* Pairs with smp_store_release() in pisa_user_init(). */
	if (!smp_load_acquire(&pisa_user_ready) &&
	    ((gfp & GFP_KERNEL) != GFP_KERNEL || !pisa_user_init()))
		return NULL;
	if (pisa_user_budget() <= 0)
		return NULL;
	nid = pisa_sanitize_nid(numa_node_id());
	page = pisa_alloc(pisa_nodes[nid].user_pa[dir], gfp);
	if (!page)
		return NULL;
	if (pisa_meta_of_pfn(page_to_pfn(page))->flags & PISA_DECRYPTED) {
		put_page(page);
		return NULL;
	}
	return page_folio(page);
}

/**
 * pisa_folio_upgrade - Migrate an unlocked order-0 folio to a PISA allocator page
 * @folio: Folio to migrate (caller holds 1 ref, dropped only when returning true)
 * @dir: Required DMA direction (DMA_TO_DEVICE or DMA_FROM_DEVICE)
 * @fbatch: Optional folio_batch holding @folio's reference to release before migration
 *
 * Return: true if @folio was isolated and caller's reference was dropped
 *         (caller must re-lookup in mapping); false if @folio is untouched.
 */
bool pisa_folio_upgrade(struct folio *folio, enum dma_data_direction dir,
			struct folio_batch *fbatch)
{
	LIST_HEAD(list);

	if (!pisa_user_init() ||
	    !pisa_user_want_dir(folio, true, dir, true) ||
	    (!is_pisa_pfn(folio_pfn(folio)) && pisa_user_budget() <= 0))
		return false;
	if (!folio_test_lru(folio))
		lru_add_drain();
	if (pisa_user_busy(folio, 1) || !isolate_folio_to_list(folio, &list))
		return false;
	/* Drop caller's reference so migrate_pages() sees only expected refs. */
	if (fbatch)
		folio_batch_release(fbatch);
	else
		folio_put(folio);
	pisa_user_migrate_dir(&list, true, dir, false,
			      GFP_NOWAIT | __GFP_HARDWALL | __GFP_NOWARN);
	return true;
}

bool __pisa_bdev_enabled(struct block_device *bdev, enum dma_data_direction dir)
{
	struct device *dev;

	if (!bdev || !bdev->bd_disk)
		return false;
	for (dev = disk_to_dev(bdev->bd_disk); dev; dev = dev->parent) {
		if (dir == DMA_FROM_DEVICE ?
		    READ_ONCE(dev->pisa_rx_bufs) :
		    READ_ONCE(dev->pisa_tx_bufs))
			return true;
	}
	return false;
}

bool __pisa_mapping_enabled(const struct address_space *mapping, enum dma_data_direction dir)
{
	struct super_block *sb;

	if (!mapping || !mapping->host || !mapping->host->i_sb)
		return false;
	sb = mapping->host->i_sb;
	return __pisa_bdev_enabled(sb_is_blkdev_sb(sb) ?
				   I_BDEV(mapping->host) : sb->s_bdev, dir);
}

#define PISA_USER_BATCH	512

static unsigned long pisa_user_scrub_alloc(struct pisa_alloc *pa,
					  enum dma_data_direction dir,
					  unsigned int mode,
					  unsigned long budget)
{
	unsigned int wasted_pct = READ_ONCE(pisa_wasted_pct);
	unsigned int old_ms = READ_ONCE(pisa_old_ms);
	unsigned long bpp = PISA_BLOCKS(0), in_use, free_blocks;
	unsigned long max_age, base_pfn = 0, flags;
	DECLARE_BITMAP(inuse_map, PISA_MAX_BLOCKS);
	struct list_head *lists[] = { &pa->partial_dirty, &pa->partial };
	struct pisa_meta *meta, *target = NULL;
	unsigned int i, idx, count = 0;
	bool should_release = false;
	unsigned long migrated = 0;
	LIST_HEAD(list);
	long held;

	if (!wasted_pct || !old_ms)
		return 0;

	pisa_pcp_drain(pa);

	held = pisa_alloc_held_pages(pa);
	in_use = READ_ONCE(pa->blocks_in_use);
	free_blocks = held > 0 && (unsigned long)held * bpp > in_use ?
		      (unsigned long)held * bpp - in_use : 0;
	if (held <= 0 || free_blocks * 100 <= (unsigned long)held * bpp * wasted_pct)
		return 0;

	max_age = msecs_to_jiffies(min(old_ms, PISA_OLD_MS_MAX));

	spin_lock_irqsave(&pa->lock, flags);
	for (i = 0; i < ARRAY_SIZE(lists) && !target; i++) {
		list_for_each_entry_reverse(meta, lists[i], list) {
			if (mode == 1 && &meta->list == lists[i]->next)
				break;
			if (time_after(jiffies, meta->alloc_jiffies + max_age)) {
				target = meta;
				break;
			}
		}
	}
	if (target) {
		base_pfn = pisa_meta_to_pfn(target);
		bitmap_or(inuse_map, target->clean_bitmap, target->dirty_bitmap, bpp);
		bitmap_complement(inuse_map, inuse_map, bpp);
		WRITE_ONCE(target->on_list, PISA_LIST_FULL);
		list_move(&target->list, &pa->full);
	}
	spin_unlock_irqrestore(&pa->lock, flags);

	if (!target)
		return 0;

	for_each_set_bit(idx, inuse_map, bpp) {
		unsigned long pfn = base_pfn + idx;
		struct folio *folio;

		rcu_read_lock();
		if (!is_pisa_pfn(pfn)) {
			rcu_read_unlock();
			continue;
		}
		folio = page_folio(pfn_to_page(pfn));
		if (!folio_try_get(folio)) {
			rcu_read_unlock();
			continue;
		}
		if (!is_pisa_pfn(pfn) || folio != page_folio(pfn_to_page(pfn))) {
			rcu_read_unlock();
			folio_put(folio);
			continue;
		}
		rcu_read_unlock();

		if (!pisa_user_want_dir(folio, false, dir, true) ||
		    pisa_user_busy(folio, 1) ||
		    !isolate_folio_to_list(folio, &list)) {
			folio_put(folio);
			continue;
		}
		folio_put(folio);
		if (++count >= min_t(unsigned long, budget, PISA_USER_BATCH))
			break;
	}

	if (!list_empty(&list)) {
		migrated = pisa_user_migrate_dir(&list, mode == 1, dir, true,
						 GFP_KERNEL | __GFP_NOWARN);
		pisa_pcp_drain(pa);
	}

	spin_lock_irqsave(&pa->lock, flags);
	if (READ_ONCE(target->pa) == pa) {
		WRITE_ONCE(target->alloc_jiffies, jiffies);
		should_release = pisa_place_meta(target);
	}
	spin_unlock_irqrestore(&pa->lock, flags);
	if (should_release)
		pisa_schedule_reclaim();

	return migrated;
}

bool pisa_user_scrub_node(int nid, unsigned long budget, u64 deadline)
{
	unsigned int mode = READ_ONCE(pisa_scrub_migrate);
	unsigned long done = 0;
	unsigned int dir;

	/* Pairs with smp_store_release() in pisa_user_init(). */
	if (!mode || mode > 2 || !smp_load_acquire(&pisa_user_ready))
		return false;

	for (dir = 0; dir < ARRAY_SIZE(pisa_nodes[nid].user_pa); dir++) {
		struct pisa_alloc *pa = pisa_nodes[nid].user_pa[dir];
		unsigned long n;

		if (!pa)
			continue;
		while ((n = pisa_user_scrub_alloc(pa, dir, mode, budget - done))) {
			done += n;
			if (done >= budget || local_clock() >= deadline)
				return true;
			cond_resched();
		}
	}
	return false;
}

/**
 * pisa_madvise - MADV_PISA / MADV_NOPISA on [@start, @end) of @vma
 * @vma: VMA, with the mmap lock held for reading
 * @start: Start address
 * @end: End address
 * @to_pisa: true to move present pages into PISA, false to move them out
 *
 * Return: 0, -EINVAL for unsupported mappings, or -EOPNOTSUPP if disabled.
 */
int pisa_madvise(struct vm_area_struct *vma, unsigned long start, unsigned long end, bool to_pisa)
{
	gfp_t gfp = GFP_USER | __GFP_NOWARN;
	struct folio_walk fw;
	unsigned long addr;
	unsigned int n = 0;
	LIST_HEAD(list);

	if (vma->vm_flags & (VM_SHARED | VM_IO | VM_PFNMAP | VM_HUGETLB))
		return -EINVAL;
	if (to_pisa && !pisa_user_init())
		return -EOPNOTSUPP;
	lru_add_drain();
	for (addr = start; addr < end; addr += PAGE_SIZE) {
		struct folio *folio = folio_walk_start(&fw, vma, addr, 0);

		if (folio) {
			if (pisa_user_want_dir(folio, to_pisa, DMA_TO_DEVICE, false) &&
			    !pisa_user_busy(folio, 0) && isolate_folio_to_list(folio, &list))
				n++;
			folio_walk_end(&fw, vma);
		}
		if (n == PISA_USER_BATCH) {
			pisa_user_migrate_dir(&list, to_pisa, DMA_TO_DEVICE, false, gfp);
			n = 0;
		}
		cond_resched();
	}
	pisa_user_migrate_dir(&list, to_pisa, DMA_TO_DEVICE, false, gfp);
	return 0;
}

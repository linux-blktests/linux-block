// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * PISA user and page-cache folios: allocate or migrate order-0 folios into
 * per-node PISA allocators so zero-copy TX and block I/O use 2MB IOMMU mappings.
 * Disabled on CoCo guests (user PTEs map pages encrypted).
 */
#include <linux/cc_platform.h>
#include <linux/pisa.h>
#include <linux/gfp.h>
#include <linux/migrate.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/nodemask.h>
#include <linux/pagewalk.h>
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

/* True once per-node user allocators have been allocated, serialized by pisa_user_lock. */
static bool pisa_user_ready __read_mostly;
static DEFINE_MUTEX(pisa_user_lock);

/* Lazily create per-node user allocators on first use (process context). */
static bool pisa_user_init(void)
{
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
		if (!pisa_nodes[nid].user_pa)
			pisa_nodes[nid].user_pa = pisa_create(nid, 0, DMA_TO_DEVICE);
		if (!pisa_nodes[nid].user_pa)
			goto out;	/* retried on the next call */
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
		const struct pisa_alloc *pa = pisa_nodes[nid].user_pa;

		used += pa ? READ_ONCE(pa->blocks_in_use) : 0;
	}
	return used;
}

/* Pages that can still be moved in before reaching pisa.user_max_4K_pages. */
static long pisa_user_budget(void)
{
	return (long)(READ_ONCE(pisa_user_max_4k_pages) - pisa_user_in_use());
}

/* Is @folio worth moving into (@to_pisa) or out of PISA memory? */
static bool pisa_user_want(struct folio *folio, bool to_pisa)
{
	if (!folio_test_anon(folio) || folio_is_zone_device(folio) ||
	    folio_test_ksm(folio) || folio_test_large(folio) ||
	    folio_maybe_mapped_shared(folio))
		return false;
	return is_pisa_pfn(folio_pfn(folio)) != to_pisa;
}

/* Return true if @folio has references beyond its mappings, swap cache, and @extra. */
static bool pisa_user_busy(struct folio *folio, int extra)
{
	return folio_ref_count(folio) > folio_expected_ref_count(folio) + extra;
}

struct pisa_user_mtc {
	gfp_t	gfp;
	long	budget;
};

/* new_folio_t for migration into PISA memory. */
static struct folio *pisa_user_new_folio(struct folio *src, unsigned long private)
{
	struct pisa_user_mtc *mtc = (void *)private;
	int nid = folio_nid(src);
	struct page *page;

	if (mtc->budget <= 0)
		return NULL;
	page = pisa_alloc(pisa_nodes[nid].user_pa, mtc->gfp);
	if (!page)
		return NULL;
	if (pisa_meta_of_pfn(page_to_pfn(page))->flags & PISA_DECRYPTED) {
		put_page(page);
		mtc->budget = 0;
		return NULL;
	}
	mtc->budget--;
	return page_folio(page);
}

/* new_folio_t for migration out of PISA memory: allocators never serve these. */
static struct folio *pisa_user_old_folio(struct folio *src, unsigned long private)
{
	return __folio_alloc_node(GFP_HIGHUSER_MOVABLE | __GFP_NOWARN, 0, folio_nid(src));
}

/* Migrate the isolated folios on @list; failures are put back. */
static void pisa_user_migrate(struct list_head *list, bool to_pisa, gfp_t gfp)
{
	struct pisa_user_mtc mtc = { .gfp = gfp, .budget = LONG_MAX };
	enum migrate_mode mode = MIGRATE_SYNC;

	if (list_empty(list))
		return;
	if (to_pisa) {
		mtc.budget = pisa_user_budget();
		if (!gfpflags_allow_blocking(gfp))
			mode = MIGRATE_ASYNC;
	}
	if (migrate_pages(list, to_pisa ? pisa_user_new_folio : pisa_user_old_folio,
			  NULL, (unsigned long)&mtc, mode, MR_SYSCALL, NULL))
		putback_movable_pages(list);
}

/**
 * pisa_upgrade_user_pages - Try to move user pages about to be sent into PISA
 * @pages: Pages from iov_iter_get_pages2(), one reference each
 * @nr: Number of entries in @pages
 *
 * Best effort, process context. Pages that cannot be moved (e.g. still
 * referenced by an in-flight skb, or in a large folio) are skipped; for TCP
 * with pisa_tx_bufs enabled the caller copies them instead.
 *
 * Return: false if nothing was attempted and the references are untouched;
 * true if all references were dropped and the caller must look the pages up
 * again.
 */
bool pisa_upgrade_user_pages(struct page **pages, unsigned int nr)
{
	bool drained = false;
	LIST_HEAD(list);
	unsigned int i, want = 0;

	if (!pisa_user_init())
		return false;
	/* Common case: all pages already in PISA, no budget check needed. */
	for (i = 0; i < nr; i++)
		want += pisa_user_want(page_folio(pages[i]), true);
	if (!want)
		return false;
	if (pisa_user_budget() <= 0)
		return false;
	for (i = 0; i < nr; i++) {
		struct folio *folio = page_folio(pages[i]);

		if (!pisa_user_want(folio, true))
			continue;
		/* A freshly faulted page may still sit in a per-CPU LRU batch. */
		if (!drained && !folio_test_lru(folio)) {
			lru_add_drain();
			drained = true;
		}
		/* The reference from iov_iter_get_pages2() is expected. */
		if (pisa_user_busy(folio, 1))
			continue;
		isolate_folio_to_list(folio, &list);
	}
	if (list_empty(&list))
		return false;
	/* Migration fails on pages with references it does not expect. */
	for (i = 0; i < nr; i++)
		put_page(pages[i]);
	pisa_user_migrate(&list, true,
			  GFP_NOWAIT | __GFP_HARDWALL | __GFP_NOWARN);
	return true;
}

#define PISA_USER_BATCH	512

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
			if (pisa_user_want(folio, to_pisa) && !pisa_user_busy(folio, 0) &&
			    isolate_folio_to_list(folio, &list))
				n++;
			folio_walk_end(&fw, vma);
		}
		if (n == PISA_USER_BATCH) {
			pisa_user_migrate(&list, to_pisa, gfp);
			n = 0;
		}
		cond_resched();
	}
	pisa_user_migrate(&list, to_pisa, gfp);
	return 0;
}

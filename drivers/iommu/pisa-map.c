// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * PISA per-domain IOVA window management and IOMMU mapping.
 * See Documentation/core-api/pisa.rst for the architecture overview.
 */

#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/dma-map-ops.h>
#include <linux/dma-mapping.h>
#include <linux/pisa.h>
#include <linux/iommu.h>
#include <linux/iova.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>

#include "dma-iommu.h"
#include "pisa-priv.h"

#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "pisa."

/* Optional module param override for pisa_nr_slots (0 = auto: 2 * max_pages). */
static unsigned int pisa_cfg_slots __read_mostly;
module_param_named(slots, pisa_cfg_slots, uint, 0444);

/*
 * Number of 2MB IOVA slots in each domain's window (computed at init from
 * pisa_cfg_slots or 2 * max_pages). Each active PISA page holds one slot
 * in [0, pisa_nr_slots) and maps at slot * PISA_SIZE in every domain's window.
 */
unsigned int pisa_nr_slots __read_mostly;
u64 pisa_window_size __read_mostly;
/* One bit per IOVA slot, set while an active PISA page holds the slot. */
static unsigned long *pisa_slot_bitmap __read_mostly;
/* Metadata of the PISA page backing each active slot, or NULL. */
static struct pisa_meta **pisa_slot2meta __read_mostly;
static unsigned int pisa_slot_hint;	/* no free slot below this */
/* Protects pisa_slot_bitmap and pisa_slot_hint. */
static DEFINE_SPINLOCK(pisa_slot_lock);

/* Cost is typically low though the bitmap can be up to O(100K) bits on large systems. */
int pisa_slot_alloc(struct pisa_meta *meta)
{
	unsigned long flags;
	unsigned int slot;

	spin_lock_irqsave(&pisa_slot_lock, flags);
	slot = find_next_zero_bit(pisa_slot_bitmap, pisa_nr_slots, pisa_slot_hint);
	if (slot < pisa_nr_slots) {
		__set_bit(slot, pisa_slot_bitmap);
		pisa_slot_hint = slot + 1;
		WRITE_ONCE(meta->slot, slot);
		WRITE_ONCE(pisa_slot2meta[slot], meta);
	}
	spin_unlock_irqrestore(&pisa_slot_lock, flags);

	if (slot >= pisa_nr_slots)
		return -ENOSPC;
	return 0;
}

/* Return @slot once no domain can translate it any more. */
void pisa_slot_free(unsigned int slot)
{
	unsigned long flags;

	spin_lock_irqsave(&pisa_slot_lock, flags);
	WRITE_ONCE(pisa_slot2meta[slot], NULL);
	__clear_bit(slot, pisa_slot_bitmap);
	if (slot < pisa_slot_hint)
		pisa_slot_hint = slot;
	spin_unlock_irqrestore(&pisa_slot_lock, flags);
}

void __init pisa_slots_init(void)
{
	/* Fixed at boot: sizes every domain's window (default 2 * max_pages). */
	pisa_nr_slots = pisa_cfg_slots ?: min_t(unsigned long, 2 * pisa_max_pages, UINT_MAX >> 1);
	pisa_slot_bitmap = kvcalloc(BITS_TO_LONGS(pisa_nr_slots),
				    sizeof(unsigned long), GFP_KERNEL);
	pisa_slot2meta = kvcalloc(pisa_nr_slots, sizeof(*pisa_slot2meta), GFP_KERNEL);
	if (!pisa_slot_bitmap || !pisa_slot2meta) {
		kvfree(pisa_slot_bitmap);
		kvfree(pisa_slot2meta);
		pisa_slot_bitmap = NULL;
		pisa_slot2meta = NULL;
		pisa_nr_slots = 0;
	}
	/* Size of every domain's window: one 2MB page per slot. */
	pisa_window_size = (u64)pisa_nr_slots << PISA_SHIFT;
}

/*
 * Registry of PISA IOMMU domains (0 .. PISA_MAX_DOMAINS - 1). Each slot is
 * FREE (!domain && !base), ACTIVE (domain), or DRAINING (!domain && base) while
 * pisa_domain_release() clears @meta->domains_mapped bits.
 */
static struct {
	struct iommu_domain *domain;
	dma_addr_t base;
	spinlock_t map_lock;	/* serialises iommu_map() in __pisa_map_phys() */
	atomic_t slots;
	char name[32];
} pisa_domains[PISA_MAX_DOMAINS] __read_mostly;
static DEFINE_SPINLOCK(pisa_domains_lock);

/* Protects pisa_unmap_all() readers against concurrent pisa_domain_release(). */
DEFINE_STATIC_SRCU(pisa_srcu);

/* Bumped under pisa_domains_lock whenever a domain index is released. */
unsigned int pisa_idx_gen __read_mostly;

void pisa_domains_show(struct seq_file *s)
{
	unsigned int active = 0, draining = 0;
	char bmap[PISA_MAX_DOMAINS];
	unsigned long flags;
	int idx;

	spin_lock_irqsave(&pisa_domains_lock, flags);
	for (idx = 0; idx < PISA_MAX_DOMAINS; idx++) {
		if (pisa_domains[idx].domain) {
			active++;
			bmap[idx] = '1';
		} else if (pisa_domains[idx].base) {
			draining++;
			bmap[idx] = 'd';
		} else {
			bmap[idx] = '.';
		}
	}
	spin_unlock_irqrestore(&pisa_domains_lock, flags);

	pisa_seq_kv(s, "domains", { "active", active }, { "draining", draining },
		    { "max", PISA_MAX_DOMAINS });
	for (idx = 0; idx < PISA_MAX_DOMAINS; idx++) {
		if ((idx & 63) == 0)
			seq_printf(s, "  %-12s", idx ? "" : "domains_map");
		if ((idx & 7) == 0)
			seq_putc(s, ' ');
		seq_putc(s, bmap[idx]);
		if ((idx & 63) == 63 || idx == PISA_MAX_DOMAINS - 1)
			seq_putc(s, '\n');
	}

	spin_lock_irqsave(&pisa_domains_lock, flags);
	for (idx = 0; idx < PISA_MAX_DOMAINS; idx++) {
		if (!pisa_domains[idx].domain)
			continue;
		seq_printf(s, "  domain_%-5d base %pad size %lluM slots %d name %s\n",
			   idx, &pisa_domains[idx].base, pisa_window_size >> 20,
			   atomic_read(&pisa_domains[idx].slots), pisa_domains[idx].name);
	}
	spin_unlock_irqrestore(&pisa_domains_lock, flags);
}
/* Report a short IOMMU unmap and mark @meta quarantined so it is never reused. */
static void pisa_quarantine_meta(struct pisa_meta *meta, struct iommu_domain *domain,
				 int idx, dma_addr_t iova, size_t unmapped)
{
	pr_err_ratelimited("pisa: unmap of IOVA %pad in domain %p (index %d) returned %zu, quarantining PISA page\n",
			   &iova, domain, idx, unmapped);
	pisa_stat_atomic_inc(pisa_reclaim_stats.unmap_fail);
	WRITE_ONCE(meta->flags, meta->flags | PISA_QUARANTINED);
}

/*
 * Unmap @meta's leaf PTE from every active domain holding it. Returns 0 on
 * success, or -EIO if any unmap failed (@meta is then quarantined).
 */
int pisa_unmap_all(struct pisa_meta *meta)
{
	dma_addr_t offset = pisa_meta_win_offset(meta);
	int idx, srcu_idx;

	srcu_idx = srcu_read_lock(&pisa_srcu);
	for_each_set_bit(idx, meta->domains_mapped, PISA_MAX_DOMAINS) {
		struct iommu_domain *domain;
		unsigned long flags;
		size_t unmapped;
		dma_addr_t base;

		if (!test_and_clear_bit(idx, meta->domains_mapped))
			continue;
		atomic_dec(&pisa_domains[idx].slots);

		spin_lock_irqsave(&pisa_domains_lock, flags);
		domain = pisa_domains[idx].domain;
		base = pisa_domains[idx].base;
		spin_unlock_irqrestore(&pisa_domains_lock, flags);

		/* Free, or draining: pisa_domain_release() handles the bit. */
		if (!domain)
			continue;

		unmapped = iommu_unmap(domain, base + offset, PISA_SIZE);
		if (unlikely(unmapped != PISA_SIZE))
			pisa_quarantine_meta(meta, domain, idx, base + offset, unmapped);
	}
	srcu_read_unlock(&pisa_srcu, srcu_idx);

	return (meta->flags & PISA_QUARANTINED) ? -EIO : 0;
}

/* Clear domain @idx from all populated slots. */
static unsigned int pisa_forget_domain(int idx)
{
	unsigned int slot, dropped = 0;

	rcu_read_lock();
	for_each_set_bit(slot, pisa_slot_bitmap, pisa_nr_slots) {
		struct pisa_meta *meta = READ_ONCE(pisa_slot2meta[slot]);

		if (meta && test_bit(idx, meta->domains_mapped) &&
		    test_and_clear_bit(idx, meta->domains_mapped))
			dropped++;
	}
	rcu_read_unlock();
	return dropped;
}

/*
 * Release @domain's registry index and clear its bit in all active
 * PISA pages, waiting out concurrent unmappers on @pisa_srcu before freeing
 * the slot.
 */
void pisa_domain_release(struct iommu_domain *domain)
{
	struct pisa_window *win;
	unsigned int dropped;
	unsigned long flags;
	int idx;

	/* Nothing has ever been active, so nothing can reference @domain. */
	if (!static_branch_unlikely(&pisa_key))
		return;

	win = pisa_dma_window(domain);
	/* @domain never active, so no PISA page can be holding a bit for it. */
	if (!win || !smp_load_acquire(&win->base))
		return;

	idx = win->domain_idx - PISA_IDX_FIRST;
	spin_lock_irqsave(&pisa_domains_lock, flags);
	if (pisa_domains[idx].domain != domain) {
		spin_unlock_irqrestore(&pisa_domains_lock, flags);
		return;
	}
	/* Leaving @base set moves the slot to DRAINING state */
	pisa_domains[idx].domain = NULL;
	spin_unlock_irqrestore(&pisa_domains_lock, flags);

	dropped = pisa_forget_domain(idx);

	/* Wait out in-flight pisa_unmap_all() readers before reusing @idx. */
	synchronize_srcu(&pisa_srcu);

	/* Mark slot FREE and bump @pisa_idx_gen so NOIDX domains retry. */
	spin_lock_irqsave(&pisa_domains_lock, flags);
	pisa_domains[idx].base = 0;
	atomic_set(&pisa_domains[idx].slots, 0);
	pisa_domains[idx].name[0] = '\0';
	WRITE_ONCE(pisa_idx_gen, pisa_idx_gen + 1);
	spin_unlock_irqrestore(&pisa_domains_lock, flags);

	if (dropped)
		pr_debug("pisa: released %u PISA page mappings for domain %p (index %d)\n",
			 dropped, domain, idx);
}

/*
 * Remove @meta's leaf PTE from live @domain (registered at @idx with @base),
 * batching the IOTLB flush into @gather. Returns 1 if unmapped, 0 otherwise.
 */
static unsigned int pisa_unmap_domain_locked(struct pisa_meta *meta,
					     struct iommu_domain *domain,
					     int idx, dma_addr_t base,
					     struct iommu_iotlb_gather *gather)
{
	dma_addr_t iova = base + pisa_meta_win_offset(meta);
	size_t unmapped;

	if (!test_and_clear_bit(idx, meta->domains_mapped))
		return 0;
	atomic_dec(&pisa_domains[idx].slots);

	unmapped = iommu_unmap_fast(domain, iova, PISA_SIZE, gather);
	if (unlikely(unmapped != PISA_SIZE))
		pisa_quarantine_meta(meta, domain, idx, iova, unmapped);
	return 1;
}

/*
 * Unmap all PISA leaf PTEs from a domain whose last DMA API user detached,
 * keeping its window and domain index so mappings are re-installed on demand.
 */
void pisa_domain_quiesce(struct iommu_domain *domain)
{
	struct iommu_iotlb_gather gather;
	struct pisa_window *win;
	unsigned int slot, done = 0;
	bool release = false;
	dma_addr_t base;
	int idx;

	if (!static_branch_unlikely(&pisa_key))
		return;
	win = pisa_dma_window(domain);
	/* Pairs with smp_store_release() in pisa_window_assign(). */
	base = win ? smp_load_acquire(&win->base) : 0;
	if (!base)
		return;
	idx = win->domain_idx - PISA_IDX_FIRST;

	iommu_iotlb_gather_init(&gather);
	/* Keep call_rcu()-freed pages from reaching the buddy allocator before IOTLB sync. */
	rcu_read_lock();
	for_each_set_bit(slot, pisa_slot_bitmap, pisa_nr_slots) {
		struct pisa_meta *meta = READ_ONCE(pisa_slot2meta[slot]);
		struct pisa_alloc *pa;
		unsigned long flags;

		if (!meta || !test_bit(idx, meta->domains_mapped))
			continue;
		done += pisa_unmap_domain_locked(meta, domain, idx, base, &gather);
		if (likely(!(meta->flags & PISA_QUARANTINED)))
			continue;
		pa = READ_ONCE(meta->pa);
		if (!pa)
			continue;
		spin_lock_irqsave(&pa->lock, flags);
		if (meta->pa == pa) {
			if (meta->on_list == PISA_LIST_IDLE_CLEAN ||
			    meta->on_list == PISA_LIST_IDLE_DIRTY)
				pa->num_idle_pages--;
			release |= pisa_place_meta(meta);
		}
		spin_unlock_irqrestore(&pa->lock, flags);
	}

	if (done)
		iommu_iotlb_sync(domain, &gather);
	rcu_read_unlock();
	if (release)
		pisa_schedule_reclaim();
	if (done)
		pr_debug("pisa: unmapped %u PISA pages from idle domain %p (index %d)\n",
			 done, domain, idx);
}

/* Allocate a PISA_SIZE-aligned IOVA window of @size bytes from @domain. */
static dma_addr_t pisa_dma_window_alloc(struct device *dev, struct iommu_domain *domain, u64 size)
{
	u64 limit = min_not_zero(dma_get_mask(dev), dev->bus_dma_limit);
	struct iova_domain *iovad = pisa_dma_iovad(domain);
	unsigned long shift, iova_len;
	struct iova *new_iova;

	limit = min_not_zero(limit, dev->coherent_dma_mask);

	if (!iovad)
		return 0;

	if (domain->geometry.force_aperture)
		limit = min_t(u64, limit, domain->geometry.aperture_end);

	/* Ignore devices with too many constraints. */
	if (limit <= DMA_BIT_MASK(32) || size > limit - PISA_SIZE)
		return 0;

	shift = iova_shift(iovad);
	iova_len = (size + PISA_SIZE) >> shift;

	/* Ignore advisory dev->iommu->pci_32bit_workaround preference. */
	new_iova = alloc_iova(iovad, iova_len, limit >> shift, false);
	if (!new_iova)
		return 0;

	return ALIGN((dma_addr_t)new_iova->pfn_lo << shift, PISA_SIZE);
}

/*
 * Assign @domain an IOVA window and dense domain index on first use, recording
 * permanent or retryable failures in @win->domain_idx.
 */
int pisa_window_assign(struct device *dev, struct iommu_domain *domain, struct pisa_window *win)
{
	u64 limit = min_not_zero(dma_get_mask(dev), dev->bus_dma_limit);
	u64 size = pisa_window_size;
	unsigned long flags;
	dma_addr_t base = 0;
	int idx, ret;

	limit = min_not_zero(limit, dev->coherent_dma_mask);

	if (!dev_is_dma_coherent(dev))
		return -EOPNOTSUPP;

	if (limit <= DMA_BIT_MASK(32) || size > limit - PISA_SIZE)
		return -ENOSPC;

	if (!(domain->pgsize_bitmap & PISA_SIZE)) {
		if (cmpxchg(&win->domain_idx, PISA_IDX_NONE, PISA_IDX_NOHUGE) == PISA_IDX_NONE)
			dev_warn_ratelimited(dev, "pisa: domain lacks a %luKB page size, not PISA\n",
					     (unsigned long)(PISA_SIZE >> 10));
		return -EOPNOTSUPP;
	}

	spin_lock_irqsave(&pisa_domains_lock, flags);

	/* Bail if another CPU got here first, or if declined earlier. */
	ret = win->base ? 0 : pisa_window_declined(win);
	if (win->base || ret) {
		spin_unlock_irqrestore(&pisa_domains_lock, flags);
		return ret;
	}

	for (idx = 0; idx < PISA_MAX_DOMAINS; idx++) {
		if (!pisa_domains[idx].domain && !pisa_domains[idx].base)
			break;
	}
	if (idx == PISA_MAX_DOMAINS) {
		win->idx_gen = pisa_idx_gen;
		WRITE_ONCE(win->domain_idx, PISA_IDX_NOIDX);
		ret = -EBUSY;
	} else {
		base = pisa_dma_window_alloc(dev, domain, size);
		if (!base) {
			WRITE_ONCE(win->domain_idx, PISA_IDX_NOWINDOW);
			ret = -ENOSPC;
		} else {
			pisa_domains[idx].domain = domain;
			pisa_domains[idx].base = base;
			spin_lock_init(&pisa_domains[idx].map_lock);
			atomic_set(&pisa_domains[idx].slots, 0);
			strscpy(pisa_domains[idx].name, dev_name(dev),
				sizeof(pisa_domains[idx].name));
			WRITE_ONCE(win->domain_idx, idx + PISA_IDX_FIRST);
			/* Publish .domain_idx before .base (paired with is_pisa_iova()). */
			smp_store_release(&win->base, base);
		}
	}
	spin_unlock_irqrestore(&pisa_domains_lock, flags);

	if (ret == -EBUSY)
		pr_warn_ratelimited("pisa: all %d domain indices in use, not PISA for domain %p until one is released\n",
				    PISA_MAX_DOMAINS, domain);
	else if (ret == -ENOSPC)
		dev_warn_ratelimited(dev,
				     "pisa: no free %llu MB IOVA range for a PISA window\n",
				     size >> 20);
	else
		dev_info(dev, "pisa: domain %p index %d window %pad + %llu MB\n",
			 domain, idx, &base, size >> 20);
	return ret;
}

/*
 * Compute the window IOVA of active address @phys for @dev and store it in
 * *@iova. On first use in a domain, reserves @win via alloc_iova(), and on
 * first use of a PISA page in that domain, installs its 2MB leaf PTE via
 * iommu_map(..., GFP_ATOMIC) under spinlocks.
 * Returns 0 on success, or negative errno if @phys/@prot/@dev cannot use the window.
 */
int __pisa_map_phys(dma_addr_t *iova, struct device *dev,
		    struct iommu_domain *domain, phys_addr_t phys,
		    size_t size, int prot)
{
	struct pisa_window *win = pisa_dma_window(domain);
	unsigned long pfn = phys >> PAGE_SHIFT, flags;
	struct pisa_meta *meta;
	unsigned int domain_idx;
	int block_prot, ret;
	dma_addr_t addr;
	u64 limit;

	if (unlikely(!iova || !dev || !win || !dev_is_dma_coherent(dev) ||
		     (phys & (PISA_SIZE - 1)) + size > PISA_SIZE))
		return -EINVAL;

	meta = pisa_meta_of_pfn(pfn);

	/* Every leaf PTE of the page carries IOMMU_CACHE | @meta->prot. */
	block_prot = IOMMU_CACHE | meta->prot;
	if (unlikely(prot & ~block_prot)) {
		pisa_stat_atomic_inc(meta->pa->stats.fallback_prot);
		return -EACCES;
	}

	/* Acquire pairs with the .base release in pisa_window_assign(). */
	if (unlikely(!smp_load_acquire(&win->base))) {
		/* Test cached decline in @domain_idx before taking @pisa_domains_lock. */
		ret = pisa_window_declined(win);
		if (likely(!ret))
			ret = pisa_window_assign(dev, domain, win);

		if (ret) {
			if (ret == -EOPNOTSUPP)
				pisa_stat_atomic_inc(meta->pa->stats.fallback_nohuge);
			else if (ret == -EBUSY)
				pisa_stat_atomic_inc(meta->pa->stats.fallback_noidx);
			else
				pisa_stat_atomic_inc(meta->pa->stats.fallback_nowindow);
			return ret;
		}
	}

	addr = pisa_phys_to_iova(win, meta, phys);

	/* Check @dev's own DMA mask and bus limit against the window IOVA. */
	limit = min_not_zero(dma_get_mask(dev), dev->bus_dma_limit);
	limit = min_not_zero(limit, dev->coherent_dma_mask);
	if (unlikely(addr + size - 1 > limit)) {
		pisa_stat_atomic_inc(meta->pa->stats.fallback_nowindow);
		return -ENOSPC;
	}

	domain_idx = win->domain_idx - PISA_IDX_FIRST;
	if (likely(test_bit(domain_idx, meta->domains_mapped))) {
		*iova = addr;
		return 0;
	}

	/* First use of this PISA page in this domain: install the leaf PTE. */
	ret = 0;
	spin_lock_irqsave(&pisa_domains[domain_idx].map_lock, flags);
	if (!test_bit(domain_idx, meta->domains_mapped)) {
		phys_addr_t pisa_phys = phys & PISA_MASK;

		ret = iommu_map(domain, pisa_phys_to_iova(win, meta, pisa_phys),
				pisa_pte_phys(meta, pisa_phys), PISA_SIZE, block_prot, GFP_ATOMIC);
		if (unlikely(ret)) {
			pisa_stat_atomic_inc(meta->pa->stats.fallback_maperr);
		} else {
			/* Ensure leaf PTE is visible before setting the domain bit. */
			smp_mb__before_atomic();
			set_bit(domain_idx, meta->domains_mapped);
			atomic_inc(&pisa_domains[domain_idx].slots);
			pisa_stat_atomic_inc(meta->pa->stats.page_map_cnt);
		}
	}
	spin_unlock_irqrestore(&pisa_domains[domain_idx].map_lock, flags);
	if (unlikely(ret))
		return ret;

	*iova = addr;
	return 0;
}

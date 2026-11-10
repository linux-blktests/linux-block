/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* See Documentation/core-api/pisa.rst for the architecture overview. */
#ifndef _LINUX_PISA_H
#define _LINUX_PISA_H

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/dma-mapping.h>
#include <linux/jump_label.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/numa.h>
#include <linux/folio_batch.h>
#include <linux/rcupdate.h>

struct address_space;
struct block_device;
struct device;
struct folio_batch;
struct iommu_domain;

#ifdef CONFIG_PISA

#define PISA_SHIFT		21U
#define PISA_SIZE		(1UL << PISA_SHIFT)
#define PISA_MASK		(~(PISA_SIZE - 1))
#define PISA_ORDER		(PISA_SHIFT - PAGE_SHIFT)

/*
 * Each struct pisa_meta entry in pisa_meta_array has size PISA_META_SIZE
 * (256 B) and starts with a u8 flags byte.
 */
#define PISA_META_SHIFT		8
#define PISA_META_SIZE		(1U << PISA_META_SHIFT)
#define PISA_CHUNK_ORDER	(PISA_ORDER + PAGE_SHIFT - PISA_META_SHIFT)

enum {
	PISA_ACTIVE		= BIT(0), /* page is owned by a pisa_alloc */
	PISA_QUARANTINED	= BIT(1), /* IOMMU unmap failed: never reuse */
	PISA_DECRYPTED		= BIT(2), /* page was set_memory_decrypted() */
};

/* Enabled on first pisa_meta_init() to activate fast-path hooks. */
DECLARE_STATIC_KEY_FALSE(pisa_key);

struct pisa_meta;
extern struct pisa_meta *pisa_meta_array;
extern unsigned long pisa_meta_nframes;
extern unsigned long *pisa_chunk_bitmap;

int pisa_meta_init(void);

bool __is_pisa_direct(phys_addr_t phys, size_t size);

/* fast membership check for pisa pfn/pages */
static inline bool is_pisa_pfn(unsigned long pfn)
{
	unsigned long frame = pfn >> PISA_ORDER;
	const u8 *flags;

	if (!static_branch_unlikely(&pisa_key))
		return false;
	if (unlikely(frame >= pisa_meta_nframes ||
		     !test_bit_acquire(pfn >> PISA_CHUNK_ORDER, pisa_chunk_bitmap)))
		return false;

	flags = (const u8 *)pisa_meta_array + (frame << PISA_META_SHIFT);
	return READ_ONCE(*flags) & PISA_ACTIVE;
}

static inline bool is_pisa_direct(phys_addr_t phys, size_t size)
{
	if (!static_branch_unlikely(&pisa_key))
		return false;

	return __is_pisa_direct(phys, size);
}

static inline bool is_pisa_page(const struct page *page);

bool __pisa_free_page(struct page *page);
bool free_page_prepare_pisa(struct page *page, unsigned int order);

static inline bool pisa_free_page(struct page *page)
{
	bool ret;

	if (!static_branch_unlikely(&pisa_key))
		return false;
	rcu_read_lock();
	ret = is_pisa_page(page) && __pisa_free_page(page);
	rcu_read_unlock();

	return ret;
}

void *pisa_alloc_coherent(struct page **pagep, struct device *dev,
			  struct iommu_domain *domain, size_t size,
			  gfp_t gfp, unsigned long attrs);

static inline bool pisa_free_coherent(struct page *page, size_t size)
{
	unsigned long count = PAGE_ALIGN(size) >> PAGE_SHIFT;

	if (!page || !is_pisa_page(page))
		return false;
	while (count--)
		__free_page(page++);
	return true;
}

unsigned long pisa_alloc_pages_bulk(gfp_t gfp, unsigned int order,
				    int preferred_nid, nodemask_t *nodemask,
				    int nr_pages, struct page **page_array,
				    bool frozen);

struct folio *pisa_alloc_folio(gfp_t gfp, unsigned int order, int nid);
bool pisa_has_free_blocks_rx(const struct device *dev, unsigned int order, int nid);
bool pisa_page_can_recycle(const struct page *page);
void *pisa_skb_head_alloc_node(gfp_t flags, int node);

static inline gfp_t pisa_rx_gfp(const struct device *dev)
{
	return dev && READ_ONCE(dev->pisa_rx_bufs) ? __GFP_PISA_RW : 0;
}

/* current->task_frag_pisa lifetime, see task_page_frag(). */
static inline void pisa_task_frag_init(struct task_struct *tsk)
{
	tsk->task_frag_pisa.page = NULL;
}

static inline void pisa_task_frag_release(struct task_struct *tsk)
{
	if (tsk->task_frag_pisa.page)
		put_page(tsk->task_frag_pisa.page);
}

/* User pages in PISA blocks, see drivers/iommu/pisa-user.c */
DECLARE_STATIC_KEY_FALSE(pisa_user_key);
bool pisa_upgrade_user_pages(struct page **pages, unsigned int nr,
			     enum dma_data_direction dir, bool pinned);
struct folio *__pisa_filemap_alloc(const struct address_space *mapping,
				   gfp_t gfp, bool is_write);
bool pisa_folio_upgrade(struct folio *folio, enum dma_data_direction dir,
			struct folio_batch *fbatch);
bool __pisa_bdev_enabled(struct block_device *bdev, enum dma_data_direction dir);
bool __pisa_mapping_enabled(const struct address_space *mapping,
			    enum dma_data_direction dir);
void pisa_stats_inc_user_copy(void);
int pisa_madvise(struct vm_area_struct *vma, unsigned long start,
		 unsigned long end, bool to_pisa);

/* Is pisa.user_max_4K_pages non-zero? */
static inline bool pisa_user_enabled(void)
{
	return static_branch_unlikely(&pisa_user_key);
}

static inline bool is_bdev_pisa_enabled(struct block_device *bdev,
					enum dma_data_direction dir)
{
	return pisa_user_enabled() && __pisa_bdev_enabled(bdev, dir);
}

static inline bool pisa_mapping_enabled(const struct address_space *mapping,
					enum dma_data_direction dir)
{
	return pisa_user_enabled() && __pisa_mapping_enabled(mapping, dir);
}

static inline bool pisa_filemap_upgrade(const struct address_space *mapping,
					struct folio *folio, bool write_wait)
{
	return write_wait && pisa_mapping_enabled(mapping, DMA_TO_DEVICE) &&
	       pisa_folio_upgrade(folio, DMA_TO_DEVICE, NULL);
}

static inline bool pisa_writeback_upgrade(const struct address_space *mapping,
					  struct folio *folio, pgoff_t *index,
					  struct folio_batch *fbatch)
{
	pgoff_t idx;

	if (!pisa_mapping_enabled(mapping, DMA_TO_DEVICE))
		return false;
	idx = folio->index;
	if (!pisa_folio_upgrade(folio, DMA_TO_DEVICE, fbatch))
		return false;
	*index = idx;
	return true;
}

static inline struct folio *
pisa_filemap_alloc(const struct address_space *mapping, gfp_t gfp,
		   unsigned int order, bool is_write)
{
	if (order || !pisa_user_enabled())
		return NULL;
	return __pisa_filemap_alloc(mapping, gfp, is_write);
}

#else /* !CONFIG_PISA */

static inline int pisa_meta_init(void)
{
	return -EOPNOTSUPP;
}

bool free_page_prepare_pisa(struct page *page, unsigned int order);

static inline bool is_pisa_pfn(unsigned long pfn)
{
	return false;
}

static inline bool is_pisa_direct(phys_addr_t phys, size_t size)
{
	return false;
}

static inline bool pisa_free_page(struct page *page)
{
	return false;
}

static inline void *pisa_alloc_coherent(struct page **pagep,
					struct device *dev,
					struct iommu_domain *domain,
					size_t size, gfp_t gfp,
					unsigned long attrs)
{
	return NULL;
}

static inline bool pisa_free_coherent(struct page *page, size_t size)
{
	return false;
}

static inline void *pisa_skb_head_alloc_node(gfp_t flags, int node)
{
	return NULL;
}

static inline bool pisa_page_can_recycle(const struct page *page)
{
	return true;
}

static inline unsigned long
pisa_alloc_pages_bulk(gfp_t gfp, unsigned int order, int preferred_nid,
		      nodemask_t *nodemask, int nr_pages,
		      struct page **page_array, bool frozen)
{
	return 0;
}

static inline struct folio *
pisa_alloc_folio(gfp_t gfp, unsigned int order, int nid)
{
	return NULL;
}

static inline gfp_t pisa_rx_gfp(const struct device *dev)
{
	return 0;
}

static inline bool pisa_has_free_blocks_rx(const struct device *dev,
					   unsigned int order, int nid)
{
	return false;
}

static inline void pisa_task_frag_init(struct task_struct *tsk)
{
}

static inline void pisa_task_frag_release(struct task_struct *tsk)
{
}

static inline bool pisa_user_enabled(void)
{
	return false;
}

static inline bool pisa_upgrade_user_pages(struct page **pages, unsigned int nr,
					   enum dma_data_direction dir,
					   bool pinned)
{
	return false;
}

static inline bool pisa_folio_upgrade(struct folio *folio,
				      enum dma_data_direction dir,
				      struct folio_batch *fbatch)
{
	return false;
}

static inline bool is_bdev_pisa_enabled(struct block_device *bdev,
					enum dma_data_direction dir)
{
	return false;
}

static inline bool pisa_mapping_enabled(const struct address_space *mapping,
					enum dma_data_direction dir)
{
	return false;
}

static inline bool pisa_filemap_upgrade(const struct address_space *mapping,
					struct folio *folio, bool write_wait)
{
	return false;
}

static inline bool pisa_writeback_upgrade(const struct address_space *mapping,
					  struct folio *folio, pgoff_t *index,
					  struct folio_batch *fbatch)
{
	return false;
}

static inline struct folio *
pisa_filemap_alloc(const struct address_space *mapping, gfp_t gfp,
		   unsigned int order, bool is_write)
{
	return NULL;
}

static inline void pisa_stats_inc_user_copy(void)
{
}

static inline int pisa_madvise(struct vm_area_struct *vma, unsigned long start,
			       unsigned long end, bool to_pisa)
{
	return -EINVAL;
}

#endif /* CONFIG_PISA */

static inline struct page *
pisa_alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
		 nodemask_t *nodemask)
{
	struct page *page = NULL;

	pisa_alloc_pages_bulk(gfp, order, preferred_nid, nodemask, 1, &page, true);
	return page;
}

static inline bool is_pisa_phys(phys_addr_t phys)
{
	return is_pisa_pfn(phys >> PAGE_SHIFT);
}

static inline bool is_pisa_page(const struct page *page)
{
	return is_pisa_pfn(page_to_pfn(page));
}

#endif /* _LINUX_PISA_H */

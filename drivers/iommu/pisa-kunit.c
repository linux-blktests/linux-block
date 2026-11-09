// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * KUnit tests for the opaque struct pisa_meta table API.
 */
#include <kunit/test.h>
#include <linux/gfp.h>
#include <linux/pisa.h>
#include <linux/iommu.h>
#include <linux/iova.h>
#include <linux/mm.h>
#include <linux/shrinker.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#include "dma-iommu.h"
#include "pisa-priv.h"

static void test_meta_init_and_roundtrip(struct kunit *test)
{
	unsigned long pfn, base_pfn;
	struct pisa_meta *m_pfn;
	struct page *page;

	KUNIT_ASSERT_EQ(test, pisa_meta_init(), 0);
	/* Second call must be idempotent. */
	KUNIT_ASSERT_EQ(test, pisa_meta_init(), 0);

	page = alloc_page(GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, page);

	pfn = page_to_pfn(page);
	base_pfn = ALIGN_DOWN(pfn, 1UL << PISA_ORDER);
	__free_page(page);

	KUNIT_ASSERT_EQ(test, pisa_meta_ensure_pfn(pfn, true), 0);
	m_pfn = pisa_meta_of_pfn(pfn);
	KUNIT_EXPECT_PTR_EQ(test, pisa_meta_of_pfn(base_pfn), m_pfn);
	KUNIT_EXPECT_EQ(test, pisa_meta_to_pfn(m_pfn), base_pfn);
}

static void test_meta_invalid_phys(struct kunit *test)
{
	struct pisa_meta *meta;

	KUNIT_ASSERT_EQ(test, pisa_meta_init(), 0);

	meta = pisa_meta_of_pfn(ULONG_MAX >> PAGE_SHIFT);
	KUNIT_ASSERT_NOT_NULL(test, meta);
	KUNIT_EXPECT_EQ(test, pisa_meta_to_pfn(meta), ULONG_MAX);
	KUNIT_EXPECT_FALSE(test, is_pisa_pfn(ULONG_MAX >> PAGE_SHIFT));
	KUNIT_EXPECT_NE(test, pisa_meta_ensure_pfn(ULONG_MAX >> PAGE_SHIFT, false), 0);
}

static void pisa_meta_set_active(struct pisa_meta *meta, bool active)
{
	WRITE_ONCE(meta->flags, active ? PISA_ACTIVE : 0);
}

static void test_meta_active_toggle(struct kunit *test)
{
	unsigned long pfn, base_pfn;
	struct pisa_meta *meta;
	struct page *page;

	KUNIT_ASSERT_EQ(test, pisa_meta_init(), 0);

	page = alloc_pages(GFP_KERNEL, PISA_ORDER);
	KUNIT_ASSERT_NOT_NULL(test, page);

	pfn = page_to_pfn(page);
	base_pfn = ALIGN_DOWN(pfn, 1UL << PISA_ORDER);
	/* The buddy allocator returns naturally aligned blocks. */
	KUNIT_EXPECT_EQ(test, pfn, base_pfn);
	if (pisa_meta_ensure_pfn(pfn, true)) {
		__free_pages(page, PISA_ORDER);
		KUNIT_FAIL(test, "pisa_meta_ensure_pfn(%lu) failed", pfn);
		return;
	}
	KUNIT_EXPECT_EQ(test, pisa_meta_ensure_pfn(pfn, false), 0);
	meta = pisa_meta_of_pfn(pfn);

	KUNIT_EXPECT_FALSE(test, is_pisa_pfn(pfn));

	pisa_meta_set_active(meta, true);
	KUNIT_EXPECT_TRUE(test, is_pisa_pfn(base_pfn));
	KUNIT_EXPECT_TRUE(test, is_pisa_pfn(pfn));
	KUNIT_EXPECT_TRUE(test, is_pisa_pfn(base_pfn + (1UL << PISA_ORDER) - 1));

	pisa_meta_set_active(meta, false);
	KUNIT_EXPECT_FALSE(test, is_pisa_pfn(pfn));

	__free_pages(page, PISA_ORDER);
}

static void test_alloc_and_recycle(struct kunit *test)
{
	const struct {
		unsigned int order;
		bool ro;
	} cases[] = {
		{ 0, false },
		{ 2, true },
		{ SKB_FRAG_PAGE_ORDER, true },
	};
	struct shrink_control sc = { .nr_to_scan = ULONG_MAX };
	struct page *p1, *p2, *bulk[3];
	struct pisa_alloc *pa;
	unsigned long old_max;
	unsigned int i;

	KUNIT_EXPECT_NULL(test, pisa_create(first_memory_node, 0, DMA_NONE));
	KUNIT_EXPECT_NULL(test, pisa_create(first_memory_node, PISA_ORDER + 1,
					    DMA_BIDIRECTIONAL));
	KUNIT_EXPECT_NULL(test, pisa_node_pa(first_memory_node, 1, false));
	KUNIT_EXPECT_NULL(test, pisa_node_pa(first_memory_node, 0, true));
	KUNIT_EXPECT_NULL(test, pisa_node_pa(first_memory_node, PISA_ORDER + 1, false));
	pisa_set_name(NULL, "ignored");

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		unsigned int order = cases[i].order;

		pa = pisa_node_pa(first_memory_node, order, cases[i].ro);
		KUNIT_ASSERT_NOT_NULL(test, pa);
		pisa_shrink_scan(NULL, &sc);
		KUNIT_EXPECT_NULL(test, pisa_alloc(pa, GFP_KERNEL | __GFP_ACCOUNT));
		KUNIT_EXPECT_NULL(test, pisa_alloc(pa, GFP_KERNEL | __GFP_DMA32));
		KUNIT_EXPECT_NULL(test, pisa_alloc(pa, GFP_KERNEL | __GFP_THISNODE));

		p1 = pisa_alloc(pa, GFP_KERNEL | __GFP_ZERO);
		KUNIT_ASSERT_NOT_NULL(test, p1);
		KUNIT_EXPECT_TRUE(test, is_pisa_page(p1));

		/* Freeing p1 returns it to the allocator; next allocation reuses index 0. */
		__free_pages(p1, order);
		p2 = pisa_alloc(pa, GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, p2);
		if (!want_init_on_alloc(GFP_KERNEL) || want_init_on_free() || order == PISA_ORDER)
			KUNIT_EXPECT_PTR_EQ(test, p1, p2);

		if (order == 0) {
			/* Bulk alloc skips already populated entries. */
			bulk[0] = NULL;
			bulk[1] = p2;
			bulk[2] = NULL;
			KUNIT_EXPECT_EQ(test,
					pisa_alloc_bulk(pa, GFP_KERNEL, 3, bulk, false),
					3UL);
			KUNIT_EXPECT_PTR_EQ(test, bulk[1], p2);
			KUNIT_EXPECT_NOT_NULL(test, bulk[0]);
			KUNIT_EXPECT_NOT_NULL(test, bulk[2]);
			/* Declined GFP reports populated prefix length. */
			KUNIT_EXPECT_EQ(test,
					pisa_alloc_bulk(pa,
							GFP_KERNEL | __GFP_ACCOUNT,
							3, bulk, false),
					3UL);
			if (bulk[0])
				__free_pages(bulk[0], 0);
			if (bulk[2])
				__free_pages(bulk[2], 0);
		}

		if (p2)
			__free_pages(p2, order);
		pisa_shrink_scan(NULL, &sc);
	}

	/* Plain alloc_page() without __GFP_PISA_* comes from the buddy allocator. */
	p1 = alloc_page(GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, p1);
	KUNIT_EXPECT_FALSE(test, is_pisa_page(p1));
	__free_pages(p1, 0);

	/* Global budget cap (pisa_max_pages = 0) refuses new PISA pages. */
	pa = pisa_node_pa(first_memory_node, 2, true);
	KUNIT_ASSERT_NOT_NULL(test, pa);
	old_max = READ_ONCE(pisa_max_pages);
	WRITE_ONCE(pisa_max_pages, 0);
	WRITE_ONCE(pisa_reservoir_max, 0);
	KUNIT_EXPECT_NULL(test, pisa_alloc(pa, GFP_KERNEL));
	WRITE_ONCE(pisa_reservoir_max, 16);
	WRITE_ONCE(pisa_max_pages, old_max);
}

#ifdef CONFIG_IOMMU_DMA
static void test_window_helpers(struct kunit *test)
{
	struct device dev = { .numa_node = NUMA_NO_NODE };
	struct iommu_domain dummy_domain = {};
	struct pisa_window win = {};
	dma_addr_t d;

	KUNIT_ASSERT_EQ(test, pisa_meta_init(), 0);

	/* Empty window (base == 0) never owns any IOVA. */
	KUNIT_EXPECT_FALSE(test, is_pisa_iova(&win, 0));
	KUNIT_EXPECT_FALSE(test, is_pisa_iova(&win, SZ_4G));

	win.base = SZ_4G;
	KUNIT_EXPECT_FALSE(test, is_pisa_iova(&win, SZ_4G - 1));
	KUNIT_EXPECT_TRUE(test, is_pisa_iova(&win, SZ_4G));
	KUNIT_EXPECT_TRUE(test, is_pisa_iova(&win, SZ_4G + pisa_window_size - 1));
	KUNIT_EXPECT_FALSE(test, is_pisa_iova(&win, SZ_4G + pisa_window_size));

	/* Sentinel values in pisa_window_declined(). */
	win.domain_idx = PISA_IDX_NONE;
	KUNIT_EXPECT_EQ(test, pisa_window_declined(&win), 0);
	win.domain_idx = PISA_IDX_NOHUGE;
	KUNIT_EXPECT_EQ(test, pisa_window_declined(&win), -EOPNOTSUPP);
	win.domain_idx = PISA_IDX_NOWINDOW;
	KUNIT_EXPECT_EQ(test, pisa_window_declined(&win), -ENOSPC);
	win.domain_idx = PISA_IDX_NOIDX;
	win.idx_gen = READ_ONCE(pisa_idx_gen);
	KUNIT_EXPECT_EQ(test, pisa_window_declined(&win), -EBUSY);
	win.idx_gen--;
	KUNIT_EXPECT_EQ(test, pisa_window_declined(&win), 0);

	/* A device without an IOMMU group has no PISA window. */
	KUNIT_EXPECT_NE(test, pisa_map_phys(&d, NULL, NULL, 0, PAGE_SIZE, 0), 0);
	KUNIT_EXPECT_NE(test, pisa_map_phys(&d, &dev, NULL, 0, PAGE_SIZE, 0), 0);
	/* Releasing an unregistered domain with an active allocator is a safe no-op. */
	pisa_domain_release(&dummy_domain);
}

/*
 * Fake DMA domain for the mapping and coherent allocation tests, backed by a
 * real iommu_dma_cookie and no-op page table ops.
 */
static int fake_map_pages(struct iommu_domain *domain, unsigned long iova,
			  phys_addr_t paddr, size_t pgsize, size_t pgcount,
			  int prot, gfp_t gfp, size_t *mapped)
{
	*mapped = pgsize * pgcount;
	return 0;
}

static size_t fake_unmap_pages(struct iommu_domain *domain, unsigned long iova,
			       size_t pgsize, size_t pgcount,
			       struct iommu_iotlb_gather *iotlb_gather)
{
	return pgsize * pgcount;
}

static const struct iommu_domain_ops fake_domain_ops = {
	.map_pages = fake_map_pages,
	.unmap_pages = fake_unmap_pages,
};

static struct iommu_domain fake_domain = {
	.type = IOMMU_DOMAIN_DMA,
	.pgsize_bitmap = SZ_4K | PISA_SIZE,
	.ops = &fake_domain_ops,
};

static void fake_domain_teardown(void *unused)
{
	iommu_put_dma_cookie(&fake_domain);
	fake_domain.cookie_type = IOMMU_COOKIE_NONE;
	fake_domain.iova_cookie = NULL;
	iova_cache_put();
}

static int fake_domain_setup(struct kunit *test)
{
	int ret = iova_cache_get();

	if (ret)
		return ret;
	ret = iommu_get_dma_cookie(&fake_domain);
	if (ret) {
		iova_cache_put();
		return ret;
	}
	init_iova_domain(pisa_dma_iovad(&fake_domain), SZ_4K, 1);
	return kunit_add_action_or_reset(test, fake_domain_teardown, NULL);
}

static void test_map_and_domain_lifecycle(struct kunit *test)
{
	struct device dev = { .init_name = "pisa_map_kunit", .numa_node = NUMA_NO_NODE,
			      .coherent_dma_mask = DMA_BIT_MASK(64) };
	struct shrink_control sc = { .nr_to_scan = ULONG_MAX };
	struct pisa_window *win;
	struct pisa_meta *meta;
	struct pisa_alloc *pa;
	unsigned int domain_idx;
	dma_addr_t d1, d2;
	struct page *p;
	phys_addr_t phys;

	dev.dma_mask = &dev.coherent_dma_mask;
	set_dev_node(&dev, first_memory_node);
#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE) || \
	defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || \
	defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL)
	dev.dma_coherent = true;
#endif
	KUNIT_ASSERT_EQ(test, fake_domain_setup(test), 0);
	win = pisa_dma_window(&fake_domain);

	pa = pisa_node_pa(first_memory_node, 2, true);
	KUNIT_ASSERT_NOT_NULL(test, pa);
	p = pisa_alloc(pa, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, p);

	phys = page_to_phys(p);
	meta = pisa_meta_of_pfn(page_to_pfn(p));
	KUNIT_EXPECT_TRUE(test, is_pisa_phys(phys));

	/* TX-only allocator declines IOMMU_WRITE mappings. */
	KUNIT_EXPECT_EQ(test,
			pisa_map_phys(&d1, &dev, &fake_domain, phys, PAGE_SIZE,
				      IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE), -EACCES);

	/* First map assigns the window and installs the 2MB PTE. */
	KUNIT_ASSERT_EQ(test,
			pisa_map_phys(&d1, &dev, &fake_domain, phys, PAGE_SIZE,
				      IOMMU_READ | IOMMU_CACHE), 0);
	KUNIT_EXPECT_TRUE(test, is_pisa_iova(win, d1));
	domain_idx = win->domain_idx - PISA_IDX_FIRST;
	KUNIT_EXPECT_TRUE(test, test_bit(domain_idx, meta->domains_mapped));

	/* Second map at an offset hits the lockless fast path. */
	KUNIT_ASSERT_EQ(test,
			pisa_map_phys(&d2, &dev, &fake_domain, phys + 128, 256,
				      IOMMU_READ | IOMMU_CACHE), 0);
	KUNIT_EXPECT_EQ(test, d2, d1 + 128);

	/* Quiescing the domain unmaps the PISA page but keeps the window. */
	pisa_domain_quiesce(&fake_domain);
	KUNIT_EXPECT_FALSE(test, test_bit(domain_idx, meta->domains_mapped));
	KUNIT_ASSERT_EQ(test,
			pisa_map_phys(&d2, &dev, &fake_domain, phys, PAGE_SIZE,
				      IOMMU_READ | IOMMU_CACHE), 0);
	KUNIT_EXPECT_EQ(test, d2, d1);
	KUNIT_EXPECT_TRUE(test, test_bit(domain_idx, meta->domains_mapped));

	/* Releasing the domain forgets the mapping bit across allocators. */
	pisa_domain_release(&fake_domain);
	KUNIT_EXPECT_FALSE(test, test_bit(domain_idx, meta->domains_mapped));

	/* Re-map into a fresh window so shrinking exercises pisa_unmap_all(). */
	*win = (struct pisa_window){};
	KUNIT_EXPECT_EQ(test,
			pisa_map_phys(&d1, &dev, &fake_domain, phys, PAGE_SIZE,
				      IOMMU_READ | IOMMU_CACHE), 0);

	__free_pages(p, 2);
	pisa_shrink_scan(NULL, &sc);
}
#endif /* CONFIG_IOMMU_DMA */

static void test_reservoir_and_scrubber(struct kunit *test)
{
	KUNIT_ASSERT_EQ(test, pisa_meta_init(), 0);
	KUNIT_EXPECT_EQ(test, READ_ONCE(pisa_reservoir_max), 16U);
}

static struct kunit_case pisa_meta_test_cases[] = {
	KUNIT_CASE(test_meta_init_and_roundtrip),
	KUNIT_CASE(test_meta_invalid_phys),
	KUNIT_CASE(test_meta_active_toggle),
	KUNIT_CASE(test_alloc_and_recycle),
#ifdef CONFIG_IOMMU_DMA
	KUNIT_CASE(test_window_helpers),
	KUNIT_CASE(test_map_and_domain_lifecycle),
#endif
	KUNIT_CASE(test_reservoir_and_scrubber),
	{}
};

static struct kunit_suite pisa_meta_test_suite = {
	.name = "pisa_meta",
	.test_cases = pisa_meta_test_cases,
};

kunit_test_suite(pisa_meta_test_suite);
MODULE_DESCRIPTION("KUnit tests for struct pisa_meta table and PISA allocator");
MODULE_LICENSE("Dual BSD/GPL");

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * KUnit tests for the opaque struct pisa_meta table API.
 */
#include <kunit/test.h>
#include <linux/gfp.h>
#include <linux/pisa.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <net/sock.h>

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
	struct page *p1, *p2, *bulk[3];
	struct pisa_alloc *pa;
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
	}

	/* Plain alloc_page() without __GFP_PISA_* comes from the buddy allocator. */
	p1 = alloc_page(GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, p1);
	KUNIT_EXPECT_FALSE(test, is_pisa_page(p1));
	__free_pages(p1, 0);
}

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

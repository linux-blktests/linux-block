// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * PISA per-domain IOVA window management and IOMMU mapping.
 * See Documentation/core-api/pisa.rst for the architecture overview.
 */

#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/pisa.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

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

.. SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

=============================================
PISA: Pre-mapped IOVA Superpage Allocator
=============================================

Overview
========

PISA is a memory allocator that provides DMA-able memory backed
by large physically contiguous pages (typically 2MB), and mapped by
IOMMU leaves of the same size.
Devices can opt-in to use PISA memory for descriptor rings,
header buffers, tx and rx data buffers, and zerocopy I/O.

PISA has the following features:

- greatly reduced IOTLB pressure by using fewer and much larger
  IOMMU entries
- greatly reduced DMA map/unmap costs. Mapping only happens when the first
  block from a 2MB page is used. Unmapping is a no-op for the caller,
  and happens in a separate worker the 2MB page is fully unused
- much better security than DMA-FQ, because buffers are not returned
  to the buddy allocator (where they could be used for code or sensitive
  data) until all IOMMU and IOTLB mappings have been flushed.
  Note that the mappings are kept active during the lifetime of buffers,
  but this is the same thing that happens e.g. with pagepool, even in strict
  IOMMU mode (DMA).
- can remove the cost of copying into bounce buffers e.g. for overcommitted
  or Confidential Computing VMs.

For devices that do not opt-in to PISA, the IOMMU keeps using the
native IOMMU mode (DMA or DMA-FQ).

Note that PISA is fully integrated with relevant kernel APIs so
devices can use it without device-specific code changes.

What PISA is not
================
For avoidance of doubt: PISA is essentially a specialized memory allocator,
modeled after alloc_pages() and related APIs. The main difference is that
it enforces some properties on the memory it provides so that other operations
(IOMMU mapping and unmapping, high rate allocations, identification...)
can be implemented efficiently and with the desired security properties.

It is not a specialized cache or pagepool or slab allocator:
we have already plenty of them, built on top of the buddy allocator.
PISA sits below these existing subsystems and acts as a memory provider.

It is not a custom netdev feature. While network devices are the primary
user, disks and other compute accelerators can use it, again, as a replacement
for the alloc_pages() allocator.

Background and motivations
==========================

I/O devices typically access at least 3-4 different memory regions on
each transaction (network packet or disk request):

- command, completion and buffer queues
- optionally, header or metadata buffers (e.g., NIC packet headers, NVMe SGL...)
- data buffers (TX socket buffers, NIC RX buffers, disk I/O buffers)

Enabling the IOMMU impacts performance for the following reasons:

- CPU cost to install/remove IOMMU Page Table Entries (PTEs)
  (``dma_map_*()``, ``dma_unmap_*()``)
- CPU/system overhead to flush the IOTLB, ie remove stale PTEs that could give
  access to sensitive data or code when memory is recycled for other purposes.
- Higher DMA read/write latency from IOMMU page walks when the working set
  exceeds the IOTLB size, backpressuring the bus via flow control.
  This is one of the biggest bottlenecks for high speed devices:
  typical network devices have very little IOVA locality, and that makes
  the IOTLB almost completely ineffective.

There are known methods to mitigate these problems:

1. Recycling I/O buffers and their IOMMU mappings removes most of the DMA
   map/unmap costs. This is common practice for command, completion and
   buffer queues, as well as disk I/O and network receive buffers.  Network
   TX buffers are a noticeable exception. They normally come from
   ``alloc_pages()`` calls unaware of the leaf device, and require
   mapping/unmapping on each use.

2. Lazily flushing the IOTLB (as implemented by DMA-FQ) amortizes a
   very expensive operation (up to several microseconds to wait for
   completion, necessary for security), but the way it is implemented
   in DMA-FQ compromises on security: IOTLB flush requests are run
   periodically in batches, but the underlying memory is recycled without
   waiting. During that window, the physical memory is still accessible,
   opening the door to exfiltration or corruption of sensitive data/code.

3. The set of PTEs in active use can be significantly reduced by mapping larger
   blocks, e.g. 2MB large pages instead of the usual 4KB (PTE). This is not
   currently pursued by the kernel.

PISA addresses all the above with a combination of simple, known concepts,
implemented in a way that integrates smoothly with the kernel and drivers:

- intercept calls to the small set of functions used to allocate, map,
  unmap, and free device-accessible memory (rings and buffers)
- return memory backed by physically contiguous 2MB PISA pages and 2MB IOMMU
  mappings
- heavily recycle memory and mappings
- wait until the IOTLB has been flushed before returning unused PISA pages
  to the system

Execution is what makes PISA practical: the implementation intercepts
a small set of kernel APIs so that device will inherit the benefits with
little if any changes, and the design is such that these intercepts have
minimal impact on the original functions.

Furthermore, since PISA intercepts allocations of device-accessible
memory, it can transparently configure unencrypted mode, required for
confidential computing. Under a paravirtualized IOMMU, the long-lived 2MB
mappings also make host-side pinning of DMA memory a rare event.

Limitations
===========

PISA is currently limited to systems with 2MB large pages, which
is the vast majority of existing platforms. This is enforced at compile time.

Decoupling the allocation size from 2MB can be made without much effort,
so the mechanisms can be extended to systems with 16K/64K page size.

The implementation assumes non-preemptible spinlocks, so PISA is not
compatible with ``PREEMPT_RT``. This is enforced at compile time.

PISA can only be used by DMA-coherent devices. This is enforced at runtime.

IOMMU mappings for data buffers follow the direction the allocator was created
with. Receive pools (``page_pool``) are ``DMA_BIDIRECTIONAL``, so received
buffers can be retransmitted (XDP_TX, forwarding) without a new mapping.
Allocators that only hold transmit data, such as socket TX fragments, are
``DMA_TO_DEVICE``. Allocators created
``DMA_TO_DEVICE`` or ``DMA_FROM_DEVICE`` have their PISA pages mapped device
read-only or write-only, and a mapping that requests other access falls back
to a per-buffer mapping.

IOMMU mappings for queues are also ``DMA_BIDIRECTIONAL``, though stricter modes
can be implemented trivially.

Implementation details
======================

Most of the code size and design complexity relates to the handling
of exceptional events (device teardown, memory hotplug) and to
the safe release of pages through deferred tasks, RCU and grace
periods.

The implementation lives in ``drivers/iommu/pisa-*.c`` and
``include/linux/pisa.h``, and relies on the components described below.
We use the name "PISA" to refer to the second-level physically contiguous
pages (typically 2MB) used for I/O memory, but the design is not tightly
bound to the use of a PISA page.

The set of functions that need to be intercepted is relatively small:

- ``page_pool_dev_alloc*()``, socket TX page frags, ``__free_pages()``
- ``dma_alloc_attrs()``, ``dma_map_*()``, ``dma_unmap_*()``

and most devices will automatically inherit the benefits.

Requirements (for performance and functionality)
================================================

- efficient identification of PISA pages, based on either their Physical
  Address (PA) or their I/O Virtual Address (IOVA)
- fast access to PISA page metadata
- fast allocation under highly concurrent usage
- efficient DMA map/unmap
- comprehensive lifetime management
- support for confidential computing (decrypted DMA buffers)

Internal mechanisms
===================

We use the following components:

- **PISA metadata** (``struct pisa_meta``):

  Identification of PISA pages could be done in principle with a flag in
  ``struct page``, but that would not solve the management of per-page
  metadata.

  PISA addresses both requirements without depending on ``struct page``
  using an idea similar to ``pageblock_flags``. Each PISA page used as a
  buffer requires only 256B of metadata, or 0.01% overhead. For metadata,
  we reserve a sparse virtual memory region of approximate size
  ``max_possible_pfn * 256 / PISA_SIZE`` (``pisa.max_bits=N`` on the
  command line covers ``2^N`` bytes of physical address space instead; RAM
  above the covered range is not used by PISA), so the metadata can be accessed
  directly using the PISA page index.  A metadata page is backed when a
  allocator first takes a PISA page in its 32MB chunk, from any context: the
  page tables are allocated beforehand for present RAM, and by a memory
  hotplug notifier for memory added later. A compact bitmap (1 bit per
  32MB chunk, or 4KB per 1TB of address space) tracks which metadata
  pages are backed, allowing fast lockless validation and direct array
  indexing.

  ``struct pisa_meta`` has flags to mark the page status (used as
  PISA buffer, or decrypted for confidential computing), and tracks
  which subpages are free, which domains have an active IOMMU mapping for
  the page, and holds list/RCU linkage to manage its lifetime.

- **Per-domain reserved PISA IOVA ranges**:

  Another key requirement is to quickly resolve the PA-IOVA mapping for a
  given domain. Since a PISA page can be mapped in multiple domains (e.g.
  a network buffer used to route packets between different NICs), it would
  be too expensive to manage random PA-IOVA mappings created on the fly.
  Each PISA page gets a dense slot number when it enters PISA, and is
  mapped at the same offset, ``slot * PISA_SIZE``, in
  every domain's window. PISA reserves on each domain an IOVA range of
  ``pisa.slots * 2MB`` (by default 2 * ``max_pages`` slots, i.e. a
  quarter of RAM): its size does not depend on the physical memory layout,
  and IOVAs do not expose physical addresses. The IOVA allocation happens
  the first time a domain is used, hence a IOVA within the reserved range
  will uniquely identify a PISA page. Slots are handed out lowest first
  and reused only after the page has been unmapped from every domain.

- **alloc_pages() compatible pisa_alloc allocator for I/O buffers**:

  PISA implements a pisa_alloc object for fixed-order page allocations
  that is a natural fit for the allocation of NIC receive buffers and tx
  socket buffers. The API is similar to ``alloc_pages()`` (in fact, it is an
  almost direct replacement) and pisa_allocs are instantiated as follows:

  - per node, order-0 ``DMA_BIDIRECTIONAL`` (``__GFP_PISA_RW``), with per-CPU
    block caches, to provide RX buffer pages
  - per node, ``DMA_TO_DEVICE`` (``__GFP_PISA_RO``), with per-CPU block caches
    to provide order-3 (``SKB_FRAG_PAGE_ORDER``) pages to refill tx socket buffers; on a miss,
    an ordinary order-0 page is used. Order-2 ``DMA_TO_DEVICE`` (without per-CPU
    caches) is also provided for small skb heads on systems with few CPUs.

  - per node, order-0 ``DMA_BIDIRECTIONAL`` (``pisa_alloc_coherent()``),
    carving naturally aligned contiguous 4KB page ranges (up to ``PISA_SIZE``)
    to back coherent ``dma_alloc_attrs()`` queues and header bounce buffers
    when ``dev->pisa_coherent`` is enabled.


- **Fine grained control**

  Both for experimentation and production use, it is useful to have
  some form of control on which devices want to use PISA and for
  what. PISA exposes the following controls. Keep in mind that full
  performance can only be achieved if all regions are mapped using PISA.

  - ``/sys/devices/*/*/pisa_{coherent,rx_bufs,tx_bufs,tx_skb_heads}``
    per-device entries that control whether a device uses PISA for coherent
    allocations, RX buffers, TX socket page fragments, and small TX skb heads

- **Safe release of memory to the system**

  A key feature of PISA is that memory is not released to the system
  while there are active IOMMU mappings. Release of buffers is managed
  as follows

  1. on ``__free_pages()`` or ``dma_free_attrs()``, blocks are returned to
     PISA, IOMMU mappings are still active, and they can be recycled

  2. when all blocks in a PISA page are unused, the page is moved to the
     allocator's "idle" list, still with active mappings and available for reuse,
     unless the allocator already holds max_idle_pages idle pages

  3. pages above that per-allocator watermark are released by a reclaim work
     item, and under memory pressure the shrinker also releases idle pages
     from all allocators: the iommu mappings are removed and a synchronous IOTLB
     flush is issued. The pages are no longer usable for allocations but not
     returned to the buddy allocator yet

  4. once the previous step is complete, the system schedules ``call_rcu()``
     and waits for an RCU grace period (and re-encrypts the page if it was
     decrypted) before returning the PISA page to the buddy allocator.

- **Handling domain destruction**

  When a device/domain is destroyed, all I/O issued by the device must have
  been quiesced and memory released via ``__free_pages()`` or ``dma_free*()``.
  PISA hooks into the domain destructor (``iommu_put_dma_cookie()``) and
  forgets the disappearing domain: its bit is cleared in every active
  PISA page, without touching the domain's page tables, which the owner
  frees wholesale. The domain index is reused only after an SRCU grace
  period.

- **Handling loss of the last DMA API user**

  ``dma_unmap_*()`` never removes window PTEs, so when the last driver using
  a group's default domain through the DMA API unbinds, or the group's DMA
  ownership is taken (VFIO, iommufd), ``pisa_domain_quiesce()`` unmaps every
  active PISA page from that domain and flushes the IOTLB. The window
  and domain index are kept; PTEs are re-installed on demand if a driver binds
  again. In-flight page_pool pages, which ``page_pool_scrub()`` cannot unmap,
  are covered the same way.

- **Allocation and compound splitting**:

  An allocator that needs memory calls ``pisa_alloc_split_page()`` to allocate a
  physically contiguous PISA page on the calling CPU's NUMA node, and
  ``split_page_compound()`` to split it into independent blocks of
  ``pa->order``. These blocks can be independently passed through the
  networking stack.

Modified kernel APIs and runtime controls
=========================================

PISA integrates transparently into existing kernel memory, DMA, and
networking APIs. Allocation of PISA memory is opt-in via per-device sysfs
attributes or module parameters. Mapping, unmapping, and freeing automatically detects
whether a buffer or IOVA belongs to PISA:

- **Streaming DMA map and unmap** (``dma_map_page_attrs()``,
  ``dma_map_single_attrs()``, ``dma_map_sg_attrs()`` and
  ``dma_unmap_page_attrs()``, ``dma_unmap_single_attrs()``,
  ``dma_unmap_sg_attrs()`` via ``drivers/iommu/dma-iommu.c`` and
  ``kernel/dma/direct.c``):

  - On map, any buffer belonging to a PISA page
    (``is_pisa_phys(phys)``) is mapped via the domain's reserved
    PISA IOVA window with a simple addition, typically reusing
    existing mappings. Under ``dma-direct``, decrypted PISA pages
    (``is_pisa_direct(phys, size)``) can be mapped directly without
    ``swiotlb`` bounce.

    On unmap, IOVAs can be identified as PISA buffers with a simple
    range check and that results in a no-operation.

- **Coherent DMA allocation and free** (``dma_alloc_attrs()`` /
  ``dma_alloc_coherent()`` and ``dma_free_attrs()`` / ``dma_free_coherent()``
  via ``drivers/iommu/dma-iommu.c`` and ``kernel/dma/direct.c``):

  - PISA is enabled per device via ``/sys/devices/.../pisa_coherent``
    (``dev->pisa_coherent``). When set, sleepable ``GFP_KERNEL`` coherent
    allocations up to ``PISA_SIZE`` are rounded up to 4KB, carved out of
    the per-node order-0 ``pisa_alloc`` via ``pisa_alloc_coherent()``, and
    mapped through the domain's PISA IOVA window (or directly at their
    physical/decrypted DMA address for ``dma-direct``). ``dma_free_attrs()``
    releases the order-0 pages via ``pisa_free_coherent()``, which recycles
    them back to the allocator.

- **Page allocator release** (``__free_pages()`` / ``put_page()`` via
  ``__free_pages_prepare()`` in ``mm/page_alloc.c``):

  - ``pisa_free_page()`` checks ``is_pisa_page(page)``
    and recycles PISA subpages back to their owning ``pisa_alloc``
    instead of releasing them to the buddy allocator while their 2MB IOMMU
    mappings remain active.

- **IOMMU domain teardown** (``iommu_put_dma_cookie()`` in
  ``drivers/iommu/dma-iommu.c``):

  - A call to ``pisa_domain_release()`` before freeing a
    domain's IOVA cookie and page tables clears cached domain state across
    all allocators. Existing IOMMU mappings and IOTLB flush has already happened.

- **Networking ``page_pool``** (``net/core/page_pool.c``):

  - PISA is enabled per device via ``/sys/devices/.../pisa_rx_bufs``
    (``dev->pisa_rx_bufs``). ``__page_pool_alloc_netmems_slow()`` adds
    ``__GFP_PISA_RW`` via ``pisa_rx_gfp()`` when ``PP_FLAG_DMA_MAP`` is set,
    allocating RX pages from the per-node ``DMA_BIDIRECTIONAL`` PISA
    allocator and falling back to the buddy allocator on exhaustion.

- **Socket TX page fragments** (``sk_page_frag_dst()`` and
  ``skb_page_frag_refill()`` in ``net/core/sock.c``):

  - When enabled per device via ``/sys/devices/.../pisa_tx_bufs``,
    socket TX fragments are allocated from per-node ``pisa_alloc`` instances,
    with per-CPU block caches in front of them.
    These allocators are ``DMA_TO_DEVICE``: devices can only read them, and
    callers that map fragments for device writes get per-buffer mappings.
  - Only data routed to a device with a DMA parent, outside IPsec, is copied
    into them (TCP, UDP/raw), through a dedicated
    per-task frag. Loopback, virtual devices, kTLS, sockmap, KCM and MPTCP
    use ordinary pages. ESP output uses the allocators through
    ``skb_page_frag_refill_dev()``, when their egress device can use them.

- **Small skb heads** (``kmalloc_reserve()`` in ``net/core/skbuff.c``):

  - When enabled per device via ``/sys/devices/.../pisa_tx_skb_heads``,
    small skb heads come from the ``skbuff_small_head_pisa`` slab cache,
    whose slab pages are blocks of per-node TX-only ``pisa_alloc``
    instances (created ``DMA_TO_DEVICE``), zeroed when taken from the allocator.
    Mappings of these heads that request device write access fall back to
    per-buffer IOMMU mappings.

- **NIC driver RX buffers**

  - Controlled per device by ``/sys/devices/.../pisa_rx_bufs``
    (``dev->pisa_rx_bufs``) for queue modes managing their own page rings
    (e.g. ``gve`` GQI-RDA).

- **User pages for MSG_ZEROCOPY** (``drivers/iommu/pisa-user.c``):

  - ``madvise(MADV_PISA)`` migrates the present private anonymous pages
    of a range into blocks of per-node ``DMA_TO_DEVICE`` allocators, so that
    zerocopy sends from them use the PISA window instead of per-send IOMMU
    mappings or hypervisor pinning. ``MADV_NOPISA`` migrates them back to
    ordinary pages. Both are allowed through ``process_madvise()``.
    Freeing the pages (``munmap()``, ``MADV_DONTNEED``, exit, reclaim)
    returns the blocks to their allocators.
  - ``/sys/module/pisa/parameters/user_max_4K_pages``: Soft cap on user
    pages held in PISA blocks, in 4 KB pages (``max_pages`` counts PISA
    pages). When non-zero, eligible pages are also migrated on
    ``MSG_ZEROCOPY`` sends (best effort, non-blocking, skipping pages still
    referenced by in-flight skbs); 0 (default) disables both. With
    ``pisa_tx_bufs`` also enabled, pages that are not in PISA
    after that (cap reached, busy, large, shared or file-backed) are copied
    by TCP into PISA socket frags instead of being sent zerocopy (other
    senders still send them zerocopy); the copy is not reported to the
    application.
  - Not available on CoCo guests: decrypted blocks cannot be mapped to user
    space, and whole pages would be shared with the host.

- **Global memory limit and observability:**

  - ``/sys/module/pisa/parameters/max_pages``: Global cap on PISA
    pages held by all allocators and the per-node reservoirs
    (defaults to 1/8th of physical RAM, at least 16 pages).
  - ``/sys/module/pisa/parameters/reservoir_max``: Per-NUMA-node reservoir
    target of pre-allocated PISA pages (defaults to 16 per memory node).
  - ``/sys/module/pisa/parameters/scrub_max``: Max idle PISA pages
    scrubbed per background pass (0 disables background scrubbing).
  - ``/sys/kernel/debug/pisa/allocs``: Debugfs summary of global, per-node,
    user-page, and per-allocator allocation, mapping, and fallback counters.

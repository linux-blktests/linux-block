// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES.
 */
#include <linux/dma-buf.h>
#include <linux/pci-p2pdma.h>
#include <linux/dma-resv.h>

#include "vfio_pci_priv.h"

MODULE_IMPORT_NS("DMA_BUF");

struct vfio_pci_dma_buf {
	struct dma_buf *dmabuf;
	struct vfio_pci_core_device *vdev;
	struct list_head dmabufs_elm;
	struct phys_vec phys_vec;
	u8 revoked : 1;
};

static int vfio_pci_dma_buf_attach(struct dma_buf *dmabuf,
				   struct dma_buf_attachment *attachment)
{
	struct vfio_pci_dma_buf *priv = dmabuf->priv;

	if (!attachment->peer2peer)
		return -EOPNOTSUPP;

	if (priv->revoked)
		return -ENODEV;

	switch (pci_p2pdma_map_type(priv->vdev->provider, attachment->dev)) {
	case PCI_P2PDMA_MAP_THRU_HOST_BRIDGE:
		break;
	case PCI_P2PDMA_MAP_BUS_ADDR:
		/*
		 * There is no need in IOVA at all for this flow.
		 * We rely on attachment->priv == NULL as a marker
		 * for this mode.
		 */
		return 0;
	default:
		return -EINVAL;
	}

	attachment->priv = kzalloc(sizeof(struct dma_iova_state), GFP_KERNEL);
	if (!attachment->priv)
		return -ENOMEM;

	dma_iova_try_alloc(attachment->dev, attachment->priv, 0, priv->phys_vec.len);
	return 0;
}

static void vfio_pci_dma_buf_detach(struct dma_buf *dmabuf,
				    struct dma_buf_attachment *attachment)
{
	kfree(attachment->priv);
}

static void fill_sg_entry(struct scatterlist *sgl, unsigned int length,
			 dma_addr_t addr)
{
	sg_set_page(sgl, NULL, length, 0);
	sg_dma_address(sgl) = addr;
	sg_dma_len(sgl) = length;
}

static struct sg_table *
vfio_pci_dma_buf_map(struct dma_buf_attachment *attachment,
		     enum dma_data_direction dir)
{
	struct vfio_pci_dma_buf *priv = attachment->dmabuf->priv;
	struct p2pdma_provider *provider = priv->vdev->provider;
	struct dma_iova_state *state = attachment->priv;
	struct phys_vec *phys_vec = &priv->phys_vec;
	struct scatterlist *sgl;
	struct sg_table *sgt;
	dma_addr_t addr;
	int ret;

	dma_resv_assert_held(priv->dmabuf->resv);

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	ret = sg_alloc_table(sgt, 1, GFP_KERNEL | __GFP_ZERO);
	if (ret)
		goto err_kfree_sgt;

	sgl = sgt->sgl;

	if (!state) {
		addr = pci_p2pdma_bus_addr_map(provider, phys_vec->paddr);
	} else if (dma_use_iova(state)) {
		ret = dma_iova_link(attachment->dev, state, phys_vec->paddr, 0,
				    phys_vec->len, dir, DMA_ATTR_SKIP_CPU_SYNC);
		if (ret)
			goto err_free_table;

		ret = dma_iova_sync(attachment->dev, state, 0, phys_vec->len);
		if (ret)
			goto err_unmap_dma;

		addr = state->addr;
	} else {
		addr = dma_map_phys(attachment->dev, phys_vec->paddr,
				    phys_vec->len, dir, DMA_ATTR_SKIP_CPU_SYNC);
		ret = dma_mapping_error(attachment->dev, addr);
		if (ret)
			goto err_free_table;
	}

	fill_sg_entry(sgl, phys_vec->len, addr);
	return sgt;

err_unmap_dma:
	dma_iova_destroy(attachment->dev, state, phys_vec->len, dir,
			 DMA_ATTR_SKIP_CPU_SYNC);
err_free_table:
	sg_free_table(sgt);
err_kfree_sgt:
	kfree(sgt);
	return ERR_PTR(ret);
}

static void vfio_pci_dma_buf_unmap(struct dma_buf_attachment *attachment,
				   struct sg_table *sgt,
				   enum dma_data_direction dir)
{
	struct vfio_pci_dma_buf *priv = attachment->dmabuf->priv;
	struct dma_iova_state *state = attachment->priv;
	struct scatterlist *sgl;
	int i;

	if (!state)
		; /* Do nothing */
	else if (dma_use_iova(state))
		dma_iova_destroy(attachment->dev, state, priv->phys_vec.len,
				 dir, DMA_ATTR_SKIP_CPU_SYNC);
	else
		for_each_sgtable_dma_sg(sgt, sgl, i)
			dma_unmap_phys(attachment->dev, sg_dma_address(sgl),
				       sg_dma_len(sgl), dir,
				       DMA_ATTR_SKIP_CPU_SYNC);

	sg_free_table(sgt);
	kfree(sgt);
}

static void vfio_pci_dma_buf_release(struct dma_buf *dmabuf)
{
	struct vfio_pci_dma_buf *priv = dmabuf->priv;

	/*
	 * Either this or vfio_pci_dma_buf_cleanup() will remove from the list.
	 * The refcount prevents both.
	 */
	if (priv->vdev) {
		down_write(&priv->vdev->memory_lock);
		list_del_init(&priv->dmabufs_elm);
		up_write(&priv->vdev->memory_lock);
		vfio_device_put_registration(&priv->vdev->vdev);
	}
	kfree(priv);
}

static const struct dma_buf_ops vfio_pci_dmabuf_ops = {
	.attach = vfio_pci_dma_buf_attach,
	.detach = vfio_pci_dma_buf_detach,
	.map_dma_buf = vfio_pci_dma_buf_map,
	.release = vfio_pci_dma_buf_release,
	.unmap_dma_buf = vfio_pci_dma_buf_unmap,
};

static void dma_ranges_to_p2p_phys(struct vfio_pci_dma_buf *priv,
				   struct vfio_device_feature_dma_buf *dma_buf)
{
	struct pci_dev *pdev = priv->vdev->pdev;

	priv->phys_vec.len = dma_buf->length;
	priv->phys_vec.paddr = pci_resource_start(pdev, dma_buf->region_index);
	priv->phys_vec.paddr += dma_buf->offset;
}

static int validate_dmabuf_input(struct vfio_pci_core_device *vdev,
				 struct vfio_device_feature_dma_buf *dma_buf)
{
	struct pci_dev *pdev = vdev->pdev;
	u32 bar = dma_buf->region_index;
	u64 offset = dma_buf->offset;
	u64 len = dma_buf->length;
	resource_size_t bar_size;
	u64 sum;

	/*
	 * For PCI the region_index is the BAR number like  everything else.
	 */
	if (bar >= VFIO_PCI_ROM_REGION_INDEX)
		return -ENODEV;

	if (!(pci_resource_flags(pdev, bar) & IORESOURCE_MEM))
		return -EINVAL;

	if (!PAGE_ALIGNED(offset) || !PAGE_ALIGNED(len))
		return -EINVAL;

	bar_size = pci_resource_len(pdev, bar);
	if (check_add_overflow(offset, len, &sum) || sum > bar_size)
		return -EINVAL;

	return 0;
}

int vfio_pci_core_feature_dma_buf(struct vfio_pci_core_device *vdev, u32 flags,
				  struct vfio_device_feature_dma_buf __user *arg,
				  size_t argsz)
{
	struct vfio_device_feature_dma_buf get_dma_buf = {};
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct vfio_pci_dma_buf *priv;
	int ret;

	ret = vfio_check_feature(flags, argsz, VFIO_DEVICE_FEATURE_GET,
				 sizeof(get_dma_buf));
	if (ret != 1)
		return ret;

	if (copy_from_user(&get_dma_buf, arg, sizeof(get_dma_buf)))
		return -EFAULT;

	ret = validate_dmabuf_input(vdev, &get_dma_buf);
	if (ret)
		return ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->vdev = vdev;
	dma_ranges_to_p2p_phys(priv, &get_dma_buf);

	if (!vfio_device_try_get_registration(&vdev->vdev)) {
		ret = -ENODEV;
		goto err_free_priv;
	}

	exp_info.ops = &vfio_pci_dmabuf_ops;
	exp_info.size = priv->phys_vec.len;
	exp_info.flags = get_dma_buf.open_flags;
	exp_info.priv = priv;

	priv->dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(priv->dmabuf)) {
		ret = PTR_ERR(priv->dmabuf);
		goto err_dev_put;
	}

	/* dma_buf_put() now frees priv */
	INIT_LIST_HEAD(&priv->dmabufs_elm);
	down_write(&vdev->memory_lock);
	dma_resv_lock(priv->dmabuf->resv, NULL);
	priv->revoked = !__vfio_pci_memory_enabled(vdev);
	list_add_tail(&priv->dmabufs_elm, &vdev->dmabufs);
	dma_resv_unlock(priv->dmabuf->resv);
	up_write(&vdev->memory_lock);

	/*
	 * dma_buf_fd() consumes the reference, when the file closes the dmabuf
	 * will be released.
	 */
	return dma_buf_fd(priv->dmabuf, get_dma_buf.open_flags);

err_dev_put:
	vfio_device_put_registration(&vdev->vdev);
err_free_priv:
	kfree(priv);
	return ret;
}

void vfio_pci_dma_buf_move(struct vfio_pci_core_device *vdev, bool revoked)
{
	struct vfio_pci_dma_buf *priv;
	struct vfio_pci_dma_buf *tmp;

	lockdep_assert_held_write(&vdev->memory_lock);

	list_for_each_entry_safe(priv, tmp, &vdev->dmabufs, dmabufs_elm) {
		if (!get_file_active(&priv->dmabuf->file))
			continue;

		if (priv->revoked != revoked) {
			dma_resv_lock(priv->dmabuf->resv, NULL);
			priv->revoked = revoked;
			dma_buf_move_notify(priv->dmabuf);
			dma_resv_unlock(priv->dmabuf->resv);
		}
		dma_buf_put(priv->dmabuf);
	}
}

void vfio_pci_dma_buf_cleanup(struct vfio_pci_core_device *vdev)
{
	struct vfio_pci_dma_buf *priv;
	struct vfio_pci_dma_buf *tmp;

	down_write(&vdev->memory_lock);
	list_for_each_entry_safe(priv, tmp, &vdev->dmabufs, dmabufs_elm) {
		if (!get_file_active(&priv->dmabuf->file))
			continue;

		dma_resv_lock(priv->dmabuf->resv, NULL);
		list_del_init(&priv->dmabufs_elm);
		priv->vdev = NULL;
		priv->revoked = true;
		dma_buf_move_notify(priv->dmabuf);
		dma_resv_unlock(priv->dmabuf->resv);
		vfio_device_put_registration(&vdev->vdev);
		dma_buf_put(priv->dmabuf);
	}
	up_write(&vdev->memory_lock);
}

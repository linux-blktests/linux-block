// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_DMA_BUF_H
#define IOU_DMA_BUF_H

#include <linux/dma-buf-io.h>
#include <linux/io_uring_types.h>

#include "rsrc.h"

static inline struct dma_buf_io_ctx *io_priv_to_dmabuf(void *data)
{
	return data;
}

static inline struct dma_buf_io_ctx *io_buf_to_dmabuf(struct io_mapped_ubuf *imu)
{
	return io_priv_to_dmabuf(imu->priv);
}

int __io_register_dmabuf(struct io_ring_ctx *ctx,
			struct io_uring_regbuf_desc *desc,
			struct io_mapped_ubuf *imu);

static inline void io_detach_dmabuf_map(struct io_kiocb *req)
{
	if (!IS_ENABLED(CONFIG_DMA_SHARED_BUFFER))
		return;
	if (!(req->flags & REQ_F_DMABUF) || !req->dmabuf_map)
		return;
	dma_buf_io_map_drop(req->dmabuf_map);
	req->dmabuf_map = NULL;
}

static inline int io_attach_dmabuf_map(struct io_kiocb *req,
					struct iov_iter *iter,
					unsigned issue_flags)
{
	bool nowait = issue_flags & IO_URING_F_NONBLOCK;
	struct io_mapped_ubuf *imu;
	struct dma_buf_io_map *map;

	if (!(req->flags & REQ_F_DMABUF))
		return 0;
	if (!IS_ENABLED(CONFIG_DMA_SHARED_BUFFER))
		return -EOPNOTSUPP;

	imu = req->buf_node->buf;
	map = dma_buf_io_get_map(io_buf_to_dmabuf(imu), nowait);
	if (unlikely(IS_ERR(map)))
		return PTR_ERR(map);
	req->dmabuf_map = map;
	iter->dmabuf_map = map;
	return 0;
}

static inline int io_import_dmabuf_map(struct io_kiocb *req,
				int ddir, struct iov_iter *iter,
				struct io_mapped_ubuf *imu,
				size_t len, size_t offset)
{
	if (!IS_ENABLED(CONFIG_DMA_SHARED_BUFFER))
		return -EOPNOTSUPP;
	if (unlikely(!dma_buf_io_file_compatible(io_buf_to_dmabuf(imu),
						 req->file)))
		return -EBADF;
	req->flags |= REQ_F_DMABUF;
	iov_iter_dmabuf_map(iter, ddir, NULL, offset, len);
	return 0;
}

static inline int io_register_dmabuf(struct io_ring_ctx *ctx,
			struct io_uring_regbuf_desc *desc,
			struct io_mapped_ubuf *imu)
{
	if (!IS_ENABLED(CONFIG_DMA_SHARED_BUFFER))
		return -EOPNOTSUPP;
	return __io_register_dmabuf(ctx, desc, imu);
}

#endif /* IOU_DMA_BUF_H */

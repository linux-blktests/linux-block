#include "dma-buf.h"

static inline void io_release_dmabuf(void *priv)
{
	dma_buf_io_ctx_release(io_priv_to_dmabuf(priv));
}

int __io_register_dmabuf(struct io_ring_ctx *ctx,
			struct io_uring_regbuf_desc *desc,
			struct io_mapped_ubuf *imu)
{
	struct dma_buf_io_ctx *dmabuf_ctx;
	struct file *target_file = NULL;
	struct dma_buf *dmabuf = NULL;
	int ret;

	/*
	 * We have to drop the dma-buf map early when IO is finished. Disable
	 * IOPOLL for now as we can't wait potentially infintely for a task
	 * to do that.
	 */
	if (ctx->flags & IORING_SETUP_IOPOLL)
		return -EOPNOTSUPP;
	if (desc->uaddr || desc->size)
		return -EINVAL;

	target_file = fget(desc->target_fd);
	if (!target_file) {
		ret = -EBADF;
		goto err;
	}
	dmabuf = dma_buf_get(desc->dmabuf_fd);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		dmabuf = NULL;
		goto err;
	}
	ret = io_validate_user_buf_range(0, dmabuf->size);
	if (ret)
		goto err;

	ret = dma_buf_io_ctx_create(target_file, dmabuf, DMA_BIDIRECTIONAL,
				    &dmabuf_ctx);
	if (ret)
		goto err;

	imu->len = dmabuf->size;
	imu->release = io_release_dmabuf;
	imu->priv = dmabuf_ctx;
	imu->flags = IO_REGBUF_F_DMABUF;
	imu->dir = IO_BUF_DEST | IO_BUF_SOURCE;
	dma_buf_put(dmabuf);
	fput(target_file);
	return 0;
err:
	if (target_file)
		fput(target_file);
	if (dmabuf)
		dma_buf_put(dmabuf);
	return ret;
}


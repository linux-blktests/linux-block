// SPDX-License-Identifier: GPL-2.0

#include "cancel.h"

#if defined(CONFIG_EPOLL)
int io_epoll_wait_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
			 unsigned int issue_flags);
bool io_epoll_wait_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			      bool cancel_all);

int io_epoll_ctl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_epoll_ctl(struct io_kiocb *req, unsigned int issue_flags);
int io_epoll_wait_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_epoll_wait(struct io_kiocb *req, unsigned int issue_flags);
#else
static inline bool io_epoll_wait_remove_all(struct io_ring_ctx *ctx,
					    struct io_uring_task *tctx,
					    bool cancel_all)
{
	return false;
}
static inline int io_epoll_wait_cancel(struct io_ring_ctx *ctx,
				       struct io_cancel_data *cd,
				       unsigned int issue_flags)
{
	return 0;
}
#endif

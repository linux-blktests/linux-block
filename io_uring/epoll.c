// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/io_uring.h>
#include <linux/eventpoll.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "epoll.h"
#include "poll.h"

struct io_epoll {
	struct file			*file;
	int				epfd;
	int				op;
	int				fd;
	struct epoll_event		event;
};

struct io_epoll_wait {
	struct file			*file;
	int				maxevents;
	struct epoll_event __user	*events;
	struct wait_queue_entry		wait;
};

int io_epoll_ctl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_epoll *epoll = io_kiocb_to_cmd(req, struct io_epoll);

	if (sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;

	epoll->epfd = READ_ONCE(sqe->fd);
	epoll->op = READ_ONCE(sqe->len);
	epoll->fd = READ_ONCE(sqe->off);

	if (ep_op_has_event(epoll->op)) {
		struct epoll_event __user *ev;

		ev = u64_to_user_ptr(READ_ONCE(sqe->addr));
		if (copy_from_user(&epoll->event, ev, sizeof(*ev)))
			return -EFAULT;
	}

	return 0;
}

int io_epoll_ctl(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_epoll *ie = io_kiocb_to_cmd(req, struct io_epoll);
	int ret;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;

	ret = do_epoll_ctl(ie->epfd, ie->op, ie->fd, &ie->event, force_nonblock);
	if (force_nonblock && ret == -EAGAIN)
		return -EAGAIN;

	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

static void __io_epoll_finish(struct io_kiocb *req, int res)
{
	struct io_epoll_wait *iew = io_kiocb_to_cmd(req, struct io_epoll_wait);

	lockdep_assert_held(&req->ctx->uring_lock);

	epoll_wait_remove(req->file, &iew->wait);
	hlist_del_init(&req->hash_node);
	io_req_set_res(req, res, 0);
	req->io_task_work.func = io_req_task_complete;
	io_req_task_work_add(req);
}

static void __io_epoll_cancel(struct io_kiocb *req)
{
	__io_epoll_finish(req, -ECANCELED);
}

static bool __io_epoll_wait_cancel(struct io_kiocb *req)
{
	io_poll_mark_cancelled(req);
	if (io_poll_get_ownership(req))
		__io_epoll_cancel(req);
	return true;
}

bool io_epoll_wait_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			      bool cancel_all)
{
	return io_cancel_remove_all(ctx, tctx, &ctx->epoll_list, cancel_all, __io_epoll_wait_cancel);
}

int io_epoll_wait_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
			 unsigned int issue_flags)
{
	return io_cancel_remove(ctx, cd, issue_flags, &ctx->epoll_list, __io_epoll_wait_cancel);
}

static void io_epoll_retry(struct io_kiocb *req, struct io_tw_state *ts)
{
	int v;

	do {
		v = atomic_read(&req->poll_refs);
		if (unlikely(v != 1)) {
			if (WARN_ON_ONCE(!(v & IO_POLL_REF_MASK)))
				return;
			if (v & IO_POLL_CANCEL_FLAG) {
				__io_epoll_cancel(req);
				return;
			}
			if (v & IO_POLL_FINISH_FLAG)
				return;
		}
		v &= IO_POLL_REF_MASK;
	} while (atomic_sub_return(v, &req->poll_refs) & IO_POLL_REF_MASK);

	io_req_task_submit(req, ts);
}

static int io_epoll_execute(struct io_kiocb *req)
{
	struct io_epoll_wait *iew = io_kiocb_to_cmd(req, struct io_epoll_wait);

	list_del_init_careful(&iew->wait.entry);
	if (io_poll_get_ownership(req)) {
		req->io_task_work.func = io_epoll_retry;
		io_req_task_work_add(req);
	}

	return 1;
}

static __cold int io_epoll_pollfree_wake(struct io_kiocb *req)
{
	struct io_epoll_wait *iew = io_kiocb_to_cmd(req, struct io_epoll_wait);

	io_poll_mark_cancelled(req);
	list_del_init_careful(&iew->wait.entry);
	io_epoll_execute(req);
	return 1;
}

static int io_epoll_wait_fn(struct wait_queue_entry *wait, unsigned mode,
			    int sync, void *key)
{
	struct io_kiocb *req = wait->private;
	__poll_t mask = key_to_poll(key);

	if (unlikely(mask & POLLFREE))
		return io_epoll_pollfree_wake(req);

	return io_epoll_execute(req);
}

int io_epoll_wait_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_epoll_wait *iew = io_kiocb_to_cmd(req, struct io_epoll_wait);

	if (sqe->off || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	iew->maxevents = READ_ONCE(sqe->len);
	iew->events = u64_to_user_ptr(READ_ONCE(sqe->addr));
	if (req->flags & REQ_F_BUFFER_SELECT && iew->events)
		return -EINVAL;

	iew->wait.flags = 0;
	iew->wait.private = req;
	iew->wait.func = io_epoll_wait_fn;
	INIT_LIST_HEAD(&iew->wait.entry);
	INIT_HLIST_NODE(&req->hash_node);
	atomic_set(&req->poll_refs, 0);
	return 0;
}

int io_epoll_wait(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_epoll_wait *iew = io_kiocb_to_cmd(req, struct io_epoll_wait);
	struct epoll_event __user *evs = iew->events;
	struct io_ring_ctx *ctx = req->ctx;
	int maxevents = iew->maxevents;
	unsigned int cflags = 0;
	int ret;

	io_ring_submit_lock(ctx, issue_flags);

	if (io_do_buffer_select(req)) {
		size_t len = maxevents * sizeof(*evs);

		ret = -ENOBUFS;
		evs = io_buffer_select(req, &len, 0);
		if (unlikely(!evs))
			goto err;
		maxevents = len / sizeof(*evs);
	}

	ret = epoll_queue(req->file, evs, maxevents, &iew->wait, false);
	if (ret == -EIOCBQUEUED) {
		io_kbuf_recycle(req, 0);
		if (hlist_unhashed(&req->hash_node))
			hlist_add_head(&req->hash_node, &ctx->epoll_list);
		io_ring_submit_unlock(ctx, issue_flags);
		return IOU_ISSUE_SKIP_COMPLETE;
	} else if (ret > 0) {
		cflags = io_put_kbuf(req, ret * sizeof(*evs), 0);
	} else if (!ret) {
		io_kbuf_recycle(req, 0);
	} else {
err:
		req_set_fail(req);
	}
	hlist_del_init(&req->hash_node);
	io_ring_submit_unlock(ctx, issue_flags);
	io_req_set_res(req, ret, cflags);
	return IOU_OK;
}

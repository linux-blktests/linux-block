// SPDX-License-Identifier: GPL-2.0

#define IO_POLL_ALLOC_CACHE_MAX 32

enum {
	IO_APOLL_OK,
	IO_APOLL_ABORTED,
	IO_APOLL_READY
};

struct io_poll {
	struct file			*file;
	struct wait_queue_head		*head;
	__poll_t			events;
	int				retries;
	struct wait_queue_entry		wait;
};

struct async_poll {
	struct io_poll		poll;
	struct io_poll		*double_poll;
};

#define IO_POLL_CANCEL_FLAG	BIT(31)
#define IO_POLL_RETRY_FLAG	BIT(30)
#define IO_POLL_REF_MASK	GENMASK(29, 0)

bool io_poll_get_ownership_slowpath(struct io_kiocb *req);

/*
 * We usually have 1-2 refs taken, 128 is more than enough and we want to
 * maximise the margin between this amount and the moment when it overflows.
 */
#define IO_POLL_REF_BIAS	128

/*
 * Must only be called inside issue_flags & IO_URING_F_MULTISHOT, or
 * potentially other cases where we already "own" this poll request.
 */
static inline void io_poll_multishot_retry(struct io_kiocb *req)
{
	atomic_inc(&req->poll_refs);
}

/*
 * If refs part of ->poll_refs (see IO_POLL_REF_MASK) is 0, it's free. We can
 * bump it and acquire ownership. It's disallowed to modify requests while not
 * owning it, that prevents from races for enqueueing task_work's and b/w
 * arming poll and wakeups.
 */
static inline bool io_poll_get_ownership(struct io_kiocb *req)
{
	if (unlikely(atomic_read(&req->poll_refs) >= IO_POLL_REF_BIAS))
		return io_poll_get_ownership_slowpath(req);
	return !(atomic_fetch_inc(&req->poll_refs) & IO_POLL_REF_MASK);
}

static inline void io_poll_mark_cancelled(struct io_kiocb *req)
{
	atomic_or(IO_POLL_CANCEL_FLAG, &req->poll_refs);
}


int io_poll_add_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_poll_add(struct io_kiocb *req, unsigned int issue_flags);

int io_poll_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_poll_remove(struct io_kiocb *req, unsigned int issue_flags);

struct io_cancel_data;
int io_poll_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		   unsigned issue_flags);
int io_arm_poll_handler(struct io_kiocb *req, unsigned issue_flags);
bool io_poll_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			bool cancel_all);

void io_poll_task_func(struct io_kiocb *req, struct io_tw_state *ts);

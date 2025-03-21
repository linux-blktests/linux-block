#ifndef IOU_REQ_REF_H
#define IOU_REQ_REF_H

#include <linux/atomic.h>
#include <linux/io_uring_types.h>

/*
 * Shamelessly stolen from the mm implementation of page reference checking,
 * see commit f958d7b528b1 for details.
 */
#define req_ref_zero_or_close_to_overflow(req)	\
	((unsigned int) atomic_read(&(req->refs)) + 127u <= 127u)

static inline bool req_ref_inc_not_zero(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	return atomic_inc_not_zero(&req->refs);
}

static inline bool req_ref_put_and_test_atomic(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(data_race(req->flags) & REQ_F_REFCOUNT));
	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	return atomic_dec_and_test(&req->refs);
}

static inline bool req_ref_put_and_test(struct io_kiocb *req)
{
	if (likely(!(req->flags & REQ_F_REFCOUNT)))
		return true;

	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	return atomic_dec_and_test(&req->refs);
}

static inline void req_ref_get(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	atomic_inc(&req->refs);
}

static inline void req_ref_put(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	atomic_dec(&req->refs);
}

static inline void __io_req_set_refcount(struct io_kiocb *req, int nr)
{
	if (!(req->flags & REQ_F_REFCOUNT)) {
		req->flags |= REQ_F_REFCOUNT;
		atomic_set(&req->refs, nr);
	}
}

static inline void io_req_set_refcount(struct io_kiocb *req)
{
	__io_req_set_refcount(req, 1);
}

#define IO_RING_REF_DEAD	(1UL << (BITS_PER_LONG - 1))
#define IO_RING_REF_MASK	(~IO_RING_REF_DEAD)

static inline bool io_ring_ref_is_dying(struct io_ring_ctx *ctx)
{
	return atomic_long_read(&ctx->refs) & IO_RING_REF_DEAD;
}

static inline void io_ring_ref_put_many(struct io_ring_ctx *ctx, int nr_refs)
{
	unsigned long refs;

	refs = atomic_long_sub_return(nr_refs, &ctx->refs);
	if (!(refs & IO_RING_REF_MASK))
		complete(&ctx->ref_comp);
}

static inline void io_ring_ref_put(struct io_ring_ctx *ctx)
{
	io_ring_ref_put_many(ctx, 1);
}

static inline void io_ring_ref_kill(struct io_ring_ctx *ctx)
{
	atomic_long_xor(IO_RING_REF_DEAD, &ctx->refs);
	io_ring_ref_put(ctx);
}

static inline void io_ring_ref_init(struct io_ring_ctx *ctx)
{
	atomic_long_set(&ctx->refs, 1);
}

static inline void io_ring_ref_get_many(struct io_ring_ctx *ctx, int nr_refs)
{
	atomic_long_add(nr_refs, &ctx->refs);
}

static inline void io_ring_ref_get(struct io_ring_ctx *ctx)
{
	atomic_long_inc(&ctx->refs);
}
#endif

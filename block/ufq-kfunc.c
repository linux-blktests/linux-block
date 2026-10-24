// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 */
#include <linux/init.h>
#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <trace/events/block.h>
#include "blk.h"
#include "ufq-iosched.h"

__bpf_kfunc_start_defs();

__bpf_kfunc struct request *bpf_request_acquire(struct request *rq)
{
	if (req_ref_inc_not_zero(rq))
		return rq;
	return NULL;
}

__bpf_kfunc void bpf_request_release(struct request *rq)
{
	if (req_ref_put_and_test(rq))
		__blk_mq_free_request(rq);
}

__bpf_kfunc bool bpf_request_bio_try_merge(struct request *rq, struct bio *bio,
					   unsigned int nr_segs)
{
	struct request_queue *q;
	struct blk_mq_ctx *ctx;
	bool merged = false;

	if (!rq || !bio || !rq->q)
		return false;

	q = rq->q;
	if (blk_queue_enter(q, BLK_MQ_REQ_NOWAIT))
		return false;
	ctx = rq->mq_ctx;
	if (!ufq_is_queue(q) || !ctx || !bio->bi_bdev ||
	    !bio->bi_bdev->bd_disk || bio->bi_bdev->bd_disk->queue != q)
		goto out;

	/*
	 * KF_SPINLOCK_SAFE callers (BPF merge_bio) often already hold a scheduler
	 * lock taken with irqsave (e.g. PFQ dd->lock).  Blocking on ctx->lock
	 * nesting that order deadlocks / hard-locks under load.  Trylock: skip
	 * the merge if ctx is busy; bio will be issued as a new request.
	 */
	if (!spin_trylock(&ctx->lock))
		goto out;

	merged = blk_attempt_bio_merge(q, rq, bio, nr_segs, true) == BIO_MERGE_OK;
	spin_unlock(&ctx->lock);
out:
	blk_queue_exit(q);
	return merged;
}

__bpf_kfunc struct request *bpf_request_try_merge(struct request *rq, struct request *next)
{
	struct request_queue *q;
	struct blk_mq_ctx *ctx;
	struct ufq_data *ufq;
	struct request *free = NULL;

	if (!rq || !next || !rq->q || rq->q != next->q)
		return NULL;

	q = rq->q;
	if (blk_queue_enter(q, BLK_MQ_REQ_NOWAIT))
		return NULL;
	if (!ufq_is_queue(q))
		goto out;

	ufq = q->elevator->elevator_data;
	if (rq->mq_ctx != next->mq_ctx || rq->mq_hctx != next->mq_hctx)
		goto out;

	ctx = rq->mq_ctx;
	if (!ctx)
		goto out;

	/* Same nesting rule as bpf_request_bio_try_merge (see comment there). */
	if (!spin_trylock(&ctx->lock))
		goto out;

	free = bpf_attempt_merge(q, rq, next);
	if (free) {
		if (q->last_merge == free)
			q->last_merge = NULL;
		list_del_init(&free->queuelist);
		atomic_dec(&ufq->rqs_count);
	}
	spin_unlock(&ctx->lock);
out:
	blk_queue_exit(q);
	return free;
}

/*
 * Elevator private slot write for UFQ BPF.
 *
 * BPF cannot STX into request->elv.priv[] (verifier: "only read is supported"
 * without btf_struct_access).  Reads are fine from BPF; only the store needs
 * this KF_SPINLOCK_SAFE kfunc (same pattern as bpf_request_try_merge).
 *
 * @val is a raw address / tagged qid scalar from BPF (not an owning ref).
 */
__bpf_kfunc void bpf_request_set_elv_priv1(struct request *rq, u64 val)
{
	if (!rq)
		return;
	rq->elv.priv[1] = (void *)(uintptr_t)val;
}

__bpf_kfunc_end_defs();

#if defined(CONFIG_X86_KERNEL_IBT)
static const void * const __used __section(".discard.ibt_endbr_noseal")
__ibt_noseal_bpf_request_release = (void *)bpf_request_release;
#endif

BTF_KFUNCS_START(ufq_kfunc_set_ops)
BTF_ID_FLAGS(func, bpf_request_acquire, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_request_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_request_bio_try_merge, KF_SPINLOCK_SAFE)
BTF_ID_FLAGS(func, bpf_request_try_merge, KF_SPINLOCK_SAFE)
BTF_ID_FLAGS(func, bpf_request_set_elv_priv1, KF_SPINLOCK_SAFE)
BTF_KFUNCS_END(ufq_kfunc_set_ops)

static const struct btf_kfunc_id_set bpf_ufq_kfunc_set = {
	.owner			= THIS_MODULE,
	.set			= &ufq_kfunc_set_ops,
};

BTF_ID_LIST(bpf_ufq_dtor_kfunc_ids)
BTF_ID(struct, request)
BTF_ID(func, bpf_request_release)

int bpf_ufq_kfunc_init(void)
{
	int ret;
	const struct btf_id_dtor_kfunc bpf_ufq_dtor_kfunc[] = {
		{
		  .btf_id       = bpf_ufq_dtor_kfunc_ids[0],
		  .kfunc_btf_id = bpf_ufq_dtor_kfunc_ids[1]
		},
	};

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &bpf_ufq_kfunc_set);
	if (ret)
		return ret;
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_ufq_kfunc_set);
	if (ret)
		return ret;
	ret = register_btf_id_dtor_kfuncs(bpf_ufq_dtor_kfunc,
					  ARRAY_SIZE(bpf_ufq_dtor_kfunc),
					  THIS_MODULE);
	if (ret)
		return ret;

	return 0;
}

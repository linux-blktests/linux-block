// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/sbitmap.h>
#include <linux/workqueue.h>

#include <trace/events/block.h>

#include "elevator.h"
#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"
#include "blk-mq-debugfs.h"
#include "ufq-iosched.h"

static DEFINE_MUTEX(ufq_active_queues_lock);
static LIST_HEAD(ufq_active_queues);

enum ufq_priv_state {
	UFQ_PRIV_NOT_IN_SCHED = 0,
	UFQ_PRIV_IN_BPF = 1,
	UFQ_PRIV_IN_UFQ = 2,
	UFQ_PRIV_IN_SCHED = 3,
};

/* has_work can run from completion softirq, so all users need irq-safe locking. */
static inline bool ufq_insert_err_pending(struct ufq_data *ufq)
{
	unsigned long flags;
	bool pending;

	spin_lock_irqsave(&ufq->insert_err_lock, flags);
	pending = !list_empty(&ufq->insert_err_list);
	spin_unlock_irqrestore(&ufq->insert_err_lock, flags);
	return pending;
}

/*
 * Move @rq off ctx->rq_lists onto ufq->insert_err_list after BPF insert_req
 * failed.  Keeps BPF-owned (still on ctx) rqs unreachable to err drain.
 */
static bool ufq_move_to_insert_err(struct ufq_data *ufq, struct request *rq)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;
	enum hctx_type type = hctx->type;
	unsigned long flags;
	int bit;

	spin_lock(&ctx->lock);
	if (!((uintptr_t)rq->elv.priv[0] & UFQ_PRIV_IN_BPF) ||
	    rq->rq_flags & RQF_STARTED || list_empty(&rq->queuelist)) {
		spin_unlock(&ctx->lock);
		return false;
	}
	list_del_init(&rq->queuelist);
	bit = ctx->index_hw[type];
	if (list_empty(&ctx->rq_lists[type]))
		sbitmap_clear_bit(&hctx->ctx_map, bit);
	if (hctx->queue->last_merge == rq)
		hctx->queue->last_merge = NULL;
	rq->elv.priv[0] = (void *)((uintptr_t)rq->elv.priv[0]
				  & ~UFQ_PRIV_IN_BPF);
	spin_unlock(&ctx->lock);

	spin_lock_irqsave(&ufq->insert_err_lock, flags);
	list_add_tail(&rq->queuelist, &ufq->insert_err_list);
	spin_unlock_irqrestore(&ufq->insert_err_lock, flags);
	return true;
}

/* A BPF policy may accidentally pop a request belonging to another queue. */
static void ufq_recover_bad_dispatch(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct ufq_data *owner;

	if (!q || !rq->mq_ctx || !rq->mq_hctx ||
	    blk_queue_enter(q, BLK_MQ_REQ_NOWAIT))
		return;
	if (ufq_is_queue(q)) {
		owner = q->elevator->elevator_data;
		if (ufq_move_to_insert_err(owner, rq))
			blk_mq_run_hw_queues(q, true);
	}
	blk_queue_exit(q);
}

/* Pop one insert-fail rq; sets RQF_STARTED like blk_mq_dequeue_from_ctx. */
static struct request *ufq_dispatch_insert_err(struct ufq_data *ufq)
{
	struct request *rq;
	unsigned long flags;

	spin_lock_irqsave(&ufq->insert_err_lock, flags);
	rq = list_first_entry_or_null(&ufq->insert_err_list, struct request,
				      queuelist);
	if (rq) {
		list_del_init(&rq->queuelist);
		rq->rq_flags |= RQF_STARTED;
		if (ufq->q->last_merge == rq)
			ufq->q->last_merge = NULL;
	}
	spin_unlock_irqrestore(&ufq->insert_err_lock, flags);

	if (rq)
		atomic_inc(&ufq->insert_err_handled);
	return rq;
}

static struct request *ufq_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct ufq_data *ufq = hctx->queue->elevator->elevator_data;
	const struct ufq_iosched_ops *ops;
	struct blk_mq_ctx *ctx;
	struct request *rq = NULL;
	unsigned short idx;

	/* Failed inserts are no longer on ctx lists, even after BPF detach. */
	rq = ufq_dispatch_insert_err(ufq);
	if (rq) {
		atomic_dec(&ufq->rqs_count);
		return rq;
	}

	ops = ufq_bpfops_tryget();
	if (ops && ops->dispatch_req) {
		rq = ops->dispatch_req(hctx->queue);
		if (!rq) {
			ufq_bpfops_put();
			atomic_inc(&ufq->ops_stats.dispatch_null_count);
			return NULL;
		}

		if (unlikely(rq->q != hctx->queue || !rq->mq_ctx ||
			     !rq->mq_hctx)) {
			atomic_inc(&ufq->ops_stats.dispatch_bad_state_count);
			ufq_recover_bad_dispatch(rq);
			if (WARN_ON_ONCE(req_ref_put_and_test(rq)))
				__blk_mq_free_request(rq);
			ufq_bpfops_put();
			return NULL;
		}

		/*
		 * The BPF insert_req callback bumps the request's reference
		 * count; dispatch_req returns that same request with an extra
		 * reference held. The kernel must put that reference here,
		 * and the request's refcount is always greater than zero at
		 * this point.
		 */
		if (WARN_ON_ONCE(req_ref_put_and_test(rq))) {
			__blk_mq_free_request(rq);
			ufq_bpfops_put();
			return NULL;
		}

		ctx = rq->mq_ctx;
		spin_lock(&ctx->lock);
		if (unlikely(blk_mq_rq_state(rq) != MQ_RQ_IDLE ||
			     (rq->rq_flags & RQF_STARTED) ||
			     list_empty(&rq->queuelist))) {
			atomic_inc(&ufq->ops_stats.dispatch_bad_state_count);
			spin_unlock(&ctx->lock);
			ufq_bpfops_put();
			return NULL;
		}
		list_del_init(&rq->queuelist);
		rq->rq_flags |= RQF_STARTED;
		if (hctx->queue->last_merge == rq)
			hctx->queue->last_merge = NULL;
		if (list_empty(&ctx->rq_lists[rq->mq_hctx->type]))
			sbitmap_clear_bit(&rq->mq_hctx->ctx_map,
					  ctx->index_hw[rq->mq_hctx->type]);
		spin_unlock(&ctx->lock);
		atomic_inc(&ufq->ops_stats.dispatch_ok_count);
		atomic64_add(blk_rq_sectors(rq), &ufq->ops_stats.dispatch_ok_sectors);
		rq->elv.priv[0] = (void *)((uintptr_t)rq->elv.priv[0]
				  & ~UFQ_PRIV_IN_UFQ);
		ufq_bpfops_put();
	} else {
		if (ops)
			ufq_bpfops_put();
		/* Do not dispatch an in-progress BPF insertion via the fallback. */
		if (!ops && ufq_bpfops_draining())
			return NULL;
		ctx = READ_ONCE(hctx->dispatch_from);
		rq = blk_mq_dequeue_from_ctx(hctx, ctx);
		if (rq) {
			idx = rq->mq_ctx->index_hw[hctx->type];
			if (++idx == hctx->nr_ctx)
				idx = 0;
			WRITE_ONCE(hctx->dispatch_from, hctx->ctxs[idx]);
		}
	}

	if (rq)
		atomic_dec(&ufq->rqs_count);
	return rq;
}

/*
 * Called by __blk_mq_alloc_request(). The shallow_depth value set by this
 * function is used by __blk_mq_get_tag().
 */
static void ufq_limit_depth(blk_opf_t opf, struct blk_mq_alloc_data *data)
{
	struct ufq_data *ufq = data->q->elevator->elevator_data;

	/* Do not throttle synchronous reads. */
	if (op_is_sync(opf) && !op_is_write(opf))
		return;

	/*
	 * Throttle asynchronous requests and writes such that these requests
	 * do not block the allocation of synchronous requests.
	 */
	data->shallow_depth = ufq->async_depth;
}

static void ufq_depth_updated(struct request_queue *q)
{
	struct ufq_data *ufq = q->elevator->elevator_data;

	ufq->async_depth = q->nr_requests;
	q->async_depth = q->nr_requests;
	blk_mq_set_min_shallow_depth(q, 1);
}

static int ufq_init_sched(struct request_queue *q, struct elevator_queue *eq)
{
	const struct ufq_iosched_ops *ops;
	struct ufq_data *ufq;

	ufq = kzalloc_node(sizeof(*ufq), GFP_KERNEL, q->node);
	if (!ufq)
		return -ENOMEM;

	eq->elevator_data = ufq;
	ufq->q = q;
	INIT_LIST_HEAD(&ufq->active_node);
	INIT_LIST_HEAD(&ufq->insert_err_list);
	spin_lock_init(&ufq->insert_err_lock);

	blk_queue_flag_set(QUEUE_FLAG_SQ_SCHED, q);
	q->elevator = eq;

	q->async_depth = q->nr_requests;
	ufq->async_depth = q->nr_requests;

	ops = ufq_bpfops_tryget();
	if (ops) {
		if (ops->init_sched)
			ops->init_sched(q);
		ufq_bpfops_put();
	}

	mutex_lock(&ufq_active_queues_lock);
	list_add_tail(&ufq->active_node, &ufq_active_queues);
	mutex_unlock(&ufq_active_queues_lock);

	ufq_depth_updated(q);
	return 0;
}

static void ufq_exit_sched(struct elevator_queue *e)
{
	const struct ufq_iosched_ops *ops;
	struct ufq_data *ufq = e->elevator_data;

	ops = ufq_bpfops_tryget();
	if (ops) {
		if (ops->exit_sched)
			ops->exit_sched(ufq->q);
		ufq_bpfops_put();
	}

	mutex_lock(&ufq_active_queues_lock);
	if (!list_empty(&ufq->active_node))
		list_del_init(&ufq->active_node);
	mutex_unlock(&ufq_active_queues_lock);

	WARN_ON_ONCE(atomic_read(&ufq->rqs_count));
	WARN_ON_ONCE(!list_empty(&ufq->insert_err_list));

	kfree(ufq);
	e->elevator_data = NULL;
}

void ufq_kick_all_hw_queues(void)
{
	struct ufq_data *ufq;

	mutex_lock(&ufq_active_queues_lock);
	list_for_each_entry(ufq, &ufq_active_queues, active_node)
		blk_mq_run_hw_queues(ufq->q, true);
	mutex_unlock(&ufq_active_queues_lock);
}

static int ufq_drain_ctx_rqs(struct ufq_data *ufq)
{
	struct request_queue *q = ufq->q;
	unsigned long deadline = jiffies + 8 * HZ;

	while (atomic_read(&ufq->rqs_count) > 0 && time_before(jiffies, deadline)) {
		blk_mq_run_hw_queues(q, false);
		if (atomic_read(&ufq->rqs_count) > 0) {
			struct blk_mq_hw_ctx *hctx;
			unsigned long i;

			queue_for_each_hw_ctx(q, hctx, i)
				flush_delayed_work(&hctx->run_work);
			flush_delayed_work(&q->requeue_work);
		}
		cond_resched();
	}

	if (atomic_read(&ufq->rqs_count) > 0) {
		pr_warn_ratelimited("ufq: drain timeout (%d rqs) before BPF attach\n",
				    atomic_read(&ufq->rqs_count));
		return -EBUSY;
	}
	return 0;
}

/*
 * Mirror elevator_change(): freeze each queue, cancel mq dispatch work,
 * then drain software-ctx requests while BPF callbacks are still off.
 * @enable runs with all those queues still frozen so new ctx backlog cannot
 * race ahead of turning BPF dispatch on.
 */
int ufq_prepare_bpf_attach(int (*enable)(void *kdata), void *kdata)
{
	struct ufq_data *ufq;
	unsigned int memflags;
	int frozen = 0, ret = 0;

	mutex_lock(&ufq_active_queues_lock);
	if (list_empty(&ufq_active_queues)) {
		mutex_unlock(&ufq_active_queues_lock);
		return enable(kdata);
	}

	memflags = memalloc_noio_save();
	list_for_each_entry(ufq, &ufq_active_queues, active_node) {
		/* Count the freeze before waiting so a timeout unwinds it too. */
		blk_freeze_queue_start(ufq->q);
		frozen++;
		if (!blk_mq_freeze_queue_wait_timeout(ufq->q, 8 * HZ)) {
			pr_warn_ratelimited("ufq: freeze timeout (%d queued rqs) before BPF attach\n",
					    atomic_read(&ufq->rqs_count));
			ret = -EBUSY;
			goto unfreeze;
		}
		blk_mq_cancel_work_sync(ufq->q);
		ret = ufq_drain_ctx_rqs(ufq);
		if (ret)
			goto unfreeze;
	}

	ret = enable(kdata);
unfreeze:
	list_for_each_entry(ufq, &ufq_active_queues, active_node) {
		if (!frozen--)
			break;
		blk_mq_unfreeze_queue_nomemrestore(ufq->q);
	}
	memalloc_noio_restore(memflags);
	mutex_unlock(&ufq_active_queues_lock);
	return ret;
}

static bool ufq_bio_merge(struct request_queue *q, struct bio *bio,
			  unsigned int nr_segs)
{
	struct ufq_data *ufq = q->elevator->elevator_data;
	const struct ufq_iosched_ops *ops;
	struct request *rq = NULL, *last;
	enum bio_merge_status mstat;
	struct blk_mq_ctx *ctx;
	bool ret = false;

	/*
	 * Levels of merges:
	 *	nomerges:  No merges at all attempted
	 *	noxmerges: Only simple one-hit cache try
	 *	merges:    All merge tries attempted
	 */
	if (blk_queue_nomerges(q) || !bio_mergeable(bio))
		return false;

	last = q->last_merge;
	if (last) {
		ctx = last->mq_ctx;
		spin_lock(&ctx->lock);
		if (last == q->last_merge && !list_empty(&last->queuelist)
		    && elv_bio_merge_ok(last, bio)) {
			mstat = blk_attempt_bio_merge(q, last, bio, nr_segs, true);
			if (mstat == BIO_MERGE_OK) {
				spin_unlock(&ctx->lock);
				atomic_inc(&ufq->ops_stats.merge_bio_ok_count);
				atomic64_add(bio->bi_iter.bi_size >> SECTOR_SHIFT,
					     &ufq->ops_stats.merge_bio_ok_sectors);
				return true;
			}
			if (mstat == BIO_MERGE_FAILED) {
				spin_unlock(&ctx->lock);
				return false;
			}
		}
		spin_unlock(&ctx->lock);
	}

	if (blk_queue_noxmerges(q))
		return false;

	ops = ufq_bpfops_tryget();
	if (ops) {
		if (ops->merge_bio) {
			rq = ops->merge_bio(q, bio, nr_segs, &ret);
			if (ret) {
				atomic_inc(&ufq->ops_stats.merge_bio_ok_count);
				atomic64_add(bio->bi_iter.bi_size >> SECTOR_SHIFT,
					     &ufq->ops_stats.merge_bio_ok_sectors);
			} else {
				ufq_bpfops_put();
				return false;
			}

			if (rq) {
				spin_lock(&rq->mq_ctx->lock);
				if (!list_empty(&rq->queuelist)) {
					list_del_init(&rq->queuelist);
					atomic_dec(&ufq->rqs_count);
				}
				spin_unlock(&rq->mq_ctx->lock);
				/* merge_bio transfers an extra BPF-owned reference. */
				WARN_ON_ONCE(req_ref_put_and_test(rq));
				blk_mq_free_request(rq);
				ufq_bpfops_put();
				atomic_inc(&ufq->ops_stats.merge_request_ok_count);
				atomic64_add(bio->bi_iter.bi_size >> SECTOR_SHIFT,
					     &ufq->ops_stats.merge_request_ok_sectors);
				return ret;
			}
		}
		ufq_bpfops_put();
	}

	return ret;
}

static enum elv_merge ufq_try_insert_merge(struct request_queue *q,
					   struct request **new)
{
	const struct ufq_iosched_ops *ops;
	struct request *target = NULL, *free = NULL, *last, *rq = *new;
	struct ufq_data *ufq = q->elevator->elevator_data;
	enum elv_merge type = ELEVATOR_NO_MERGE;
	int merge_type = ELEVATOR_NO_MERGE;

	if (!rq_mergeable(rq))
		return ELEVATOR_NO_MERGE;

	if (blk_queue_nomerges(q))
		return ELEVATOR_NO_MERGE;

	last = q->last_merge;
	if (last) {
		spin_lock(&last->mq_ctx->lock);
		if (last == q->last_merge && !list_empty(&last->queuelist)
		    && bpf_attempt_merge(q, last, rq)) {
			spin_unlock(&last->mq_ctx->lock);
			type = ELEVATOR_BACK_MERGE;
			free = rq;
			*new = NULL;
			goto end;
		}
		spin_unlock(&last->mq_ctx->lock);
	}

	if (blk_queue_noxmerges(q))
		return ELEVATOR_NO_MERGE;

	ops = ufq_bpfops_tryget();
	if (ops && ops->merge_req) {
		target = ops->merge_req(q, rq, &merge_type);
		type = (enum elv_merge)merge_type;
	}

	if (target && WARN_ON_ONCE(req_ref_put_and_test(target))) {
		__blk_mq_free_request(target);
		ufq_bpfops_put();
		return ELEVATOR_NO_MERGE;
	}

	if (type == ELEVATOR_NO_MERGE || !target) {
		if (ops)
			ufq_bpfops_put();
		return ELEVATOR_NO_MERGE;
	} else if (type == ELEVATOR_FRONT_MERGE) {
		if (rq->mq_ctx != target->mq_ctx || rq->mq_hctx != target->mq_hctx)
			goto rollback;
		spin_lock(&target->mq_ctx->lock);
		free = bpf_attempt_merge(q, rq, target);
		if (!free) {
			spin_unlock(&target->mq_ctx->lock);
			goto rollback;
		}
		rq->elv.priv[0] = (void *)((uintptr_t)rq->elv.priv[0]
				  | UFQ_PRIV_IN_UFQ);
		list_replace_init(&target->queuelist, &rq->queuelist);
		rq->fifo_time = target->fifo_time;
		q->last_merge = rq;
	} else if (type == ELEVATOR_BACK_MERGE) {
		spin_lock(&target->mq_ctx->lock);
		free = bpf_attempt_merge(q, target, rq);
		if (!free) {
			spin_unlock(&target->mq_ctx->lock);
			goto rollback;
		}
		*new = target;
		q->last_merge = target;
	}

	spin_unlock(&target->mq_ctx->lock);
	if (ops)
		ufq_bpfops_put();
end:
	atomic_inc(&ufq->ops_stats.merge_request_ok_count);
	atomic64_add(blk_rq_sectors(free), &ufq->ops_stats.merge_request_ok_sectors);
	blk_mq_free_request(free);
	return type;

rollback:
	if (ops) {
		if (ops->insert_req && ops->insert_req(q, target, 0)) {
			pr_err("ufq-iosched: rollback insert_req error\n");
			if (ufq_move_to_insert_err(ufq, target))
				atomic_inc(&ufq->ops_stats.insert_err_count);
		}
		ufq_bpfops_put();
	}

	return ELEVATOR_NO_MERGE;
}

static void ufq_insert_requests(struct blk_mq_hw_ctx *hctx,
			       struct list_head *list,
			       blk_insert_t flags)
{
	struct request_queue *q = hctx->queue;
	struct ufq_data *ufq = q->elevator->elevator_data;
	const struct ufq_iosched_ops *ops;
	struct blk_mq_ctx *ctx;
	enum elv_merge type;
	int bit, ret = 0;

	ops = ufq_bpfops_tryget();

	while (!list_empty(list)) {
		struct request *rq;

		rq = list_first_entry(list, struct request, queuelist);
		list_del_init(&rq->queuelist);

		type = ufq_try_insert_merge(q, &rq);
		/* Hold rq across publication and any concurrent dispatch. */
		if (rq && WARN_ON_ONCE(!req_ref_inc_not_zero(rq)))
			continue;
		if (type == ELEVATOR_NO_MERGE) {
			rq->fifo_time = jiffies;
			ctx = rq->mq_ctx;
			rq->elv.priv[0] = (void *)((uintptr_t)rq->elv.priv[0]
					  | UFQ_PRIV_IN_UFQ);
			spin_lock(&ctx->lock);
			if (flags & BLK_MQ_INSERT_AT_HEAD)
				list_add(&rq->queuelist, &ctx->rq_lists[hctx->type]);
			else
				list_add_tail(&rq->queuelist,
					&ctx->rq_lists[hctx->type]);

			bit = ctx->index_hw[hctx->type];
			if (!sbitmap_test_bit(&hctx->ctx_map, bit))
				sbitmap_set_bit(&hctx->ctx_map, bit);
			q->last_merge = rq;
			spin_unlock(&ctx->lock);
			atomic_inc(&ufq->rqs_count);
		}

		if (ops && rq && ops->insert_req) {
			rq->elv.priv[0] = (void *)((uintptr_t)rq->elv.priv[0]
				  | UFQ_PRIV_IN_BPF);
			ret = ops->insert_req(q, rq, flags);
			if (ret) {
				pr_err("ufq-iosched: bpf insert_req error (%d)\n", ret);
				/*
				 * Leave BPF-owned peers on ctx; park this rq
				 * on insert_err_list for dedicated drain.
				 */
				if (ufq_move_to_insert_err(ufq, rq))
					atomic_inc(&ufq->ops_stats.insert_err_count);
			} else {
				atomic_inc(&ufq->ops_stats.insert_ok_count);
				atomic64_add(blk_rq_sectors(rq), &ufq->ops_stats.insert_ok_sectors);
			}
		}
		if (rq && req_ref_put_and_test(rq))
			__blk_mq_free_request(rq);
	}

	if (ops)
		ufq_bpfops_put();
}

static void ufq_prepare_request(struct request *rq)
{
	rq->elv.priv[0] = (void *)(uintptr_t)UFQ_PRIV_NOT_IN_SCHED;
}

static void ufq_finish_request(struct request *rq)
{
	const struct ufq_iosched_ops *ops;
	struct ufq_data *ufq = rq->q->elevator->elevator_data;

	/*
	 * The block layer core may call ufq_finish_request() without having
	 * called ufq_insert_requests(). Skip requests that bypassed I/O
	 * scheduling.
	 */
	if (!((uintptr_t)rq->elv.priv[0] & UFQ_PRIV_IN_BPF))
		return;

	ops = ufq_bpfops_tryget();
	if (ops) {
		if (ops->finish_req)
			ops->finish_req(rq);
		ufq_bpfops_put();
	}

	atomic_inc(&ufq->ops_stats.finish_ok_count);
	atomic64_add(blk_rq_stats_sectors(rq), &ufq->ops_stats.finish_ok_sectors);
}

static bool ufq_has_work(struct blk_mq_hw_ctx *hctx)
{
	const struct ufq_iosched_ops *ops;
	struct ufq_data *ufq = hctx->queue->elevator->elevator_data;
	int rqs_count = atomic_read(&ufq->rqs_count);
	int policy_has_work;

	ops = ufq_bpfops_tryget();
	if (!ops)
		return rqs_count > 0;

	policy_has_work = ops->has_req ?
		ops->has_req(hctx->queue, rqs_count) : rqs_count;
	ufq_bpfops_put();
	if (!policy_has_work && rqs_count > 0)
		atomic_inc(&ufq->ops_stats.has_work_false_pending_count);

	return policy_has_work || ufq_insert_err_pending(ufq);
}

#ifdef CONFIG_BLK_DEBUG_FS
static int ufq_ops_stats_show(void *data, struct seq_file *m)
{
	struct request_queue *q = data;
	struct ufq_data *ufq = q->elevator->elevator_data;
	struct ufq_ops_stats *s = &ufq->ops_stats;

	/* for debug */
	seq_printf(m, "dispatch_ok_count %d\n",
		   atomic_read(&s->dispatch_ok_count));
	seq_printf(m, "dispatch_ok_sectors %lld\n",
		   (long long)atomic64_read(&s->dispatch_ok_sectors));
	seq_printf(m, "dispatch_null_count %d\n",
		   atomic_read(&s->dispatch_null_count));
	seq_printf(m, "dispatch_bad_state_count %d\n",
		   atomic_read(&s->dispatch_bad_state_count));
	seq_printf(m, "has_work_false_pending_count %d\n",
		   atomic_read(&s->has_work_false_pending_count));
	seq_printf(m, "insert_ok_count %d\n",
		   atomic_read(&s->insert_ok_count));
	seq_printf(m, "insert_ok_sectors %lld\n",
		   (long long)atomic64_read(&s->insert_ok_sectors));
	seq_printf(m, "insert_err_count %d\n",
		   atomic_read(&s->insert_err_count));
	seq_printf(m, "insert_err_handled %d\n",
		   atomic_read(&ufq->insert_err_handled));
	seq_printf(m, "rqs_count %d\n",
		   atomic_read(&ufq->rqs_count));
	seq_printf(m, "merge_req_ok_count %d\n",
		   atomic_read(&s->merge_request_ok_count));
	seq_printf(m, "merge_req_ok_sectors %lld\n",
		   (long long)atomic64_read(&s->merge_request_ok_sectors));
	seq_printf(m, "merge_bio_ok_count %d\n",
		   atomic_read(&s->merge_bio_ok_count));
	seq_printf(m, "merge_bio_ok_sectors %lld\n",
		   (long long)atomic64_read(&s->merge_bio_ok_sectors));
	seq_printf(m, "finish_ok_count %d\n",
		   atomic_read(&s->finish_ok_count));
	seq_printf(m, "finish_ok_sectors %lld\n",
		   (long long)atomic64_read(&s->finish_ok_sectors));
	return 0;
}

static const struct blk_mq_debugfs_attr ufq_iosched_debugfs_attrs[] = {
	{"ops_stats", 0400, ufq_ops_stats_show},
	{},
};
#endif

static struct elevator_type ufq_iosched_mq = {
	.ops = {
		.depth_updated		= ufq_depth_updated,
		.limit_depth		= ufq_limit_depth,
		.insert_requests	= ufq_insert_requests,
		.dispatch_request	= ufq_dispatch_request,
		.prepare_request	= ufq_prepare_request,
		.finish_request		= ufq_finish_request,
		.bio_merge		= ufq_bio_merge,
		.has_work		= ufq_has_work,
		.init_sched		= ufq_init_sched,
		.exit_sched		= ufq_exit_sched,
	},

#ifdef CONFIG_BLK_DEBUG_FS
	.queue_debugfs_attrs = ufq_iosched_debugfs_attrs,
#endif
	.elevator_name = "ufq",
	.elevator_alias = "ufq_iosched",
	.elevator_owner = THIS_MODULE,
};
bool ufq_is_queue(struct request_queue *q)
{
	struct elevator_queue *e = READ_ONCE(q->elevator);

	/* Caller must hold a queue usage reference. */
	return e && e->type == &ufq_iosched_mq;
}

static int __init ufq_init(void)
{
	int ret;

	ret = elv_register(&ufq_iosched_mq);
	if (ret)
		return ret;

	ret = bpf_ufq_kfunc_init();
	if (ret) {
		pr_err("ufq-iosched: Failed to register kfunc sets (%d)\n", ret);
		elv_unregister(&ufq_iosched_mq);
		return ret;
	}

	ret = bpf_ufq_ops_init();
	if (ret) {
		pr_err("ufq-iosched: Failed to register struct_ops (%d)\n", ret);
		elv_unregister(&ufq_iosched_mq);
		return ret;
	}

	return 0;
}

static void __exit ufq_exit(void)
{
	elv_unregister(&ufq_iosched_mq);
}

module_init(ufq_init);
module_exit(ufq_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS("ufq-iosched");
MODULE_AUTHOR("Kaitao Cheng <chengkaitao@kylinos.cn>");
MODULE_DESCRIPTION("User-programmable Flexible Queueing");

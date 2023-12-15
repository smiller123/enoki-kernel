/*
 * Copyright 2021 Google LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/anon_inodes.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/atomic.h>
#include <linux/kvm_host.h>
#include <uapi/linux/sched/types.h>
#include <linux/file.h>
#ifdef CONFIG_X86_64
#include <asm/apic.h>
#endif

#include <linux/ghost.h>

#include <trace/events/sched.h>

#include "sched.h"


static struct enoki_sched_type *enoki_scheds;
static DEFINE_RWLOCK(enoki_scheds_lock);
static struct enoki_queue *top_record_queue;

/*
 * Use per-cpu memory instead of stack memory to avoid memsetting.  We only
 * send one message at a time per cpu.
 */
static DEFINE_PER_CPU(struct bpf_ghost_msg, bpf_ghost_msg);

/*
 * We do not want to make 'SG_COOKIE_CPU_BITS' larger than necessary so that
 * we can maximize the number of times a sequence counter can increment before
 * overflowing.
 */
#if (CONFIG_NR_CPUS < 2048)
#define SG_COOKIE_CPU_BITS	11
#else
#define SG_COOKIE_CPU_BITS	14
#endif
#define SG_COOKIE_CPU_SHIFT	(63 - SG_COOKIE_CPU_BITS)	/* MSB=0 */

unsigned long sysctl_ghost_cfs_load_added = 1024;

static void _ghost_task_new(struct rq *rq, struct task_struct *p,
			    bool runnable);
static void ghost_task_yield(struct rq *rq, struct task_struct *p);
static void ghost_task_blocked(struct rq *rq, struct task_struct *p);
static void task_dead_ghost(struct task_struct *p);
static void task_deliver_msg_task_new(struct rq *rq, struct task_struct *p,
				      bool runnable);
static void task_deliver_msg_task_prio_changed(struct rq *rq, struct task_struct *p);
static void task_deliver_msg_affinity_changed(struct rq *rq,
					      struct task_struct *p,
					      struct cpumask *mask);
static void task_deliver_msg_departed(struct rq *rq, struct task_struct *p);
static void task_deliver_msg_wakeup(struct rq *rq, struct task_struct *p);
static void task_deliver_msg_latched(struct rq *rq, struct task_struct *p,
				     bool latched_preempt);
int do_balance(struct rq *rq, struct enoki_sched_type *sched_type, struct rq_flags *rf);
static int balance_ghost(struct rq *rq, struct task_struct *prev,
			 struct rq_flags *rf);
static void migrate_task_rq_ghost(struct task_struct *p, int new_cpu);
static int select_task_rq_ghost(struct task_struct *p, int cpu, int wake_flags);
static bool cpu_deliver_msg_tick(struct rq *rq, struct task_struct *p, int queued);
static int cpu_deliver_msg_pnt(struct rq *rq, struct enoki_sched_type *sched_type);
static void cpu_deliver_msg_pnt_err(struct rq *rq, int pid, int err,
				    struct enoki_sched_type *sched_type);
static int task_target_cpu(struct task_struct *p);
static void release_from_ghost(struct rq *rq, struct task_struct *p);
static void _ghost_task_preempted(struct rq *rq, struct task_struct *p,
				  bool was_latched);

struct rq *move_queued_task(struct rq *rq, struct rq_flags *rf,
			    struct task_struct *p, int new_cpu);

static const struct file_operations queue_fops;
static inline int produce_for_sched_type_no_lock(
				    struct enoki_sched_type *sched_type,
				    struct bpf_ghost_msg *msg);
static inline int produce_for_sched_type(
				    struct enoki_sched_type *sched_type,
				    struct bpf_ghost_msg *msg);

int ghost_run_pid_on(uint64_t pid, int run_flags, int cpu);

#define WRITEK_PENDING_WAKEUP	0x01
#define WRITEK_PENDING_OUTPUT	0x02

static DEFINE_PER_CPU(int, writek_pending);

static void wake_up_writek_work_func(struct irq_work *irq_work)
{
	struct enoki_sched_type **p;
	int pending = __this_cpu_xchg(writek_pending, 0);
}

static DEFINE_PER_CPU(struct irq_work, wake_up_writek_work) =
	IRQ_WORK_INIT_LAZY(wake_up_writek_work_func);

void defer_file_output(void)
{
	preempt_disable();
	__this_cpu_or(writek_pending, WRITEK_PENDING_OUTPUT);
	irq_work_queue(this_cpu_ptr(&wake_up_writek_work));
	preempt_enable();
}

int writek_deferred(void)
{
	int r;

	// TODO: make our copy of vprintk emit that saves the expected info
	defer_file_output();

	return r;
}


static struct enoki_sched_type **find_enoki_sched(int policy)
{
	struct enoki_sched_type **p;
	for (p = &enoki_scheds; *p; p = &(*p)->next)
		if ((*p)->policy == policy)
			break;
	return p;
}

int register_enoki_sched(const void *sched,
		int policy, const void* process_message)
{
	int res = 0;
	struct enoki_sched_type ** p;
	struct enoki_sched_type *sched_type;

	sched_type = kzalloc(sizeof(struct enoki_sched_type), GFP_KERNEL);
	sched_type->policy = policy;
	sched_type->msg_size = 0;
	sched_type->sched = sched;
	sched_type->process_message = process_message;
	sched_type->owner = (struct module *) 0;
	rwlock_init(&sched_type->sched_lock);
	sched_type->next = (struct enoki_sched_type *) 0;
	setup_sched_ioctl(policy);

	write_lock(&enoki_scheds_lock);
	p = find_enoki_sched(policy);
	if (*p)
		res = -EBUSY;
	else
		*p = sched_type;
	write_unlock(&enoki_scheds_lock);
	printk(KERN_INFO "enoki scheduler name registered %d", policy);
	do_report_timing = 100000;
	return res;
}
EXPORT_SYMBOL(register_enoki_sched);

int unregister_enoki_sched(const void *sched)
{
	struct enoki_sched_type ** tmp;
	printk(KERN_INFO "unregistering enoki scheduler");

	write_lock(&enoki_scheds_lock);
	tmp = &enoki_scheds;
	while (*tmp) {
		if (sched == (*tmp)->sched) {
			*tmp = (*tmp)->next;
			write_unlock(&enoki_scheds_lock);
			synchronize_rcu();
			return 0;
		}
		tmp = &(*tmp)->next;
	}
	write_unlock(&enoki_scheds_lock);

	return -EINVAL;
}
EXPORT_SYMBOL(unregister_enoki_sched);

int reregister_enoki_sched(const void *sched, int policy, const void* process_message) {
	struct enoki_sched_type ** tmp;
	write_lock(&enoki_scheds_lock);
	tmp = &enoki_scheds;
	while (*tmp) {
		if (policy == (*tmp)->policy) {
			struct bpf_ghost_msg msg;
			memset(&msg, 0, sizeof(msg));
			struct enoki_msg_payload_rereg_prep *prep_payload = &msg.rereg_prep;
			struct enoki_msg_payload_rereg_init *init_payload = &msg.rereg_init;
			void *data;
			write_lock(&(*tmp)->sched_lock);

			msg.type = MSG_REREGISTER_PREPARE;
			produce_for_sched_type_no_lock(*tmp, &msg);
			data = prep_payload->data;

			(*tmp)->sched = sched;
			(*tmp)->process_message = process_message;

			memset(&msg, 0, sizeof(msg));
			msg.type = MSG_REREGISTER_INIT;
			init_payload->data = data;
			produce_for_sched_type_no_lock(*tmp, &msg);

			write_unlock(&(*tmp)->sched_lock);
			write_unlock(&enoki_scheds_lock);
			synchronize_rcu();
			return 0;
		}
		tmp = &(*tmp)->next;
	}
	write_unlock(&enoki_scheds_lock);
	return -EINVAL;
}
EXPORT_SYMBOL(reregister_enoki_sched);

int file_write_deferred(char *buf)
{
	if (top_record_queue) {
		spin_lock(&top_record_queue->lock);
		char *start = (char *)top_record_queue->addr;
		struct enoki_queue_header *header = (struct enoki_queue_header *)start;
		uint32_t index = header->head & (header->nelems - 1);
		start += header->offset;
		// start points to an array of length 256 size str
		char *item = start + (index * 256);
		strscpy(item, buf, strlen(buf));
		header->head += 1;
		spin_unlock(&top_record_queue->lock);
	}
	return 0;
}
EXPORT_SYMBOL(file_write_deferred);

//TODO: probably remove
void init_ghost_rq(struct ghost_rq *ghost_rq)
{
	INIT_LIST_HEAD(&ghost_rq->tasks);
}

static inline bool ghost_can_schedule(struct rq *rq)
{
	const struct sched_class *class = rq->curr->sched_class;

	lockdep_assert_held(&rq->lock);
	if (ghost_class(class) || class == &idle_sched_class)
		return true;

	/* A higher priority task is running, must wait to schedule ghost. */
	return false;
}

static inline void schedule_next(struct rq *rq, bool resched)
{
	lockdep_assert_held(&rq->lock);


	/*
	 * If a task running on a non-ghost CPU switches into ghost then
	 * this function is called via set_next_task_ghost() but without
	 * an agent associated with 'rq'.
	 *
	 * Regardless we still need to do resched_curr() so resist the
	 * temptation to do an early return.
	 */
	if (unlikely(!rq->ghost.agent))
		goto done;

done:
	if (resched && ghost_can_schedule(rq))
		resched_curr(rq);
}

static inline void schedule_agent(struct rq *rq, bool resched)
{
}

static inline void force_offcpu(struct rq *rq, bool resched)
{
	VM_BUG_ON(!ghost_class(rq->curr->sched_class));

	schedule_next(rq, resched);
}

static void __update_curr_ghost(struct rq *rq, bool update_sw)
{
	struct task_struct *curr = rq->curr;
	u64 delta, now;

	/*
	 * Bail if this due to a "spurious" dequeue.
	 *
	 * For e.g. dequeue_task_ghost() is called when scheduling properties
	 * of a runnable ghost task change (e.g. nice or cpu affinity), but
	 * if that task is not oncpu then nothing needs to be done here.
	 */
	if (!ghost_class(curr->sched_class))
		return;

	VM_BUG_ON(!curr->se.exec_start);

	now = rq_clock_task(rq);
	delta = now - curr->se.exec_start;
	if ((s64)delta > 0) {
		curr->se.sum_exec_runtime += delta;
		account_group_exec_runtime(curr, delta);
		cgroup_account_cputime(curr, delta);
		curr->se.exec_start = now;
	}
}

static void update_curr_ghost(struct rq *rq)
{
	__update_curr_ghost(rq, true);
}

static void prio_changed_ghost(struct rq *rq, struct task_struct *p, int old)
{
	task_deliver_msg_task_prio_changed(rq, p);
}

static void switched_to_ghost(struct rq *rq, struct task_struct *p)
{
	if (!task_running(rq, p)) {
		p->ghost.new_task = false;
		ghost_task_new(rq, p);
	} else {
		/*
		 * Wait for an oncpu task to schedule before advertising
		 * it to the agent. There isn't much the agent can do as
		 * long as the task is oncpu anyways.
		 *
		 * Note that if a running task switches into ghost then
		 * __sched_setscheduler -> set_next_task_ghost guarantees
		 * a context switch to the local agent at the earliest
		 * possible opportunity.
		 */
		p->ghost.twi.wake_up_cpu = cpu_of(rq);
		p->ghost.twi.valid = 1;
		p->ghost.new_task = true;  /* see ghost_prepare_task_switch() */
	}
}

static void switched_from_ghost(struct rq *rq, struct task_struct *p)
{
	/*
	 * A running task can be switched into ghost while it is executing
	 * sched_setscheduler(cfs). Make sure TASK_NEW is produced before
	 * TASK_DEPARTED in this case.
	 *
	 * Note that unlike TASK_AFFINITY_CHANGED (which we just forget in
	 * a similar situation) we must produce TASK_DEPARTED so the task's
	 * status_word is freed by the agent.
	 *
	 * Also note that we must call ghost_task_new() here before calling
	 * release_from_ghost() since the former sets things up for the
	 * latter to tear down (e.g. adding task to enclave->task_list).
	 */
	if (unlikely(p->ghost.new_task)) {
		WARN_ON_ONCE(!task_current(rq, p));
		p->ghost.new_task = false;
		/*
		 * Task is departing from ghost so don't advertise it as
		 * runnable otherwise the agent could try to schedule it
		 * before it sees TASK_DEPARTED (in this case the commit
		 * fails with GHOST_TXN_INVALID_TARGET which is treated as
		 * a fatal error by the agent).
		 */
		_ghost_task_new(rq, p, /*runnable=*/false);
	}

	release_from_ghost(rq, p);

	/*
	 * Mark end of the switchto chain (if any) since the oncpu task
	 * is no longer being scheduled by ghost.
	 */
	if (task_current(rq, p)) {
		WARN_ON_ONCE(rq->ghost.switchto_count < 0);
		rq->ghost.switchto_count = 0;
	}
}

static void dequeue_task_ghost(struct rq *rq, struct task_struct *p, int flags)
{
	const bool spurious = flags & DEQUEUE_SAVE;
	const bool sleeping = flags & DEQUEUE_SLEEP;

	/*
	 * A task is accumulating cputime only when it is oncpu. Thus it is
	 * useless to call update_curr_ghost for a task that is 'on_rq' but
	 * is not running (in this case we'll just update the cputime of
	 * whatever task happens to be oncpu).
	 *
	 * Ordinarily we wouldn't care but we routinely dequeue_task_ghost()
	 * when migrating a task via ghost_move_task() during txn commit so
	 * we call update_curr_ghost() only if 'p' is actually running.
	 */
	if (task_current(rq, p))
		update_curr_ghost(rq);

	BUG_ON(rq->ghost.ghost_nr_running <= 0);
	rq->ghost.ghost_nr_running--;
	sub_nr_running(rq, 1);

	list_del_init(&p->ghost.run_list);

	if (sleeping) {
		WARN_ON_ONCE(p->ghost.blocked_task);
		p->ghost.blocked_task = true;
		ghost_task_blocked(rq, p);

		/*
		 * Return to local agent if it has expressed interest in
		 * this edge.
		 *
		 * We don't need the full resched_curr() functionality here
		 * because this must be followed by pick_next_task().
		 */
	} else {
		ghost_task_preempted(rq, p);
	}
}

static void put_prev_task_ghost(struct rq *rq, struct task_struct *p)
{
	update_curr_ghost(rq);
}

static void
enqueue_task_ghost(struct rq *rq, struct task_struct *p, int flags)
{
	add_nr_running(rq, 1);
	rq->ghost.ghost_nr_running++;
}

static void set_next_task_ghost(struct rq *rq, struct task_struct *p,
				bool first)
{
	WARN_ON_ONCE(first);

	p->se.exec_start = rq_clock_task(rq);

	/*
	 * This can happen when a running task switches into ghost on a cpu
	 * without an agent (not common).
	 */
	if (unlikely(!rq->ghost.agent)) {
		force_offcpu(rq, true);
		return;
	}
}

/*
 * Called from the timer tick handler while holding the rq->lock.  Called only
 * if a ghost task is current.
 */
static void task_tick_ghost(struct rq *rq, struct task_struct *p, int queued)
{
	struct task_struct *agent = rq->ghost.agent;

	/*
	 * This can happen if a running task enters ghost on a CPU that
	 * is not associated with an agent but a timer interrupt sneaks
	 * in before we get the task offcpu.
	 */

	__update_curr_ghost(rq, false);

	if (queued) {
		rq->ghost.must_resched = true;
	}
	cpu_deliver_msg_tick(rq, p, queued);
}



static int validate_next_task(struct rq *rq, struct task_struct *next,
			      int *state)
{
	lockdep_assert_held(&rq->lock);


	return 0;
}

static int validate_next_offcpu(struct rq *rq, struct task_struct *next,
				int *state)
{
	lockdep_assert_held(&rq->lock);

	if (next && task_running(rq, next)) {
		return -EAGAIN;
	}

	return 0;
}

static inline void ghost_prepare_switch(struct rq *rq, struct task_struct *prev,
					struct task_struct *next)
{

	if (next) {
		next->ghost.last_runnable_at = 0;

		if (likely(next != prev)) {

			next->se.exec_start = rq_clock_task(rq);
		}
	}
}

/*
 * Produce voluntary task state change msgs first (e.g. TASK_BLOCKED,
 * TASK_YIELD in case they end up waking the local agent).
 *
 * Returns 'false' if 'prev' should not be considered for a preemption edge.
 *
 * The basic idea is to elide TASK_PREEMPTED if a voluntary task state change
 * msg was already produced for 'prev' (for e.g. agents don't expect to see a
 * TASK_PREEMPTED immediately after a TASK_BLOCKED).
 */
bool ghost_produce_prev_msgs(struct rq *rq, struct task_struct *prev)
{
	if (!task_has_ghost_policy(prev)) {
		return false;
	}

	if (prev->ghost.new_task) {
		prev->ghost.new_task = false;
		ghost_task_new(rq, prev);

		/*
		 * An oncpu task can switch into ghost and yield or block
		 * before getting offcpu. We don't want this leaking into
		 * the next time this task gets oncpu (for e.g. imagine
		 * 'yield_task' leaking and the task blocks the next time
		 * it gets oncpu).
		 */
		prev->ghost.blocked_task = false;
		prev->ghost.yield_task = false;
		return false;
	}

	/*
	 * 'prev' was running when it yielded but now that it's
	 * off the cpu we can safely let the agent know about it.
	 */
	if (prev->ghost.yield_task) {
		WARN_ON_ONCE(prev->ghost.blocked_task);
		prev->ghost.yield_task = false;
		return false;
	}

	if (prev->ghost.blocked_task) {
		prev->ghost.blocked_task = false;
		return false;
	}

	return true;
}

static struct task_struct *pick_next_task_ghost(struct rq *rq)
{
	struct task_struct *agent = rq->ghost.agent;
	struct task_struct *prev = rq->curr;
	struct task_struct *next = NULL;
	int pid_ret;
	struct enoki_sched_type *p;

	/*
	 * We made it to ghost's pick_next_task so no need to check whether
	 * 'prev' was preempted by a higher priority sched_class.
	 *
	 * We prefer to use an explicit signal over checking the sched_class
	 * of 'next' in ghost_prepare_task_switch() because sometimes even
	 * higher priority sched classes can pick 'rq->idle' to run next.
	 * (e.g. pick_next_task_fair() does this with core tagging enabled).
	 */
	if (rq->ghost.switchto_count == 0) {
		/*
		 * This is the only time we clear check_prev_preemption without
		 * sending a TASK_PREEMPT.
		 */
		if (rq->ghost.run_flags & ELIDE_PREEMPT)
			rq->ghost.check_prev_preemption = false;
	} else {
		WARN_ON_ONCE(rq->ghost.switchto_count > 0);

		/*
		 * We mark that the switchto chain has ended at the top of PNT
		 * (switchto_count < 0). Usually we will pick a different task
		 * (another sched_class or rq->ghost.latched_task) but this is
		 * not guaranteed (rq->lock can be dropped in PNT and runnable
		 * tasks can migrate to other cpus).
		 *
		 * We set 'must_resched' to guarantee a context switch on this
		 * CPU so the 'switchto_count' bookkeeping can be squared away
		 * via context_switch()->ghost_prepare_task_switch().
		 *
		 * Note that if 'prev' is forced offcpu we will still produce
		 * a TASK_PREEMPTED(prev) courtesy of 'check_prev_preemption'.
		 */
		rq->ghost.must_resched = true;
	}

again:
	for (p = enoki_scheds; p; p = p->next) {
		// It's possible that we can return a task from pnt that can't
		// be found for some reason I can't figure out. Just give an
		// error back to the scheduler and let it try again until
		// it has nothing to schedule.
		do {
			pid_ret = cpu_deliver_msg_pnt(rq, p);
			if (pid_ret > 0) {
				next = find_task_by_pid_ns(pid_ret, &init_pid_ns);
				if (next) {
					goto done;
				} else {
					cpu_deliver_msg_pnt_err(rq, pid_ret, 1, p);
				}
			}
		} while (pid_ret > 0);
	}

	/*
	 * Handle a couple of unusual code paths:
	 * - 'prev' blocked but it was woken up before it got off the
	 *   runqueue (see 'light' wakeup in ttwu_remote()).
	 * - 'prev' blocked voluntarily but __schedule() made it runnable
	 *   to handle a pending signal.
	 * - cond_resched() called __schedule(preempt) but there isn't
	 *   any higher priority task to switch to.
	 */
	if (task_has_ghost_policy(prev) && prev->state == TASK_RUNNING) {
		/*
		 * When an agent blocks via ghost_run() we end up here with
		 * 'prev == agent' via schedule(). Without the check below
		 * we will simply return 'prev' (aka the agent) from this
		 * function and subvert the blocking in ghost_run().
		 */
		if (unlikely(prev != agent && !rq->ghost.must_resched)) {
			next = prev;
			rq->ghost.check_prev_preemption = false;
			goto done;
		}
	}
	if (!next) {
		for (p = enoki_scheds; p; p = p->next) {
			struct rq_flags rf;
			int moved = do_balance(rq, p, &rf);
			if (moved)
				goto again;
		}
	}

done:
	ghost_prepare_switch(rq, prev, next);
	rq->ghost.must_resched = false;

	return next;
}

static void check_preempt_curr_ghost(struct rq *rq, struct task_struct *p,
				     int wake_flags)
{
}

static void yield_task_ghost(struct rq *rq)
{
	struct task_struct *curr = rq->curr;

	/*
	 * Task is yielding so get it offcpu. We don't need the full
	 * resched_curr() functionality here because sched_yield()
	 * calls schedule() immediately after.
	 */
	if (rq->ghost.run_flags & RTLA_ON_YIELD)
		schedule_agent(rq, false);
	else
		force_offcpu(rq, false);

	/*
	 * Hold off on announcing that the task has yielded just yet.
	 *
	 * The agent is allowed to do a ghost_run() as soon as it sees
	 * the YIELD msg, but this task is oncpu without 'need_resched'
	 * so validate_next_task() will flag this as an error.
	 *
	 * Fix this by deferring the YIELD msg until the task is truly
	 * off the cpu.
	 *
	 * N.B. although 'rq->lock' is held here sched_yield() drops
	 * it before calling schedule() making the race with ghost_run()
	 * possible.
	 */
	WARN_ON_ONCE(curr->ghost.yield_task);
	rq->ghost.must_resched = true;
	curr->ghost.yield_task = true;
	ghost_task_yield(rq, curr);
}

static void set_cpus_allowed_ghost(struct task_struct *p,
				   const struct cpumask *newmask, u32 flags)
{
	struct rq_flags rf;
	struct rq *rq = task_rq(p);
	bool locked = false;

	/*
	 * N.B. sched_setaffinity() can race with exit() such that the task
	 * is already dead and contents of 'p->ghost' are no longer valid.
	 *
	 * Task msg delivery handles this properly but be careful when
	 * accessing 'p->ghost' directly in this function.
	 */
	task_deliver_msg_affinity_changed(rq, p, newmask);

	if (locked)
		__task_rq_unlock(rq, &rf);

	set_cpus_allowed_common(p, newmask, flags);
}

static void task_woken_ghost(struct rq *rq, struct task_struct *p)
{
	WARN_ON_ONCE(!task_on_rq_queued(p));

	if (unlikely(p->ghost.new_task)) {
		p->ghost.new_task = false;
		ghost_task_new(rq, p);
		return;
	}
	task_deliver_msg_wakeup(rq, p);
}

DEFINE_SCHED_CLASS(ghost) = {
	.update_curr		= update_curr_ghost,
	.prio_changed		= prio_changed_ghost,
	.switched_to		= switched_to_ghost,
	.switched_from		= switched_from_ghost,
	.task_dead		= task_dead_ghost,
	.dequeue_task		= dequeue_task_ghost,
	.put_prev_task		= put_prev_task_ghost,
	.enqueue_task		= enqueue_task_ghost,
	.set_next_task		= set_next_task_ghost,
	.task_tick		= task_tick_ghost,
	.pick_next_task		= pick_next_task_ghost,
	.check_preempt_curr	= check_preempt_curr_ghost,
	.yield_task		= yield_task_ghost,
#ifdef CONFIG_SMP
	.balance		= balance_ghost,
	.select_task_rq		= select_task_rq_ghost,
	.migrate_task_rq	= migrate_task_rq_ghost,
	.task_woken		= task_woken_ghost,
	.set_cpus_allowed	= set_cpus_allowed_ghost,
#endif
};

/*
 * Migrate 'next' (if necessary) in preparation to run it on 'cpu'.
 *
 * An important side-effect is that 'next' is guaranteed to not be
 * cached on any cpu when this function returns (e.g. latched_task).
 */
static struct rq *ghost_move_task(struct rq *rq, struct task_struct *next,
				  int cpu, struct rq_flags *rf)
{
	lockdep_assert_held(&rq->lock);
	lockdep_assert_held(&next->pi_lock);

	WARN_ON_ONCE(rq->ghost.skip_latched_preemption);

	/*
	 * Cleared in invalidate_cached_tasks() via move_queued_task()
	 * and dequeue_task_ghost(). We cannot clear it here because
	 * move_queued_task() will release rq->lock (the rq returned
	 * by move_queued_task() is different than the one passed in).
	 */
	rq->ghost.skip_latched_preemption = true;

	/*
	 * 'next' was enqueued on a different CPU than where the agent
	 * wants to run it now so migrate it to this runqueue before
	 * switching to it.
	 */
	if (unlikely(task_cpu(next) != cpu)) {
		VM_BUG_ON(task_running(rq, next));
		VM_BUG_ON(!task_on_rq_queued(next));
		update_rq_clock(rq);
		rq = move_queued_task(rq, rf, next, cpu);
	}

	return rq;
}

int _ghost_mmap_common(struct vm_area_struct *vma, ulong mapsize)
{
	static const struct vm_operations_struct ghost_vm_ops = {};

	/*
	 * VM_MAYSHARE indicates that MAP_SHARED was set in 'mmap' flags.
	 *
	 * Checking VM_SHARED seems intuitive here but this bit is cleared
	 * by do_mmap() if the underlying file is readonly (as is the case
	 * for a sw_region file).
	 */
	if (!(vma->vm_flags & VM_MAYSHARE))
		return -EINVAL;

	/*
	 * Mappings are always readable and 'do_mmap()' ensures that
	 * FMODE_WRITE and VM_WRITE are coherent so the only remaining
	 * check is against VM_EXEC.
	 */
	if (vma->vm_flags & VM_EXEC)
		return -EACCES;

	/* The entire region must be mapped */
	if (vma->vm_pgoff)
		return -EINVAL;

	if (vma->vm_end - vma->vm_start != mapsize)
		return -EINVAL;

	/*
	 * Don't allow mprotect(2) to relax permissions beyond what
	 * would have been allowed by this function.
	 *
	 * Mappings always readable and 'do_mmap()' ensures that
	 * FMODE_WRITE and VM_MAYWRITE are coherent so just clear
	 * VM_MAYEXEC here.
	 */
	vma->vm_flags &= ~VM_MAYEXEC;
	vma->vm_flags |= VM_DONTCOPY;

	/*
	 * Initialize 'vma->vm_ops' to avoid vma_is_anonymous() false-positive.
	 */
	vma->vm_ops = &ghost_vm_ops;
	return 0;
}

/*
 * Helper function for mapping status_word and similar regions into userspace.
 *
 * 'addr' must have been obtained from vmalloc_user().
 */
int ghost_region_mmap(struct file *file, struct vm_area_struct *vma,
		      void *addr, ulong mapsize)
{
	int error;

	error = _ghost_mmap_common(vma, mapsize);
	if (!error)
		error = remap_vmalloc_range(vma, addr, 0);

	return error;
}

/*
 * Free the memory resources associated with the ghost_queue (must be called
 * in sleepable process context).
 */
static void __queue_free_work(struct work_struct *work)
{
	struct enoki_sched_type *sched;
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_unreg_queue *unreg_q_payload;
	struct enoki_queue *q = container_of(work, struct enoki_queue,
					     free_work);
	struct enoki_sched_type **sched_ptr = find_enoki_sched(q->policy);
	sched = *sched_ptr;
	memset(&msg, 0, sizeof(msg));
	unreg_q_payload = &msg.unreg_queue;

	msg.type = MSG_UNREGISTER_QUEUE;
	unreg_q_payload->id = q->id;

	produce_for_sched_type(sched, &msg);
	vfree(q->addr);
	kfree(q);
}

static void __reverse_queue_free_work(struct work_struct *work)
{
	struct enoki_sched_type *sched;
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_unreg_queue *unreg_q_payload;
	struct enoki_queue *q = container_of(work, struct enoki_queue,
					     free_work);
	struct enoki_sched_type **sched_ptr = find_enoki_sched(q->policy);
	sched = *sched_ptr;
	memset(&msg, 0, sizeof(msg));
	unreg_q_payload = &msg.unreg_rev_queue;

	msg.type = MSG_UNREGISTER_REV_QUEUE;
	unreg_q_payload->id = q->id;

	produce_for_sched_type(sched, &msg);
	vfree(q->addr);
	kfree(q);
}

static void __record_free_work(struct work_struct *work)
{
	struct enoki_queue *q = container_of(work, struct enoki_queue,
					     free_work);
	struct enoki_sched_type **sched_ptr = find_enoki_sched(q->policy);
	struct enoki_sched_type *sched = *sched_ptr;
	if (sched) {
		sched->record_queue = NULL;
	}
	vfree(q->addr);
	kfree(q);
}

void _queue_free_rcu_callback(struct rcu_head *rhp)
{
	struct enoki_queue *q = container_of(rhp, struct enoki_queue, rcu);

	/*
	 * Further defer work to a preemptible process context: the rcu
	 * callback may be called from a softirq context and cannot block.
	 */
	schedule_work(&q->free_work);
}

static void __queue_kref_release(struct kref *k)
{
	struct enoki_queue *q = container_of(k, struct enoki_queue, kref);

	/*
	 * We may be called from awkward contexts that hold scheduler
	 * locks or that are non-preemptible and this runs afoul of
	 * sleepable locks taken during vfree(q->addr).
	 *
	 * Defer freeing of queue memory to an rcu callback (this has
	 * nothing to do with rcu and we use it solely for convenience).
	 */
	call_rcu(&q->rcu, _queue_free_rcu_callback);
}

static inline void queue_decref(struct enoki_queue *q)
{
	kref_put(&q->kref, __queue_kref_release);
}

static inline void queue_incref(struct enoki_queue *q)
{
	kref_get(&q->kref);
}

/*
 * Prepare task 'p' to participate in ghost scheduling.
 *
 * Hold the enclave lock.
 *
 * The underlying 'task_struct' is stable because:
 * - it is protected by 'p->pi_lock' (called via sched_setscheduler).
 * - it is being created (called via sched_fork).
 */
static int __ghost_prep_task(struct task_struct *p,
			     bool forked,
			     struct enoki_sched_type *sched_type)
{
	int error = 0;


	/*
	 * Clean up state from a previous incarnation (e.g. ghost->cfs->ghost).
	 */
	sched_ghost_entity_init(p);

	p->ghost.new_task = forked;
	p->ghost.agent_type = sched_type;
done:
	return error;
}

static int ghost_prep_task(struct task_struct *p,
			   bool forked, struct enoki_sched_type *sched_type)
{
	int error;
	unsigned long irq_fl;

	error = __ghost_prep_task(p, forked, sched_type);

	return error;
}

int ghost_sched_fork(struct task_struct *p)
{
	struct rq *rq;
	struct rq_flags rf;
	int ret;

	VM_BUG_ON(!task_has_ghost_policy(p));

	/*
	 * Another task could be attempting to setsched current out of ghOSt.
	 * To keep current's enclave valid, we synchronize with the RQ lock.
	 */
	rq = task_rq_lock(current, &rf);
	if (!ghost_policy(current->policy)) {
		task_rq_unlock(rq, current, &rf);
		/* It's not quite ECHILD, but it'll tell us where to look. */
		return -ECHILD;
	}
	ret = ghost_prep_task(p, true, current->ghost.agent_type);
	task_rq_unlock(rq, current, &rf);

	return ret;
}

/*
 * For tasks attempting to join ghost, __sched_setscheduler() needs to pass us
 * the enclave, and it needs to manage the reference counting on the fd and its
 * underlying kn.  This is because we can't call ghost_fdput_enclave directly
 * while holding the rq lock, because it eventually calls kernfs_put_active,
 * which grabs the rq lock.
 *
 * You'd think we could use a balance_callback, and pass it the fd_to_put
 * (f_enc) and whether or not it had an enclave.  However, there's no good place
 * to put those arguments.  We could stash them in struct ghost_rq, but for one
 * small problem: the rq lock is released before balance_callback() runs.  That
 * means someone else could grab the lock, then setsched another task, thereby
 * clobbering the args stored in ghost_rq.
 *
 * We can't dynamically allocate memory either, since we're holding the rq lock.
 * I even considered reusing the sched_attr struct: cast it to some other struct
 * and hang it off a linked list on the rq.  The problem there is that although
 * we will call balance_callback when we return to __sched_setscheduler(),
 * balance_callback makes no guarantees about when the callback will run.  If
 * two threads call balance_callback(), one of them will run the callbacks and
 * the other will return immediately.  If we return immediately, then we can't
 * use the schedattr.
 *
 * The most reasonable fix for all of this is to directly call
 * ghost_fdput_enclave() from __sched_setscheduler().
 */
int ghost_setscheduler(struct task_struct *p, struct rq *rq,
		       const struct sched_attr *attr,
		       int *reset_on_fork)
{
	int oldpolicy = p->policy;
	int newpolicy = attr->sched_policy;
	int ret;
	struct enoki_sched_type ** sched_type;

	if (WARN_ON_ONCE(!ghost_policy(oldpolicy) && !ghost_policy(newpolicy)))
		return -EINVAL;


	/*
	 * If the process is dying, finish_task_switch will call task_dead
	 * *after* releasing the rq lock.  We don't know if task_dead was called
	 * yet, and it will be called without holding any locks.  This can break
	 * ghost for both task scheduling into ghost and out of ghost.
	 * - If we're entering ghost, but already ran task_dead from our old
	 *   sched class, then we'll never run ghost_task_dead.
	 * - If we're leaving ghost, we need to run either ghost_task_dead xor
	 *   setscheduler from ghost, but we have no nice way of knowing if we
	 *   already ran ghost_task_dead.
	 */
	if (p->state == TASK_DEAD)
		return -ESRCH;
	/* Cannot change attributes for a ghost task after creation. */
	if (oldpolicy == newpolicy)
		return -EPERM;

	/* Task 'p' is departing the ghost sched class. */
	if (ghost_policy(oldpolicy)) {
		return 0;
	}

	sched_type = find_enoki_sched(newpolicy);
	if (!(*sched_type)) {
		return -EBADF;
	}
	p->ghost.new_task = false;
	p->ghost.agent_type = *sched_type;

	return 0;
}

static int queue_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct enoki_queue *q = file->private_data;

	return ghost_region_mmap(file, vma, q->addr, q->mapsize);
}

static int queue_release(struct inode *inode, struct file *file)
{
	struct enoki_queue *q = file->private_data;
	queue_decref(q);		/* drop inode reference */
	return 0;
}

static const struct file_operations queue_fops = {
	.release		= queue_release,
	.mmap			= queue_mmap,
};

int enoki_enter_queue(int policy,
		       struct enoki_ioc_enter_queue __user *arg) {
	struct enoki_ioc_enter_queue enter_queue;
	struct enoki_sched_type *sched;
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_enter_queue *enter_q_payload;
	struct enoki_sched_type **sched_ptr = find_enoki_sched(policy);
	if (!(*sched_ptr)) {
		return -EBADF;
	}
	sched = *sched_ptr;

	if (copy_from_user(&enter_queue, arg,
			   sizeof(struct enoki_ioc_enter_queue)))
		return -EFAULT;

	memset(&msg, 0, sizeof(msg));
	enter_q_payload = &msg.enter_queue;

	msg.type = MSG_ENTER_QUEUE;
	enter_q_payload->entries = enter_queue.entries;
	enter_q_payload->id = enter_queue.id;

	produce_for_sched_type(sched, &msg);
	return 0;
}

int enoki_create_queue(int policy,
		       struct enoki_ioc_create_queue __user *arg)
{
	ulong size;
	int error = 0, fd, elems, node, flags;
	struct enoki_queue *q;
	struct enoki_queue_header *h;
	struct enoki_ioc_create_queue create_queue;
	struct enoki_sched_type *sched;
	struct bpf_ghost_msg msg;
	struct bpf_ghost_msg msg2;
	struct enoki_msg_payload_msg_size *msg_size_payload;
	struct enoki_msg_payload_create_queue *msg_create_queue;
	uint32_t msg_size;

	const int valid_flags = 0;	/* no flags for now */
	struct enoki_sched_type **sched_ptr = find_enoki_sched(policy);
	if (!(*sched_ptr)) {
		return -EBADF;
	}
	sched = *sched_ptr;

	if (copy_from_user(&create_queue, arg,
			   sizeof(struct enoki_ioc_create_queue)))
		return -EFAULT;

	elems = create_queue.elems;
	flags = create_queue.flags;
	memset(&msg, 0, sizeof(msg));
	msg_size_payload = &msg.msg_size;

	msg.type = MSG_MSG_SIZE;

	produce_for_sched_type(sched, &msg);
	msg_size = msg_size_payload->msg_size;
	if (!msg_size) {
		return -EINVAL;
	}

	if (elems > GHOST_MAX_QUEUE_ELEMS || !is_power_of_2(elems))
		return -EINVAL;

	if (flags & ~valid_flags)
		return -EINVAL;

	// nelems, readptr, writeptr
	size = sizeof(struct enoki_queue_header);
	size += elems * msg_size;
	size = PAGE_ALIGN(size);

	error = put_user(size, &arg->mapsize);
	if (error)
		return error;

	q = kzalloc(sizeof(struct enoki_queue), GFP_KERNEL);
	if (!q) {
		error = -ENOMEM;
		return error;
	}

	kref_init(&q->kref); /* sets to 1; inode gets its own reference */
	q->addr = vmalloc_user(size);
	if (!q->addr) {
		error = -ENOMEM;
		goto err_vmalloc;
	}

	h = q->addr;
	// I think alignment is probably ok
	h->offset = sizeof(struct enoki_queue_header);
	h->nelems = elems;
	h->head = 0;
	h->tail = 0;

	q->policy = policy;
	q->nelems = elems;
	q->mapsize = size;
	q->msg_size = msg_size;
	q->mask = elems - 1;

	memset(&msg2, 0, sizeof(msg2));
	msg_create_queue = &msg2.create_queue;

	msg2.type = MSG_CREATE_QUEUE;
	msg_create_queue->pid = current->pid;
	msg_create_queue->q = q->addr;
	produce_for_sched_type(sched, &msg2);
	q->id = msg_create_queue->id;
	error = put_user(msg_create_queue->id, &arg->id);
	if (error)
		return error;

	fd = anon_inode_getfd("[ghost_queue]", &queue_fops, q,
			      O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		error = fd;
		goto err_getfd;
	}

	INIT_WORK(&q->free_work, __queue_free_work);

	return fd;

err_getfd:
	vfree(q->addr);
err_vmalloc:
	kfree(q);
	return error;
}

int enoki_create_reverse_queue(int policy,
		       struct enoki_ioc_create_queue __user *arg)
{
	ulong size;
	int error = 0, fd, elems, node, flags;
	struct enoki_queue *q;
	struct enoki_queue_header *h;
	struct enoki_ioc_create_queue create_queue;
	struct enoki_sched_type *sched;
	struct bpf_ghost_msg msg;
	struct bpf_ghost_msg msg2;
	struct enoki_msg_payload_msg_size *msg_size_payload;
	struct enoki_msg_payload_create_queue *msg_create_queue;
	uint32_t msg_size;

	const int valid_flags = 0;	/* no flags for now */
	struct enoki_sched_type **sched_ptr = find_enoki_sched(policy);
	if (!(*sched_ptr)) {
		return -EBADF;
	}
	sched = *sched_ptr;

	if (copy_from_user(&create_queue, arg,
			   sizeof(struct enoki_ioc_create_queue)))
		return -EFAULT;

	elems = create_queue.elems;
	flags = create_queue.flags;
	memset(&msg, 0, sizeof(msg));
	msg_size_payload = &msg.msg_size;

	msg.type = MSG_REV_MSG_SIZE;

	produce_for_sched_type(sched, &msg);
	msg_size = msg_size_payload->msg_size;
	if (!msg_size) {
		return -EINVAL;
	}

	if (elems > GHOST_MAX_QUEUE_ELEMS || !is_power_of_2(elems))
		return -EINVAL;

	if (flags & ~valid_flags)
		return -EINVAL;
	size = sizeof(struct enoki_queue_header);
	size += elems * msg_size;
	size = PAGE_ALIGN(size);

	error = put_user(size, &arg->mapsize);
	if (error)
		return error;

	q = kzalloc(sizeof(struct enoki_queue), GFP_KERNEL);
	if (!q) {
		error = -ENOMEM;
		return error;
	}

	kref_init(&q->kref); /* sets to 1; inode gets its own reference */
	q->addr = vmalloc_user(size);
	if (!q->addr) {
		error = -ENOMEM;
		goto err_vmalloc;
	}

	h = q->addr;
	// I think alignment is probably ok
	h->offset = sizeof(struct enoki_queue_header);
	h->nelems = elems;
	h->head = 0;
	h->tail = 0;

	q->policy = policy;
	q->nelems = elems;
	q->mapsize = size;
	q->msg_size = msg_size;
	q->mask = elems - 1;

	memset(&msg2, 0, sizeof(msg2));
	msg_create_queue = &msg2.create_rev_queue;

	msg2.type = MSG_CREATE_REV_QUEUE;
	msg_create_queue->pid = current->pid;
	msg_create_queue->q = q->addr;
	produce_for_sched_type(sched, &msg2);
	q->id = msg_create_queue->id;
	error = put_user(msg_create_queue->id, &arg->id);

	fd = anon_inode_getfd("[ghost_queue]", &queue_fops, q,
			      O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		error = fd;
		goto err_getfd;
	}

	INIT_WORK(&q->free_work, __reverse_queue_free_work);

	return fd;

err_getfd:
	vfree(q->addr);
err_vmalloc:
	kfree(q);
	return error;
}

int enoki_create_top_record(
		       struct enoki_ioc_create_queue __user *arg)
{
	ulong size;
	int error = 0, fd, elems, node, flags;
	struct enoki_queue *q;
	struct enoki_queue_header *h;
	struct enoki_ioc_create_queue create_queue;
	struct enoki_sched_type *sched;
	// TODO: figure out the correct message size
	uint32_t msg_size = 256;

	const int valid_flags = 0;	/* no flags for now */

	if (copy_from_user(&create_queue, arg,
			   sizeof(struct enoki_ioc_create_queue)))
		return -EFAULT;

	elems = create_queue.elems;
	flags = create_queue.flags;

	if (!is_power_of_2(elems))
		return -EINVAL;

	if (flags & ~valid_flags)
		return -EINVAL;

	// nelems, readptr, writeptr
	size = sizeof(struct enoki_queue_header);
	size += elems * msg_size;
	size = PAGE_ALIGN(size);

	error = put_user(size, &arg->mapsize);
	if (error)
		return error;

	q = kzalloc(sizeof(struct enoki_queue), GFP_KERNEL);
	if (!q) {
		error = -ENOMEM;
		return error;
	}

	spin_lock_init(&q->lock);
	kref_init(&q->kref); /* sets to 1; inode gets its own reference */
	q->addr = vmalloc_user(size);
	if (!q->addr) {
		error = -ENOMEM;
		goto err_vmalloc;
	}

	h = q->addr;
	// I think alignment is probably ok
	h->offset = sizeof(struct enoki_queue_header);
	h->nelems = elems;
	h->head = 0;
	h->tail = 0;

	q->nelems = elems;
	q->mapsize = size;
	q->msg_size = msg_size;
	q->mask = elems - 1;

	fd = anon_inode_getfd("[ghost_record]", &queue_fops, q,
			      O_RDWR | O_CLOEXEC);
	top_record_queue = q;
	if (fd < 0) {
		error = fd;
		goto err_getfd;
	}

	INIT_WORK(&q->free_work, __record_free_work);

	return fd;

err_getfd:
	vfree(q->addr);
err_vmalloc:
	kfree(q);
	return error;
}

int enoki_create_record(int policy,
		       struct enoki_ioc_create_queue __user *arg)
{
	ulong size;
	int error = 0, fd, elems, node, flags;
	struct enoki_queue *q;
	struct enoki_queue_header *h;
	struct enoki_ioc_create_queue create_queue;
	struct enoki_sched_type *sched;
	// TODO: figure out the correct message size
	uint32_t msg_size = 256;

	const int valid_flags = 0;	/* no flags for now */
	struct enoki_sched_type **sched_ptr = find_enoki_sched(policy);
	if (!(*sched_ptr)) {
		return -EBADF;
	}
	sched = *sched_ptr;

	if (copy_from_user(&create_queue, arg,
			   sizeof(struct enoki_ioc_create_queue)))
		return -EFAULT;

	elems = create_queue.elems;
	flags = create_queue.flags;

	if (elems > GHOST_MAX_QUEUE_ELEMS || !is_power_of_2(elems))
		return -EINVAL;

	if (flags & ~valid_flags)
		return -EINVAL;
	// nelems, readptr, writeptr
	size = sizeof(struct enoki_queue_header);
	size += elems * msg_size;
	size = PAGE_ALIGN(size);

	error = put_user(size, &arg->mapsize);
	if (error)
		return error;

	q = kzalloc(sizeof(struct enoki_queue), GFP_KERNEL);
	if (!q) {
		error = -ENOMEM;
		return error;
	}

	kref_init(&q->kref); /* sets to 1; inode gets its own reference */
	q->addr = vmalloc_user(size);
	if (!q->addr) {
		error = -ENOMEM;
		goto err_vmalloc;
	}

	h = q->addr;
	// I think alignment is probably ok
	h->offset = sizeof(struct enoki_queue_header);
	h->nelems = elems;
	h->head = 0;
	h->tail = 0;

	q->policy = policy;
	q->nelems = elems;
	q->mapsize = size;
	q->msg_size = msg_size;
	q->mask = elems - 1;

	fd = anon_inode_getfd("[ghost_record]", &queue_fops, q,
			      O_RDWR | O_CLOEXEC);
	sched->record_queue = q;
	if (fd < 0) {
		error = fd;
		goto err_getfd;
	}

	INIT_WORK(&q->free_work, __record_free_work);

	return fd;

err_getfd:
	vfree(q->addr);
err_vmalloc:
	kfree(q);
	return error;
}

int enoki_send_hint(int policy,
		       void __user *user_arg)
{
	struct bpf_ghost_msg msg;
	struct bpf_ghost_msg msg2;
	struct enoki_msg_payload_msg_size *msg_size_payload;
	struct enoki_msg_payload_send_hint *send_hint_payload;
	uint32_t msg_size;
	struct enoki_sched_type *sched;
	struct enoki_sched_type **sched_ptr = find_enoki_sched(policy);
	void *arg;
	if (!(*sched_ptr)) {
		return -EBADF;
	}
	sched = *sched_ptr;

	memset(&msg, 0, sizeof(msg));
	msg_size_payload = &msg.msg_size;
	msg.type = MSG_MSG_SIZE;

	produce_for_sched_type(sched, &msg);
	msg_size = msg_size_payload->msg_size;
	if (!msg_size) {
		return -EINVAL;
	}
	arg = kzalloc(msg_size, GFP_KERNEL);
	if (copy_from_user(arg, user_arg,
			   msg_size))
		return -EFAULT;

	memset(&msg2, 0, sizeof(msg2));
	send_hint_payload = &msg2.send_hint;
	msg2.type = MSG_SEND_HINT;
	send_hint_payload->arg = arg;

	produce_for_sched_type(sched, &msg2);
	return 0;
}

static int _produce(uint32_t barrier, int type,
		    void *payload, int payload_size,
		    struct enoki_sched_type *sched_type,
		    bool lock)
{
	int msglen;
	int ret;

	msglen = sizeof(struct enoki_msg) + payload_size;
	ret = 0;
	if (sched_type && sched_type->process_message) {
		if (lock) {
			read_lock(&sched_type->sched_lock);
		}
		sched_type->process_message(sched_type->sched,
				type, msglen, barrier,
				payload, payload_size, &ret);
		if (lock) {
			read_unlock(&sched_type->sched_lock);
		}
	}

	return ret;
}


static inline int __produce_for_task(struct enoki_sched_type *sched_type,
				     struct bpf_ghost_msg *msg,
				     uint32_t barrier, bool lock)
{
	void *payload;
	int payload_size;

	msg->seqnum = barrier;

	switch (msg->type) {
	case MSG_TASK_DEAD:
		payload = &msg->dead;
		payload_size = sizeof(msg->dead);
		break;
	case MSG_TASK_BLOCKED:
		payload = &msg->blocked;
		payload_size = sizeof(msg->blocked);
		break;
	case MSG_TASK_WAKEUP:
		payload = &msg->wakeup;
		payload_size = sizeof(msg->wakeup);
		break;
	case MSG_TASK_NEW:
		payload = &msg->newt;
		payload_size = sizeof(msg->newt);
		break;
	case MSG_TASK_PREEMPT:
		payload = &msg->preempt;
		payload_size = sizeof(msg->preempt);
		break;
	case MSG_TASK_YIELD:
		payload = &msg->yield;
		payload_size = sizeof(msg->yield);
		break;
	case MSG_TASK_DEPARTED:
		payload = &msg->departed;
		payload_size = sizeof(msg->departed);
		break;
	case MSG_TASK_SWITCHTO:
		payload = &msg->switchto;
		payload_size = sizeof(msg->switchto);
		break;
	case MSG_TASK_AFFINITY_CHANGED:
		payload = &msg->affinity;
		payload_size = sizeof(msg->affinity);
		break;
	case MSG_TASK_LATCHED:
		payload = &msg->latched;
		payload_size = sizeof(msg->latched);
		break;
	case MSG_CPU_TICK:
		payload = &msg->cpu_tick;
		payload_size = sizeof(msg->cpu_tick);
		break;
	case MSG_CPU_TIMER_EXPIRED:
		payload = &msg->timer;
		payload_size = sizeof(msg->timer);
		break;
	case MSG_CPU_NOT_IDLE:
		payload = &msg->cpu_not_idle;
		payload_size = sizeof(msg->cpu_not_idle);
		break;
	case MSG_PNT:
		payload = &msg->pnt;
		payload_size = sizeof(msg->pnt);
		break;
	case MSG_PNT_ERR:
		payload = &msg->pnt_err;
		payload_size = sizeof(msg->pnt_err);
		break;
	case MSG_TASK_SELECT_RQ:
		payload = &msg->select;
		payload_size = sizeof(msg->select);
		break;
	case MSG_TASK_MIGRATE_RQ:
		payload = &msg->migrate;
		payload_size = sizeof(msg->migrate);
		break;
	case MSG_BALANCE:
		payload = &msg->balance;
		payload_size = sizeof(msg->balance);
		break;
	case MSG_BALANCE_ERR:
		payload = &msg->balance_err;
		payload_size = sizeof(msg->balance_err);
		break;
	case MSG_REREGISTER_PREPARE:
		payload = &msg->rereg_prep;
		payload_size = sizeof(msg->rereg_prep);
		break;
	case MSG_REREGISTER_INIT:
		payload = &msg->rereg_init;
		payload_size = sizeof(msg->rereg_init);
		break;
	case MSG_MSG_SIZE:
		payload = &msg->msg_size;
		payload_size = sizeof(msg->msg_size);
		break;
	case MSG_REV_MSG_SIZE:
		payload = &msg->msg_size;
		payload_size = sizeof(msg->msg_size);
		break;
	case MSG_SEND_HINT:
		payload = &msg->send_hint;
		payload_size = sizeof(msg->send_hint);
		break;
	case MSG_CREATE_QUEUE:
		payload = &msg->create_queue;
		payload_size = sizeof(msg->create_queue);
		break;
	case MSG_CREATE_REV_QUEUE:
		payload = &msg->create_rev_queue;
		payload_size = sizeof(msg->create_rev_queue);
		break;
	case MSG_ENTER_QUEUE:
		payload = &msg->enter_queue;
		payload_size = sizeof(msg->enter_queue);
		break;
	case MSG_UNREGISTER_QUEUE:
		payload = &msg->unreg_queue;
		payload_size = sizeof(msg->unreg_queue);
		break;
	case MSG_UNREGISTER_REV_QUEUE:
		payload = &msg->unreg_rev_queue;
		payload_size = sizeof(msg->unreg_rev_queue);
		break;
	case MSG_CLEANUP:
		payload = &msg->cleanup;
		payload_size = sizeof(msg->cleanup);
		break;
	case MSG_TASK_PRIO_CHANGED:
		payload = &msg->prio_changed;
		payload_size = sizeof(msg->prio_changed);
		break;
	default:
		WARN(1, "unknown bpg_ghost_msg type %d!\n", msg->type);
		return -EINVAL;
	};
	return _produce(barrier, msg->type,
			payload, payload_size, sched_type, lock);
}

static inline int produce_for_task(struct task_struct *p,
				   struct bpf_ghost_msg *msg)
{
	return __produce_for_task(p->ghost.agent_type, msg, 0, true);
}


static void migrate_task_rq_ghost(struct task_struct *p, int new_cpu) {
	struct rq *rq = task_rq(p);
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_migrate_task_rq *payload = &msg.migrate;
	memset(&msg, 0, sizeof(msg));

	msg.type = MSG_TASK_MIGRATE_RQ;
	payload->pid = p->pid;
	payload->new_cpu = new_cpu;
	produce_for_task(p, &msg);
	p->ghost.twi.wake_up_cpu = new_cpu;
	p->ghost.twi.valid = 1;
}

static int select_task_rq_ghost(struct task_struct *p, int cpu, int wake_flags)
{
	struct rq_flags rf;
	int waker_cpu = smp_processor_id();
	int new_cpu;
	struct rq *rq = task_rq(p);
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_select_task_rq *payload = &msg.select;
	memset(&msg, 0, sizeof(msg));

	/* For anything but wake ups, just return the task_cpu */
	if (!(wake_flags & (WF_TTWU | WF_FORK)))
		return task_cpu(p);

	msg.type = MSG_TASK_SELECT_RQ;
	payload->pid = p->pid;
	payload->waker_cpu = waker_cpu;
	payload->prev_cpu = cpu;
	produce_for_task(p, &msg);
	new_cpu = payload->ret_cpu;
	p->ghost.twi.wake_up_cpu = new_cpu;
	p->ghost.twi.valid = 1;

	p->ghost.twi.waker_cpu = waker_cpu;
	p->ghost.twi.last_ran_cpu = task_cpu(p);

	return p->ghost.twi.wake_up_cpu;
}

static inline void cpu_deliver_msg_balance_err(struct rq *rq,
					int pid,
					int err,
				      struct enoki_sched_type *sched_type)
{
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_balance_err *payload;
	int ret;
	memset(&msg, 0, sizeof(msg));
	payload = &msg.balance_err;
	msg.type = MSG_BALANCE_ERR;
	payload->cpu = cpu_of(rq);
	payload->pid = pid;
	payload->err = err;
	produce_for_sched_type(sched_type, &msg);
}

int do_balance(struct rq *rq, struct enoki_sched_type *sched_type, struct rq_flags *rf) {
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_balance *payload = &msg.balance;
	uint64_t move_pid;
	memset(&msg, 0, sizeof(msg));
	msg.type = MSG_BALANCE;
	payload->cpu = cpu_of(rq);
	rq_unpin_lock(rq, rf);
	int moved = 0;

	do {
		produce_for_sched_type(sched_type, &msg);
		if (payload->do_move) {
			int ret;
			move_pid = payload->move_pid;
			ret = ghost_run_pid_on(move_pid, 0, cpu_of(rq));
			if (ret < 0) {
				cpu_deliver_msg_balance_err(rq, move_pid, ret, sched_type);
			} else {
				moved += 1;
			}
		}
	} while (payload->do_move);
	rq_repin_lock(rq, rf);
	return moved;
}

static int balance_ghost(struct rq *rq, struct task_struct *prev,
			 struct rq_flags *rf)
{

	do_balance(rq, prev->ghost.agent_type, rf);
	return rq_adj_nr_running(rq);
}

static inline int produce_for_sched_type(
				    struct enoki_sched_type *sched_type,
				    struct bpf_ghost_msg *msg)
{
	return __produce_for_task(sched_type, msg, 0, true);
}

static inline int produce_for_sched_type_no_lock(
				    struct enoki_sched_type *sched_type,
				    struct bpf_ghost_msg *msg)
{
	return __produce_for_task(sched_type, msg, 0, false);
}

static inline bool cpu_deliver_msg_tick(struct rq *rq, struct task_struct *p,
		int queued)
{
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_cpu_tick *payload = &msg.cpu_tick;
	memset(&msg, 0, sizeof(msg));

	msg.type = MSG_CPU_TICK;
	payload->cpu = cpu_of(rq);
	payload->queued = queued;

	return !produce_for_task(p, &msg);
}

/*
 * When called from pick_next_task() context returns 'true' if 'rq->cpu'
 * is exiting switchto and 'false' otherwise (e.g. when producing the
 * TASK_BLOCKED/TASK_YIELD/TASK_PREEMPT msgs).
 *
 * When called outside pick_next_task() context returns 'true' if 'rq->cpu'
 * is currently in a switchto chain and 'false' otherwise (e.g. when producing
 * TASK_DEPARTED msg for an oncpu ghost task).
 *
 * Technically this could be split into two APIs one for 'switchto_count < 0'
 * and another for 'switchto_count > 0' but that feels like overkill.
 */
static bool ghost_in_switchto(struct rq *rq)
{
	return rq->ghost.switchto_count ? true : false;
}

/*
 * Returns 0 if we should produce a message for the task, < 0 otherwise.
 *
 */
static inline int __task_deliver_common(struct rq *rq, struct task_struct *p)
{
	lockdep_assert_held(&rq->lock);

	/*
	 * There should not be any deferred TASK_NEW at this point so WARN
	 * and proceed. The agent will also flag that it received a msg from
	 * an unknown task which is useful in case kernel log is unavailable.
	 * (for e.g. see b/193059731).
	 */
	WARN_ON_ONCE(p->ghost.new_task);

	/*
	 * Inhibit tasks msgs until agent acknowledges receipt of an earlier
	 * TASK_DEPARTED (by freeing the task's status_word). This ensures
	 * that msgs belonging to the previous incarnation of the task are
	 * drained before any msg from its current incarnation is produced.
	 */
	return 0;
}

static void task_deliver_msg_task_new(struct rq *rq, struct task_struct *p,
				      bool runnable)
{
	struct bpf_ghost_msg msg;
	memset(&msg, 0, sizeof(msg));
	struct enoki_msg_payload_task_new *payload = &msg.newt;

	msg.type = MSG_TASK_NEW;
	payload->pid = p->pid;
	payload->tgid = p->tgid;
	payload->runnable = runnable;
	payload->runtime = p->se.sum_exec_runtime;
	payload->prio = p->prio;
	if (p->ghost.twi.valid) {
		payload->wake_up_cpu = p->ghost.twi.wake_up_cpu;
	} else {
		payload->wake_up_cpu = -1;
	}

	produce_for_task(p, &msg);
}

static void task_deliver_msg_task_prio_changed(struct rq *rq, struct task_struct *p)
{
	struct bpf_ghost_msg msg;
	memset(&msg, 0, sizeof(msg));
	struct enoki_msg_payload_task_prio_changed *payload = &msg.prio_changed;

	msg.type = MSG_TASK_PRIO_CHANGED;
	payload->pid = p->pid;
	payload->prio = p->prio;

	produce_for_task(p, &msg);
}

static void task_deliver_msg_yield(struct rq *rq, struct task_struct *p)
{
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_task_yield *payload = &msg.yield;
	memset(&msg, 0, sizeof(msg));

	if (__task_deliver_common(rq, p))
		return;

	msg.type = MSG_TASK_YIELD;
	payload->pid = p->pid;
	payload->runtime = p->se.sum_exec_runtime;
	payload->cpu = cpu_of(rq);
	payload->cpu_seqnum = ++rq->ghost.cpu_seqnum;
	payload->agent_data = 0;
	payload->from_switchto = ghost_in_switchto(rq);

	produce_for_task(p, &msg);
}

static void task_deliver_msg_preempt(struct rq *rq, struct task_struct *p,
				     bool from_switchto, bool was_latched)
{
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_task_preempt *payload = &msg.preempt;
	memset(&msg, 0, sizeof(msg));

	if (__task_deliver_common(rq, p))
		return;

	/*
	 * It doesn't make sense to produce a TASK_PREEMPT while a switchto
	 * chain is active.
	 *
	 * Stated differently TASK_PREEMPT is only expected when:
	 * 1. the task is not part of an active switchto chain:
	 *    - a task that got oncpu via __schedule().
	 *    - a latched_task.
	 * 2. the task was in an active switchto chain that is now broken:
	 *    - preempted by a higher priority sched_class.
	 *    - preempted by the agent doing a transaction commit.
	 */
	WARN_ON_ONCE(from_switchto && rq->ghost.switchto_count > 0);

	msg.type = MSG_TASK_PREEMPT;
	payload->pid = p->pid;
	payload->runtime = p->se.sum_exec_runtime;
	payload->cpu = cpu_of(rq);
	payload->cpu_seqnum = ++rq->ghost.cpu_seqnum;
	payload->agent_data = 0;
	payload->from_switchto = from_switchto;
	payload->was_latched = was_latched;

	produce_for_task(p, &msg);
}

static void task_deliver_msg_blocked(struct rq *rq, struct task_struct *p)
{
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_task_blocked *payload = &msg.blocked;
	memset(&msg, 0, sizeof(msg));

	if (__task_deliver_common(rq, p))
		return;

	msg.type = MSG_TASK_BLOCKED;
	payload->pid = p->pid;
	payload->runtime = p->se.sum_exec_runtime;
	payload->cpu = cpu_of(rq);
	payload->cpu_seqnum = ++rq->ghost.cpu_seqnum;
	payload->from_switchto = ghost_in_switchto(rq);

	produce_for_task(p, &msg);
}

static void task_deliver_msg_dead(struct rq *rq, struct task_struct *p)
{
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_task_dead *payload = &msg.dead;
	memset(&msg, 0, sizeof(msg));

	if (__task_deliver_common(rq, p))
		return;

	msg.type = MSG_TASK_DEAD;
	payload->pid = p->pid;
	produce_for_task(p, &msg);
}

static void task_deliver_msg_departed(struct rq *rq, struct task_struct *p)
{
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_task_departed *payload = &msg.departed;
	memset(&msg, 0, sizeof(msg));

	if (__task_deliver_common(rq, p))
		return;

	msg.type = MSG_TASK_DEPARTED;
	payload->pid = p->pid;
	payload->cpu = cpu_of(rq);
	payload->cpu_seqnum = ++rq->ghost.cpu_seqnum;
	if (task_current(rq, p) && ghost_in_switchto(rq))
		payload->from_switchto = true;
	else
		payload->from_switchto = false;
	payload->was_current = task_current(rq, p);

	produce_for_task(p, &msg);
}

static void task_deliver_msg_affinity_changed(struct rq *rq,
					      struct task_struct *p,
					      struct cpumask *mask)
{
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_task_affinity_changed *payload =
		&msg.affinity;
	memset(&msg, 0, sizeof(msg));

	/*
	 * A running task can be switched into ghost while it is executing
	 * sched_setaffinity. In this case the TASK_NEW msg is held pending
	 * until the task schedules and producing the TASK_AFFINITY_CHANGED
	 * msg is useless at best since the agent has no idea about this task.
	 */
	if (unlikely(p->ghost.new_task))
		return;

	if (__task_deliver_common(rq, p))
		return;

	msg.type = MSG_TASK_AFFINITY_CHANGED;
	payload->pid = p->pid;
	payload->cpumask = cpumask_bits(mask)[0];

	produce_for_task(p, &msg);
}

static void task_deliver_msg_latched(struct rq *rq, struct task_struct *p,
				     bool latched_preempt)
{
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_task_latched *payload = &msg.latched;
	memset(&msg, 0, sizeof(msg));

	if (__task_deliver_common(rq, p))
		return;

	msg.type = MSG_TASK_LATCHED;
	payload->pid = p->pid;
	payload->commit_time = ktime_get_ns();
	payload->cpu = cpu_of(rq);
	payload->cpu_seqnum = ++rq->ghost.cpu_seqnum;
	payload->latched_preempt = latched_preempt;

	produce_for_task(p, &msg);
}

static inline bool deferrable_wakeup(struct task_struct *p)
{
#ifdef notyet
	/*
	 * If 'p' held a lock while it was blocked then the wakeup
	 * is not deferrable since other tasks might be waiting on it.
	 */
	if (p->lockdep_depth)
		return false;
#endif

	return p->sched_deferrable_wakeup;
}

static void task_deliver_msg_wakeup(struct rq *rq, struct task_struct *p)
{
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_task_wakeup *payload = &msg.wakeup;
	memset(&msg, 0, sizeof(msg));

	if (__task_deliver_common(rq, p))
		return;

	msg.type = MSG_TASK_WAKEUP;
	payload->pid = p->pid;
	payload->agent_data = 0;
	payload->deferrable = deferrable_wakeup(p);
	payload->last_ran_cpu = p->ghost.twi.last_ran_cpu;
	payload->wake_up_cpu = p->ghost.twi.wake_up_cpu;
	payload->waker_cpu = p->ghost.twi.waker_cpu;

	produce_for_task(p, &msg);
}

static void task_deliver_msg_switchto(struct rq *rq, struct task_struct *p)
{
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_task_switchto *payload = &msg.switchto;
	memset(&msg, 0, sizeof(msg));

	if (__task_deliver_common(rq, p))
		return;

	msg.type = MSG_TASK_SWITCHTO;
	payload->pid = p->pid;
	payload->runtime = p->se.sum_exec_runtime;
	payload->cpu = cpu_of(rq);
	payload->cpu_seqnum = ++rq->ghost.cpu_seqnum;

	produce_for_task(p, &msg);
}

static inline int cpu_deliver_msg_pnt(struct rq *rq,
				      struct enoki_sched_type *sched_type)
{
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_pnt *payload;
	struct task_struct *curr = rq->curr;
	int ret;
	memset(&msg, 0, sizeof(msg));
	payload = &msg.pnt;

	msg.type = MSG_PNT;
	payload->cpu = cpu_of(rq);
	if (!curr || !task_has_ghost_policy(curr) || curr->on_rq & DEQUEUE_SLEEP) {
		payload->is_curr = false;
	} else {
		payload->is_curr = true;
		payload->curr_pid = curr->pid;
		payload->curr_runtime = curr->se.sum_exec_runtime;
	}

	produce_for_sched_type(sched_type, &msg);
	if (payload->pick_task) {
		return payload->ret_pid;
	} else {
		return -1;
	}
}

static inline void cpu_deliver_msg_pnt_err(struct rq *rq,
					int pid,
					int err,
				      struct enoki_sched_type *sched_type)
{
	struct bpf_ghost_msg msg;
	struct enoki_msg_payload_pnt_err *payload;
	int ret;
	memset(&msg, 0, sizeof(msg));
	payload = &msg.pnt_err;
	msg.type = MSG_PNT_ERR;
	payload->cpu = cpu_of(rq);
	payload->pid = pid;
	payload->err = err;
	produce_for_sched_type(sched_type, &msg);
}

static void release_from_ghost(struct rq *rq, struct task_struct *p)
{
	ulong flags;


	lockdep_assert_held(&rq->lock);
	lockdep_assert_held(&p->pi_lock);

	WARN_ON_ONCE(p->ghost.new_task);

	if (p->state != TASK_DEAD) {
		task_deliver_msg_departed(rq, p);
	} else {
		task_deliver_msg_dead(rq, p);
	}
	WARN_ON_ONCE(p->state != TASK_DEAD);
}

static void ghost_delayed_put_task_struct(struct rcu_head *rhp)
{
	struct task_struct *tsk = container_of(rhp, struct task_struct,
					       ghost.rcu);
	put_task_struct(tsk);
}

static void task_dead_ghost(struct task_struct *p)
{
	struct rq_flags rf;
	struct rq *rq;
	struct callback_head *head;

	WARN_ON_ONCE(preemptible());

	rq = task_rq_lock(p, &rf);
	release_from_ghost(rq, p);
	head = splice_balance_callbacks(rq);
	task_rq_unlock(rq, p, &rf);

	get_task_struct(p);
	call_rcu(&p->ghost.rcu, ghost_delayed_put_task_struct);

	/*
	 * 'rq_pin_lock' issues a warning when the there are pending callback
	 * functions for the runqueue. The point of this warning is to ensure
	 * that callbacks are run in a timely manner
	 * (https://lkml.org/lkml/2020/9/11/1027).
	 *
	 * When 'release_from_ghost' adds a callback to the balance queue in the
	 * task_dead path, there is no subsequent call to 'balance_callbacks'
	 * before 'rq_pin_lock' is called. This causes the warning to be issued.
	 *
	 * To avoid the warning, we manually call 'balance_callbacks' here.
	 */
	balance_callbacks(rq, head);
}

/*
 * Update the scheduling state used by pick_next_task_ghost().
 */
static void ghost_set_pnt_state(struct rq *rq, struct task_struct *p,
				int run_flags)
{
	lockdep_assert_held(&rq->lock);

	rq->ghost.must_resched = false;
	rq->ghost.run_flags = run_flags;
}

static void _ghost_task_preempted(struct rq *rq, struct task_struct *p,
				  bool was_latched)
{
	bool from_switchto;

	lockdep_assert_held(&rq->lock);
	VM_BUG_ON(task_rq(p) != rq);

       /*
        * When TASK_PREEMPTED is produced before returning from pick_next_task
        * (e.g. via pick_next_ghost_agent) we don't have an up-to-date runtime
        * since put_prev_task() hasn't been called yet.
        *
        * Therefore if 'p == rq->curr' we must do update_curr_ghost() by hand.
        */
       if (p == rq->curr)
               update_curr_ghost(rq);

	/*
	 * If a latched task was preempted then by definition it was not
	 * part of any switchto chain.
	 */
	from_switchto = was_latched ? false : ghost_in_switchto(rq);

	/* Produce MSG_TASK_PREEMPT into 'p->ghost.dst_q' */
	task_deliver_msg_preempt(rq, p, from_switchto, was_latched);

}

void ghost_task_preempted(struct rq *rq, struct task_struct *p)
{
	lockdep_assert_held(&rq->lock);
	VM_BUG_ON(task_rq(p) != rq);

	_ghost_task_preempted(rq, p, false);
}

void ghost_task_got_oncpu(struct rq *rq, struct task_struct *p)
{
	lockdep_assert_held(&rq->lock);
	VM_BUG_ON(task_rq(p) != rq);

	/*
	 * We must defer sending TASK_LATCHED until any prev ghost tasks got off
	 * cpu.  Otherwise the agent will have a hard time reconciling the
	 * current cpu state.
	 */
	if (rq->ghost.run_flags & SEND_TASK_LATCHED) {
		task_deliver_msg_latched(rq, p, false);
		/* Do not send the message more than once per commit. */
		rq->ghost.run_flags &= ~SEND_TASK_LATCHED;
	}
}

static void _ghost_task_new(struct rq *rq, struct task_struct *p, bool runnable)
{
	lockdep_assert_held(&rq->lock);
	VM_BUG_ON(task_rq(p) != rq);

       /* See explanation in ghost_task_preempted() */
       if (p == rq->curr)
               update_curr_ghost(rq);

	task_deliver_msg_task_new(rq, p, runnable);
}

void ghost_task_new(struct rq *rq, struct task_struct *p)
{
	_ghost_task_new(rq, p, task_on_rq_queued(p));
}

static void ghost_task_yield(struct rq *rq, struct task_struct *p)
{
	lockdep_assert_held(&rq->lock);
	VM_BUG_ON(task_rq(p) != rq);

       /* See explanation in ghost_task_preempted() */
       if (p == rq->curr)
               update_curr_ghost(rq);

	task_deliver_msg_yield(rq, p);
}

static void ghost_task_blocked(struct rq *rq, struct task_struct *p)
{
	lockdep_assert_held(&rq->lock);
	VM_BUG_ON(task_rq(p) != rq);

	task_deliver_msg_blocked(rq, p);
}

/*
 * Checks that the run flags are valid for a ghOSt txn or a ghost_run syscall.
 */
static inline bool run_flags_valid(int run_flags, int valid_run_flags)
{
	if (run_flags & ~valid_run_flags)
		return false;

	/*
	 * RTLA_ON_IDLE can be combined with GHOST_NULL_GTID (which is equal to
	 * 0), but should not be combined with any other special GTIDs.
	 */
	if ((run_flags & RTLA_ON_IDLE))
		return false;

	if ((run_flags & NEED_CPU_NOT_IDLE))
		return false;

	return true;
}


static int __ghost_run_pid_on(uint64_t pid, int run_flags,
			       int cpu)
{
	struct rq_flags rf;
	struct rq *this_rq, *old_rq;
	int err = 0;
	struct task_struct *next;

	const int supported_flags = RTLA_ON_PREEMPT	|
				    RTLA_ON_BLOCKED	|
				    RTLA_ON_YIELD	|
				    NEED_L1D_FLUSH	|
				    ELIDE_PREEMPT	|
				    SEND_TASK_LATCHED	|
				    DO_NOT_PREEMPT	|
				    0;

	WARN_ON_ONCE(preemptible());

	if (cpu < 0)
		return -EINVAL;
	if (cpu >= nr_cpu_ids || !cpu_online(cpu))
		return -ERANGE;

	if (!run_flags_valid(run_flags, supported_flags))
		return -EINVAL;


	next = find_task_by_pid_ns(pid, &init_pid_ns);
	if (next == NULL) {
		return -ENOENT;
	}
	old_rq = task_rq(next);
	if (cpu_of(old_rq) == cpu) {
		// Already running on the correct CPU
		return 0;
	}
	this_rq = cpu_rq(cpu);
	double_lock_balance(this_rq, old_rq);

	err = validate_next_task(this_rq, next, /*state=*/ NULL);
	if (err) {
		double_unlock_balance(this_rq, old_rq);
		return err;
	}

	if (task_running(old_rq, next)) {
		double_unlock_balance(this_rq, old_rq);
		return -EBUSY;
	}

	deactivate_task(old_rq, next, 0);
	set_task_cpu(next, cpu);
	activate_task(this_rq, next, 0);

	double_unlock_balance(this_rq, old_rq);
	resched_curr(this_rq);

	return 0;
}

int ghost_run_pid_on(uint64_t pid, int run_flags, int cpu)
{
	return __ghost_run_pid_on(pid, run_flags, cpu);
}


#ifndef SYS_SWITCHTO_SWITCH_FLAGS_LAZY_EXEC_CLOCK
#define SYS_SWITCHTO_SWITCH_FLAGS_LAZY_EXEC_CLOCK	0x10000
#endif

void ghost_switchto(struct rq *rq, struct task_struct *prev,
		    struct task_struct *next, int switchto_flags)
{
	lockdep_assert_held(&rq->lock);
	VM_BUG_ON(prev != rq->curr);
	VM_BUG_ON(prev->state == TASK_RUNNING);
	VM_BUG_ON(next->state == TASK_RUNNING);
	VM_BUG_ON(!ghost_class(prev->sched_class));
	VM_BUG_ON(!ghost_class(next->sched_class));
	VM_BUG_ON(rq->ghost.check_prev_preemption);
	VM_BUG_ON(rq->ghost.switchto_count < 0);

	if (switchto_flags & SYS_SWITCHTO_SWITCH_FLAGS_LAZY_EXEC_CLOCK) {
		next->se.exec_start = prev->se.exec_start;
	} else {
		update_curr_ghost(rq);
		next->se.exec_start = rq_clock_task(rq);
	}

	list_del_init(&prev->ghost.run_list);

	list_add_tail(&next->ghost.run_list, &rq->ghost.tasks);
	next->ghost.last_runnable_at = 0;	/* we're on_cpu */

	if (++rq->ghost.switchto_count == 1) {
		/*
		 * Produce MSG_TASK_SWITCHTO but don't wake up the agent.
		 * In per-cpu models, agent wakeup will preempt the task
		 * and break the switchto chain before it even gets started.
		 */
		task_deliver_msg_switchto(rq, prev);
	}
}

void ghost_cpu_idle(void)
{
	struct rq *rq = this_rq();
	struct rq_flags rf;

	WARN_ON_ONCE(current != rq->idle);

	rq_lock_irq(rq, &rf);
	if (rq->ghost.dont_idle_once) {
		set_tsk_need_resched(current);
		set_preempt_need_resched();
		rq->ghost.dont_idle_once = false;
	}
	rq_unlock_irq(rq, &rf);
}

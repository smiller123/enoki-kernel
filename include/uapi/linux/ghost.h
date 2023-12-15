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

#ifndef _UAPI_SCHED_GHOST_H_
#define _UAPI_SCHED_GHOST_H_

#ifdef __KERNEL__
#include <linux/limits.h>
#else
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#endif

// NOLINTBEGIN

/*
 * Define SCHED_GHOST via the ghost uapi unless it has already been defined
 * via the proper channels (i.e. the official <sched.h> uapi header file).
 */
#ifndef SCHED_GHOST
#define SCHED_GHOST		18
#endif

struct enoki_ioc_create_queue {
	uint32_t elems;
	uint32_t flags;
	ulong mapsize;
	int id;
};

struct enoki_ioc_enter_queue {
	int id;
	uint32_t entries;
};

#define ENOKI_IOC_NULL			_IO('g', 0)
#define ENOKI_IOC_CREATE_QUEUE		_IOWR('g', 3, struct enoki_ioc_create_queue)
#define ENOKI_IOC_ENTER_QUEUE		_IOWR('g', 11, struct enoki_ioc_enter_queue)
#define ENOKI_IOC_CREATE_RECORD		_IOWR('g', 12, struct enoki_ioc_create_queue)
#define ENOKI_IOC_SEND_HINT		_IOWR('g', 13, const void __user *)
#define ENOKI_IOC_CREATE_REV_QUEUE	_IOWR('g', 14, struct enoki_ioc_create_queue)

/*
 * Queue APIs.
 */
struct enoki_queue_header {
	uint32_t offset;
	uint32_t nelems;	/* power-of-2 size of msgs */
	uint32_t head;
	uint32_t tail;
};
#define GHOST_QUEUE_VERSION	0

struct enoki_msg {
	uint16_t type;		/* message type */
	uint16_t length;	/* length of this message including payload */
	uint32_t seqnum;	/* sequence number for this msg source */
	uint32_t payload[0];	/* variable length payload */
};

/*
 * Messages are grouped by type and each type can have up to 64 messages.
 * (the limit of 64 is arbitrary).
 */
#define _MSG_TASK_FIRST	64
#define _MSG_TASK_LAST	(_MSG_TASK_FIRST + 64 - 1)

#define _MSG_CPU_FIRST	128
#define _MSG_CPU_LAST	(_MSG_CPU_FIRST + 64 - 1)

/* message types */
enum {
	/* misc msgs */
	MSG_NOP			= 0,

	/* task messages */
	MSG_TASK_DEAD		= _MSG_TASK_FIRST,
	MSG_TASK_BLOCKED,
	MSG_TASK_WAKEUP,
	MSG_TASK_NEW,
	MSG_TASK_PREEMPT,
	MSG_TASK_YIELD,
	MSG_TASK_DEPARTED,
	MSG_TASK_SWITCHTO,
	MSG_TASK_AFFINITY_CHANGED,
	MSG_TASK_LATCHED,
	MSG_TASK_SELECT_RQ,
	MSG_TASK_MIGRATE_RQ,
	MSG_TASK_PRIO_CHANGED,

	/* cpu messages */
	MSG_CPU_TICK		= _MSG_CPU_FIRST,
	MSG_CPU_TIMER_EXPIRED,
	MSG_CPU_NOT_IDLE,	/* requested via run_flags: NEED_CPU_NOT_IDLE */
	MSG_PNT,
	MSG_PNT_ERR,
	MSG_BALANCE,
	MSG_BALANCE_ERR,
	MSG_REREGISTER_PREPARE,
	MSG_REREGISTER_INIT,
	MSG_MSG_SIZE,
	MSG_REV_MSG_SIZE,
	MSG_SEND_HINT,
	MSG_CREATE_QUEUE,
	MSG_CREATE_REV_QUEUE,
	MSG_ENTER_QUEUE,
	MSG_UNREGISTER_QUEUE,
	MSG_UNREGISTER_REV_QUEUE,
	MSG_CLEANUP,
};

struct enoki_msg_payload_task_new {
	uint64_t pid;
	uint64_t tgid;
	uint64_t runtime;	/* cumulative runtime in ns */
	uint16_t runnable;
	int prio;
	int wake_up_cpu;
};

struct enoki_msg_payload_task_preempt {
	uint64_t pid;
	uint64_t runtime;	/* cumulative runtime in ns */
	uint64_t cpu_seqnum;	/* cpu sequence number */
	uint64_t agent_data;	/* used by bpf */
	int cpu;
	char from_switchto;
	char was_latched;
};

struct enoki_msg_payload_task_yield {
	uint64_t pid;
	uint64_t runtime;	/* cumulative runtime in ns */
	uint64_t cpu_seqnum;
	uint64_t agent_data;	/* used by bpf */
	int cpu;
	char from_switchto;
};

struct enoki_msg_payload_task_blocked {
	uint64_t pid;
	uint64_t runtime;	/* cumulative runtime in ns */
	uint64_t cpu_seqnum;
	int cpu;
	char from_switchto;
};

struct enoki_msg_payload_task_dead {
	uint64_t pid;
};

struct enoki_msg_payload_task_departed {
	uint64_t pid;
	uint64_t cpu_seqnum;
	int cpu;
	char from_switchto;
	char was_current;
};

struct enoki_msg_payload_task_affinity_changed {
	uint64_t pid;
	uint64_t cpumask;
};

struct enoki_msg_payload_task_wakeup {
	uint64_t pid;
	uint64_t agent_data;	/* used by bpf */
	char deferrable;	/* bool: 0 or 1 */

	int last_ran_cpu;	/*
				 * CPU that task last ran on (may be different
				 * than where it was last scheduled by the
				 * agent due to switchto).
				 */

	int wake_up_cpu;	/*
				 * CPU where the task was woken up (this is
				 * typically where the task last ran but it
				 * may also be the waker's cpu).
				 */

	int waker_cpu;		/* CPU of the waker task */
};

struct enoki_msg_payload_task_switchto {
	uint64_t pid;
	uint64_t runtime;	/* cumulative runtime in ns */
	uint64_t cpu_seqnum;
	int cpu;
};

struct enoki_msg_payload_task_latched {
	uint64_t pid;
	uint64_t commit_time;
	uint64_t cpu_seqnum;
	int cpu;
	char latched_preempt;
};

struct enoki_msg_payload_cpu_not_idle {
	int cpu;
	uint64_t next_pid;
};

struct enoki_msg_payload_cpu_tick {
	int cpu;
	int queued;
};

struct enoki_msg_payload_timer {
	int cpu;
	uint64_t cookie;
};

struct enoki_msg_payload_pnt {
	int cpu;
	bool is_curr;
	uint64_t curr_pid;
	uint64_t curr_runtime;
	bool pick_task;
	uint64_t ret_pid;
};

struct enoki_msg_payload_pnt_err {
	int cpu;
	uint64_t pid;
	int err;
};

struct enoki_msg_payload_balance_err {
	int cpu;
	uint64_t pid;
	int err;
};

struct enoki_msg_payload_select_task_rq {
	uint64_t pid;
	int waker_cpu;
	int prev_cpu;
	int ret_cpu;
};

struct enoki_msg_payload_migrate_task_rq {
	uint64_t pid;
	int new_cpu;
};

struct enoki_msg_payload_balance {
	int cpu;
	bool do_move;
	uint64_t move_pid;
};

struct enoki_msg_payload_task_prio_changed {
	uint64_t pid;
	int prio;
};

struct enoki_msg_payload_rereg_prep {
	void *data;
};

struct enoki_msg_payload_rereg_init {
	void *data;
};

struct enoki_msg_payload_msg_size {
	uint32_t msg_size;
};

struct enoki_msg_payload_send_hint {
	void *arg;
};

struct enoki_msg_payload_create_queue {
	void *q;
	uint64_t pid;
	int id;
};

struct enoki_msg_payload_enter_queue {
	int id;
	uint32_t entries;
};

struct enoki_msg_payload_unreg_queue {
	int id;
};

struct enoki_msg_payload_cleanup {
	struct file *record_file;
};

struct bpf_ghost_msg {
	union {
		struct enoki_msg_payload_task_dead	dead;
		struct enoki_msg_payload_task_blocked	blocked;
		struct enoki_msg_payload_task_wakeup	wakeup;
		struct enoki_msg_payload_task_new	newt;
		struct enoki_msg_payload_task_preempt	preempt;
		struct enoki_msg_payload_task_yield	yield;
		struct enoki_msg_payload_task_departed	departed;
		struct enoki_msg_payload_task_switchto	switchto;
		struct enoki_msg_payload_task_affinity_changed	affinity;
		struct enoki_msg_payload_task_latched	latched;
		struct enoki_msg_payload_cpu_tick	cpu_tick;
		struct enoki_msg_payload_timer		timer;
		struct enoki_msg_payload_cpu_not_idle	cpu_not_idle;
		struct enoki_msg_payload_pnt		pnt;
		struct enoki_msg_payload_pnt_err	pnt_err;
		struct enoki_msg_payload_select_task_rq select;
		struct enoki_msg_payload_migrate_task_rq migrate;
		struct enoki_msg_payload_balance	balance;
		struct enoki_msg_payload_balance_err	balance_err;
		struct enoki_msg_payload_task_prio_changed	prio_changed;
		struct enoki_msg_payload_rereg_prep	rereg_prep;
		struct enoki_msg_payload_rereg_init	rereg_init;
		struct enoki_msg_payload_msg_size	msg_size;
		struct enoki_msg_payload_send_hint	send_hint;
		struct enoki_msg_payload_create_queue	create_queue;
		struct enoki_msg_payload_create_queue	create_rev_queue;
		struct enoki_msg_payload_enter_queue	enter_queue;
		struct enoki_msg_payload_unreg_queue	unreg_queue;
		struct enoki_msg_payload_unreg_queue	unreg_rev_queue;
		struct enoki_msg_payload_cleanup	cleanup;
	};
	uint16_t type;
	uint32_t seqnum;
};

#ifdef __cplusplus
#include <atomic>
typedef std::atomic<uint32_t> _ghost_ring_index_t;
#else
typedef volatile uint32_t _ghost_ring_index_t;
#endif

struct enoki_ring {
	/*
	 * kernel produces at 'head & (nelems-1)' and
	 * agent consumes from 'tail & (nelems-1)'.
	 *
	 * kernel increments 'overflow' any time there aren't enough
	 * free slots to produce a message.
	 */
	void *msgs;
	uint32_t nelems;
	uint32_t head;
	uint32_t tail;

};

#define GHOST_MAX_QUEUE_ELEMS	65536	/* arbitrary */

/*
 * Define ghOSt syscall numbers here until they can be discovered via
 * <unistd.h>.
 */
#ifndef __NR_ghost_run
#define __NR_ghost_run	450
#endif
#ifndef __NR_ghost
#define __NR_ghost	451
#endif

/* flags accepted by ghost_run() */
#define RTLA_ON_PREEMPT	  (1 << 0)  /* Return To Local Agent on preemption */
#define RTLA_ON_BLOCKED	  (1 << 1)  /* Return To Local Agent on block */
#define RTLA_ON_YIELD	  (1 << 2)  /* Return To Local Agent on yield */
#define RTLA_ON_IDLE	  (1 << 5)  /* Return To Local Agent on idle */
#define NEED_L1D_FLUSH	  (1 << 6)  /* Flush L1 dcache before entering guest */
#define NEED_CPU_NOT_IDLE (1 << 7)  /* Notify agent when a non-idle task is
				     * scheduled on the cpu.
				     */
#define ELIDE_PREEMPT     (1 << 9)  /* Do not send TASK_PREEMPT if we preempt
				     * a previous ghost task on this cpu
				     */
#define SEND_TASK_LATCHED (1 << 10) /* Send TASK_LATCHED at commit time */
/* After the task is latched, don't immediately preempt it if the cpu local
 * agent is picked to run; wait at least until the next sched tick hits
 * (assuming the agent is still running). This provides a good tradeoff between
 * avoiding spurious preemption and preventing an unbounded blackout for the
 * latched task while the agent is runnable.
 */
#define DEFER_LATCHED_PREEMPTION_BY_AGENT (1 << 11)
#define DO_NOT_PREEMPT	  (1 << 12) /* Do not preempt running tasks */

/* txn->commit_flags */
#define COMMIT_AT_SCHEDULE	(1 << 0) /* commit when oncpu task schedules */
#define COMMIT_AT_TXN_COMMIT	(1 << 1) /* commit in GHOST_COMMIT_TXN op */
#define ALLOW_TASK_ONCPU	(1 << 2) /* If task is running on a remote cpu
					  * then let continue running there.
					  */
#define ELIDE_AGENT_BARRIER_INC	(1 << 3) /* Do not increment the agent
					  * barrier (ie. on successfully
					  * latching the task).
					  */
#define INC_AGENT_BARRIER_ON_FAILURE	(1 << 4) /* Increment agent_barrier
						  * on transaction failure.
						  */

/* Union of all COMMIT_AT_XYZ flags */
#define COMMIT_AT_FLAGS		(COMMIT_AT_SCHEDULE | COMMIT_AT_TXN_COMMIT)




/*
 * ghost tids referring to normal tasks always have a positive value:
 * (0 | 22 bits of actual pid_t | 41 bit non-zero seqnum)
 *
 * The embedded 'pid' following linux terminology is actually referring
 * to the thread id (i.e. what would be returned by syscall(__NR_gettid)).
 */
#define GHOST_TID_SEQNUM_BITS	41
#define GHOST_TID_PID_BITS	22

// NOLINTEND

#endif	/* _UAPI_SCHED_GHOST_H_ */

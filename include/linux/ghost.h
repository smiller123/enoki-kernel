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

#ifndef _SCHED_GHOST_H_
#define _SCHED_GHOST_H_

#include <linux/ioctl.h>
#include <linux/file.h>
#include <linux/kref.h>
#include <linux/workqueue.h>
#include <linux/ktime.h>

#define GHOST_MAX_SW_REGIONS	64
#define GHOST_CPU_DATA_REGION_SIZE \
	(sizeof(struct ghost_cpu_data) * num_possible_cpus())

struct ghost_agent_type {
	int policy;
	const void *agent;
	void (*process_message) (const void* agent, int type, int msglen, uint32_t barrier,
			void *payload, int payload_size, int *retval);
	struct module *owner;
	rwlock_t agent_lock;
	struct ghost_agent_type * next;
};

extern int register_ghost_agent(
		const void *agent,
		int policy,
		const void *process_message
);
extern int reregister_ghost_agent(
		const void *agent,
		int policy,
		const void *process_message
);
extern int unregister_ghost_agent(const void*);

extern int ghost_run_pid_on(uint64_t pid, int run_flags, int cpu);

struct enclave_work {
	struct list_head link;
	unsigned int nr_decrefs;
	bool run_task_reaper;
};

/*
 * ghost_enclave is a container for the agents, queues and sw_regions
 * that express the scheduling policy for a set of CPUs.
 */
struct ghost_enclave {
	/*
	 * 'lock' serializes mutation of 'sw_region_list' as well as
	 * allocation and freeing of status words within a region.
	 *
	 * 'lock' also serializes mutation of 'def_q'.
	 *
	 * 'lock' requires the irqsave variant of spin_lock because
	 * it is called in code paths with the 'rq->lock' held and
	 * interrupts disabled.
	 */
	spinlock_t lock;
	struct kref kref;
	struct list_head sw_region_list;
	ulong sw_region_ids[BITS_TO_LONGS(GHOST_MAX_SW_REGIONS)];

	struct ghost_cpu_data **cpu_data;
	struct cpumask cpus;

	struct ghost_queue *def_q;	/* default queue */

	struct list_head inhibited_task_list;
	struct list_head task_list;	/* all non-agent tasks in the enclave */
	unsigned long nr_tasks;
	struct work_struct task_reaper;
	struct enclave_work ew;		/* to defer work while holding locks */
	struct work_struct enclave_actual_release;/* work for enclave_release */

	/*
	 * max_unscheduled: How long a task can be runnable, but unscheduled,
	 * before the kernel thinks the enclave failed and queues the
	 * enclave_destroyer.
	 */
	ktime_t max_unscheduled;
	struct work_struct enclave_destroyer;

	bool switchto_disabled;
	bool wake_on_waker_cpu;
	bool commit_at_tick;

	unsigned long id;
	int is_dying;
	bool agent_online;		/* userspace says agent can schedule. */
	struct kernfs_node *enclave_dir;

#ifdef CONFIG_BPF
	struct bpf_prog *bpf_tick;
	struct bpf_prog *bpf_pnt;
	struct bpf_prog *bpf_msg_send;
#endif
};

struct ghost_queue {
	/*
	 * 'lock' protects 'refs' as well as the association between a
	 *  message source and its queue and status_word.
	 *
	 *  See go/ghost-queue-change for more details.
	 */
	spinlock_t lock;
	struct kref kref;

	struct ghost_enclave *enclave;

	/* 'ring' and 'nelems' are read-only after initialization */
	struct ghost_ring *ring;
	uint32_t nelems;	/* power-of-2 size of ghost_ring.msgs[] */

	void *addr;		/*
				 * address of vmalloc'ed region; this is
				 * deliberately a 'void *' instead of
				 * 'ghost_queue_header *' so we don't
				 * read it even inadvertently.
				 */

	ulong mapsize;		/* size of the vmalloc'ed region */

	struct queue_notifier *notifier;  /* rcu-protected agent wakeup info */

	struct rcu_head rcu;		/* deferred free glue */
	struct work_struct free_work;
	void (*process_message) (int type, int msglen, uint32_t barrier,
			void *payload, int payload_size);
};

struct ghost_queue *fd_to_queue(struct fd f);

//void ghost_queue_register_process_func(struct ghost_queue *q,
//		                       int (*func)(int type, int msglen,
//					       uint32_t barrier, void *payload,
//					       int payload_size));

// NOLINTEND

#endif	/* _SCHED_GHOST_H_ */

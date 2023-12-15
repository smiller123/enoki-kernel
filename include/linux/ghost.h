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

struct enoki_sched_type {
	int policy;
	uint32_t msg_size;
	const void *sched;
	struct enoki_queue *record_queue;
	void (*process_message) (const void* agent,
			int type, int msglen, uint32_t barrier,
			void *payload, int payload_size, int *retval);
	void (*pick_next_task) (const void* agent,
			int cpu, int *retval);
	struct module *owner;
	rwlock_t sched_lock;
	struct enoki_sched_type * next;
};

extern int register_enoki_sched(
		const void *sched,
		int policy,
		const void *process_message
);
extern int reregister_enoki_sched(
		const void *sched,
		int policy,
		const void *process_message
);
extern int unregister_enoki_sched(const void*);

struct enoki_queue {
	/*
	 * 'lock' protects 'refs' as well as the association between a
	 *  message source and its queue and status_word.
	 *
	 *  See go/ghost-queue-change for more details.
	 */
	spinlock_t lock;
	struct kref kref;
	int policy;
	int id;


	uint32_t nelems;	/* power-of-2 size of ghost_ring.msgs[] */
	uint32_t mask;
	uint32_t msg_size;

	void *addr;		
	/*
				 * address of vmalloc'ed region; this is
				 * deliberately a 'void *' instead of
				 * 'ghost_queue_header *' so we don't
				 * read it even inadvertently.
				 */

	ulong mapsize;		/* size of the vmalloc'ed region */


	struct rcu_head rcu;		/* deferred free glue */
	struct work_struct free_work;
};

int file_write_deferred(char *buf);

// NOLINTEND

#endif	/* _SCHED_GHOST_H_ */

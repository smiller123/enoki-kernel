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

#include "sched.h"

#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/sysfs.h>
#include <linux/kernfs.h>
#include <linux/mm.h>
#include <linux/seq_buf.h>
#include <linux/seq_file.h>
#include <linux/user_namespace.h>
#include <linux/ghost.h>

#include "../../fs/kernfs/kernfs-internal.h"

static struct kernfs_root *ghost_kfs_root;

struct gf_dirent {
	char			*name;
	umode_t			mode;
	struct kernfs_ops	*ops;
	loff_t			size;
	bool			is_dir;
};



static int of_to_policy(struct kernfs_open_file *of)
{
	return (int) of->kn->priv;
}

static int seq_to_policy(struct seq_file *sf)
{
	struct kernfs_open_file *of = sf->private;

	return of_to_policy(of);
}


static int gf_ctl_open(struct kernfs_open_file *of)
{
	return 0;
}

static void gf_ctl_release(struct kernfs_open_file *of)
{
}

static int gf_ctl_show(struct seq_file *sf, void *v)
{
	int policy = seq_to_policy(sf);

	seq_printf(sf, "%lu", policy);
	return 0;
}

static int gf_top_ctl_show(struct seq_file *sf, void *v)
{
	seq_printf(sf, "0");
	return 0;
}


static ssize_t gf_ctl_write(struct kernfs_open_file *of, char *buf,
			    size_t len, loff_t off)
{

	return len;
}

static long gf_ctl_ioctl(struct kernfs_open_file *of, unsigned int cmd,
			 unsigned long arg)
{
	int policy = of_to_policy(of);
	printk(KERN_INFO "got into ioctl cmd %d", cmd);
	if (cmd == ENOKI_IOC_CREATE_QUEUE) {
		return enoki_create_queue(policy,
				(struct enoki_ioc_create_queue __user *)arg);
	}
	if (cmd == ENOKI_IOC_CREATE_REV_QUEUE) {
		return enoki_create_reverse_queue(policy,
				(struct enoki_ioc_create_queue __user *)arg);
	}
	if (cmd == ENOKI_IOC_ENTER_QUEUE) {
		return enoki_enter_queue(policy,
				(struct enoki_ioc_enter_queue __user *)arg);
	}
	if (cmd == ENOKI_IOC_CREATE_RECORD) {
		return enoki_create_record(policy,
				(struct enoki_ioc_create_queue __user *)arg);
	}
	if (cmd == ENOKI_IOC_SEND_HINT) {
		return enoki_send_hint(policy, (void __user *) arg);
	}
	return 0;
}

static long gf_top_ctl_ioctl(struct kernfs_open_file *of, unsigned int cmd,
			 unsigned long arg)
{
	if (cmd == ENOKI_IOC_CREATE_RECORD) {
		return enoki_create_top_record(
				(struct enoki_ioc_create_queue __user *)arg);
	}
	return 0;
}

static struct kernfs_ops gf_ops_sched_ctl = {
	.open			= gf_ctl_open,
	.release		= gf_ctl_release,
	.seq_show		= gf_ctl_show,
	.write			= gf_ctl_write,
	.ioctl			= gf_ctl_ioctl,
};

static struct gf_dirent sched_dirtab[] = {
	{
		.name		= "ctl",
		.mode		= 0664,
		.ops		= &gf_ops_sched_ctl,
	}
};


/* Caller is responsible for cleanup.  Removing the parent will suffice. */
static int gf_add_files(struct kernfs_node *parent, struct gf_dirent *dirtab,
			void *priv)
{
	struct gf_dirent *gft;
	struct kernfs_node *kn;

	for (gft = dirtab; gft->name; gft++) {
		if (gft->is_dir) {
			kn = kernfs_create_dir(parent, gft->name, gft->mode,
					       NULL);
		} else {
			kn = kernfs_create_file(parent, gft->name, gft->mode,
						gft->size, gft->ops, priv);
		}
		if (IS_ERR(kn))
			return PTR_ERR(kn);
	}
	return 0;
}

int setup_sched_ioctl(int policy)
{
	struct kernfs_node *dir;
	char name[31];
	int ret;

	if (snprintf(name, sizeof(name), "enclave_%d", policy) >= sizeof(name)) {
		ret = -ENOSPC;
		goto out_e;
	}

	dir = kernfs_create_dir(ghost_kfs_root->kn, name, 0555, NULL);
	if (IS_ERR(dir)) {
		ret = PTR_ERR(dir);
		goto out_e;
	}

	ret = gf_add_files(dir, sched_dirtab, (void *)policy);
	if (ret)
		goto out_dir;

	kernfs_activate(dir);	/* recursive */

	return 0;

out_dir:
	kernfs_remove(dir);	/* recursive */
out_e:
	return ret;
}


static struct kernfs_ops gf_ops_top_ctl = {
	.open			= gf_ctl_open,
	.release		= gf_ctl_release,
	.seq_show		= gf_top_ctl_show,
	.write			= gf_ctl_write,
	.ioctl			= gf_top_ctl_ioctl,
};

static struct gf_dirent top_dirtab[] = {
	{
		.name		= "ctl",
		.mode		= 0664,
		.ops		= &gf_ops_top_ctl,
	},
	{0}
};

static int __init ghost_setup_root(void)
{
	int ret = 0;
	struct kernfs_root *fs_root;

	fs_root = kernfs_create_root(NULL, KERNFS_ROOT_CREATE_DEACTIVATED |
				     KERNFS_ROOT_EXTRA_OPEN_PERM_CHECK, NULL);
	if (IS_ERR(fs_root))
		return PTR_ERR(fs_root);

	ret = gf_add_files(fs_root->kn, top_dirtab, NULL);
	if (ret) {
		kernfs_destroy_root(fs_root);
		return ret;
	}

	ghost_kfs_root = fs_root;

	kernfs_activate(ghost_kfs_root->kn);

	return ret;
}

static int ghost_get_tree(struct fs_context *fc)
{
	int ret;

	ret = kernfs_get_tree(fc);
	if (ret)
		return ret;

	return 0;
}

static void ghost_fs_context_free(struct fs_context *fc)
{
	struct kernfs_fs_context *kfc = fc->fs_private;

	kernfs_free_fs_context(fc);
	kfree(kfc);
}

static const struct fs_context_operations ghost_fs_context_ops = {
	.free		= ghost_fs_context_free,
	.get_tree	= ghost_get_tree,
};

static int ghost_init_fs_context(struct fs_context *fc)
{
	struct kernfs_fs_context *kfc;

	/* Technically, this should be in uapi/linux/magic.h. */
	#define GHOST_SUPER_MAGIC 0xBAD1DEA2

	kfc = kzalloc(sizeof(struct kernfs_fs_context), GFP_KERNEL);
	if (!kfc)
		return -ENOMEM;

	kfc->root = ghost_kfs_root;
	kfc->magic = GHOST_SUPER_MAGIC;
	fc->fs_private = kfc;
	fc->ops = &ghost_fs_context_ops;
	put_user_ns(fc->user_ns);
	fc->user_ns = get_user_ns(&init_user_ns);
	fc->global = true;
	return 0;
}

static void ghost_kill_sb(struct super_block *sb)
{
	kernfs_kill_sb(sb);
}

static struct file_system_type ghost_fs_type = {
	.name			= "ghost",
	.init_fs_context	= ghost_init_fs_context,
	.kill_sb		= ghost_kill_sb,
};

static int __init ghostfs_init(void)
{
	int ret = 0;

	ret = ghost_setup_root();
	if (ret)
		return ret;

	ret = sysfs_create_mount_point(fs_kobj, "ghost");
	if (ret)
		goto cleanup_root;

	ret = register_filesystem(&ghost_fs_type);
	if (ret)
		goto cleanup_mountpoint;

	return 0;

cleanup_mountpoint:
	sysfs_remove_mount_point(fs_kobj, "ghost");
cleanup_root:
	kernfs_destroy_root(ghost_kfs_root);
	ghost_kfs_root = NULL;

	return ret;
}

static void __exit ghostfs_exit(void)
{
	unregister_filesystem(&ghost_fs_type);
	sysfs_remove_mount_point(fs_kobj, "ghost");
	kernfs_destroy_root(ghost_kfs_root);
}

late_initcall(ghostfs_init);
__exitcall(ghostfs_exit);

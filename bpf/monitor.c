// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook

#include "vmlinux.h"
#include "../header/monitor_defs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>

char _license[] SEC("license") = "GPL";

struct monitor_ctx {
	/* which hook point is called */
	u32 event_id; /* u32? */

	/* subject information */	
	u32 pid;
	u32 ppid;
	u32 uid;

	u32 pid_id;
	u32 mnt_id;
	
	u32 pid_from_ns;
	u32 tid_from_ns;

	/* object information */
	/* could be EMPTY if not used */
	u32 o_pid;
	u32 o_uid;
	u32 o_newuid; /* for lsm/cred_prepare */
	u32 pad;
};

struct monitor_ctx_file {
	struct monitor_ctx mctx;
	char filename[NAME_MAX]; // path? or name?
	u64 o_ino;
	u32 o_mode;
	int o_mask;
};

struct monitor_ctx_filesys {
	struct monitor_ctx mctx;
	char dev_name[DEV_NAME_MAX];
	char type[FS_TYPE_MAX];
};

struct conid{
	char id[64];
};

struct nskey {
	u32 pid_id;
	u32 mnt_id;
};

struct inner_pids {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, int);
	__uint(max_entries, PID_MAX);
} pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(key_size, sizeof(struct conid));
	__uint(max_entries, DOCKER_MAX); 
	__array(values, struct inner_pids);
} conid2pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct nskey);
	__type(value, struct conid);
	__uint(max_entries, PID_MAX); 
} ns2conid SEC(".maps");

static __always_inline u32 get_task_pid(struct task_struct *task) {
	
	return BPF_CORE_READ(task, tgid);
}

static __always_inline u32 get_task_ppid(struct task_struct *task) {

	return BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline u32 get_task_uid(struct task_struct *task) {
	
	return BPF_CORE_READ(task, cred, uid.val);

}

static __always_inline u32 get_task_ns_pid(struct task_struct *task) {
	unsigned int l;
	u32 pid_from_ns;

	BPF_CORE_READ_INTO(&l, task, nsproxy, pid_ns_for_children, level);
	BPF_CORE_READ_INTO(&pid_from_ns, task, thread_pid, numbers[l].nr);
	return pid_from_ns;

}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task) {
	unsigned int l;
	u32 tgid_from_ns;

	BPF_CORE_READ_INTO(&l, task, nsproxy, pid_ns_for_children, level);
	BPF_CORE_READ_INTO(&tgid_from_ns, task, group_leader, thread_pid, numbers[l].nr);
	return tgid_from_ns;	
}

static __always_inline u32 get_task_mnt_id(struct task_struct *task) {
	
	return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);	
}

static __always_inline u32 get_task_pid_id(struct task_struct *task) {
	
	return BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);	
}

static __always_inline void set_mctx_subject(struct monitor_ctx *mctx, struct task_struct *task) {
	mctx->pid = get_task_pid(task);
	mctx->ppid = get_task_ppid(task);
	mctx->uid = get_task_uid(task);

	mctx->mnt_id = get_task_mnt_id(task);
	mctx->pid_id = get_task_pid_id(task);
	
	mctx->pid_from_ns = get_task_ns_tgid(task);
	mctx->tid_from_ns = get_task_ns_pid(task);
	
	mctx->pad = EMPTY;
}

static __always_inline void set_mctx_subject_empty(struct monitor_ctx *mctx) {
	mctx->pid = EMPTY;
	mctx->ppid = EMPTY;
	mctx->uid = EMPTY;

	mctx->mnt_id = EMPTY;
	mctx->pid_id = EMPTY;
	
	mctx->pid_from_ns = EMPTY;
	mctx->tid_from_ns = EMPTY;

	mctx->pad = EMPTY;
}
/*
SEC("lsm/cred_prepare")
int BPF_PROG(lsm_cred_preare, struct cred *new, const struct cred *old, gfp_t gfp, int ret)
{
	if (ret)	return ret;

	struct monitor_ctx mctx;
	struct task_struct *t;

	mctx.event_id = LSM_CRED_PREPARE;

	t = (struct task_struct *)bpf_get_current_task();
	if (t){
		set_mctx_subject(&mctx, t);
	}
	else {
		set_mctx_subject_empty(&mctx);
	}
	mctx.o_pid = EMPTY;
	mctx.o_uid = old->uid.val;
	mctx.o_newuid = new->uid.val;

	bpf_ringbuf_output(&ringbuf, &mctx, sizeof(struct monitor_ctx), 0);

	//if ((m.old_uid != 0) && (m.old_uid != m.uid))
	//	return -EPERM;
	
	return 0;
}
*/

SEC("lsm/task_alloc")
int BPF_PROG(lsm_task_alloc, struct task_struct *task, unsigned long clone_flags, int ret)
{
	if (ret)	return ret;

	struct monitor_ctx mctx;
	struct task_struct *t;

	mctx.event_id = LSM_TASK_ALLOC;

	t = (struct task_struct *)bpf_get_current_task();
	if (t){
		set_mctx_subject(&mctx, t);
	}
	else {
		set_mctx_subject_empty(&mctx);
	}
	mctx.o_pid = get_task_pid(task);
	mctx.o_uid = get_task_uid(task);
	mctx.o_newuid = EMPTY;

	bpf_ringbuf_output(&ringbuf, &mctx, sizeof(struct monitor_ctx), 0);

	return 0;
}

SEC("lsm/task_free")
void BPF_PROG(lsm_task_free, struct task_struct *task)
{

	struct monitor_ctx mctx;
	struct task_struct *t;

	mctx.event_id = LSM_TASK_FREE;
	
	t = (struct task_struct *)bpf_get_current_task();
	if (t) {
		set_mctx_subject(&mctx, t);
	} else {
		set_mctx_subject_empty(&mctx);
	}
	mctx.o_pid = get_task_pid(task);
	mctx.o_uid = get_task_uid(task);
	mctx.o_newuid = EMPTY;

	bpf_ringbuf_output(&ringbuf, &mctx, sizeof(struct monitor_ctx), 0);
}

/*
SEC("lsm/bprm_committed_creds")
void BPF_PROG(lsm_bprm_committed_creds, struct linux_binprm *bprm)
{
	struct monitor_ctx_bin *mctx_bin;
	struct task_struct *t;
	//char *filename;
	int len;

	mctx_bin = (struct monitor_ctx_bin *) bpf_ringbuf_reserve(&ringbuf, sizeof(struct monitor_ctx_bin), 0);
	if (!mctx_bin) {
		return;
	} 
	
	mctx_bin->mctx.event_id = LSM_BPRM_COMMITTED_CREDS;
	
	t = (struct task_struct *)bpf_get_current_task();
	if (t) {
		set_mctx_subject(&mctx_bin->mctx, t);
	} else {
		set_mctx_subject_empty(&mctx_bin->mctx);
	}
	//get_bprm_filename(bprm, mctx_bin->filename);
	
	mctx_bin->mctx.o_pid = EMPTY;
	mctx_bin->mctx.o_uid = EMPTY;
	mctx_bin->mctx.o_newuid = EMPTY;
	//filename = mctx_bin->filename;

	//bpf_ringbuf_submit(mctx_bin, 0);
	len = bpf_probe_read_str(mctx_bin->filename, NAME_MAX, bprm->filename);
	if (len > 0) {
		bpf_ringbuf_submit(mctx_bin, 0);
	} else {
		bpf_ringbuf_discard(mctx_bin, 0);
	}


}
*/

SEC("lsm/bprm_committed_creds")
void BPF_PROG(lsm_bprm_committed_creds, struct linux_binprm *bprm)
{
	struct monitor_ctx_file mctx_file = { 0, };
	struct task_struct *t;
	//int len;
	u64 len;

	mctx_file.mctx.event_id = LSM_BPRM_COMMITTED_CREDS;
	
	t = (struct task_struct *)bpf_get_current_task();
	if (t) {
		set_mctx_subject(&mctx_file.mctx, t);
	} else {
		set_mctx_subject_empty(&mctx_file.mctx);
	}
	
	mctx_file.mctx.o_pid = EMPTY;
	mctx_file.mctx.o_uid = EMPTY;
	mctx_file.mctx.o_newuid = EMPTY;
	mctx_file.o_ino = BPF_CORE_READ(bprm, executable, f_inode, i_ino);
	len = bpf_probe_read_str(mctx_file.filename, sizeof(mctx_file.filename), bprm->filename);
	if (len > 0) {
		bpf_ringbuf_output(&ringbuf, &mctx_file, sizeof(struct monitor_ctx_file), 0);
	}

}

SEC("lsm/inode_create")
int BPF_PROG(lsm_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode, int ret)
{
	if (ret) {
		return ret;
	}

	struct monitor_ctx_file mctx_file = { 0, };
	struct task_struct *t;
	int len;

	mctx_file.mctx.event_id = LSM_INODE_CREATE;
	
	t = (struct task_struct *)bpf_get_current_task();
	if (t) {
		set_mctx_subject(&mctx_file.mctx, t);
	} else {
		set_mctx_subject_empty(&mctx_file.mctx);
	}
	
	mctx_file.mctx.o_pid = EMPTY;
	mctx_file.mctx.o_uid = dentry->d_inode->i_uid.val;
	mctx_file.mctx.o_newuid = EMPTY;
	mctx_file.o_ino = dentry->d_inode->i_ino; //BPF_CORE_READ(dentry, d_inode, i_ino);
	len = bpf_probe_read_str(mctx_file.filename, sizeof(mctx_file.filename), dentry->d_name.name);
	if (len > 0) {
		bpf_ringbuf_output(&ringbuf, &mctx_file, sizeof(struct monitor_ctx_file), 0);
	}
	return 0;

}

SEC("lsm/inode_unlink")
int BPF_PROG(lsm_inode_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
	if (ret) {
		return ret;
	}

	struct monitor_ctx_file mctx_file = { 0, };
	struct task_struct *t;
	int len;

	mctx_file.mctx.event_id = LSM_INODE_UNLINK;
	
	t = (struct task_struct *)bpf_get_current_task();
	if (t) {
		set_mctx_subject(&mctx_file.mctx, t);
	} else {
		set_mctx_subject_empty(&mctx_file.mctx);
	}
	
	mctx_file.mctx.o_pid = EMPTY;
	mctx_file.mctx.o_uid = dentry->d_inode->i_uid.val;
	mctx_file.mctx.o_newuid = dentry->d_inode->i_nlink; // temporal
	mctx_file.o_ino = dentry->d_inode->i_ino; //BPF_CORE_READ(dentry, d_inode, i_ino);
	len = bpf_probe_read_str(mctx_file.filename, sizeof(mctx_file.filename), dentry->d_name.name);
	if (len > 0) {
		bpf_ringbuf_output(&ringbuf, &mctx_file, sizeof(struct monitor_ctx_file), 0);
	}
	return 0;

}

SEC("lsm/file_permission")
int BPF_PROG(lsm_file_permission, struct file *file, int mask, int ret)
{
	if (ret) {
		return ret;
	}

	struct monitor_ctx_file mctx_file = { 0, };
	struct task_struct *t;
	int len;

	mctx_file.mctx.event_id = LSM_FILE_PERMISSION;
	
	t = (struct task_struct *)bpf_get_current_task();
	if (t) {
		set_mctx_subject(&mctx_file.mctx, t);
	} else {
		set_mctx_subject_empty(&mctx_file.mctx);
	}
	
	mctx_file.mctx.o_pid = EMPTY;
	mctx_file.mctx.o_uid = file->f_inode->i_uid.val;
	mctx_file.mctx.o_newuid = EMPTY;
	mctx_file.o_ino = file->f_inode->i_ino; //BPF_CORE_READ(dentry, d_inode, i_ino);
	mctx_file.o_mask = mask;
	len = bpf_probe_read_str(mctx_file.filename, sizeof(mctx_file.filename), file->f_path.dentry->d_name.name);
	if (len > 0) {
		bpf_ringbuf_output(&ringbuf, &mctx_file, sizeof(struct monitor_ctx_file), 0);
	}
	return 0;

}

SEC("lsm/sb_mount")
int BPF_PROG(lsm_sb_mount, const char *dev_name, const struct path *path, const char *type, unsigned long flags, void *data, int ret)
{
	if (ret) {
		return ret;
	}

	struct monitor_ctx_filesys mctx_fs = {0, };
	struct task_struct *t;
	int len;

	mctx_fs.mctx.event_id = LSM_SB_MOUNT;
	
	t = (struct task_struct *)bpf_get_current_task();
	if (t) {
		set_mctx_subject(&mctx_fs.mctx, t);
	} else {
		set_mctx_subject_empty(&mctx_fs.mctx);
	}
	len = bpf_probe_read_str(mctx_fs.dev_name, sizeof(mctx_fs.dev_name), dev_name);

	if (len > 0) {
		len = bpf_probe_read_str(mctx_fs.type, sizeof(mctx_fs.type), type);
		if (len > 0) {
			bpf_ringbuf_output(&ringbuf, &mctx_fs, sizeof(struct monitor_ctx_filesys), 0);
		}
	}
	return ret;
}
SEC("tracepoint/task/task_newtask")
int tracepoint__task__task_newtask(struct trace_event_raw_task_newtask *ctx)
{
	struct monitor_ctx mctx;
	struct task_struct *t;
	
	mctx.event_id = TRACE_TASK_NEWTASK;
	
	t = (struct task_struct *)bpf_get_current_task();
	if (t) {
		set_mctx_subject(&mctx, t);
	} else {
		set_mctx_subject_empty(&mctx);	
	}
	mctx.o_pid = ctx->pid;
	mctx.o_uid = EMPTY;
	mctx.o_newuid = EMPTY;

	bpf_ringbuf_output(&ringbuf, &mctx, sizeof(struct monitor_ctx), 0);
	
	return 0;
}


SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct monitor_ctx mctx;
	struct task_struct *t;

	mctx.event_id = TRACE_SCHED_PROCESS_EXIT;

	t = (struct task_struct *)bpf_get_current_task();
	if (t) {
		set_mctx_subject(&mctx, t);
	} else {
		set_mctx_subject_empty(&mctx);
	}
	mctx.o_pid = ctx->pid;
	mctx.o_uid = EMPTY;
	mctx.o_newuid = EMPTY;	
	
	bpf_ringbuf_output(&ringbuf, &mctx, sizeof(struct monitor_ctx), 0);
	
	return 0;
}


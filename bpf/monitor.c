// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook

#include "vmlinux.h"
#include "../header/message.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>

char _license[] SEC("license") = "GPL";

struct message{
	u64 mid;
	
	u32 pid;
	u32 ppid;
	u32 uid;
	u32 old_uid;

	u32 pid_id;
	u32 mnt_id;
};

struct conid{
	char id[64];
};

struct nskey{
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
	__uint(max_entries, 1 << 12);
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

/*
SEC("lsm/cred_prepare")
int BPF_PROG(trace_fork, struct cred *new, const struct cred *old, gfp_t gfp, int ret)
{
	if (ret)	return ret;

	struct message m;

	struct task_struct *t;

	t = (struct task_struct *)bpf_get_current_task();

	m.mid = CRED_PREPARE;

	if (t){
		BPF_CORE_READ_INTO (&m.pid, t, tgid);
		BPF_CORE_READ_INTO (&m.ppid, t, real_parent, tgid);
	}
	else {
		m.pid = EMPTY;
		m.ppid = EMPTY;
		m.uid = EMPTY;
	}	
	m.old_uid = old->uid.val;
	m.uid = new->uid.val;

	bpf_ringbuf_output(&ringbuf, &m, sizeof(struct message), 0);

	//if ((m.old_uid != 0) && (m.old_uid != m.uid))
	//	return -EPERM;
	
	return 0;
}
*/
/*
SEC("lsm/task_alloc")
int BPF_PROG(trace_fork2, struct task_struct *task, unsigned long clone_flags, int ret)
{
	if (ret)	return ret;

	struct message m;
	struct task_struct *t;

	t = (struct task_struct *)bpf_get_current_task();

	m.mid = TASK_ALLOC;
	if (t){
		BPF_CORE_READ_INTO (&m.pid, task, tgid);
		BPF_CORE_READ_INTO (&m.ppid, t, real_parent, tgid);
		BPF_CORE_READ_INTO (&m.uid, t, cred, uid.val);
	}
	else {
		m.pid = EMPTY;
		m.ppid = EMPTY;
		m.uid = EMPTY;
	}

	m.old_uid = EMPTY;
	m.pid_id = EMPTY;
	m.mnt_id = EMPTY;

	bpf_ringbuf_output(&ringbuf, &m, sizeof(struct message), 0);

	return 0;
}
*/

SEC("lsm/task_free")
void BPF_PROG(lsm_task_free, struct task_struct *task)
{

	struct message m;

	m.mid = TASK_FREE;
	if (task){
		BPF_CORE_READ_INTO (&m.pid, task, tgid);
		BPF_CORE_READ_INTO (&m.ppid, task, real_parent, tgid);
		BPF_CORE_READ_INTO (&m.uid, task, cred, uid.val);

		BPF_CORE_READ_INTO (&m.pid_id, task, nsproxy, pid_ns_for_children, ns.inum);
		BPF_CORE_READ_INTO (&m.mnt_id, task, nsproxy, mnt_ns, ns.inum);

	}
	else {
		m.pid = EMPTY;
		m.ppid = EMPTY;
		m.uid = EMPTY;
		m.pid_id = EMPTY;
		m.mnt_id = EMPTY;
	}

	m.old_uid = EMPTY;

	bpf_ringbuf_output(&ringbuf, &m, sizeof(struct message), 0);
}

SEC("tracepoint/task/task_newtask")
int tracepoint__task__task_newtask(struct trace_event_raw_task_newtask *ctx)
{
	struct message m;
	struct task_struct *t;
	
	t = (struct task_struct *)bpf_get_current_task();

	m.mid = TRACE_TASK_NEWTASK;

	if (t){
		BPF_CORE_READ_INTO (&m.ppid, t, tgid);
		BPF_CORE_READ_INTO (&m.pid_id, t, nsproxy, pid_ns_for_children, ns.inum);
		BPF_CORE_READ_INTO (&m.mnt_id, t, nsproxy, mnt_ns, ns.inum);

	}
	else {
		m.pid = EMPTY;
		m.ppid = EMPTY;
		m.uid = EMPTY;
		m.pid_id = EMPTY;
		m.mnt_id = EMPTY;
	}

	m.pid = ctx->pid;
	m.uid = bpf_get_current_uid_gid();
	m.old_uid = EMPTY;

	bpf_ringbuf_output(&ringbuf, &m, sizeof(struct message), 0);
	
	return 0;
}

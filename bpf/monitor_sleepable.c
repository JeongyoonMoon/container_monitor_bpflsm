// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook

#include "vmlinux.h"
#include "../header/monitor_defs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u32 pid_last = 0;
struct file_path {
	char path[PATH_LEN];
	int len;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct file_path);
	__uint(max_entries, PID_MAX);	
} pid2path SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct file_path);
	__uint(max_entries, FILE_MAX);	
} ino2path SEC(".maps");

SEC("lsm.s/bprm_committed_creds")
void BPF_PROG(lsm_s_bprm_committed_creds, struct linux_binprm *bprm)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct file_path fp = {0, };

	if (!bpf_map_lookup_elem(&pid2path, &pid)) {
		fp.len = bpf_d_path(&bprm->file->f_path, fp.path, PATH_LEN);
		if (fp.len > 0) {
			bpf_map_update_elem(&pid2path, &pid, &fp, BPF_ANY);
		}
		pid_last = pid; /* should be deleted */
	}
	return;	
}
SEC("lsm.s/file_open")
int BPF_PROG(lsm_s_file_open, struct file *file, int ret)
{
	if (ret) {
		return ret;
	}
	
	u64 ino = file->f_inode->i_ino;
	struct file_path fp = {0, };
	
	if (!bpf_map_lookup_elem(&ino2path, &ino)) {
		fp.len = bpf_d_path(&file->f_path, fp.path, PATH_LEN);
		if (fp.len > 0) {
			bpf_map_update_elem(&ino2path, &ino, &fp, BPF_ANY);
		}
	} /* if there's no entry related to inode */
	return 0;	
}
SEC("lsm.s/inode_unlink")
int BPF_PROG(lsm_s_inode_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
	if (ret) {
		return ret;
	}

	u64 ino = dentry->d_inode->i_ino;
	u32 nlink = dentry->d_inode->i_nlink;
	if (nlink == 1u) {	
		if (bpf_map_lookup_elem(&ino2path, &ino)) {
			bpf_map_delete_elem(&ino2path, &ino);
		}
	}

	return ret;
}
/*
SEC("lsm.s/sb_mount")
int BPF_PROG(lsm_s_sb_mount, const char *dev_name, const struct path *path, const char *type, unsigned long flags, void *data, int ret)
{
	if (ret) {
		return ret;
	}

	u32 dev = path->mnt->mnt_sb.s_dev;


}
*/

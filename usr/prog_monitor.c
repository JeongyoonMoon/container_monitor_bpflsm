// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <linux/compiler.h>
#include <asm/barrier.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <time.h>
#include <sched.h>
#include <signal.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <linux/perf_event.h>
#include <linux/ring_buffer.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "monitor.skel.h"
#include "../header/monitor_defs.h"
#include "../header/container.h"

struct monitor_ctx {
	uint32_t event_id;

	uint32_t pid;
	uint32_t ppid;
	uint32_t uid;

	uint32_t pid_id;
	uint32_t mnt_id;
	
	uint32_t pid_from_ns;
	uint32_t tid_from_ns;

	uint32_t o_pid;
	uint32_t o_uid;
	uint32_t o_newuid;
	uint32_t pad;
};

struct monitor_ctx_bin {
	struct monitor_ctx mctx;
	char filename[NAME_MAX];
};

struct nskey{
	uint32_t pid_id;
	uint32_t mnt_id;
};

static int freed = 0;

static struct monitor *skel;
static struct ring_buffer *ringbuf;
static int ns2conid, conid2pids;

void sig_handler (int signo);

static int process_ringbuf(void *ctx, void *data, size_t len)
{
	struct monitor_ctx *mctx = NULL;
	struct monitor_ctx_bin *mctx_bin = NULL;
	struct nskey key;
	int new_pids;
	int pids_fd = -1;
	uint32_t pids;
	uint32_t value = EMPTY;
	char conid[64]={'\0'};
	char *temp;
	int ret;
	int is_container = 1;

	if (len == sizeof(struct monitor_ctx_bin)) {
		mctx_bin = data;
		mctx = &(mctx_bin->mctx);
	} else {
		mctx = data;
	}

	key.pid_id = mctx->pid_id;
	key.mnt_id = mctx->mnt_id;
	
	ret = bpf_map_lookup_elem(ns2conid, &key, conid);

	if (ret) {
		temp = LookupContainerID(mctx->pid);
		memcpy(conid, temp, 64);
		free(temp);
		
		if (conid[0] == '\0') {
			is_container = 0;
		}	
		else if (mctx->event_id == TRACE_TASK_NEWTASK){
			if (!bpf_map_lookup_elem(conid2pids, conid, &pids)){
				bpf_map_update_elem(ns2conid, &key, conid, BPF_ANY);
			}/* If not the first process of the container */
		}		
	} /* If nskey to container id map lookup fails */

	if (!is_container)
		return 0;

	//fprintf(stdout, "pid_id: %u, mnt_id: %u\n", key.pid_id, key.mnt_id);

	if (mctx->event_id == LSM_CRED_PREPARE) {
		fprintf(stdout, "[CRED_PREPARE] process(pid:%u,uid:%u) -> from cred(uid:%u) to cred(uid:%u)\n", mctx->pid, mctx->uid, mctx->o_uid, mctx->o_newuid);
	}
	else if (mctx->event_id == LSM_TASK_ALLOC) {
		fprintf(stdout, "[TASK_ALLOC] process (pid:%u,uid:%u) ->  process (pid:%u)\n", mctx->pid, mctx->uid, mctx->o_pid);
	} 
	else if (mctx->event_id == LSM_TASK_FREE) {
		fprintf(stdout, "[TASK_FREE] process (pid:%u,ppid:%u,uid:%u) -> process (pid:%u)\n", mctx->pid, mctx->ppid, mctx->uid, mctx->o_pid);
	}
	else if (mctx->event_id == LSM_BPRM_COMMITTED_CREDS){
		fprintf(stdout, "[BPRM_COMMITTED_CREDS process (pid:%u,ppid:%u,uid:%u) -> binary(%s)\n", mctx->pid, mctx->ppid, mctx->uid, mctx_bin->filename);
	}
	else if (mctx->event_id == TRACE_TASK_NEWTASK) {
		
		if (conid[0] != '\0') { 
			if (bpf_map_lookup_elem(conid2pids, conid, &pids)) {	
				// new inner map
				new_pids = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint32_t), PID_MAX, 0); 
				bpf_map_update_elem(conid2pids, conid, &new_pids, BPF_ANY);
				close(new_pids);
				bpf_map_lookup_elem(conid2pids, conid, &pids);
			} /*If container id to pids map lookup fails */

			// add current pid to the inner pids map
			pids_fd = bpf_map_get_fd_by_id(pids);
			bpf_map_update_elem(pids_fd, &mctx->pid, &value, BPF_ANY);
			close(pids_fd);
		} /* If container id is not empty */

		fprintf(stdout, "[TRACE_TASK_NEWTASK] process (pid:%u,uid %u) ->  process (pid:%u)\n", mctx->pid, mctx->uid, mctx->o_pid);
	}
	else if (mctx->event_id == TRACE_SCHED_PROCESS_EXIT) {
		
		if (!bpf_map_lookup_elem(conid2pids, conid, &pids)){
			/* remove current pid from the map */
			pids_fd = bpf_map_get_fd_by_id(pids);
			bpf_map_delete_elem(pids_fd, &mctx->pid);
			close(pids_fd);
		} /* if container id to pids map lookup succeeds*/

		// Assume if process in a container with process id 1, thread id 1 exit,
		// the container also exit.
		// then remove relevant NS to conid map entry and conid to pids map entry
		if (mctx->pid_from_ns == 1u && mctx->tid_from_ns == 1u){
			if (!ret)	bpf_map_delete_elem(ns2conid, &key);	
			if (pids_fd >= 0) {
				bpf_map_delete_elem(conid2pids, conid);
			}
		}
		fprintf(stdout, "[SCHED_PROCESS_EXIT] process (pid:%u,ppid:%u,uid:%u) -> process (pid:%u)\n", mctx->pid, mctx->ppid, mctx->uid, mctx->o_pid);
	}
	
	//fprintf(stdout, "pid from ns: %u tid from ns: %u \n", mctx->pid_from_ns, mctx->tid_from_ns);
	//fprintf(stdout, "containerID: %s\n", conid);

	return 0;
}

int main()
{
	int err;
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	
	setrlimit(RLIMIT_MEMLOCK, &rlim_new);
	signal (SIGINT, (void *)sig_handler);

	skel = monitor__open_and_load();
	if (!skel)
	{
		fprintf(stdout, "skeleton open&load failed\n");
		return 0;
	}

	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), process_ringbuf, NULL, NULL);
	
	if (!ringbuf){
		fprintf(stdout, "failed to create ringbuf\n");
		goto cleanup;
	}

	close(bpf_map__fd(skel->maps.pids));
	
	conid2pids = bpf_map__fd(skel->maps.conid2pids);
	ns2conid = bpf_map__fd(skel->maps.ns2conid);

	err = monitor__attach(skel);
	if (err){
		fprintf(stdout, "skeleton attachment failed: %d\n", err);
		goto cleanup;
	}


	/* poll for samples */
	while (1){
		err = ring_buffer__poll(ringbuf, -1);
	
		if (err < 0){
			fprintf(stdout, "failed to poll data from ringbuf: err %d\n", err); 
			goto cleanup;
		}
	}
cleanup:
	if (freed == 0) {
		ring_buffer__free(ringbuf);
		monitor__destroy(skel);
	}
	return 0;
}

void sig_handler(int signo){
	ring_buffer__free(ringbuf);
	monitor__destroy(skel);
	freed = 1;
}

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
#include "monitor.skel.h"
#include "../header/message.h"
#include "../header/container.h"

struct message{
	uint64_t mid;
	uint32_t pid;
	uint32_t ppid;
	uint32_t uid;
	uint32_t old_uid;

	uint32_t pid_id;
	uint32_t mnt_id;
};

struct nskey{
	uint32_t pid_id;
	uint32_t mnt_id;
};

static int freed = 0;

static struct monitor *skel;
static struct ring_buffer *ringbuf;
//static int pid2conid;
static int ns2conid;

void sig_handler (int signo);

static int process_message(void *ctx, void *data, size_t len)
{
	struct message *rcv = data;
	struct nskey key;

	char conid[64]={'\0'}, *temp;
	int ret, is_container = 1;

	//ret = bpf_map_lookup_elem(pid2conid, &rcv->pid, conid);
	key.pid_id = rcv->pid_id;
	key.mnt_id = rcv->mnt_id;
	
	ret = bpf_map_lookup_elem(ns2conid, &key, conid);

	// if map lookup fails, lookup procfs	
	if (ret) {
		temp = LookupContainerID(rcv->pid);
		memcpy(conid, temp, 64);
		free(temp);
		// if empty string
		if (conid[0] == '\0') {
			is_container = 0;
		}	
		
		else	bpf_map_update_elem(ns2conid, &key, &conid, BPF_ANY); 
	}
	//else	fprintf (stdout, "map lookup succeeded\n");


	if (rcv->mid == CRED_PREPARE){
		fprintf(stdout, "[CRED_PREPARE] pid:%u ppid:%u attempt to preare a cred uid from %u to %u\n", rcv->pid, rcv->ppid, rcv->uid, rcv->old_uid);
	}
	else if (rcv->mid == TASK_ALLOC){
		fprintf(stdout, "[TASK_ALLOC] pid:%u allocated by parent pid:%u uid:%u\n", rcv->pid, rcv->ppid, rcv->uid);
	} 
	else if (rcv->mid == TASK_FREE){
			
		// conid is not an empty string
		if (is_container) {
			//fprintf(stdout, "pid_id: %u, mnt_id: %u\n", key.pid_id, key.mnt_id);

			fprintf(stdout, "[TASK_FREE] pid:%u freed ppid:%u uid:%u\n", rcv->pid, rcv->ppid, rcv->uid);
			fprintf(stdout, "containerid:%s\n", conid);	
			//bpf_map_delete_elem(pid2conid, &rcv->pid);
		}
	}
	else if (rcv->mid == TRACE_TASK_NEWTASK){
		
		if (is_container){
			
			fprintf(stdout, "pid_id: %u, mnt_id: %u\n", key.pid_id, key.mnt_id);
			fprintf(stdout, "[TRACE_TASK_NEWTASK] pid:%u allocated by parent pid:%u uid:%u \n", rcv->pid, rcv->ppid, rcv->uid);
			fprintf(stdout, "containerID: %s\n", conid);
		}
	}	

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

	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), process_message, NULL, NULL);
	
	if (!ringbuf){
		fprintf(stdout, "failed to create ringbuf\n");
		goto cleanup;
	}

//	pid2conid = bpf_map__fd(skel->maps.pid2conid);
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

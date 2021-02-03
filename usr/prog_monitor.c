// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
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
#include "monitor.skel.h"
#include "../header/message.h"

struct message{
	uint64_t mid;
	uint32_t pid;
	uint32_t ppid;
	uint32_t uid;
	uint32_t old_uid;
	//uint64_t empty;
};

static int freed = 0;

void sig_handler (int signo);

static int process_message(void *ctx, void *data, size_t len)
{
	struct message *rcv = data;
	
	if (rcv->mid == CRED_PREPARE){
		fprintf(stdout, "[CRED_PREPARE] pid:%u ppid:%u attempt to preare a cred uid from %u to %u\n", rcv->pid, rcv->ppid, rcv->uid, rcv->old_uid);
	}
	else if (rcv->mid == TASK_ALLOC){
		fprintf(stdout, "[TASK_ALLOC] pid:%u allocated by parent pid:%u uid:%u\n", rcv->pid, rcv->ppid, rcv->uid);
	} 
	else if (rcv->mid == TRACE_TASK_NEWTASK){
		fprintf(stdout, "[TRACE_TASK_NEWTASK] pid:%u allocated by parent pid:%u uid:%u\n", rcv->pid, rcv->ppid, rcv->uid);
	}	

	return 0;
}

static struct monitor *skel;
static struct ring_buffer *ringbuf;

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

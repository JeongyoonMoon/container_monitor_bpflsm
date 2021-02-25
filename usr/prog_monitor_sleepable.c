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
#include "monitor_sleepable.skel.h"
#include "../header/monitor_defs.h"
#include "../header/container.h"

static int freed = 0;

static struct monitor_sleepable *skel;
static int pid2path;

struct file_path {
	char path[PATH_LEN];
	int len;
};

void sig_handler (int signo);

int main()
{
	struct monitor_sleepable__bss *bss;
	struct file_path fp;
	int err;
	uint32_t pid;
	char input[128];
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	
	setrlimit(RLIMIT_MEMLOCK, &rlim_new);
	signal (SIGINT, (void *)sig_handler);

	skel = monitor_sleepable__open_and_load();
	if (!skel)
	{
		fprintf(stdout, "skeleton open&load failed\n");
		return 0;
	}
	
	err = monitor_sleepable__attach(skel);
	if (err){
		fprintf(stdout, "skeleton attachment failed: %d\n", err);
		goto cleanup;
	}

	pid2path = bpf_map__fd(skel->maps.pid2path);
	bss = skel->bss;

	while (fgets(input, sizeof(input), stdin)) {
		if (strncmp(input, "exit", 4u) == 0)
			break;
	};
	pid = bss->pid_last;
	fprintf(stdout, "pid: %d\n", pid);
	if(!bpf_map_lookup_elem(pid2path, &pid, &fp)) {
		fprintf(stdout, "%s, len: %d\n", fp.path, fp.len);
	}

cleanup:
	if (freed == 0) {
		monitor_sleepable__destroy(skel);
	}
	return 0;
}

void sig_handler(int signo){
	monitor_sleepable__destroy(skel);
	freed = 1;
}

/*
 * This file is part of ltrace.
 * Copyright (C) 2009 Juan Cespedes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/ptrace.h>

#include "ltrace.h"
#include "common.h"
#include "prototype.h"


#define ABORT(msg)            {       \
	fprintf(stderr, msg);        \
	exit(-1);  }


extern void normal_exit(void);
extern void signal_exit(int sig);
extern void parse_filter_chain(const char *expr, struct filter **retp);
extern int process_bare_init(struct process *proc, const char *filename, pid_t pid, int was_exec);
extern void process_bare_destroy(struct process *proc, int was_exec);


int
main(int argc, char *argv[]) {

	//atexit(normal_exit);
	//signal(SIGINT, signal_exit);    /* Detach processes when interrupted */
	//signal(SIGTERM, signal_exit);   /*  ... or killed */
	
	VECT_INIT(&opt_F, struct opt_F_t);
	//print syscalls
	options.syscalls = 1;
	//follow subprocess
	//options.follow = 1;
	options.output = stderr;
	options.no_signals = 0;
	options.hide_caller = 1;
	
	
	init_global_config();
	
	/* Check that the binary ABI is supported before
	 * calling execute_program.  */
	struct ltelf lte = {};
	open_elf(&lte, command);
	do_close_elf(&lte);
	
	command = argv[1];
	argv = argv + 1;
	
	pid_t pid = execute_program(command, argv);
	//struct process *proc = open_program(command, pid);
	
	assert(pid != 0);
	struct process *proc = malloc(sizeof(*proc));
	if (proc == NULL) {
		exit(EXIT_FAILURE);
	        return -1;
	}
	
	
	if ((process_bare_init(proc, command, pid, 0) < 0) ||
		  (os_process_init(proc) < 0) ||
		  (arch_process_init(proc) < 0) ||
		  (proc == NULL)) {
	        fprintf(stderr, "failed to initialize process %d: %s\n",
	                pid, strerror(errno));
	        exit(EXIT_FAILURE);
	        return -1;
	}
	
	
	trace_set_options(proc);
	continue_process(pid);
	
	char filename[sizeof ("/proc/0123456789/mem")];
	sprintf(filename, "/proc/%d/mem", pid);
	fprintf(stderr, "filename is %s\n", filename);
	FILE * fp = fopen(filename, "rb");
	char * input_path = malloc(PATH_MAX);
	int ret;
	struct user_regs_struct iregs;
	
	int syscall_ret = 0;
	Event * ev;
	while (1) {
		ev = next_event();
		if (ev->type == EVENT_SYSCALL && ev->e_un.sysnum == SYS_open && !syscall_ret) {
			ptrace(PTRACE_GETREGS, pid, 0, &iregs);
			//fprintf(stderr, "Reading address %lx\n", iregs.rdi);
			ret = fseek(fp, iregs.rdi, SEEK_SET);
			fflush(fp);
			if (ret != 0)
				ABORT("failed to seek\n");
			ret = fscanf(fp, "%1024s", input_path);
			//fprintf(stderr, "going to read\n");
			//ret = fread(input_path, PATH_MAX, 1, fp);
			//if (ret != 1){ 
			if (ferror(fp)){
				ABORT("failed to read\n");
			}
			fprintf(stderr, "%s\n", input_path);
			syscall_ret = 1;
			//continue_after_syscall(ev->proc, ev->e_un.sysnum, 0);
		}else if (ev->type == EVENT_SYSCALL && ev->e_un.sysnum == SYS_open && syscall_ret) {
			//fprintf(stderr, "Ret from open\n");
			syscall_ret = 0;
		}else {
			//fprintf(stderr, "Event %d\n", ev->type);
			;
		}
		//fprintf(stderr, "call: %d\n", ev->type);
		continue_process(ev->proc->pid);
	}
	
	return 0;
}


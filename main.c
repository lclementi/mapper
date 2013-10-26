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
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <fcntl.h>

#include "ltrace.h"
#include "common.h"
#include "prototype.h"


#define ABORT(msg)            {       \
	fprintf(stderr, msg);        \
	exit(-1);  }

char * remote_buffer_string = "fingerprint=1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
extern void normal_exit(void);
extern void signal_exit(int sig);
extern void parse_filter_chain(const char *expr, struct filter **retp);
extern int process_bare_init(struct process *proc, const char *filename, pid_t pid, int was_exec);
extern void process_bare_destroy(struct process *proc, int was_exec);


/*
int
write_process(pid, ){

	int a;
	a = ptrace(PTRACE_POKETEXT, pid, sbp->addr + i * sizeof(long), a);

}
*/

unsigned long int
find_remote_buffer(unsigned int pid){

	char filename[sizeof ("/proc/0123456789/maps")];
	sprintf(filename, "/proc/%d/maps", pid);

	FILE * fp = fopen(filename, "rb");
	char binary_path[PATH_MAX];
	unsigned long start_addr, end_addr, mmap_offset, length;


	int found = 0;
	while ( fscanf(fp, "%lx-%lx %*c%*c%*c%*c %lx %*x:%*x %*d %[^\n]",
			&start_addr, &end_addr, &mmap_offset, binary_path) > 0 ){
		if (strcmp(binary_path, "[stack]") == 0 ){
			found = 1;
			break;
		}
	}//while
	fclose(fp);

	if (! found )
		return 0;

	length = end_addr - start_addr;
	sprintf(filename, "/proc/%d/mem", pid);
	int fd = open(filename, O_RDONLY);
	//ret = fseek(fp, , SEEK_SET);
	char *base_address = mmap(NULL, length, PROT_READ, MAP_SHARED, fd, start_addr);
	if (base_address == NULL)
		ABORT("failed to map n");

	found = 0; //false
	unsigned long int i, j;
	for (i = 0; i < length; i++) {
		if (base_address[i] == remote_buffer_string[0]) {
			//this could be the goodone
			found = 1;
			for (j = 0; j < strlen(remote_buffer_string); i++){
				if (base_address[i + j] != remote_buffer_string[j]) {
					break;
					found = 0;
				}
			}
			if (found)
				break;
		}
	}
	munmap(base_address, length);
	close(fd);
	
	if (found) {
		fprintf(stderr, "Pattern found at: %lx\n", start_addr + i);
		return start_addr + i;
	}
	return 1;

}


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
	unsigned long int remote_buffer = find_remote_buffer(pid);
	if (! remote_buffer ) 
		ABORT("Unable to find remove buffer\n");



	//tracing of process
	
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
			/* TODO make the format string with PATH_MAX */
			ret = fscanf(fp, "%1024s", input_path);
			if (ferror(fp)){
				ABORT("failed to read\n");
			}
			fprintf(stderr, "%s\n", input_path);
			syscall_ret = 1;
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


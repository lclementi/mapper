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
#include <sys/types.h> 
#include <sys/ipc.h> 
#include <sys/shm.h>
#include <unistd.h>

#include "ltrace.h"
#include "common.h"
#include "prototype.h"
#include "uthash.h"


#define ABORT(msg)            {       \
	fprintf(stderr, msg);        \
	exit(-1);  }

#define X86_64

// like an assert except that it always fires
#define EXITIF(x) do { \
  if (x) { \
    fprintf(stderr, "Fatal error in %s [%s:%d]\n", __FUNCTION__, __FILE__, __LINE__); \
    exit(1); \
  } \
} while(0)



char * mapping_file = "/etc/fp_mapping";
extern void normal_exit(void);
extern void signal_exit(int sig);
extern void parse_filter_chain(const char *expr, struct filter **retp);
extern int process_bare_init(struct process *proc, const char *filename, pid_t pid, int was_exec);
extern void process_bare_destroy(struct process *proc, int was_exec);
extern void handle_clone(Event *event);
extern void handle_new(Event *event);




/*
int
write_process(pid, ){

	int a;
	a = ptrace(PTRACE_POKETEXT, pid, sbp->addr + i * sizeof(long), a);

}
*/

char* localshm; // address in our address space
void* childshm; // address in child's address space
int shmid;      //key to the shared memory region
struct user_regs_struct saved_regs;


// inject a system call in the child process to tell it to attach our
// shared memory segment, so that it can read modified paths from there
//
// Setup a shared memory region within child process,
// then repeat current system call
//
// WARNING: this code is very tricky and gross!
static void 
begin_setup_shmat(int pid) {
  struct user_regs_struct cur_regs;

  assert(localshm);
  assert(!childshm); // avoid duplicate calls

  // stash away original registers so that we can restore them later
  EXITIF(ptrace(PTRACE_GETREGS, pid, NULL, (long)&cur_regs) < 0);
  memcpy(&saved_regs, &cur_regs, sizeof(cur_regs));

#if 0
  // #if defined (I386)
  // To make the target process execute a shmat() on 32-bit x86, we need to make
  // it execute the special __NR_ipc syscall with SHMAT as a param:

  /* The shmat call is implemented as a godawful sys_ipc. */
  cur_regs.orig_eax = __NR_ipc;
  /* The parameters are passed in ebx, ecx, edx, esi, edi, and ebp */
  cur_regs.ebx = SHMAT;
  /* The kernel names the rest of these, first, second, third, ptr,
   * and fifth. Only first, second and ptr are used as inputs.  Third
   * is a pointer to the output (unsigned long).
   */
  cur_regs.ecx = shmid;
  cur_regs.edx = 0; /* shmat flags */
  cur_regs.esi = (long)0; /* Pointer to the return value in the
                                          child's address space. */
  cur_regs.edi = (long)NULL; /* We don't use shmat's shmaddr */
  cur_regs.ebp = 0; /* The "fifth" argument is unused. */
  //#elif defined(X86_64)
  if (IS_32BIT_EMU) {
    // If we're on a 64-bit machine but tracing a 32-bit target process, then we
    // need to make the 32-bit __NR_ipc SHMAT syscall as though we're on a 32-bit
    // machine (see code above), except that we use registers like 'rbx' rather
    // than 'ebx'.  This was VERY SUBTLE AND TRICKY to finally get right!

    cur_regs.orig_rax = 117; // 117 is the numerical value of the __NR_ipc macro (not available on 64-bit hosts!)
    cur_regs.rbx = 21;       // 21 is the numerical value of the SHMAT macro (not available on 64-bit hosts!)
    cur_regs.rcx = shmid;
    cur_regs.rdx = 0;
    cur_regs.rsi = (long)0;
    cur_regs.rdi = (long)NULL;
    cur_regs.rbp = 0;
  }
  else {
#endif
  // If the target process is 64-bit, then life is good, because
  // there is a direct shmat syscall in x86-64!!!
  cur_regs.orig_rax = __NR_shmat;
  cur_regs.rdi = shmid;
  cur_regs.rsi = 0;
  cur_regs.rdx = 0;
  
  //#else
  //  #error "Unknown architecture (not I386 or X86_64)"
  //#endif

  EXITIF(ptrace(PTRACE_SETREGS, pid, NULL, (long)&cur_regs) < 0);
}


void 
finish_setup_shmat(int pid) {

  struct user_regs_struct cur_regs;
  EXITIF(ptrace(PTRACE_GETREGS, pid, NULL, (long)&cur_regs) < 0);

#if 0 
  //#if defined (I386)
  // setup had better been a success!
  assert(cur_regs.orig_eax == __NR_ipc);
  assert(cur_regs.eax == 0);

  // the pointer to the shared memory segment allocated by shmat() is actually
  // located in *tcp->savedaddr (in the child's address space)
  errno = 0;
  childshm = (void*)ptrace(PTRACE_PEEKDATA, pid, savedaddr, 0);
  EXITIF(errno); // PTRACE_PEEKDATA reports error in errno

  // restore original data in child's address space
  EXITIF(ptrace(PTRACE_POKEDATA, pid, savedaddr, savedword));

  saved_regs.eax = saved_regs.orig_eax;

  // back up IP so that we can re-execute previous instruction
  // TODO: is the use of 2 specific to 32-bit machines?
  saved_regs.eip = saved_regs.eip - 2;
  //#elif defined(X86_64)
  if (IS_32BIT_EMU) {
    // If we're on a 64-bit machine but tracing a 32-bit target process, then we
    // need to handle the return value of the 32-bit __NR_ipc SHMAT syscall as
    // though we're on a 32-bit machine (see code above).  This was VERY SUBTLE
    // AND TRICKY to finally get right!

    // setup had better been a success!
    assert(cur_regs.orig_rax == 117 /*__NR_ipc*/);
    assert(cur_regs.rax == 0);

    // the pointer to the shared memory segment allocated by shmat() is actually
    // located in *tcp->savedaddr (in the child's address space)
    errno = 0;

    // this is SUPER IMPORTANT ... only keep the 32 least significant bits
    // (mask with 0xffffffff) before storing the pointer in tcp->childshm,
    // since 32-bit processes only have 32-bit addresses, not 64-bit addresses :0
    childshm = (void*)(ptrace(PTRACE_PEEKDATA, pid, savedaddr, 0) & 0xffffffff);
    EXITIF(errno);
    // restore original data in child's address space
    EXITIF(ptrace(PTRACE_POKEDATA, pid, savedaddr, savedword));
  }
  else {
#endif
  // If the target process is 64-bit, then life is good, because
  // there is a direct shmat syscall in x86-64!!!
  assert(cur_regs.orig_rax == __NR_shmat);

  // the return value of the direct shmat syscall is in %rax
  childshm = (void*)cur_regs.rax;

  // the code below is identical regardless of whether the target process is
  // 32-bit or 64-bit (on a 64-bit host)
  saved_regs.rax = saved_regs.orig_rax;

  // back up IP so that we can re-execute previous instruction
  // ... wow, apparently the -2 offset works for 64-bit as well :)
  saved_regs.rip = saved_regs.rip - 2;

  EXITIF(ptrace(PTRACE_SETREGS, pid, NULL, (long)&saved_regs) < 0);

  assert(childshm);

}



struct file_mapping {
	char * original_path;
	char * rewritten_path;
	UT_hash_handle hh;         /* makes this structure hashable */
};

struct file_mapping * global_mappings;



char *
get_base_path(char * input_str){
	unsigned int len, i;
	char * return_value;

	assert(input_str);
	len = strlen(input_str);
	assert(len);

	for (i = len - 1; i >= 0; i--){
		if (input_str[i] == '/'){
			/* we hit the base path length */
			return_value = malloc(i + i);
			EXITIF(!return_value);
			memcpy(return_value, input_str, i);
			return_value[i] = '\0';
			return return_value;
		}
	}
	/* we should never get to this point */
	EXITIF(1);
}

void
init_mapping(){
	FILE *fd;
	char line_buffer[PATH_MAX * 2];
	char *orig_file, *remapped_file;
	unsigned int file_path_length, off_set, success;
	struct file_mapping *mapping;

	fd = fopen(mapping_file, "r");
	EXITIF(fd == NULL);
	while(fgets(line_buffer, PATH_MAX * 2, fd)) {
		if (line_buffer[0] == '#') {
			//skip comment
			continue;
		}
		/* for each line in the file parse the orginal file*/
		success = 0;
		for(file_path_length = 0 ; file_path_length < PATH_MAX; file_path_length++){
			if (line_buffer[file_path_length] == '\t') {
				line_buffer[file_path_length] = '\0';
				orig_file = strdup(line_buffer);
				EXITIF(orig_file == NULL);
				success = 1;
				break;
			}
		}
		EXITIF(!success);
		off_set = file_path_length + 1;
		success = 0;
		/* parse the remapped file */
		for(file_path_length = 0 ; file_path_length < PATH_MAX; file_path_length++){
			if (line_buffer[off_set + file_path_length] == '\n') {
				line_buffer[off_set + file_path_length] = '\0';
				remapped_file = strdup(line_buffer + off_set);
				EXITIF(remapped_file == NULL);
				success = 1;
				break;
			}
		}
		EXITIF(!success);
		mapping = malloc(sizeof(struct file_mapping));
		EXITIF(mapping == NULL);
		mapping->original_path = orig_file;
		mapping->rewritten_path = remapped_file;
		HASH_ADD_KEYPTR(hh, global_mappings, mapping->original_path, strlen(mapping->original_path), mapping);
#if DEBUG
		fprintf(stderr, "Loading mapping: %s -> %s\n", orig_file, remapped_file);
#endif

		/* we need to add directory remapping for stat syscall */
		mapping = malloc(sizeof(struct file_mapping));
		EXITIF(mapping == NULL);
		mapping->original_path = get_base_path(orig_file);
		mapping->rewritten_path = get_base_path(remapped_file);
		HASH_ADD_KEYPTR(hh, global_mappings, mapping->original_path, strlen(mapping->original_path), mapping);
#if DEBUG
		fprintf(stderr, "Loading mapping: %s -> %s\n", mapping->original_path, mapping->rewritten_path);
#endif
	}
}//init_mapping


int
main(int argc, char *argv[]) {

	struct ltelf lte = {};
	struct process *proc;

	char mem_filename[sizeof ("/proc/0123456789/mem")];
	FILE *mem_fp;
	/* setting_up_shm is 0 if we have to setup shm
	 * 1 if we're in the process of setting up shared memory
	 * 2 if we have set it up */
	char setting_up_shm = 0;
	key_t key;
	long page_size = 0;
	int syscall_return = 0;
	char *original_path;
	Event * ev;
	pid_t pid;
	struct file_mapping *mapping;
	int ret;
	struct user_regs_struct iregs;


	page_size = sysconf(_SC_PAGESIZE);
	proc = malloc(sizeof(*proc));
	if (proc == NULL) {
		exit(EXIT_FAILURE);
	        return -1;
	}

	original_path = malloc(PATH_MAX);
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
	init_mapping();
	
	/* Check that the binary ABI is supported before
	 * calling execute_program.  */
	open_elf(&lte, command);
	do_close_elf(&lte);
	
	/* set up local shared memory */
#ifdef DEBUG
	fprintf(stderr, "page size is %ld\n", page_size);
#endif
	/* randomly probe for a valid shm key */
	do {
		errno = 0;
		key = rand();
		shmid = shmget(key, page_size, IPC_CREAT|IPC_EXCL|0600);
	} while (shmid == -1 && errno == EEXIST);
	localshm = (char*)shmat(shmid, NULL, 0);
	
	if ((long)localshm == -1)
		ABORT("shmat");
	
	if (shmctl(shmid, IPC_RMID, NULL) == -1)
		ABORT("shmctl(IPC_RMID)");
	assert(localshm);
	/* end set up local shared memory */

	//fix the argument list	
	command = argv[1];
	argv = argv + 1;

	if (command)
		pid = execute_program(command, argv);
	else
		ABORT("You must provide a command to run");
	assert(pid != 0);
	//struct process *proc = open_program(command, pid);
	
	
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


	//tracing of process

	sprintf(mem_filename, "/proc/%d/mem", pid);
#ifdef DEBUG
	fprintf(stderr, "Memory access filename is %s\n", mem_filename);
#endif
	mem_fp = fopen(mem_filename, "rb");
	EXITIF(mem_fp == NULL);
	while (1) {
		ev = next_event();
		if (ev->type == EVENT_SYSCALL && ev->proc && ev->proc->state != STATE_IGNORED){
			/* set up the shared memory region */
			if (setting_up_shm == 0){
				begin_setup_shmat(pid);
				setting_up_shm = 1;
			} else if (setting_up_shm == 1) {
				finish_setup_shmat(pid);
				setting_up_shm = 2;
			/* end set up the shared memory region */
			} else if (!syscall_return && (ev->e_un.sysnum == SYS_open ||
					ev->e_un.sysnum == SYS_stat )) {
				ptrace(PTRACE_GETREGS, pid, 0, &iregs);
				ret = fseek(mem_fp, iregs.rdi, SEEK_SET);
				if (ret != 0)
					ABORT("failed to seek\n");
				fflush(mem_fp);
				fgets(original_path, PATH_MAX, mem_fp);
				if (ferror(mem_fp)){
					ABORT("failed to read\n");
				}
				/* lookup up if we have a mapping for the current path */
				HASH_FIND_STR(global_mappings, original_path, mapping);
				if (mapping){
					/* we have to rewrite the file path */
#ifdef DEBUG
					fprintf(stderr, "%s -> %s\n", original_path, mapping->rewritten_path);
#endif
					strcpy(localshm, mapping->rewritten_path);
					iregs.rdi = (unsigned long int)childshm;
					EXITIF(ptrace(PTRACE_SETREGS, pid, NULL, (long)&iregs) < 0);
				}else{
#ifdef DEBUG
					fprintf(stderr, "%s not found\n", original_path);
#endif
				}
				syscall_return = 1;
			}else if (syscall_return && (ev->e_un.sysnum == SYS_open ||
					ev->e_un.sysnum == SYS_stat)) {
				//fprintf(stderr, "Ret from open\n");
				syscall_return = 0;
			}
		} else if (ev->type == EVENT_NEW) {
			handle_new(ev);
		} else if (ev->type == EVENT_CLONE || ev->type == EVENT_VFORK ) {
			handle_clone(ev);
		}
		//fprintf(stderr, "call: %d\n", ev->type);
		if ( ev->proc )
			continue_process(ev->proc->pid);
		else
#ifdef DEBUG
			fprintf(stderr, "Unable to continue main process skipping...\n");
#endif
			;
	}
	fclose(mem_fp);
	return 0;
}


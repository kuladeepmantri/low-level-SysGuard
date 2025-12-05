/*
 * Auris - ARM64 Linux Syscall Table
 * Complete syscall number to name mapping with argument types
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auris.h"
#include "syscall_table.h"
#include "tracer.h"

/* Syscall table - populated at init */
static sg_syscall_desc_t *g_syscall_table = NULL;
static size_t g_syscall_count = 0;
static bool g_initialized = false;

/* Macro to define a syscall entry */
#define SYSCALL_DEF(nr, name, cat, essential, sensitive, nargs, ...) \
    { nr, #name, cat, nargs, { __VA_ARGS__ }, essential, sensitive, NULL }

/* Core syscall definitions for ARM64 Linux */
static const sg_syscall_desc_t syscall_defs[] = {
    /* I/O operations */
    SYSCALL_DEF(SYS_read, read, SYSCALL_CAT_FILE, true, false, 3,
                ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_write, write, SYSCALL_CAT_FILE, true, false, 3,
                ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_openat, openat, SYSCALL_CAT_FILE, true, false, 4,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_FLAGS, ARG_TYPE_MODE),
    SYSCALL_DEF(SYS_close, close, SYSCALL_CAT_FILE, true, false, 1,
                ARG_TYPE_FD),
    SYSCALL_DEF(SYS_lseek, lseek, SYSCALL_CAT_FILE, false, false, 3,
                ARG_TYPE_FD, ARG_TYPE_LONG, ARG_TYPE_INT),
    SYSCALL_DEF(SYS_pread64, pread64, SYSCALL_CAT_FILE, false, false, 4,
                ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_SIZE, ARG_TYPE_LONG),
    SYSCALL_DEF(SYS_pwrite64, pwrite64, SYSCALL_CAT_FILE, false, false, 4,
                ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_SIZE, ARG_TYPE_LONG),
    SYSCALL_DEF(SYS_readv, readv, SYSCALL_CAT_FILE, false, false, 3,
                ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_INT),
    SYSCALL_DEF(SYS_writev, writev, SYSCALL_CAT_FILE, false, false, 3,
                ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_INT),
    
    /* File system */
    SYSCALL_DEF(SYS_newfstatat, fstatat, SYSCALL_CAT_FILE, true, false, 4,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_PTR, ARG_TYPE_FLAGS),
    SYSCALL_DEF(SYS_fstat, fstat, SYSCALL_CAT_FILE, true, false, 2,
                ARG_TYPE_FD, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_statx, statx, SYSCALL_CAT_FILE, false, false, 5,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_FLAGS, ARG_TYPE_UINT, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_faccessat, faccessat, SYSCALL_CAT_FILE, false, false, 3,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_INT),
    SYSCALL_DEF(SYS_faccessat2, faccessat2, SYSCALL_CAT_FILE, false, false, 4,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_INT, ARG_TYPE_FLAGS),
    SYSCALL_DEF(SYS_getcwd, getcwd, SYSCALL_CAT_FILE, false, false, 2,
                ARG_TYPE_PTR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_chdir, chdir, SYSCALL_CAT_FILESYSTEM, false, false, 1,
                ARG_TYPE_PATH),
    SYSCALL_DEF(SYS_fchdir, fchdir, SYSCALL_CAT_FILESYSTEM, false, false, 1,
                ARG_TYPE_FD),
    SYSCALL_DEF(SYS_mkdirat, mkdirat, SYSCALL_CAT_FILE, false, false, 3,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_MODE),
    SYSCALL_DEF(SYS_unlinkat, unlinkat, SYSCALL_CAT_FILE, false, false, 3,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_FLAGS),
    SYSCALL_DEF(SYS_renameat, renameat, SYSCALL_CAT_FILE, false, false, 4,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_FD, ARG_TYPE_PATH),
    SYSCALL_DEF(SYS_renameat2, renameat2, SYSCALL_CAT_FILE, false, false, 5,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_FLAGS),
    SYSCALL_DEF(SYS_linkat, linkat, SYSCALL_CAT_FILE, false, false, 5,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_FLAGS),
    SYSCALL_DEF(SYS_symlinkat, symlinkat, SYSCALL_CAT_FILE, false, false, 3,
                ARG_TYPE_PATH, ARG_TYPE_FD, ARG_TYPE_PATH),
    SYSCALL_DEF(SYS_readlinkat, readlinkat, SYSCALL_CAT_FILE, false, false, 4,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_PTR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_fchmod, fchmod, SYSCALL_CAT_FILE, false, true, 2,
                ARG_TYPE_FD, ARG_TYPE_MODE),
    SYSCALL_DEF(SYS_fchmodat, fchmodat, SYSCALL_CAT_FILE, false, true, 3,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_MODE),
    SYSCALL_DEF(SYS_fchown, fchown, SYSCALL_CAT_FILE, false, true, 3,
                ARG_TYPE_FD, ARG_TYPE_UID, ARG_TYPE_GID),
    SYSCALL_DEF(SYS_fchownat, fchownat, SYSCALL_CAT_FILE, false, true, 5,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_UID, ARG_TYPE_GID, ARG_TYPE_FLAGS),
    SYSCALL_DEF(SYS_truncate, truncate, SYSCALL_CAT_FILE, false, false, 2,
                ARG_TYPE_PATH, ARG_TYPE_LONG),
    SYSCALL_DEF(SYS_ftruncate, ftruncate, SYSCALL_CAT_FILE, false, false, 2,
                ARG_TYPE_FD, ARG_TYPE_LONG),
    SYSCALL_DEF(SYS_getdents64, getdents64, SYSCALL_CAT_FILE, false, false, 3,
                ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_UINT),
    
    /* File descriptor operations */
    SYSCALL_DEF(SYS_dup, dup, SYSCALL_CAT_FILE, true, false, 1,
                ARG_TYPE_FD),
    SYSCALL_DEF(SYS_dup3, dup3, SYSCALL_CAT_FILE, true, false, 3,
                ARG_TYPE_FD, ARG_TYPE_FD, ARG_TYPE_FLAGS),
    SYSCALL_DEF(SYS_fcntl, fcntl, SYSCALL_CAT_FILE, true, false, 3,
                ARG_TYPE_FD, ARG_TYPE_INT, ARG_TYPE_ULONG),
    SYSCALL_DEF(SYS_ioctl, ioctl, SYSCALL_CAT_IO, true, false, 3,
                ARG_TYPE_FD, ARG_TYPE_ULONG, ARG_TYPE_ULONG),
    SYSCALL_DEF(SYS_pipe2, pipe2, SYSCALL_CAT_IPC, false, false, 2,
                ARG_TYPE_PTR, ARG_TYPE_FLAGS),
    
    /* Memory management */
    SYSCALL_DEF(SYS_brk, brk, SYSCALL_CAT_MEMORY, true, false, 1,
                ARG_TYPE_ULONG),
    SYSCALL_DEF(SYS_mmap, mmap, SYSCALL_CAT_MEMORY, true, false, 6,
                ARG_TYPE_PTR, ARG_TYPE_SIZE, ARG_TYPE_INT, ARG_TYPE_INT, ARG_TYPE_FD, ARG_TYPE_LONG),
    SYSCALL_DEF(SYS_munmap, munmap, SYSCALL_CAT_MEMORY, true, false, 2,
                ARG_TYPE_PTR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_mprotect, mprotect, SYSCALL_CAT_MEMORY, true, false, 3,
                ARG_TYPE_PTR, ARG_TYPE_SIZE, ARG_TYPE_INT),
    SYSCALL_DEF(SYS_mremap, mremap, SYSCALL_CAT_MEMORY, false, false, 5,
                ARG_TYPE_PTR, ARG_TYPE_SIZE, ARG_TYPE_SIZE, ARG_TYPE_FLAGS, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_madvise, madvise, SYSCALL_CAT_MEMORY, false, false, 3,
                ARG_TYPE_PTR, ARG_TYPE_SIZE, ARG_TYPE_INT),
    SYSCALL_DEF(SYS_mlock, mlock, SYSCALL_CAT_MEMORY, false, false, 2,
                ARG_TYPE_PTR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_munlock, munlock, SYSCALL_CAT_MEMORY, false, false, 2,
                ARG_TYPE_PTR, ARG_TYPE_SIZE),
    
    /* Process management */
    SYSCALL_DEF(SYS_clone, clone, SYSCALL_CAT_PROCESS, true, false, 5,
                ARG_TYPE_FLAGS, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_clone3, clone3, SYSCALL_CAT_PROCESS, false, false, 2,
                ARG_TYPE_PTR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_execve, execve, SYSCALL_CAT_PROCESS, true, true, 3,
                ARG_TYPE_PATH, ARG_TYPE_PTR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_execveat, execveat, SYSCALL_CAT_PROCESS, false, true, 5,
                ARG_TYPE_FD, ARG_TYPE_PATH, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_FLAGS),
    SYSCALL_DEF(SYS_exit, exit, SYSCALL_CAT_PROCESS, true, false, 1,
                ARG_TYPE_INT),
    SYSCALL_DEF(SYS_exit_group, exit_group, SYSCALL_CAT_PROCESS, true, false, 1,
                ARG_TYPE_INT),
    SYSCALL_DEF(SYS_wait4, wait4, SYSCALL_CAT_PROCESS, true, false, 4,
                ARG_TYPE_PID, ARG_TYPE_PTR, ARG_TYPE_INT, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_waitid, waitid, SYSCALL_CAT_PROCESS, false, false, 5,
                ARG_TYPE_INT, ARG_TYPE_PID, ARG_TYPE_PTR, ARG_TYPE_INT, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_getpid, getpid, SYSCALL_CAT_INFO, true, false, 0),
    SYSCALL_DEF(SYS_getppid, getppid, SYSCALL_CAT_INFO, false, false, 0),
    SYSCALL_DEF(SYS_gettid, gettid, SYSCALL_CAT_INFO, true, false, 0),
    SYSCALL_DEF(SYS_getpgid, getpgid, SYSCALL_CAT_INFO, false, false, 1,
                ARG_TYPE_PID),
    SYSCALL_DEF(SYS_setpgid, setpgid, SYSCALL_CAT_PROCESS, false, false, 2,
                ARG_TYPE_PID, ARG_TYPE_PID),
    SYSCALL_DEF(SYS_getsid, getsid, SYSCALL_CAT_INFO, false, false, 1,
                ARG_TYPE_PID),
    SYSCALL_DEF(SYS_setsid, setsid, SYSCALL_CAT_PROCESS, false, false, 0),
    SYSCALL_DEF(SYS_prctl, prctl, SYSCALL_CAT_SECURITY, false, true, 5,
                ARG_TYPE_INT, ARG_TYPE_ULONG, ARG_TYPE_ULONG, ARG_TYPE_ULONG, ARG_TYPE_ULONG),
    
    /* User/Group IDs */
    SYSCALL_DEF(SYS_getuid, getuid, SYSCALL_CAT_INFO, true, false, 0),
    SYSCALL_DEF(SYS_geteuid, geteuid, SYSCALL_CAT_INFO, false, false, 0),
    SYSCALL_DEF(SYS_getgid, getgid, SYSCALL_CAT_INFO, false, false, 0),
    SYSCALL_DEF(SYS_getegid, getegid, SYSCALL_CAT_INFO, false, false, 0),
    SYSCALL_DEF(SYS_setuid, setuid, SYSCALL_CAT_SECURITY, false, true, 1,
                ARG_TYPE_UID),
    SYSCALL_DEF(SYS_setgid, setgid, SYSCALL_CAT_SECURITY, false, true, 1,
                ARG_TYPE_GID),
    SYSCALL_DEF(SYS_setreuid, setreuid, SYSCALL_CAT_SECURITY, false, true, 2,
                ARG_TYPE_UID, ARG_TYPE_UID),
    SYSCALL_DEF(SYS_setregid, setregid, SYSCALL_CAT_SECURITY, false, true, 2,
                ARG_TYPE_GID, ARG_TYPE_GID),
    SYSCALL_DEF(SYS_setresuid, setresuid, SYSCALL_CAT_SECURITY, false, true, 3,
                ARG_TYPE_UID, ARG_TYPE_UID, ARG_TYPE_UID),
    SYSCALL_DEF(SYS_setresgid, setresgid, SYSCALL_CAT_SECURITY, false, true, 3,
                ARG_TYPE_GID, ARG_TYPE_GID, ARG_TYPE_GID),
    SYSCALL_DEF(SYS_getresuid, getresuid, SYSCALL_CAT_INFO, false, false, 3,
                ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_getresgid, getresgid, SYSCALL_CAT_INFO, false, false, 3,
                ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_getgroups, getgroups, SYSCALL_CAT_INFO, false, false, 2,
                ARG_TYPE_INT, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_setgroups, setgroups, SYSCALL_CAT_SECURITY, false, true, 2,
                ARG_TYPE_INT, ARG_TYPE_PTR),
    
    /* Networking */
    SYSCALL_DEF(SYS_socket, socket, SYSCALL_CAT_NETWORK, false, false, 3,
                ARG_TYPE_INT, ARG_TYPE_INT, ARG_TYPE_INT),
    SYSCALL_DEF(SYS_socketpair, socketpair, SYSCALL_CAT_NETWORK, false, false, 4,
                ARG_TYPE_INT, ARG_TYPE_INT, ARG_TYPE_INT, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_bind, bind, SYSCALL_CAT_NETWORK, false, false, 3,
                ARG_TYPE_FD, ARG_TYPE_SOCKADDR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_listen, listen, SYSCALL_CAT_NETWORK, false, false, 2,
                ARG_TYPE_FD, ARG_TYPE_INT),
    SYSCALL_DEF(SYS_accept, accept, SYSCALL_CAT_NETWORK, false, false, 3,
                ARG_TYPE_FD, ARG_TYPE_SOCKADDR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_accept4, accept4, SYSCALL_CAT_NETWORK, false, false, 4,
                ARG_TYPE_FD, ARG_TYPE_SOCKADDR, ARG_TYPE_PTR, ARG_TYPE_FLAGS),
    SYSCALL_DEF(SYS_connect, connect, SYSCALL_CAT_NETWORK, false, true, 3,
                ARG_TYPE_FD, ARG_TYPE_SOCKADDR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_getsockname, getsockname, SYSCALL_CAT_NETWORK, false, false, 3,
                ARG_TYPE_FD, ARG_TYPE_SOCKADDR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_getpeername, getpeername, SYSCALL_CAT_NETWORK, false, false, 3,
                ARG_TYPE_FD, ARG_TYPE_SOCKADDR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_sendto, sendto, SYSCALL_CAT_NETWORK, false, false, 6,
                ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_SIZE, ARG_TYPE_FLAGS, ARG_TYPE_SOCKADDR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_recvfrom, recvfrom, SYSCALL_CAT_NETWORK, false, false, 6,
                ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_SIZE, ARG_TYPE_FLAGS, ARG_TYPE_SOCKADDR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_sendmsg, sendmsg, SYSCALL_CAT_NETWORK, false, false, 3,
                ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_FLAGS),
    SYSCALL_DEF(SYS_recvmsg, recvmsg, SYSCALL_CAT_NETWORK, false, false, 3,
                ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_FLAGS),
    SYSCALL_DEF(SYS_shutdown, shutdown, SYSCALL_CAT_NETWORK, false, false, 2,
                ARG_TYPE_FD, ARG_TYPE_INT),
    SYSCALL_DEF(SYS_setsockopt, setsockopt, SYSCALL_CAT_NETWORK, false, false, 5,
                ARG_TYPE_FD, ARG_TYPE_INT, ARG_TYPE_INT, ARG_TYPE_PTR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_getsockopt, getsockopt, SYSCALL_CAT_NETWORK, false, false, 5,
                ARG_TYPE_FD, ARG_TYPE_INT, ARG_TYPE_INT, ARG_TYPE_PTR, ARG_TYPE_PTR),
    
    /* Signals */
    SYSCALL_DEF(SYS_kill, kill, SYSCALL_CAT_SIGNAL, false, true, 2,
                ARG_TYPE_PID, ARG_TYPE_SIGNAL),
    SYSCALL_DEF(SYS_tkill, tkill, SYSCALL_CAT_SIGNAL, false, true, 2,
                ARG_TYPE_PID, ARG_TYPE_SIGNAL),
    SYSCALL_DEF(SYS_tgkill, tgkill, SYSCALL_CAT_SIGNAL, false, true, 3,
                ARG_TYPE_PID, ARG_TYPE_PID, ARG_TYPE_SIGNAL),
    SYSCALL_DEF(SYS_rt_sigaction, rt_sigaction, SYSCALL_CAT_SIGNAL, true, false, 4,
                ARG_TYPE_SIGNAL, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_rt_sigprocmask, rt_sigprocmask, SYSCALL_CAT_SIGNAL, true, false, 4,
                ARG_TYPE_INT, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_rt_sigreturn, rt_sigreturn, SYSCALL_CAT_SIGNAL, true, false, 0),
    SYSCALL_DEF(SYS_sigaltstack, sigaltstack, SYSCALL_CAT_SIGNAL, false, false, 2,
                ARG_TYPE_PTR, ARG_TYPE_PTR),
    
    /* Time */
    SYSCALL_DEF(SYS_clock_gettime, clock_gettime, SYSCALL_CAT_TIME, true, false, 2,
                ARG_TYPE_INT, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_clock_getres, clock_getres, SYSCALL_CAT_TIME, false, false, 2,
                ARG_TYPE_INT, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_clock_nanosleep, clock_nanosleep, SYSCALL_CAT_TIME, false, false, 4,
                ARG_TYPE_INT, ARG_TYPE_FLAGS, ARG_TYPE_PTR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_gettimeofday, gettimeofday, SYSCALL_CAT_TIME, false, false, 2,
                ARG_TYPE_PTR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_nanosleep, nanosleep, SYSCALL_CAT_TIME, false, false, 2,
                ARG_TYPE_PTR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_times, times, SYSCALL_CAT_TIME, false, false, 1,
                ARG_TYPE_PTR),
    
    /* System info */
    SYSCALL_DEF(SYS_uname, uname, SYSCALL_CAT_INFO, false, false, 1,
                ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_sysinfo, sysinfo, SYSCALL_CAT_INFO, false, false, 1,
                ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_getrlimit, getrlimit, SYSCALL_CAT_INFO, false, false, 2,
                ARG_TYPE_UINT, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_setrlimit, setrlimit, SYSCALL_CAT_SECURITY, false, true, 2,
                ARG_TYPE_UINT, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_prlimit64, prlimit64, SYSCALL_CAT_SECURITY, false, true, 4,
                ARG_TYPE_PID, ARG_TYPE_UINT, ARG_TYPE_PTR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_getrusage, getrusage, SYSCALL_CAT_INFO, false, false, 2,
                ARG_TYPE_INT, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_getcpu, getcpu, SYSCALL_CAT_INFO, false, false, 3,
                ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_getrandom, getrandom, SYSCALL_CAT_MISC, false, false, 3,
                ARG_TYPE_PTR, ARG_TYPE_SIZE, ARG_TYPE_FLAGS),
    
    /* Futex/threading */
    SYSCALL_DEF(SYS_futex, futex, SYSCALL_CAT_IPC, true, false, 6,
                ARG_TYPE_PTR, ARG_TYPE_INT, ARG_TYPE_UINT, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_UINT),
    SYSCALL_DEF(SYS_set_tid_address, set_tid_address, SYSCALL_CAT_PROCESS, true, false, 1,
                ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_set_robust_list, set_robust_list, SYSCALL_CAT_PROCESS, true, false, 2,
                ARG_TYPE_PTR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_get_robust_list, get_robust_list, SYSCALL_CAT_PROCESS, false, false, 3,
                ARG_TYPE_PID, ARG_TYPE_PTR, ARG_TYPE_PTR),
    
    /* Polling/select */
    SYSCALL_DEF(SYS_epoll_create1, epoll_create1, SYSCALL_CAT_IO, false, false, 1,
                ARG_TYPE_FLAGS),
    SYSCALL_DEF(SYS_epoll_ctl, epoll_ctl, SYSCALL_CAT_IO, false, false, 4,
                ARG_TYPE_FD, ARG_TYPE_INT, ARG_TYPE_FD, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_epoll_pwait, epoll_pwait, SYSCALL_CAT_IO, false, false, 6,
                ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_INT, ARG_TYPE_INT, ARG_TYPE_PTR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_ppoll, ppoll, SYSCALL_CAT_IO, false, false, 5,
                ARG_TYPE_PTR, ARG_TYPE_UINT, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_SIZE),
    SYSCALL_DEF(SYS_pselect6, pselect6, SYSCALL_CAT_IO, false, false, 6,
                ARG_TYPE_INT, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_PTR),
    
    /* Filesystem operations */
    SYSCALL_DEF(SYS_mount, mount, SYSCALL_CAT_FILESYSTEM, false, true, 5,
                ARG_TYPE_PATH, ARG_TYPE_PATH, ARG_TYPE_STR, ARG_TYPE_ULONG, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_umount2, umount2, SYSCALL_CAT_FILESYSTEM, false, true, 2,
                ARG_TYPE_PATH, ARG_TYPE_FLAGS),
    SYSCALL_DEF(SYS_chroot, chroot, SYSCALL_CAT_FILESYSTEM, false, true, 1,
                ARG_TYPE_PATH),
    SYSCALL_DEF(SYS_pivot_root, pivot_root, SYSCALL_CAT_FILESYSTEM, false, true, 2,
                ARG_TYPE_PATH, ARG_TYPE_PATH),
    SYSCALL_DEF(SYS_sync, sync, SYSCALL_CAT_FILE, false, false, 0),
    SYSCALL_DEF(SYS_fsync, fsync, SYSCALL_CAT_FILE, false, false, 1,
                ARG_TYPE_FD),
    SYSCALL_DEF(SYS_fdatasync, fdatasync, SYSCALL_CAT_FILE, false, false, 1,
                ARG_TYPE_FD),
    SYSCALL_DEF(SYS_statfs, statfs, SYSCALL_CAT_FILE, false, false, 2,
                ARG_TYPE_PATH, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_fstatfs, fstatfs, SYSCALL_CAT_FILE, false, false, 2,
                ARG_TYPE_FD, ARG_TYPE_PTR),
    
    /* Security/capabilities */
    SYSCALL_DEF(SYS_capget, capget, SYSCALL_CAT_SECURITY, false, false, 2,
                ARG_TYPE_PTR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_capset, capset, SYSCALL_CAT_SECURITY, false, true, 2,
                ARG_TYPE_PTR, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_seccomp, seccomp, SYSCALL_CAT_SECURITY, false, true, 3,
                ARG_TYPE_UINT, ARG_TYPE_UINT, ARG_TYPE_PTR),
    SYSCALL_DEF(SYS_ptrace, ptrace, SYSCALL_CAT_SECURITY, false, true, 4,
                ARG_TYPE_LONG, ARG_TYPE_PID, ARG_TYPE_PTR, ARG_TYPE_PTR),
    
    /* Misc */
    SYSCALL_DEF(SYS_umask, umask, SYSCALL_CAT_FILE, false, false, 1,
                ARG_TYPE_MODE),
    SYSCALL_DEF(SYS_personality, personality, SYSCALL_CAT_PROCESS, false, false, 1,
                ARG_TYPE_ULONG),
    SYSCALL_DEF(SYS_restart_syscall, restart_syscall, SYSCALL_CAT_MISC, true, false, 0),
    SYSCALL_DEF(SYS_rseq, rseq, SYSCALL_CAT_MISC, false, false, 4,
                ARG_TYPE_PTR, ARG_TYPE_UINT, ARG_TYPE_INT, ARG_TYPE_UINT),
    SYSCALL_DEF(SYS_memfd_create, memfd_create, SYSCALL_CAT_MEMORY, false, false, 2,
                ARG_TYPE_STR, ARG_TYPE_FLAGS),
    
    /* Sentinel */
    { 0, NULL, 0, 0, { 0 }, false, false, NULL }
};

sg_error_t sg_syscall_table_init(void)
{
    if (g_initialized) {
        return SG_OK;
    }
    
    /* Count syscalls */
    size_t count = 0;
    while (syscall_defs[count].name != NULL) {
        count++;
    }
    
    /* Allocate table */
    g_syscall_table = calloc(MAX_SYSCALL_NR, sizeof(sg_syscall_desc_t));
    if (g_syscall_table == NULL) {
        return SG_ERR_NOMEM;
    }
    
    /* Populate table indexed by syscall number */
    for (size_t i = 0; i < count; i++) {
        uint32_t nr = syscall_defs[i].nr;
        if (nr < MAX_SYSCALL_NR) {
            g_syscall_table[nr] = syscall_defs[i];
        }
    }
    
    g_syscall_count = count;
    g_initialized = true;
    
    return SG_OK;
}

void sg_syscall_table_cleanup(void)
{
    if (g_syscall_table != NULL) {
        free(g_syscall_table);
        g_syscall_table = NULL;
    }
    g_syscall_count = 0;
    g_initialized = false;
}

const sg_syscall_desc_t *sg_syscall_lookup(uint32_t nr)
{
    if (!g_initialized || nr >= MAX_SYSCALL_NR) {
        return NULL;
    }
    
    if (g_syscall_table[nr].name == NULL) {
        return NULL;
    }
    
    return &g_syscall_table[nr];
}

const sg_syscall_desc_t *sg_syscall_lookup_by_name(const char *name)
{
    if (!g_initialized || name == NULL) {
        return NULL;
    }
    
    for (uint32_t i = 0; i < MAX_SYSCALL_NR; i++) {
        if (g_syscall_table[i].name != NULL &&
            strcmp(g_syscall_table[i].name, name) == 0) {
            return &g_syscall_table[i];
        }
    }
    
    return NULL;
}

const char *sg_syscall_name(uint32_t nr)
{
    const sg_syscall_desc_t *desc = sg_syscall_lookup(nr);
    if (desc == NULL) {
        return "unknown";
    }
    return desc->name;
}

int sg_syscall_nr(const char *name)
{
    const sg_syscall_desc_t *desc = sg_syscall_lookup_by_name(name);
    if (desc == NULL) {
        return -1;
    }
    return (int)desc->nr;
}

bool sg_syscall_is_category(uint32_t nr, sg_syscall_cat_t cat)
{
    const sg_syscall_desc_t *desc = sg_syscall_lookup(nr);
    if (desc == NULL) {
        return false;
    }
    return desc->category == cat;
}

bool sg_syscall_is_essential(uint32_t nr)
{
    const sg_syscall_desc_t *desc = sg_syscall_lookup(nr);
    if (desc == NULL) {
        return false;
    }
    return desc->is_essential;
}

bool sg_syscall_is_sensitive(uint32_t nr)
{
    const sg_syscall_desc_t *desc = sg_syscall_lookup(nr);
    if (desc == NULL) {
        return false;
    }
    return desc->is_sensitive;
}

size_t sg_syscall_get_by_category(sg_syscall_cat_t cat, uint32_t *out, size_t max_count)
{
    if (!g_initialized || out == NULL || max_count == 0) {
        return 0;
    }
    
    size_t count = 0;
    for (uint32_t i = 0; i < MAX_SYSCALL_NR && count < max_count; i++) {
        if (g_syscall_table[i].name != NULL &&
            g_syscall_table[i].category == cat) {
            out[count++] = i;
        }
    }
    
    return count;
}

size_t sg_syscall_get_essential(uint32_t *out, size_t max_count)
{
    if (!g_initialized || out == NULL || max_count == 0) {
        return 0;
    }
    
    size_t count = 0;
    for (uint32_t i = 0; i < MAX_SYSCALL_NR && count < max_count; i++) {
        if (g_syscall_table[i].name != NULL &&
            g_syscall_table[i].is_essential) {
            out[count++] = i;
        }
    }
    
    return count;
}

sg_error_t sg_syscall_decode_args(pid_t pid,
                                   uint32_t syscall_nr,
                                   const uint64_t raw_args[6],
                                   sg_arg_value_t decoded[6],
                                   size_t max_string_len)
{
    if (raw_args == NULL || decoded == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Initialize all args as invalid */
    for (int i = 0; i < 6; i++) {
        decoded[i].type = ARG_TYPE_NONE;
        decoded[i].valid = false;
    }
    
    const sg_syscall_desc_t *desc = sg_syscall_lookup(syscall_nr);
    if (desc == NULL) {
        /* Unknown syscall - just store raw values */
        for (int i = 0; i < 6; i++) {
            decoded[i].type = ARG_TYPE_ULONG;
            decoded[i].value.u64 = raw_args[i];
            decoded[i].valid = true;
        }
        return SG_OK;
    }
    
    /* Decode each argument based on type */
    for (int i = 0; i < desc->arg_count && i < 6; i++) {
        decoded[i].type = desc->arg_types[i];
        decoded[i].valid = true;
        
        switch (desc->arg_types[i]) {
            case ARG_TYPE_INT:
            case ARG_TYPE_SIGNAL:
                decoded[i].value.i64 = (int32_t)raw_args[i];
                break;
                
            case ARG_TYPE_UINT:
            case ARG_TYPE_FLAGS:
            case ARG_TYPE_MODE:
                decoded[i].value.u64 = (uint32_t)raw_args[i];
                break;
                
            case ARG_TYPE_LONG:
            case ARG_TYPE_PID:
                decoded[i].value.i64 = (int64_t)raw_args[i];
                break;
                
            case ARG_TYPE_ULONG:
            case ARG_TYPE_SIZE:
            case ARG_TYPE_PTR:
                decoded[i].value.u64 = raw_args[i];
                break;
                
            case ARG_TYPE_FD:
                decoded[i].value.i64 = (int32_t)raw_args[i];
                break;
                
            case ARG_TYPE_UID:
            case ARG_TYPE_GID:
                decoded[i].value.u64 = (uint32_t)raw_args[i];
                break;
                
            case ARG_TYPE_STR:
            case ARG_TYPE_PATH:
                if (raw_args[i] != 0 && pid > 0) {
                    ssize_t len = sg_read_string(pid, raw_args[i],
                                                  decoded[i].value.str,
                                                  max_string_len > 0 ? max_string_len : MAX_PATH_LEN);
                    if (len < 0) {
                        decoded[i].value.str[0] = '\0';
                        decoded[i].valid = false;
                    }
                } else {
                    decoded[i].value.str[0] = '\0';
                }
                break;
                
            case ARG_TYPE_SOCKADDR:
                if (raw_args[i] != 0 && pid > 0) {
                    /* Need the length from next arg typically */
                    size_t addr_len = (i + 1 < 6) ? (size_t)raw_args[i + 1] : 128;
                    sg_error_t err = sg_read_sockaddr(pid, raw_args[i], addr_len,
                                                       &decoded[i].value.addr);
                    if (err != SG_OK) {
                        decoded[i].valid = false;
                    }
                }
                break;
                
            default:
                decoded[i].value.u64 = raw_args[i];
                break;
        }
    }
    
    return SG_OK;
}

/* Static buffer for formatting */
static __thread char format_buf[4096];

const char *sg_syscall_format(const sg_syscall_event_t *event)
{
    if (event == NULL) {
        return "(null)";
    }
    
    int pos = 0;
    pos += snprintf(format_buf + pos, sizeof(format_buf) - pos,
                    "%s(", event->syscall_name);
    
    pos += sg_syscall_format_args(event, format_buf + pos, sizeof(format_buf) - pos);
    
    pos += snprintf(format_buf + pos, sizeof(format_buf) - pos,
                    ") = %ld", (long)event->ret_value);
    
    if (event->ret_value < 0 && event->err_no != 0) {
        pos += snprintf(format_buf + pos, sizeof(format_buf) - pos,
                        " (errno=%d)", event->err_no);
    }
    
    return format_buf;
}

int sg_syscall_format_args(const sg_syscall_event_t *event, char *buf, size_t len)
{
    if (event == NULL || buf == NULL || len == 0) {
        return 0;
    }
    
    int pos = 0;
    bool first = true;
    
    for (int i = 0; i < MAX_SYSCALL_ARGS; i++) {
        if (!event->args[i].valid) {
            continue;
        }
        
        if (!first) {
            pos += snprintf(buf + pos, len - pos, ", ");
        }
        first = false;
        
        switch (event->args[i].type) {
            case ARG_TYPE_INT:
            case ARG_TYPE_LONG:
            case ARG_TYPE_PID:
            case ARG_TYPE_SIGNAL:
                pos += snprintf(buf + pos, len - pos, "%ld",
                               (long)event->args[i].value.i64);
                break;
                
            case ARG_TYPE_UINT:
            case ARG_TYPE_ULONG:
            case ARG_TYPE_SIZE:
            case ARG_TYPE_UID:
            case ARG_TYPE_GID:
                pos += snprintf(buf + pos, len - pos, "%lu",
                               (unsigned long)event->args[i].value.u64);
                break;
                
            case ARG_TYPE_FD:
                pos += snprintf(buf + pos, len - pos, "%d",
                               (int)event->args[i].value.i64);
                break;
                
            case ARG_TYPE_FLAGS:
            case ARG_TYPE_MODE:
                pos += snprintf(buf + pos, len - pos, "0x%lx",
                               (unsigned long)event->args[i].value.u64);
                break;
                
            case ARG_TYPE_PTR:
                if (event->args[i].value.u64 == 0) {
                    pos += snprintf(buf + pos, len - pos, "NULL");
                } else {
                    pos += snprintf(buf + pos, len - pos, "0x%lx",
                                   (unsigned long)event->args[i].value.u64);
                }
                break;
                
            case ARG_TYPE_STR:
            case ARG_TYPE_PATH:
                pos += snprintf(buf + pos, len - pos, "\"%s\"",
                               event->args[i].value.str);
                break;
                
            case ARG_TYPE_SOCKADDR:
                pos += snprintf(buf + pos, len - pos, "{%s}",
                               event->args[i].value.addr.str);
                break;
                
            default:
                pos += snprintf(buf + pos, len - pos, "0x%lx",
                               (unsigned long)event->args[i].value.u64);
                break;
        }
        
        if ((size_t)pos >= len - 1) {
            break;
        }
    }
    
    return pos;
}

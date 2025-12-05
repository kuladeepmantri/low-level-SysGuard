'use client'

import ThemeToggle from './components/ThemeToggle'
import AnimatedTerminal from './components/AnimatedTerminal'

export default function Home() {

  return (
    <div className="min-h-screen bg-[var(--bg)]">
      {/* Solid fixed header */}
      <header className="fixed top-0 w-full z-50 bg-[var(--bg)] border-b border-[var(--border)]">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
          <a href="http://kuladeepmantri.com/" className="font-medium text-[var(--text)]">kuladeepmantri</a>
          <div className="flex items-center gap-4">
            <a 
              href="https://github.com/kuladeepmantri/Auris" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-sm text-[var(--text-secondary)] hover:text-[var(--text)] transition-colors"
            >
              GitHub
            </a>
            <ThemeToggle />
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 sm:px-6 pt-24 sm:pt-32 pb-16 sm:pb-24">
        {/* Hero */}
        <section className="mb-16 sm:mb-24">
          <p className="text-xs sm:text-sm text-[var(--text-muted)] mb-3 sm:mb-4 tracking-wide">ARM64 Linux Security Toolkit</p>
          <h1 className="text-4xl sm:text-5xl md:text-6xl font-light text-[var(--text)] mb-4 sm:mb-6 tracking-tight">
            Auris
          </h1>
          <p className="text-lg sm:text-xl text-[var(--text-secondary)] leading-relaxed max-w-2xl mb-4 sm:mb-6">
            Auris (Latin for "ear") is a security toolkit that intercepts every system call a process makes on ARM64 Linux. It uses the kernel's ptrace interface to attach to processes, monitor their behavior, and optionally modify their execution.
          </p>
          <p className="text-base sm:text-lg text-[var(--text-secondary)] leading-relaxed max-w-2xl">
            Version 2.0 introduces dual-purpose capabilities: defensive operations for behavioral analysis and policy enforcement, plus offensive operations for penetration testing and security research.
          </p>
        </section>

        {/* The Duality */}
        <section className="mb-16 sm:mb-24">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-8">
            <div className="p-4 sm:p-6 rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)]">
              <div className="text-sm font-medium text-blue-500 dark:text-blue-400 mb-3">Blue Team</div>
              <h3 className="text-lg font-medium text-[var(--text)] mb-3">Defensive Operations</h3>
              <p className="text-[var(--text-secondary)] text-sm leading-relaxed mb-4">
                Trace syscalls, build behavioral profiles, detect anomalies, enforce security policies. 
                Understand what normal looks like, then catch deviations.
              </p>
              <div className="text-xs text-[var(--text-muted)] font-mono">
                learn · profile · compare · policy · enforce
              </div>
            </div>
            <div className="p-4 sm:p-6 rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)]">
              <div className="text-sm font-medium text-red-500 dark:text-red-400 mb-3">Red Team</div>
              <h3 className="text-lg font-medium text-[var(--text)] mb-3">Offensive Operations</h3>
              <p className="text-[var(--text-secondary)] text-sm leading-relaxed mb-4">
                Inject shellcode, find ROP gadgets, manipulate process memory. The same ptrace 
                infrastructure that enables monitoring also enables exploitation.
              </p>
              <div className="text-xs text-[var(--text-muted)] font-mono">
                inject list · shellcode · gadgets · dump
              </div>
            </div>
          </div>
        </section>

        {/* How It Works */}
        <section className="mb-16 sm:mb-24">
          <h2 className="text-xl sm:text-2xl font-light text-[var(--text)] mb-4 sm:mb-6">How It Works</h2>
          
          <h3 className="text-base sm:text-lg font-medium text-[var(--text)] mb-3 sm:mb-4">The ptrace System Call</h3>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-6">
            Auris is built on <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">ptrace()</code>, a Linux system call that allows one process (the tracer) to observe and control another process (the tracee). This is the same mechanism used by debuggers like GDB. When Auris attaches to a process, the kernel stops the tracee before and after every system call, allowing Auris to inspect registers, read memory, and even modify the process state.
          </p>

          <h3 className="text-base sm:text-lg font-medium text-[var(--text)] mb-3 sm:mb-4">ARM64 Register Convention</h3>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            On ARM64 (AArch64) Linux, system calls follow a specific register convention:
          </p>
          <ul className="text-[var(--text-secondary)] mb-6 space-y-2 ml-4">
            <li><code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">x8</code> contains the syscall number (e.g., 221 for execve)</li>
            <li><code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">x0-x5</code> contain up to 6 arguments</li>
            <li><code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">x0</code> contains the return value after the syscall completes</li>
          </ul>
          
          <div className="p-3 sm:p-5 rounded-lg border border-[var(--border)] bg-[var(--terminal-bg)] font-mono text-xs sm:text-sm text-[var(--terminal-text)] mb-4 sm:mb-6">
            <pre className="overflow-x-auto">{`// Core tracing loop in Auris
while (1) {
    // Wait for tracee to stop at syscall entry/exit
    waitpid(pid, &status, 0);
    
    // Read all registers using GETREGSET
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    
    // Extract syscall information
    uint64_t syscall_nr = regs.regs[8];   // x8 = syscall number
    uint64_t arg0 = regs.regs[0];         // x0 = first argument
    uint64_t arg1 = regs.regs[1];         // x1 = second argument
    
    // Record, analyze, block, or inject...
    
    // Continue to next syscall
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
}`}</pre>
          </div>

          <h3 className="text-base sm:text-lg font-medium text-[var(--text)] mb-3 sm:mb-4">Capabilities Required</h3>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            To use ptrace, you need appropriate permissions. The Linux kernel's Yama security module controls ptrace access through <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">/proc/sys/kernel/yama/ptrace_scope</code>:
          </p>
          <ul className="text-[var(--text-secondary)] mb-6 space-y-2 ml-4">
            <li><strong>0</strong>: Any process can ptrace any other process owned by the same user</li>
            <li><strong>1</strong>: Only parent processes can ptrace their children (default on most systems)</li>
            <li><strong>2</strong>: Only processes with CAP_SYS_PTRACE can use ptrace</li>
            <li><strong>3</strong>: No process can use ptrace</li>
          </ul>
          <p className="text-[var(--text-secondary)] leading-relaxed">
            Auris typically requires running as root or with CAP_SYS_PTRACE capability. In Docker, use <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">--cap-add=SYS_PTRACE</code>.
          </p>
        </section>

        {/* Defense: Learning Behavior */}
        <section className="mb-16 sm:mb-24">
          <div className="text-sm font-medium text-blue-500 dark:text-blue-400 mb-3">Defense</div>
          <h2 className="text-xl sm:text-2xl font-light text-[var(--text)] mb-4 sm:mb-6">Command: learn</h2>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            The <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">learn</code> command traces a program's execution and records every system call it makes. This creates a trace file containing the complete syscall history, including syscall numbers, arguments, return values, and timing information.
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Usage:</strong> <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">auris learn [options] -- program [args...]</code>
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>What it captures:</strong>
          </p>
          <ul className="text-[var(--text-secondary)] mb-6 space-y-2 ml-4">
            <li>Every syscall number and its human-readable name (e.g., openat, read, write, mmap)</li>
            <li>All syscall arguments, with special handling for file paths, flags, and pointers</li>
            <li>Return values and error codes</li>
            <li>Timestamps for performance analysis</li>
            <li>Process metadata: PID, binary path, SHA256 hash of the executable</li>
          </ul>
          
          <AnimatedTerminal
            title="behavioral profiling"
            command="auris learn -- /bin/ls -la && auris profile -t trace-001"
            output={`[ptrace] Attached to process 2847
[trace] Intercepting syscalls...
  execve("/bin/ls", [...]) = 0
  openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY) = 3
  mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fff...
  close(3) = 0
  ...

[trace] Captured 127 syscalls in 14.2ms
Trace ID: trace-001

[profile] Computing statistics...
[profile] Shannon entropy: 3.41 bits
[profile] Behavior: file_io=yes, network=no, children=no
Profile ID: profile-001`}
          />
        </section>

        {/* Defense: Profile Command */}
        <section className="mb-16 sm:mb-24">
          <h2 className="text-xl sm:text-2xl font-light text-[var(--text)] mb-4 sm:mb-6">Command: profile</h2>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            The <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">profile</code> command analyzes a trace and builds a statistical behavioral profile. This profile captures the "fingerprint" of normal program behavior.
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Usage:</strong> <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">auris profile -t trace-id</code>
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Profile contents:</strong>
          </p>
          <ul className="text-[var(--text-secondary)] mb-6 space-y-2 ml-4">
            <li><strong>Syscall histogram:</strong> Which syscalls were used and how often</li>
            <li><strong>Shannon entropy:</strong> A measure of behavioral diversity (higher = more varied behavior)</li>
            <li><strong>File access patterns:</strong> Which files were opened, read, or written</li>
            <li><strong>Network behavior:</strong> Whether the program used sockets, connected to networks</li>
            <li><strong>Process spawning:</strong> Whether the program created child processes</li>
            <li><strong>Sensitive file access:</strong> Access to credentials, keys, or config files</li>
          </ul>
        </section>

        {/* Defense: Compare Command */}
        <section className="mb-16 sm:mb-24">
          <h2 className="text-xl sm:text-2xl font-light text-[var(--text)] mb-4 sm:mb-6">Command: compare</h2>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            The <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">compare</code> command runs a program while comparing its behavior against a baseline profile. It calculates a similarity score and flags any deviations.
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Usage:</strong> <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">auris compare -p profile-id -- program [args...]</code>
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>What it detects:</strong>
          </p>
          <ul className="text-[var(--text-secondary)] mb-6 space-y-2 ml-4">
            <li><strong>New syscalls:</strong> Syscalls that were never seen in the baseline</li>
            <li><strong>Missing syscalls:</strong> Expected syscalls that did not occur</li>
            <li><strong>Frequency anomalies:</strong> Syscalls occurring much more or less than expected</li>
            <li><strong>New file access:</strong> Files accessed that were not in the baseline</li>
            <li><strong>Network activity:</strong> Network operations when baseline had none</li>
          </ul>
          
          <AnimatedTerminal
            title="anomaly detection"
            command="auris compare -p profile-001 -- ./suspicious_binary"
            output={`[compare] Loading baseline profile-001...
[compare] Tracing ./suspicious_binary...
[compare] Analyzing behavioral differences...

Comparison Result
=================
Similarity Score: 0.34 (ANOMALOUS)

New Syscalls Detected:
  + socket (not in baseline)
  + connect (not in baseline)
  + sendto (not in baseline)

Sensitive File Access:
  ! /etc/passwd (not in baseline)
  ! ~/.ssh/id_rsa (CRITICAL - not in baseline)

Verdict: SUSPICIOUS - network activity and credential access`}
          />
        </section>

        {/* Defense: Policy and Enforce Commands */}
        <section className="mb-16 sm:mb-24">
          <h2 className="text-xl sm:text-2xl font-light text-[var(--text)] mb-4 sm:mb-6">Commands: policy and enforce</h2>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            The <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">policy</code> command generates a security policy from a behavioral profile. The <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">enforce</code> command then runs a program under that policy, blocking or alerting on violations.
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Usage:</strong>
          </p>
          <ul className="text-[var(--text-secondary)] mb-6 space-y-2 ml-4">
            <li><code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">auris policy -p profile-id</code> - Generate policy from profile</li>
            <li><code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">auris enforce -P policy-id -m alert -- program</code> - Log violations</li>
            <li><code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">auris enforce -P policy-id -m block -- program</code> - Block and terminate on violation</li>
          </ul>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Enforcement modes:</strong>
          </p>
          <ul className="text-[var(--text-secondary)] mb-6 space-y-2 ml-4">
            <li><strong>alert:</strong> Log violations but allow the program to continue. Useful for testing policies before enforcement.</li>
            <li><strong>block:</strong> When a violation occurs, the syscall is blocked (by setting x8 to -1) and the process is terminated with SIGKILL.</li>
          </ul>
          
          <AnimatedTerminal
            title="policy enforcement"
            command="auris enforce -P policy-001 -m block -- ./untrusted"
            output={`[enforce] Loading policy policy-001...
[enforce] Mode: BLOCK (violations will terminate process)
[enforce] Tracing ./untrusted...

[enforce] VIOLATION: socket() not in allowed syscalls
[enforce] Action: BLOCKED
[enforce] Process terminated with SIGKILL

Enforcement Summary
===================
Syscalls allowed: 45
Syscalls blocked: 1
Result: Process terminated due to policy violation`}
          />
        </section>

        {/* Offense: The Other Side */}
        <section className="mb-16 sm:mb-24">
          <div className="text-sm font-medium text-red-500 dark:text-red-400 mb-3">Offense</div>
          <h2 className="text-xl sm:text-2xl font-light text-[var(--text)] mb-4 sm:mb-6">Process Injection Framework</h2>
          
          <div className="p-4 mb-8 rounded-lg border border-red-300 dark:border-red-500/30 bg-red-50 dark:bg-red-500/5">
            <p className="text-sm text-red-700 dark:text-red-300 font-medium">
              Warning: For authorized security research and penetration testing only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and may result in criminal prosecution.
            </p>
          </div>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            The same ptrace mechanism that allows Auris to observe syscalls also enables it to modify process state. By writing to process memory and changing register values, Auris can inject and execute arbitrary code in a running process.
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>How injection works:</strong>
          </p>
          <ol className="text-[var(--text-secondary)] mb-6 space-y-2 ml-4 list-decimal list-inside">
            <li>Attach to the target process using PTRACE_ATTACH</li>
            <li>Wait for the process to stop (it receives SIGSTOP)</li>
            <li>Save the current register state using PTRACE_GETREGSET</li>
            <li>Save the original code at the injection point using PTRACE_PEEKDATA</li>
            <li>Write shellcode to executable memory using PTRACE_POKEDATA</li>
            <li>Set the program counter (PC) to point to the shellcode</li>
            <li>Continue execution with PTRACE_CONT</li>
            <li>Optionally restore original state after shellcode completes</li>
          </ol>
          
          <AnimatedTerminal
            title="target discovery"
            command="auris inject list"
            output={`Injectable Processes (47 found):
PID      NAME             UID      PATH
---      ----             ---      ----
1842     nginx            www-data /usr/sbin/nginx
2103     python3          user     /usr/bin/python3
2847     node             user     /usr/bin/node
3201     sleep            user     /bin/sleep
...`}
          />
        </section>

        {/* Offense: Shellcode */}
        <section className="mb-16 sm:mb-24">
          <h2 className="text-xl sm:text-2xl font-light text-[var(--text)] mb-4 sm:mb-6">Command: inject shellcode</h2>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            The <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">inject shellcode</code> command injects pre-built ARM64 shellcode into a target process and executes it.
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Usage:</strong> <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">auris inject shellcode -p PID -t TYPE [options]</code>
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Available shellcode types:</strong>
          </p>
          <ul className="text-[var(--text-secondary)] mb-6 space-y-2 ml-4">
            <li><code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">exec_sh</code> - Execute /bin/sh, spawning a shell in the target process context</li>
            <li><code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">reverse -i IP -P PORT</code> - Connect back to attacker machine and spawn shell</li>
            <li><code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">bind -P PORT</code> - Listen on a port and spawn shell when connection received</li>
            <li><code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">exec_cmd -c "command"</code> - Execute an arbitrary command</li>
          </ul>
          
          <AnimatedTerminal
            title="shellcode injection"
            command="auris inject shellcode -p 3201 -t exec_sh"
            output={`Shellcode: exec_sh
Description: Execute /bin/sh
Size: 76 bytes

Injecting into PID 3201...
[ptrace] Attached to process 3201 (sleep)
[inject] Saving registers...
[inject] Writing shellcode at 0x5555555551a0
[inject] Redirecting PC...
[inject] Executing...

Injection successful!
Return value: 0x0
Execution time: 1247 ns`}
          />
        </section>

        {/* Offense: ROP */}
        <section className="mb-16 sm:mb-24">
          <h2 className="text-xl sm:text-2xl font-light text-[var(--text)] mb-4 sm:mb-6">Command: inject gadgets</h2>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            The <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">inject gadgets</code> command scans ELF binaries to find ROP (Return-Oriented Programming) gadgets. ROP is a technique used when DEP/NX prevents direct code injection by chaining together existing code snippets that end in RET instructions.
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Usage:</strong> <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">auris inject gadgets -b /path/to/binary</code>
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Gadget types found:</strong>
          </p>
          <ul className="text-[var(--text-secondary)] mb-6 space-y-2 ml-4">
            <li><strong>RET gadgets:</strong> Simple return instructions for chaining</li>
            <li><strong>Load gadgets:</strong> Instructions that load registers from the stack (e.g., ldr x0, [sp, #8])</li>
            <li><strong>Syscall gadgets:</strong> Instructions containing svc #0 for making system calls</li>
            <li><strong>Stack pivot gadgets:</strong> Instructions that modify SP for stack manipulation</li>
          </ul>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-6">
            On ARM64, a typical ROP chain to call execve("/bin/sh", NULL, NULL) would: load x0 with pointer to "/bin/sh", set x1 and x2 to NULL, set x8 to 221 (execve syscall number), then execute svc #0.
          </p>
          
          <AnimatedTerminal
            title="rop gadgets"
            command="auris inject gadgets -b /lib/aarch64-linux-gnu/libc.so.6"
            output={`Finding ROP gadgets in libc.so.6...
[rop] Scanning executable segments...
[rop] Found 25655 gadgets

0x00027430: svc #0 [SVC]
0x00027640: ret [RET]
0x00045678: ldr x0, [sp, #8]; ldp x29, x30, [sp], #16; ret [X0 RET]
0x00067890: mov x8, #221; svc #0 [SVC]
0x00089abc: add sp, sp, #64; ret [PIVOT RET]
...

Useful Gadgets Summary:
  Load X0: 0x45678
  Syscall: 0x67890
  Stack Pivot: 0x89abc`}
          />
        </section>

        {/* Memory Operations */}
        <section className="mb-16 sm:mb-24">
          <h2 className="text-xl sm:text-2xl font-light text-[var(--text)] mb-4 sm:mb-6">Command: inject dump</h2>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            The <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">inject dump</code> command reads memory from a target process and displays it in hexdump format.
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Usage:</strong> <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">auris inject dump -p PID -a ADDRESS -n LENGTH</code>
          </p>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Use cases:</strong>
          </p>
          <ul className="text-[var(--text-secondary)] mb-6 space-y-2 ml-4">
            <li>Analyze memory layout before injection to find suitable injection points</li>
            <li>Extract runtime data, secrets, or encryption keys from process memory</li>
            <li>Verify shellcode was written correctly</li>
            <li>Forensic analysis of running processes</li>
            <li>Debugging and reverse engineering</li>
          </ul>
          
          <AnimatedTerminal
            title="memory dump"
            command="auris inject dump -p 2847 -a 0x555555555000 -n 64"
            output={`[ptrace] Attached to process 2847
Memory dump at 0x555555555000 (64 bytes):

0000555555555000  7f 45 4c 46 02 01 01 00  |.ELF....|
0000555555555008  00 00 00 00 00 00 00 00  |........|
0000555555555010  03 00 b7 00 01 00 00 00  |........|
0000555555555018  00 10 00 00 00 00 00 00  |........|
0000555555555020  40 00 00 00 00 00 00 00  |@.......|
0000555555555028  c8 a2 01 00 00 00 00 00  |........|
0000555555555030  00 00 00 00 40 00 38 00  |....@.8.|
0000555555555038  0b 00 40 00 1e 00 1d 00  |..@.....|`}
          />
        </section>

        {/* Setup */}
        <section className="mb-16 sm:mb-24">
          <h2 className="text-xl sm:text-2xl font-light text-[var(--text)] mb-4 sm:mb-6">Installation and Setup</h2>
          
          <h3 className="text-base sm:text-lg font-medium text-[var(--text)] mb-3 sm:mb-4">System Requirements</h3>
          <ul className="text-[var(--text-secondary)] mb-6 space-y-2 ml-4">
            <li><strong>Architecture:</strong> ARM64 (AArch64) only. Auris uses ARM64-specific register layouts and syscall conventions.</li>
            <li><strong>Operating System:</strong> Linux kernel 4.8 or later (for PTRACE_GETREGSET support)</li>
            <li><strong>Permissions:</strong> Root access or CAP_SYS_PTRACE capability</li>
            <li><strong>Dependencies:</strong> libcurl, openssl, json-c (for AI integration features)</li>
          </ul>

          <h3 className="text-base sm:text-lg font-medium text-[var(--text)] mb-3 sm:mb-4">Option 1: Docker (Recommended)</h3>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            Docker is the easiest way to run Auris, especially on machines that are not natively ARM64. Docker Desktop on Apple Silicon Macs or any ARM64 Linux host works out of the box.
          </p>
          
          <div className="p-3 sm:p-5 rounded-lg border border-[var(--border)] bg-[var(--terminal-bg)] font-mono text-xs sm:text-sm text-[var(--terminal-text)] mb-4 sm:mb-6">
            <pre className="overflow-x-auto">{`# Clone the repository
git clone https://github.com/kuladeepmantri/Auris.git
cd Auris

# Build the Docker image
docker build --platform linux/arm64 -t auris .

# Run with required capabilities
docker run --platform linux/arm64 \\
  --cap-add=SYS_PTRACE \\
  --security-opt seccomp=unconfined \\
  -it auris

# You are now inside the container
./build/auris version
./build/auris help`}</pre>
          </div>

          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Important Docker flags explained:</strong>
          </p>
          <ul className="text-[var(--text-secondary)] mb-6 space-y-2 ml-4">
            <li><code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">--platform linux/arm64</code> - Ensures ARM64 emulation if not on native ARM64</li>
            <li><code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">--cap-add=SYS_PTRACE</code> - Grants the ptrace capability required for tracing</li>
            <li><code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">--security-opt seccomp=unconfined</code> - Disables seccomp filtering that would block ptrace</li>
          </ul>

          <h3 className="text-base sm:text-lg font-medium text-[var(--text)] mb-3 sm:mb-4">Option 2: Native Build on ARM64 Linux</h3>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            For native ARM64 Linux systems (Raspberry Pi 4/5, AWS Graviton, Apple Silicon with Linux VM, etc.):
          </p>
          
          <div className="p-3 sm:p-5 rounded-lg border border-[var(--border)] bg-[var(--terminal-bg)] font-mono text-xs sm:text-sm text-[var(--terminal-text)] mb-4 sm:mb-6">
            <pre className="overflow-x-auto">{`# Install build dependencies (Debian/Ubuntu)
sudo apt update
sudo apt install -y build-essential cmake pkg-config \\
  libcurl4-openssl-dev libssl-dev libjson-c-dev

# Clone and build
git clone https://github.com/kuladeepmantri/Auris.git
cd Auris
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Verify the build
./auris version

# Run with sudo (or set CAP_SYS_PTRACE)
sudo ./auris learn -- /bin/ls -la`}</pre>
          </div>

          <h3 className="text-base sm:text-lg font-medium text-[var(--text)] mb-3 sm:mb-4">Data Directory</h3>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            Auris stores traces, profiles, and policies in a data directory. By default, this is <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">/data/auris</code> in Docker or <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">~/.auris</code> on native installs. You can override this with the <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">-d</code> flag:
          </p>
          
          <div className="p-3 sm:p-5 rounded-lg border border-[var(--border)] bg-[var(--terminal-bg)] font-mono text-xs sm:text-sm text-[var(--terminal-text)] mb-4 sm:mb-6">
            <pre className="overflow-x-auto">{`# Use custom data directory
auris -d /path/to/data learn -- /bin/ls

# Directory structure
/data/auris/
  traces/      # JSON trace files
  profiles/    # Behavioral profiles
  policies/    # Security policies`}</pre>
          </div>

          <h3 className="text-base sm:text-lg font-medium text-[var(--text)] mb-3 sm:mb-4">Quick Start Examples</h3>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Example 1: Trace a program and build a profile</strong>
          </p>
          <div className="p-3 sm:p-5 rounded-lg border border-[var(--border)] bg-[var(--terminal-bg)] font-mono text-xs sm:text-sm text-[var(--terminal-text)] mb-4 sm:mb-6">
            <pre className="overflow-x-auto">{`# Step 1: Learn the program's behavior
auris learn -- /usr/bin/curl https://example.com
# Output: Trace ID: abc123

# Step 2: Build a behavioral profile
auris profile -t abc123
# Output: Profile ID: def456

# Step 3: Compare future executions
auris compare -p def456 -- /usr/bin/curl https://example.com`}</pre>
          </div>

          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Example 2: Create and enforce a security policy</strong>
          </p>
          <div className="p-3 sm:p-5 rounded-lg border border-[var(--border)] bg-[var(--terminal-bg)] font-mono text-xs sm:text-sm text-[var(--terminal-text)] mb-4 sm:mb-6">
            <pre className="overflow-x-auto">{`# Generate policy from profile
auris policy -p def456
# Output: Policy ID: ghi789

# Test policy in alert mode (logs violations but allows execution)
auris enforce -P ghi789 -m alert -- ./my_program

# Enforce policy in block mode (terminates on violation)
auris enforce -P ghi789 -m block -- ./untrusted_program`}</pre>
          </div>

          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            <strong>Example 3: Offensive operations (authorized testing only)</strong>
          </p>
          <div className="p-3 sm:p-5 rounded-lg border border-[var(--border)] bg-[var(--terminal-bg)] font-mono text-xs sm:text-sm text-[var(--terminal-text)] mb-4 sm:mb-6">
            <pre className="overflow-x-auto">{`# List injectable processes
auris inject list

# Get info about a specific process
auris inject info -p 1234

# View process memory maps
auris inject maps -p 1234

# Inject shellcode (spawns /bin/sh in target)
auris inject shellcode -p 1234 -t exec_sh

# Find ROP gadgets in libc
auris inject gadgets -b /lib/aarch64-linux-gnu/libc.so.6

# Dump process memory
auris inject dump -p 1234 -a 0x400000 -n 256`}</pre>
          </div>
        </section>

        {/* Command Reference */}
        <section className="mb-16 sm:mb-24">
          <h2 className="text-xl sm:text-2xl font-light text-[var(--text)] mb-4 sm:mb-6">Command Reference</h2>
          
          <div className="p-3 sm:p-5 rounded-lg border border-[var(--border)] bg-[var(--terminal-bg)] font-mono text-xs sm:text-sm text-[var(--terminal-text)]">
            <pre className="overflow-x-auto">{`auris <command> [options] [-- program [args...]]

Commands:
  learn       Trace a program and record all syscalls
  profile     Build behavioral profile from a trace
  compare     Compare execution against baseline profile
  policy      Generate security policy from profile
  enforce     Run program under policy enforcement
  analyze     Send profile to AI for analysis
  inject      Process injection framework (offensive)
  help        Show help message
  version     Show version information

Global Options:
  -h, --help            Show help
  -V, --version         Show version
  -v, --verbose         Verbose output
  -q, --quiet           Quiet mode
  -j, --json            JSON output format
  -d, --data-dir DIR    Data directory path
  -t, --trace-id ID     Trace ID to use
  -p, --profile-id ID   Profile ID to use
  -P, --policy-id ID    Policy ID to use

Inject Subcommands:
  inject list           List injectable processes
  inject info -p PID    Show process information
  inject maps -p PID    Show memory maps
  inject shellcode      Inject and execute shellcode
  inject gadgets        Find ROP gadgets in binary
  inject dump           Dump process memory`}</pre>
          </div>
        </section>

        {/* Footer */}
        <footer className="pt-8 sm:pt-12 border-t border-[var(--border)]">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 sm:gap-4">
            <div>
              <span className="text-xs sm:text-sm text-[var(--text)]">Auris</span>
              <span className="text-xs sm:text-sm text-[var(--text-muted)]"> · </span>
              <a 
                href="https://github.com/kuladeepmantri" 
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs sm:text-sm text-[var(--text-secondary)] hover:text-[var(--text)] transition-colors"
              >
                Kuladeep Mantri
              </a>
            </div>
            <div className="text-xs sm:text-sm text-[var(--text-muted)]">
              MIT License · v2.0.0
            </div>
          </div>
        </footer>
      </main>
    </div>
  )
}

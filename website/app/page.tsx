'use client'

import { useState, useEffect } from 'react'
import ThemeToggle from './components/ThemeToggle'
import AnimatedTerminal from './components/AnimatedTerminal'

const sections = [
  { id: 'overview', label: 'Overview' },
  { id: 'demo', label: 'Live Demo' },
  { id: 'learn', label: 'Learn Command' },
  { id: 'profile', label: 'Profile Command' },
  { id: 'compare', label: 'Compare Command' },
  { id: 'policy', label: 'Policy Command' },
  { id: 'enforce', label: 'Enforce Command' },
  { id: 'ai', label: 'AI Integration' },
  { id: 'internals', label: 'Internals' },
  { id: 'sensitive', label: 'Sensitive Files' },
  { id: 'setup', label: 'Setup' },
]

export default function Home() {
  const [menuOpen, setMenuOpen] = useState(false)
  const [activeSection, setActiveSection] = useState('overview')

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveSection(entry.target.id)
          }
        })
      },
      { rootMargin: '-20% 0px -70% 0px' }
    )

    sections.forEach(({ id }) => {
      const el = document.getElementById(id)
      if (el) observer.observe(el)
    })

    return () => observer.disconnect()
  }, [])

  return (
    <div className="min-h-screen bg-[var(--bg)]">
      {/* Mobile header */}
      <header className="lg:hidden fixed top-0 w-full bg-[var(--bg)]/95 backdrop-blur-sm border-b border-[var(--border)] z-50">
        <div className="px-5 h-14 flex items-center justify-between">
          <span className="font-semibold text-[var(--text)]">low-level-SysGuard</span>
          <div className="flex items-center gap-3">
            <ThemeToggle />
            <button 
              onClick={() => setMenuOpen(!menuOpen)}
              className="p-2 -mr-2 text-[var(--text-secondary)]"
              aria-label="Menu"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                {menuOpen ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 6h16M4 12h16M4 18h16" />
                )}
              </svg>
            </button>
          </div>
        </div>
        
        {menuOpen && (
          <nav className="px-5 py-3 border-t border-[var(--border)] bg-[var(--bg)] max-h-[70vh] overflow-y-auto">
            {sections.map(s => (
              <a 
                key={s.id}
                href={`#${s.id}`}
                onClick={() => setMenuOpen(false)}
                className={`block py-2 text-sm transition-colors ${
                  activeSection === s.id 
                    ? 'text-[var(--text)] font-medium' 
                    : 'text-[var(--text-secondary)]'
                }`}
              >
                {s.label}
              </a>
            ))}
            <div className="border-t border-[var(--border)] mt-2 pt-2">
              <a 
                href="https://github.com/kuladeepmantri/low-level-SysGuard"
                className="block py-2 text-sm text-[var(--text-secondary)]"
              >
                GitHub ↗
              </a>
            </div>
          </nav>
        )}
      </header>

      {/* Desktop sidebar */}
      <aside className="hidden lg:block fixed left-0 top-0 w-52 h-screen border-r border-[var(--border)] bg-[var(--bg)] overflow-y-auto">
        <div className="p-5 pb-3">
          <h1 className="font-semibold text-[var(--text)]">low-level-SysGuard</h1>
          <p className="text-xs text-[var(--text-muted)] mt-0.5">ARM64 syscall security</p>
        </div>
        
        <nav className="px-3 pb-4">
          {sections.map(s => (
            <a 
              key={s.id}
              href={`#${s.id}`}
              className={`block px-3 py-1.5 text-sm rounded-md transition-all ${
                activeSection === s.id 
                  ? 'text-[var(--text)] bg-[var(--bg-secondary)] font-medium' 
                  : 'text-[var(--text-secondary)] hover:text-[var(--text)] hover:bg-[var(--bg-secondary)]'
              }`}
            >
              {s.label}
            </a>
          ))}
        </nav>

        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-[var(--border)] bg-[var(--bg)]">
          <div className="flex items-center justify-between px-2">
            <a 
              href="https://github.com/kuladeepmantri/low-level-SysGuard"
              className="text-sm text-[var(--text-secondary)] hover:text-[var(--text)] transition-colors"
            >
              GitHub ↗
            </a>
            <ThemeToggle />
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="lg:ml-52 px-5 lg:px-12 xl:px-16 pt-20 lg:pt-10 pb-24 max-w-3xl">
        
        {/* Overview */}
        <section id="overview" className="mb-20 scroll-mt-20">
          <div className="mb-5">
            <a href="https://github.com/kuladeepmantri/low-level-SysGuard/actions" target="_blank" rel="noopener noreferrer">
              <img src="https://github.com/kuladeepmantri/low-level-SysGuard/actions/workflows/cmake-single-platform.yml/badge.svg" alt="Build" className="h-5" />
            </a>
          </div>
          
          <h2 className="text-2xl font-semibold text-[var(--text)] mb-4">Overview</h2>
          
          <p className="text-[var(--text-secondary)] mb-4">
            SysGuard is a security tool that monitors programs at the syscall level. It intercepts every 
            system call a program makes, including file operations, network connections, and process creation. 
            This data is used to build behavioral profiles, detect anomalies, and enforce security policies.
          </p>
          
          <p className="text-[var(--text-secondary)] mb-4">
            Built for ARM64 Linux using the kernel&apos;s ptrace interface. Runs entirely in userspace 
            with no kernel modules required. Designed for containerized environments.
          </p>

          <div className="flex flex-wrap gap-x-6 gap-y-2 text-sm text-[var(--text-muted)]">
            <span>C11</span>
            <span>~15,000 lines</span>
            <span>json-c</span>
            <span>OpenSSL</span>
            <span>libcurl</span>
          </div>
        </section>

        {/* Live Demo */}
        <section id="demo" className="mb-20 scroll-mt-20">
          <h2 className="text-2xl font-semibold text-[var(--text)] mb-4">Live Demo</h2>
          <p className="text-[var(--text-secondary)] mb-6">
            Complete workflow showing tracing, profiling, anomaly detection, and policy enforcement.
          </p>
          
          <AnimatedTerminal
            title="sysguard demo"
            command="sysguard learn -- /bin/ls -la && sysguard profile -t trace-001"
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

        {/* Learn Command */}
        <section id="learn" className="mb-20 scroll-mt-20">
          <h2 className="text-2xl font-semibold text-[var(--text)] mb-4">Learn Command</h2>
          
          <p className="text-[var(--text-secondary)] mb-4">
            The <code>learn</code> command traces a program and records every syscall it makes. 
            It captures the syscall number, all six arguments, return value, and timing information.
          </p>

          <p className="text-[var(--text-secondary)] mb-6">
            Tracing uses <code>ptrace(PTRACE_SYSCALL)</code> which stops the process at every 
            syscall entry and exit. On ARM64, the syscall number is in register <code>x8</code>, 
            arguments in <code>x0</code> through <code>x5</code>.
          </p>

          <AnimatedTerminal
            title="learn"
            command="sysguard learn -- /usr/bin/curl https://example.com"
            output={`[ptrace] Attached to process 3201
[ptrace] Options: TRACESYSGOOD | TRACEFORK | TRACECLONE

Intercepting syscalls...
  execve("/usr/bin/curl", ["curl", "https://example.com"]) = 0
  brk(NULL) = 0x5555557a4000
  openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY) = 3
  socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4
  connect(4, {sa_family=AF_INET, sin_port=443, sin_addr="93.184.216.34"}) = 0
  write(4, "GET / HTTP/1.1\\r\\n...", 78) = 78
  read(4, "HTTP/1.1 200 OK\\r\\n...", 4096) = 1256
  close(4) = 0
  ...

[trace] Captured 342 syscalls in 847ms
[store] Saved to /data/sysguard/traces/a8f3b2c1.json

Trace ID: a8f3b2c1`}
          />
        </section>

        {/* Profile Command */}
        <section id="profile" className="mb-20 scroll-mt-20">
          <h2 className="text-2xl font-semibold text-[var(--text)] mb-4">Profile Command</h2>
          
          <p className="text-[var(--text-secondary)] mb-4">
            The <code>profile</code> command analyzes a trace and builds a behavioral fingerprint. 
            It computes syscall frequency distributions, Shannon entropy, and behavior flags.
          </p>

          <p className="text-[var(--text-secondary)] mb-6">
            Entropy measures behavioral diversity. Low entropy means repetitive patterns like 
            read/write loops. High entropy indicates varied syscall usage. The profiler also 
            tracks file access patterns and network endpoints.
          </p>

          <AnimatedTerminal
            title="profile"
            command="sysguard profile -t a8f3b2c1"
            output={`[profile] Loading trace a8f3b2c1...
[profile] Computing syscall statistics...

Syscall Distribution:
  read       89  (26.0%)
  write      67  (19.6%)
  close      34  (9.9%)
  socket     12  (3.5%)
  connect    12  (3.5%)
  openat     11  (3.2%)
  ...18 more unique syscalls

[profile] Shannon entropy: 3.87 bits
[profile] Analyzing behavior...
  - File I/O: yes (openat, read, write)
  - Network: yes (socket, connect detected)
  - Children: no
  - Sensitive: no

[store] Saved to /data/sysguard/profiles/c4d2e1f0.json

Profile ID: c4d2e1f0`}
          />
        </section>

        {/* Compare Command */}
        <section id="compare" className="mb-20 scroll-mt-20">
          <h2 className="text-2xl font-semibold text-[var(--text)] mb-4">Compare Command</h2>
          
          <p className="text-[var(--text-secondary)] mb-4">
            The <code>compare</code> command runs a program and checks its behavior against a baseline profile. 
            It detects new syscalls, frequency spikes, and suspicious patterns.
          </p>

          <p className="text-[var(--text-secondary)] mb-6">
            Anomaly thresholds: new syscalls score 0.7, frequency spikes over 3x score 0.5, 
            sensitive file access scores 0.8. The deviation score is a weighted sum normalized to [0,1].
          </p>

          <AnimatedTerminal
            title="compare"
            command="sysguard compare -p c4d2e1f0 -- /usr/bin/curl https://evil.com"
            output={`[ptrace] Attached to process 3847
[trace] Captured 412 syscalls in 923ms
[compare] Loading baseline profile c4d2e1f0...
[compare] Analyzing deviations...

ANOMALY DETECTED

Deviation Score: 0.68
Risk Score: 0.82

Anomalies found:
  [CRITICAL] openat("/etc/passwd", O_RDONLY)
             Sensitive file access (severity: 0.8)
  
  [HIGH] write() called 156 times (baseline: 67)
         Frequency 2.3x higher than normal (severity: 0.4)
  
  [HIGH] connect() to 185.234.xx.xx:4444
         New endpoint not in baseline (severity: 0.6)`}
          />
        </section>

        {/* Policy Command */}
        <section id="policy" className="mb-20 scroll-mt-20">
          <h2 className="text-2xl font-semibold text-[var(--text)] mb-4">Policy Command</h2>
          
          <p className="text-[var(--text-secondary)] mb-4">
            The <code>policy</code> command generates security rules from a profile. Every syscall 
            observed in the baseline gets an ALLOW rule. Everything else defaults to ALERT or BLOCK.
          </p>

          <p className="text-[var(--text-secondary)] mb-6">
            Policies can include path-based rules using glob patterns. For example, allow 
            <code>openat()</code> for <code>/etc/hosts</code> but block for <code>~/.ssh/*</code>.
          </p>

          <AnimatedTerminal
            title="policy"
            command="sysguard policy -p c4d2e1f0"
            output={`[policy] Loading profile c4d2e1f0...
[policy] Generating rules from baseline...

Policy created: pol-7a3b

  Rules: 24 syscalls allowed
  Default: BLOCK

  ALLOW: read, write, close, openat, fstat, mmap
  ALLOW: socket, connect, sendto, recvfrom
  ALLOW: brk, mprotect, munmap, rt_sigaction
  ...
  
  BLOCK: execve, fork, clone, ptrace
  BLOCK: openat ~/.ssh/*, ~/.aws/*, ~/.gnupg/*

[store] Saved to /data/sysguard/policies/pol-7a3b.json

Policy ID: pol-7a3b`}
          />
        </section>

        {/* Enforce Command */}
        <section id="enforce" className="mb-20 scroll-mt-20">
          <h2 className="text-2xl font-semibold text-[var(--text)] mb-4">Enforce Command</h2>
          
          <p className="text-[var(--text-secondary)] mb-4">
            The <code>enforce</code> command runs a program under policy control. In alert mode, 
            violations are logged but allowed. In block mode, violations are prevented and the 
            process is terminated.
          </p>

          <p className="text-[var(--text-secondary)] mb-6">
            Blocking works by overwriting the syscall number with -1 using <code>PTRACE_SETREGSET</code> 
            before the kernel executes it. The kernel returns <code>-ENOSYS</code>. Then SysGuard 
            sends <code>SIGKILL</code> to terminate the process.
          </p>

          <AnimatedTerminal
            title="enforce"
            command="sysguard enforce -P pol-7a3b -m block -- ./malware"
            output={`[enforce] Loading policy pol-7a3b (24 rules)
[enforce] Mode: BLOCK (terminate on violation)
[ptrace] Attached to process 4102

[syscall] read(3, ...) = 512                    ALLOW
[syscall] mmap(NULL, 4096, ...) = 0x7fff...     ALLOW
[syscall] openat("/etc/passwd", ...)            ALLOW
[syscall] openat("/home/user/.ssh/id_rsa", ...) BLOCK
          Reason: path matches blocked pattern ~/.ssh/*
          Action: injecting -ENOSYS, sending SIGKILL

[enforce] Process 4102 terminated

Enforcement Summary:
  Total syscalls:  38
  Allowed:         37
  Blocked:          1
  Duration:        12ms`}
          />
        </section>

        {/* AI Integration */}
        <section id="ai" className="mb-20 scroll-mt-20">
          <h2 className="text-2xl font-semibold text-[var(--text)] mb-4">AI Integration</h2>
          
          <p className="text-[var(--text-secondary)] mb-4">
            SysGuard includes an optional AI client that can send profiles and traces to a Local LLM 
            (like Ollama) or an OpenAI-compatible API for natural language analysis.
          </p>

          <p className="text-[var(--text-secondary)] mb-6">
            The AI analyzes the behavioral fingerprint to identify potential security risks, 
            explain suspicious patterns, and recommend hardening steps. It&apos;s designed to be privacy-first: 
            by default, it connects to <code>http://localhost:11434</code> (Ollama).
          </p>

          <AnimatedTerminal
            title="ai analysis"
            command="sysguard analyze -p c4d2e1f0 -a http://localhost:11434/api/generate -M llama3"
            output={`[ai] Connecting to http://localhost:11434...
[ai] Model: llama3
[ai] Sending profile c4d2e1f0 for analysis...

Analysis Result:
----------------
RISK LEVEL: MEDIUM
RISK SCORE: 0.45

Summary:
The program behaves like a network client (curl/wget). It performs DNS lookups 
and HTTP connections. However, it accesses sensitive file /etc/passwd which is 
unusual for a simple web client.

Security Concerns:
1. Access to /etc/passwd suggests potential reconnaissance.
2. Network activity combined with file reads could indicate exfiltration.

Recommendations:
- Restrict file access to only necessary config files.
- Monitor outbound connections to unknown IPs.`}
          />

          <p className="text-[var(--text-secondary)] mt-6">
            You can also point it to Cloud APIs (OpenAI, Anthropic, Gemini) by changing the endpoint 
            and providing an API key via environment variables. The prompt structure is optimized 
            for security analysis.
          </p>
        </section>

        {/* Internals */}
        <section id="internals" className="mb-20 scroll-mt-20">
          <h2 className="text-2xl font-semibold text-[var(--text)] mb-4">Internals</h2>
          
          <p className="text-[var(--text-secondary)] mb-4">
            SysGuard uses <code>ptrace(PTRACE_SYSCALL)</code> to intercept syscalls. When a traced 
            process makes a syscall, the kernel stops it and notifies SysGuard. The tracer then 
            reads the CPU registers to extract syscall information.
          </p>

          <AnimatedTerminal
            title="ptrace internals"
            command="cat tracer.c"
            output={`// ARM64 register reading
struct user_pt_regs regs;
struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };

ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);

uint64_t syscall_nr = regs.regs[8];   // x8 = syscall number
uint64_t arg0 = regs.regs[0];         // x0 = first argument
uint64_t arg1 = regs.regs[1];         // x1 = second argument
uint64_t arg2 = regs.regs[2];         // x2 = third argument
// ... up to x5 for 6 arguments

// Blocking a syscall
regs.regs[8] = -1;  // invalid syscall
ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
kill(pid, SIGKILL);`}
          />

          <p className="text-[var(--text-secondary)] mt-6">
            The profiler computes Shannon entropy to measure behavioral diversity:
          </p>

          <div className="mt-4 p-4 rounded-lg border border-[var(--border)] dark:border-[var(--terminal-border,var(--border))] bg-[var(--terminal-bg)] font-mono text-sm text-[var(--terminal-text)]">
            <pre>{`entropy = -Σ p(x) * log2(p(x))

where p(x) = count(syscall_x) / total_syscalls`}</pre>
          </div>
        </section>

        {/* Sensitive Files */}
        <section id="sensitive" className="mb-20 scroll-mt-20">
          <h2 className="text-2xl font-semibold text-[var(--text)] mb-4">Sensitive File Detection</h2>
          
          <p className="text-[var(--text-secondary)] mb-6">
            SysGuard monitors file access against 50+ patterns for sensitive paths. Access to these 
            files is flagged in profiles and can trigger alerts during enforcement.
          </p>

          <div className="p-4 rounded-lg border border-[var(--border)] dark:border-[var(--terminal-border,var(--border))] bg-[var(--terminal-bg)] font-mono text-sm text-[var(--terminal-text)]">
            <pre>{`CRITICAL
  ~/.ssh/id_*              SSH private keys
  /etc/shadow              password hashes
  ~/.gnupg/private-keys*   GPG private keys
  ~/.git-credentials       Git auth tokens

HIGH
  ~/.aws/credentials       AWS access keys
  ~/.kube/config           Kubernetes config
  ~/.docker/config.json    Docker registry auth
  .env, .env.*             environment secrets

MEDIUM
  /etc/passwd              user accounts
  ~/.ssh/config            SSH configuration
  ~/.gitconfig             Git configuration`}</pre>
          </div>
        </section>

        {/* Setup */}
        <section id="setup" className="mb-16 scroll-mt-20">
          <h2 className="text-2xl font-semibold text-[var(--text)] mb-4">Setup</h2>
          
          <p className="text-[var(--text-secondary)] mb-4">
            SysGuard requires <code>CAP_SYS_PTRACE</code> capability. Docker is the easiest way to run it:
          </p>

          <AnimatedTerminal
            title="docker"
            command="docker build --platform linux/arm64 -t sysguard ."
            output={`[+] Building 45.2s
 => [1/8] FROM debian:bookworm-slim
 => [2/8] RUN apt-get update && apt-get install -y ...
 => [3/8] COPY . /src
 => [4/8] RUN cmake -B build -DCMAKE_BUILD_TYPE=Release
 => [5/8] RUN cmake --build build
 => Successfully built sysguard

# Run with ptrace capability
docker run --platform linux/arm64 \\
  --cap-add=SYS_PTRACE \\
  --security-opt seccomp=unconfined \\
  -it sysguard`}
          />

          <p className="text-[var(--text-secondary)] mt-8 mb-4">
            For native builds on ARM64 Linux:
          </p>

          <div className="p-4 rounded-lg border border-[var(--border)] dark:border-[var(--terminal-border,var(--border))] bg-[var(--terminal-bg)] font-mono text-sm text-[var(--terminal-text)]">
            <pre>{`# Install dependencies
apt install build-essential cmake \\
  libcurl4-openssl-dev libssl-dev libjson-c-dev

# Build
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Run (needs CAP_SYS_PTRACE)
sudo ./sysguard learn -- /bin/ls`}</pre>
          </div>
        </section>

        {/* Footer */}
        <footer className="pt-8 border-t border-[var(--border)] text-sm text-[var(--text-muted)]">
          MIT License
          <span className="mx-2">·</span>
          <a href="https://github.com/kuladeepmantri/low-level-SysGuard" className="text-[var(--text-secondary)] hover:text-[var(--text)] transition-colors">
            github.com/kuladeepmantri/low-level-SysGuard
          </a>
        </footer>
      </main>

      {/* Scroll to top button */}
      <button
        onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
        className="fixed bottom-6 right-6 p-3 rounded-full bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text)] shadow-lg transition-all hover:scale-105 lg:hidden"
        aria-label="Scroll to top"
      >
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 10l7-7m0 0l7 7m-7-7v18" />
        </svg>
      </button>
    </div>
  )
}

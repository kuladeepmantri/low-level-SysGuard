'use client'

import { useState, useEffect } from 'react'
import ThemeToggle from './components/ThemeToggle'
import AnimatedTerminal from './components/AnimatedTerminal'

const sections = [
  { id: 'overview', label: 'Overview', icon: '◈' },
  { id: 'demo', label: 'Live Demo', icon: '▶' },
  { id: 'learn', label: 'Learn Command', icon: '○' },
  { id: 'profile', label: 'Profile Command', icon: '○' },
  { id: 'compare', label: 'Compare Command', icon: '○' },
  { id: 'policy', label: 'Policy Command', icon: '○' },
  { id: 'enforce', label: 'Enforce Command', icon: '○' },
  { id: 'ai', label: 'AI Integration', icon: '◇' },
  { id: 'internals', label: 'Internals', icon: '◇' },
  { id: 'sensitive', label: 'Sensitive Files', icon: '◇' },
  { id: 'setup', label: 'Setup', icon: '◇' },
]

export default function Home() {
  const [menuOpen, setMenuOpen] = useState(false)
  const [activeSection, setActiveSection] = useState('overview')
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 10)
    }
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

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
      {/* Mobile header - SOLID background, no transparency */}
      <header className={`lg:hidden fixed top-0 w-full z-50 transition-all duration-200 ${
        scrolled 
          ? 'bg-[var(--bg)] shadow-[var(--shadow-md)] border-b border-[var(--border)]' 
          : 'bg-[var(--bg)] border-b border-[var(--border)]'
      }`}>
        <div className="px-5 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <span className="font-semibold text-[var(--text)]">Auris</span>
          </div>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <button 
              onClick={() => setMenuOpen(!menuOpen)}
              className="p-2 -mr-2 text-[var(--text-secondary)] hover:text-[var(--text)] hover:bg-[var(--bg-secondary)] rounded-lg transition-colors"
              aria-label="Menu"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                {menuOpen ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                )}
              </svg>
            </button>
          </div>
        </div>
        
        {/* Mobile menu with animation */}
        <div className={`overflow-hidden transition-all duration-200 ease-out ${
          menuOpen ? 'max-h-[70vh] opacity-100' : 'max-h-0 opacity-0'
        }`}>
          <nav className="px-4 py-3 border-t border-[var(--border)] bg-[var(--bg-secondary)]">
            {sections.map(s => (
              <a 
                key={s.id}
                href={`#${s.id}`}
                onClick={() => setMenuOpen(false)}
                className={`flex items-center gap-2 px-3 py-2.5 text-sm rounded-lg transition-all ${
                  activeSection === s.id 
                    ? 'text-[var(--accent)] bg-[var(--accent)]/10 font-medium' 
                    : 'text-[var(--text-secondary)] hover:text-[var(--text)] hover:bg-[var(--bg-tertiary)]'
                }`}
              >
                <span className="text-xs opacity-50">{s.icon}</span>
                {s.label}
              </a>
            ))}
            <div className="border-t border-[var(--border)] mt-3 pt-3">
              <a 
                href="https://github.com/kuladeepmantri/Auris"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 px-3 py-2.5 text-sm text-[var(--text-secondary)] hover:text-[var(--text)] rounded-lg hover:bg-[var(--bg-tertiary)] transition-colors"
              >
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                  <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                </svg>
                View on GitHub
              </a>
            </div>
          </nav>
        </div>
      </header>

      {/* Desktop sidebar - SOLID background with shadow */}
      <aside className="hidden lg:flex flex-col fixed left-0 top-0 w-56 h-screen border-r border-[var(--border)] bg-[var(--bg)] shadow-[var(--shadow)]">
        <div className="p-5 pb-4 border-b border-[var(--border)]">
          <div>
            <h1 className="font-semibold text-[var(--text)] text-sm">Auris</h1>
            <p className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">Syscall Intelligence</p>
          </div>
        </div>
        
        <nav className="flex-1 overflow-y-auto px-3 py-4">
          <div className="space-y-0.5">
            {sections.map(s => (
              <a 
                key={s.id}
                href={`#${s.id}`}
                className={`flex items-center gap-2.5 px-3 py-2 text-[13px] rounded-lg transition-all ${
                  activeSection === s.id 
                    ? 'text-[var(--accent)] bg-[var(--accent)]/10 font-medium' 
                    : 'text-[var(--text-secondary)] hover:text-[var(--text)] hover:bg-[var(--bg-secondary)]'
                }`}
              >
                <span className={`text-[10px] ${activeSection === s.id ? 'opacity-100' : 'opacity-40'}`}>{s.icon}</span>
                {s.label}
              </a>
            ))}
          </div>
        </nav>

        <div className="p-4 border-t border-[var(--border)] bg-[var(--bg-secondary)]">
          <div className="flex items-center justify-between">
            <a 
              href="https://github.com/kuladeepmantri/Auris"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-[13px] text-[var(--text-secondary)] hover:text-[var(--text)] transition-colors"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
              </svg>
              GitHub
            </a>
            <ThemeToggle />
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="lg:ml-56 px-5 lg:px-12 xl:px-16 pt-20 lg:pt-10 pb-24 max-w-3xl">
        
        {/* Overview */}
        <section id="overview" className="mb-16 scroll-mt-20">
          <div className="mb-6 flex flex-wrap items-center gap-3">
            <a href="https://github.com/kuladeepmantri/Auris/actions" target="_blank" rel="noopener noreferrer" className="inline-block">
              <img src="https://github.com/kuladeepmantri/Auris/actions/workflows/cmake-single-platform.yml/badge.svg" alt="Build Status" className="h-5 rounded" />
            </a>
            <span className="px-2.5 py-1 text-xs font-medium bg-[var(--bg-secondary)] text-[var(--text-secondary)] border border-[var(--border)] rounded-full">v1.0.0</span>
          </div>
          
          <h2 className="text-2xl font-bold text-[var(--text)] mb-4">Overview</h2>
          
          <p className="text-[var(--text-secondary)] mb-4 leading-relaxed">
            Auris is a research-grade security tool that listens to programs at the syscall level. It intercepts every 
            system call a program makes — file operations, network connections, process creation — and uses this data 
            to build behavioral profiles, detect anomalies, and enforce security policies.
          </p>
          
          <p className="text-[var(--text-secondary)] mb-6 leading-relaxed">
            Built for ARM64 Linux using the kernel&apos;s ptrace interface. Runs entirely in userspace 
            with no kernel modules required. Connects to local or cloud LLMs for natural language analysis.
          </p>

          {/* Tech stack badges */}
          <div className="flex flex-wrap gap-2">
            {['C11', 'ARM64', 'ptrace', 'OpenSSL', 'json-c', 'libcurl'].map((tech) => (
              <span 
                key={tech}
                className="px-3 py-1.5 text-xs font-medium bg-[var(--bg-secondary)] text-[var(--text-secondary)] rounded-lg border border-[var(--border)]"
              >
                {tech}
              </span>
            ))}
          </div>
        </section>

        {/* Live Demo */}
        <section id="demo" className="mb-20 scroll-mt-20">
          <h2 className="text-2xl font-semibold text-[var(--text)] mb-4">Live Demo</h2>
          <p className="text-[var(--text-secondary)] mb-6">
            Complete workflow showing tracing, profiling, anomaly detection, and policy enforcement.
          </p>
          
          <AnimatedTerminal
            title="auris demo"
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
            command="auris learn -- /usr/bin/curl https://example.com"
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
            command="auris profile -t a8f3b2c1"
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
            command="auris compare -p c4d2e1f0 -- /usr/bin/curl https://evil.com"
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
            command="auris policy -p c4d2e1f0"
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
            before the kernel executes it. The kernel returns <code>-ENOSYS</code>. Then Auris 
            sends <code>SIGKILL</code> to terminate the process.
          </p>

          <AnimatedTerminal
            title="enforce"
            command="auris enforce -P pol-7a3b -m block -- ./malware"
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
            Auris includes an optional AI client that can send profiles and traces to a local LLM 
            (Ollama) or cloud APIs for natural language analysis.
          </p>

          <p className="text-[var(--text-secondary)] mb-6">
            The AI analyzes behavioral fingerprints to identify potential security risks, 
            explain suspicious patterns, and recommend hardening steps. Privacy-first by default: 
            connects to <code>localhost:11434</code> (Ollama).
          </p>

          <AnimatedTerminal
            title="ai analysis"
            command="auris analyze -p c4d2e1f0 --endpoint http://localhost:11434"
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
            Auris uses <code>ptrace(PTRACE_SYSCALL)</code> to intercept syscalls. When a traced 
            process makes a syscall, the kernel stops it and notifies Auris. The tracer then 
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
            Auris monitors file access against 50+ patterns for sensitive paths. Access to these 
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
            Auris requires <code>CAP_SYS_PTRACE</code> capability. Docker is the easiest way to run it:
          </p>

          <AnimatedTerminal
            title="docker"
            command="docker build --platform linux/arm64 -t auris ."
            output={`[+] Building 45.2s
 => [1/8] FROM debian:bookworm-slim
 => [2/8] RUN apt-get update && apt-get install -y ...
 => [3/8] COPY . /src
 => [4/8] RUN cmake -B build -DCMAKE_BUILD_TYPE=Release
 => [5/8] RUN cmake --build build
 => Successfully built auris

# Run with ptrace capability
docker run --platform linux/arm64 \\
  --cap-add=SYS_PTRACE \\
  --security-opt seccomp=unconfined \\
  -it auris`}
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
sudo ./auris learn -- /bin/ls`}</pre>
          </div>
        </section>

        {/* Footer */}
        <footer className="mt-16 pt-8 border-t border-[var(--border)]">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <span className="text-sm font-medium text-[var(--text)]">Auris</span>
              <span className="text-sm text-[var(--text-muted)]"> · Built by </span>
              <a 
                href="https://github.com/kuladeepmantri" 
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm font-medium text-[var(--text)] hover:text-[var(--accent)] transition-colors"
              >
                Kuladeep Mantri
              </a>
            </div>
            <div className="flex items-center gap-4 text-sm text-[var(--text-muted)]">
              <span>MIT License</span>
              <span className="hidden sm:inline">·</span>
              <a 
                href="https://github.com/kuladeepmantri/Auris" 
                target="_blank"
                rel="noopener noreferrer"
                className="text-[var(--text-secondary)] hover:text-[var(--accent)] transition-colors"
              >
                View on GitHub
              </a>
            </div>
          </div>
          <p className="mt-4 text-xs text-[var(--text-muted)]">
            ARM64 syscall tracer and behavioral security analyzer.
          </p>
        </footer>
      </main>

      {/* Scroll to top button - improved styling */}
      <button
        onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
        className="fixed bottom-6 right-6 p-3 rounded-xl bg-[var(--bg)] border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--accent)] hover:border-[var(--accent)] shadow-[var(--shadow-md)] transition-all duration-200 hover:shadow-lg active:scale-95"
        aria-label="Scroll to top"
      >
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
        </svg>
      </button>
    </div>
  )
}

import { ArrowUpRight, Github, Terminal as TerminalIcon } from 'lucide-react';
import TerminalDemo from './components/TerminalDemo';

export default function Home() {
  return (
    <main className="min-h-screen bg-[#fafafa] text-[#1a1a1a] dark:bg-[#0a0a0a] dark:text-[#e5e5e5] selection:bg-black selection:text-white dark:selection:bg-white dark:selection:text-black">
      
      {/* Navigation / Header */}
      <nav className="fixed top-0 left-0 w-full border-b border-gray-200 dark:border-gray-800 bg-[#fafafa]/80 dark:bg-[#0a0a0a]/80 backdrop-blur-sm z-50">
        <div className="max-w-3xl mx-auto px-6 h-16 flex items-center justify-between font-mono text-sm">
          <span className="font-semibold tracking-tight">SYSGUARD / v1.0.0</span>
          <a 
            href="https://github.com/kuladeepmantri/low-level-SysGuard"
            className="flex items-center gap-2 hover:text-gray-600 dark:hover:text-gray-400 transition-colors"
          >
            <Github size={14} />
            <span>Source</span>
          </a>
        </div>
      </nav>

      <article className="max-w-3xl mx-auto px-6 pt-32 pb-24">
        
        {/* Title & Abstract */}
        <header className="mb-16 border-b border-gray-200 dark:border-gray-800 pb-8">
          <h1 className="font-serif text-4xl md:text-5xl font-bold mb-6 tracking-tight text-black dark:text-white">
            SysGuard: Runtime Security Analysis for ARM64 Linux Containers
          </h1>
          
          <div className="flex flex-col md:flex-row md:items-baseline gap-4 md:gap-8 text-sm text-gray-500 dark:text-gray-400 font-mono mb-8">
            <span>Kuladeep Mantri</span>
            <span>December 2025</span>
            <div className="flex items-center gap-2 text-green-600 dark:text-green-500">
              <span className="w-2 h-2 rounded-full bg-current animate-pulse" />
              Build Passing
            </div>
          </div>

          <div className="bg-gray-50 dark:bg-gray-900 p-6 rounded-lg border border-gray-100 dark:border-gray-800">
            <h2 className="font-mono text-xs uppercase tracking-widest text-gray-500 mb-3">Abstract</h2>
            <p className="font-serif text-lg leading-relaxed text-gray-700 dark:text-gray-300">
              SysGuard is a low-level security application designed to characterize and enforce behavioral integrity in Linux processes. By leveraging the <code>ptrace</code> mechanism and statistical profiling, it establishes a baseline of normal system call activity. Deviations from this baseline are detected in real-time, allowing for automated policy enforcement and anomaly detection suitable for containerized environments.
            </p>
          </div>
        </header>

        {/* 1. Introduction */}
        <section className="mb-16">
          <h2 className="font-serif text-2xl font-bold mb-6 text-black dark:text-white flex items-center gap-3">
            <span className="font-mono text-base text-gray-400 font-normal">01</span>
            Introduction
          </h2>
          <p className="text-lg leading-relaxed text-gray-700 dark:text-gray-300 mb-6">
            Modern container security often relies on static analysis or broad capability restrictions. SysGuard takes a dynamic approach, treating the sequence and frequency of system calls as a unique "fingerprint" of a process.
          </p>
          <p className="text-lg leading-relaxed text-gray-700 dark:text-gray-300">
            The system operates in four distinct phases: learning (tracing), profiling (modeling), policy generation, and enforcement. This cycle ensures that security policies are derived from actual application behavior rather than manual configuration.
          </p>
        </section>

        {/* 2. Runtime Demonstration (Figure 1) */}
        <section className="mb-16">
          <figure className="my-8">
            <div className="rounded border border-gray-200 dark:border-gray-800 overflow-hidden shadow-sm">
              <TerminalDemo />
            </div>
            <figcaption className="mt-4 font-mono text-xs text-gray-500 text-center">
              Figure 1: Interactive demonstration of the CLI workflow—tracing a process, generating a profile, and enforcing a policy.
            </figcaption>
          </figure>
        </section>

        {/* 3. Methodology */}
        <section className="mb-16">
          <h2 className="font-serif text-2xl font-bold mb-8 text-black dark:text-white flex items-center gap-3">
            <span className="font-mono text-base text-gray-400 font-normal">02</span>
            Methodology
          </h2>
          
          <div className="grid gap-8">
            <MethodItem 
              step="01" 
              title="Syscall Interception" 
              desc="Uses PTRACE_SYSCALL to pause execution at entry and exit of every system call, reading registers (x8 for nr, x0-x5 for args) to capture state."
            />
            <MethodItem 
              step="02" 
              title="Behavioral Profiling" 
              desc="Aggregates syscall frequencies and sequences into a JSON profile. Boolean flags track specific behaviors like network I/O or privilege escalation."
            />
            <MethodItem 
              step="03" 
              title="Policy Synthesis" 
              desc="Transforms the behavioral profile into a strict allowlist policy. Syscalls not observed during the learning phase are flagged as violations."
            />
            <MethodItem 
              step="04" 
              title="Enforcement" 
              desc="Applies the policy at runtime. Violations can trigger logging (Alert Mode) or process termination (Block Mode)."
            />
          </div>
        </section>

        {/* 4. Capabilities */}
        <section className="mb-16">
          <h2 className="font-serif text-2xl font-bold mb-8 text-black dark:text-white flex items-center gap-3">
            <span className="font-mono text-base text-gray-400 font-normal">03</span>
            Capabilities
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <CapabilityCard 
              title="Anomaly Detection" 
              desc="Calculates deviation scores between runtime traces and baseline profiles."
            />
            <CapabilityCard 
              title="Sensitive Path Tracking" 
              desc="Monitors file access to critical system paths (e.g., /etc/shadow, ~/.ssh)."
            />
            <CapabilityCard 
              title="Data Flow Analysis" 
              desc="Tracks potential data exfiltration patterns via socket writes."
            />
            <CapabilityCard 
              title="AI Integration" 
              desc="Optional LLM interface to explain security anomalies in natural language."
            />
          </div>
        </section>

        {/* Footer / References */}
        <footer className="border-t border-gray-200 dark:border-gray-800 pt-8 mt-24">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 text-sm text-gray-500 font-mono">
            <div>
              <p>SysGuard Project © 2025</p>
              <p>Released under MIT License</p>
            </div>
            <div className="flex gap-6">
              <a href="https://github.com/kuladeepmantri/low-level-SysGuard" className="hover:text-black dark:hover:text-white transition-colors flex items-center gap-2">
                Repository <ArrowUpRight size={12} />
              </a>
              <a href="#" className="hover:text-black dark:hover:text-white transition-colors flex items-center gap-2">
                Documentation <ArrowUpRight size={12} />
              </a>
            </div>
          </div>
        </footer>

      </article>
    </main>
  );
}

function MethodItem({ step, title, desc }: { step: string, title: string, desc: string }) {
  return (
    <div className="flex flex-col md:flex-row gap-4 md:gap-8 items-start">
      <div className="font-mono text-sm text-gray-400 shrink-0 pt-1">{step}</div>
      <div>
        <h3 className="font-bold text-lg mb-2 text-gray-900 dark:text-gray-100">{title}</h3>
        <p className="text-gray-600 dark:text-gray-400 leading-relaxed">{desc}</p>
      </div>
    </div>
  );
}

function CapabilityCard({ title, desc }: { title: string, desc: string }) {
  return (
    <div className="p-6 bg-gray-50 dark:bg-gray-900/50 border border-gray-100 dark:border-gray-800 rounded-lg">
      <h3 className="font-bold mb-2 font-mono text-sm uppercase tracking-wider text-gray-900 dark:text-gray-100">{title}</h3>
      <p className="text-sm text-gray-600 dark:text-gray-400">{desc}</p>
    </div>
  );
}

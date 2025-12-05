import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'low-level-SysGuard — ARM64 Linux Syscall Tracer & Security Analyzer',
  description: 'A ptrace-based security tool for syscall tracing, behavioral profiling, and policy enforcement on ARM64 Linux systems.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var stored = localStorage.getItem('theme');
                  if (stored === 'dark') {
                    document.documentElement.classList.add('dark');
                  }
                } catch (e) {}
              })();
            `,
          }}
        />
      </head>
      <body className="antialiased">
        {children}
      </body>
    </html>
  )
}

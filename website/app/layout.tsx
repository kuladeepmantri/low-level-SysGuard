import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Auris — ARM64 Syscall Tracer & Behavioral Security Analyzer',
  description: 'A research-grade ptrace-based tool for syscall tracing, behavioral profiling, anomaly detection, and policy enforcement on ARM64 Linux.',
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

import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Auris v2.0 · ARM64 Security Toolkit for Defense & Offense',
  description: 'Auris is a research-grade ARM64 Linux security toolkit combining syscall tracing, behavioral analysis, and policy enforcement (blue team) with process injection, shellcode execution, and ROP chain building (red team).',
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

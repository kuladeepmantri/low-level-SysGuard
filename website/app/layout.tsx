import './globals.css'
import type { Metadata } from 'next'
import { Inter, JetBrains_Mono, Merriweather } from 'next/font/google'

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' })
const jetbrainsMono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-jetbrains-mono' })
const merriweather = Merriweather({ weight: ['300', '400', '700', '900'], subsets: ['latin'], variable: '--font-merriweather' })

export const metadata: Metadata = {
  title: 'SysGuard: Runtime Security Analysis for ARM64',
  description: 'A behavioral profiling and policy enforcement system for Linux containers.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable} ${merriweather.variable}`}>
      <body className="bg-[#0f1115] text-slate-300 antialiased selection:bg-white/20">{children}</body>
    </html>
  )
}

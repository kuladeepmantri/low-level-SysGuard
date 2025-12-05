'use client'

import { useState, useEffect, useRef } from 'react'

interface AnimatedTerminalProps {
  command: string
  output: string
  title?: string
  minHeight?: number
}

export default function AnimatedTerminal({ command, output, title = 'terminal' }: AnimatedTerminalProps) {
  const [displayedCommand, setDisplayedCommand] = useState('')
  const [showOutput, setShowOutput] = useState(false)
  const [hasAnimated, setHasAnimated] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  
  // Calculate the height based on output lines to prevent layout shift
  const outputLines = output.split('\n').length
  const estimatedHeight = Math.max(200, 60 + (outputLines * 22)) // 60px for header/padding, 22px per line

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !hasAnimated) {
          setHasAnimated(true)
          animateTerminal()
        }
      },
      { threshold: 0.3 }
    )

    if (ref.current) {
      observer.observe(ref.current)
    }

    return () => observer.disconnect()
  }, [hasAnimated])

  const animateTerminal = () => {
    let i = 0
    const fullCommand = `$ ${command}`
    
    const interval = setInterval(() => {
      if (i <= fullCommand.length) {
        setDisplayedCommand(fullCommand.slice(0, i))
        i++
      } else {
        clearInterval(interval)
        setTimeout(() => setShowOutput(true), 150)
      }
    }, 25)
  }

  const getLineStyle = (line: string) => {
    if (line.includes('[CRITICAL]') || line.includes('BLOCK') || line.includes('terminated') || line.includes('ANOMALY')) {
      return 'text-[var(--terminal-red)]'
    }
    if (line.includes('[HIGH]') || line.includes('[MEDIUM]') || line.includes('Deviation') || line.includes('Risk')) {
      return 'text-[var(--terminal-yellow)]'
    }
    if (line.includes('ALLOW') || line.includes('Trace ID') || line.includes('Profile ID') || line.includes('saved') || line.includes('created') || line.includes('Policy ID') || line.includes('Successfully')) {
      return 'text-[var(--terminal-green)]'
    }
    if (line.startsWith('[') || line.startsWith('  -') || line.startsWith(' =>')) {
      return 'text-[var(--terminal-dim)]'
    }
    return 'text-[var(--terminal-text)]'
  }

  return (
    <div 
      ref={ref}
      className="rounded-xl overflow-hidden border border-[var(--border)] dark:border-[#1e293b] bg-[var(--terminal-bg)] shadow-[var(--shadow-md)]"
      style={{ minHeight: `${estimatedHeight}px` }}
    >
      {/* Terminal header with macOS-style buttons */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-[#1e293b] bg-[#0c1222]">
        <div className="flex gap-2">
          <div className="w-3 h-3 rounded-full bg-[#ff5f57] hover:bg-[#ff5f57]/80 transition-colors cursor-pointer"></div>
          <div className="w-3 h-3 rounded-full bg-[#febc2e] hover:bg-[#febc2e]/80 transition-colors cursor-pointer"></div>
          <div className="w-3 h-3 rounded-full bg-[#28c840] hover:bg-[#28c840]/80 transition-colors cursor-pointer"></div>
        </div>
        <div className="flex-1 text-center">
          <span className="text-xs font-medium text-[var(--terminal-dim)]">{title}</span>
        </div>
        <div className="w-[52px]"></div> {/* Spacer for centering */}
      </div>
      
      {/* Terminal content */}
      <div className="p-5 font-mono text-[13px] leading-[1.7] overflow-x-auto">
        <div className="text-[var(--terminal-text)]">
          <span className="text-[var(--terminal-green)]">$</span>
          <span className="ml-2">{displayedCommand.slice(2)}</span>
          {!showOutput && hasAnimated && (
            <span className="inline-block w-2 h-[18px] bg-[var(--terminal-text)] animate-pulse ml-0.5 align-middle"></span>
          )}
        </div>
        
        {showOutput && (
          <div className="mt-3 space-y-0">
            {output.split('\n').map((line, i) => (
              <div key={i} className={`${getLineStyle(line)} whitespace-pre`}>
                {line || '\u00A0'}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

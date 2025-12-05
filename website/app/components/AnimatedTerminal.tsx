'use client'

import { useState, useEffect, useRef } from 'react'

interface AnimatedTerminalProps {
  command: string
  output: string
  title?: string
}

export default function AnimatedTerminal({ command, output, title = 'terminal' }: AnimatedTerminalProps) {
  const [displayedCommand, setDisplayedCommand] = useState('')
  const [showOutput, setShowOutput] = useState(false)
  const [hasAnimated, setHasAnimated] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

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
    if (line.includes('ALLOW') || line.includes('Trace ID') || line.includes('Profile ID') || line.includes('saved') || line.includes('created')) {
      return 'text-[var(--terminal-green)]'
    }
    if (line.startsWith('[') || line.startsWith('  -')) {
      return 'text-[var(--terminal-dim)]'
    }
    return 'text-[var(--terminal-text)]'
  }

  return (
    <div 
      ref={ref}
      className="rounded-lg overflow-hidden border border-[var(--border)] dark:border-[var(--terminal-border,var(--border))] bg-[var(--terminal-bg)]"
    >
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[var(--border)] dark:border-[var(--terminal-border,var(--border))] bg-[var(--terminal-bg)]">
        <div className="flex gap-2">
          <div className="w-2.5 h-2.5 rounded-full bg-[#ef4444]/70"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-[#eab308]/70"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-[#22c55e]/70"></div>
        </div>
        <span className="ml-3 text-xs text-[var(--terminal-dim)]">{title}</span>
      </div>
      
      <div className="p-4 font-mono text-[13px] leading-relaxed min-h-[120px]">
        <div className="text-[var(--terminal-text)]">
          {displayedCommand}
          {!showOutput && hasAnimated && (
            <span className="inline-block w-1.5 h-4 bg-[var(--terminal-text)] animate-pulse ml-0.5"></span>
          )}
        </div>
        
        {showOutput && (
          <div className="mt-2">
            {output.split('\n').map((line, i) => (
              <div key={i} className={getLineStyle(line)}>
                {line || '\u00A0'}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

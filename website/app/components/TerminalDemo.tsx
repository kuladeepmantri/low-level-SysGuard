'use client';

import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { Terminal, Play, RotateCcw } from 'lucide-react';

const COMMANDS = [
  { text: './sysguard learn -t demo -- /bin/ls', output: 'Tracing process... Trace saved: demo (124 syscalls)' },
  { text: './sysguard profile -t demo', output: 'Profile created: 26b4... (Behavior: File I/O, Network I/O)' },
  { text: './sysguard policy -p 26b4...', output: 'Policy generated: 87d6... (Rules: 42, Default: Alert)' },
  { text: './sysguard enforce -P 87d6... -- /bin/ls', output: 'Enforcing... Policy: 87d6... \nStatistics: 73 allowed, 0 violations.' },
];

export default function TerminalDemo() {
  const [step, setStep] = useState(0);
  const [lines, setLines] = useState<{ type: 'cmd' | 'out', text: string }[]>([]);
  const [isTyping, setIsTyping] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines]);

  const runStep = async () => {
    if (isTyping || step >= COMMANDS.length) return;

    setIsTyping(true);
    const cmd = COMMANDS[step];
    
    // Simulate typing
    let currentText = '';
    for (let i = 0; i < cmd.text.length; i++) {
      await new Promise(r => setTimeout(r, 30));
      currentText += cmd.text[i];
      setLines(prev => {
        const newLines = [...prev];
        if (newLines.length > 0 && newLines[newLines.length - 1].type === 'cmd' && newLines[newLines.length - 1].text !== cmd.text) {
             newLines[newLines.length - 1].text = currentText;
             return newLines;
        } else if (newLines.length === 0 || newLines[newLines.length - 1].type !== 'cmd') {
             return [...prev, { type: 'cmd', text: currentText }];
        }
        return newLines;
      });
    }
    
    // Show output after delay
    await new Promise(r => setTimeout(r, 500));
    setLines(prev => [...prev, { type: 'out', text: cmd.output }]);
    setStep(s => s + 1);
    setIsTyping(false);
  };

  const reset = () => {
    setStep(0);
    setLines([]);
  };

  return (
    <div className="rounded overflow-hidden bg-[#1a1a1a] border border-gray-800 w-full font-mono text-sm">
      <div className="bg-[#2a2a2a] px-4 py-2 flex items-center justify-between border-b border-gray-800">
        <div className="text-gray-500 text-xs flex items-center gap-2">
          <Terminal size={12} />
          <span>sysguard-session</span>
        </div>
      </div>
      
      <div 
        ref={scrollRef}
        className="p-4 h-[300px] overflow-y-auto text-gray-300 space-y-2 scrollbar-thin scrollbar-thumb-gray-700 scrollbar-track-transparent"
      >
        {lines.map((line, i) => (
          <div key={i} className={`${line.type === 'cmd' ? 'text-white' : 'text-gray-400'}`}>
            {line.type === 'cmd' && <span className="text-gray-500 mr-2">$</span>}
            {line.text}
          </div>
        ))}
        {lines.length === 0 && <div className="text-gray-600">Waiting for input...</div>}
      </div>

      <div className="bg-[#2a2a2a] p-3 border-t border-gray-800 flex justify-end gap-2">
        <button 
          onClick={reset}
          className="p-2 hover:bg-[#3a3a3a] rounded text-gray-400 transition-colors"
          title="Reset"
        >
          <RotateCcw size={14} />
        </button>
        <button 
          onClick={runStep}
          disabled={isTyping || step >= COMMANDS.length}
          className="flex items-center gap-2 px-3 py-1.5 bg-white hover:bg-gray-200 disabled:opacity-50 disabled:cursor-not-allowed text-black rounded text-xs font-medium transition-colors"
        >
          <Play size={12} />
          {step >= COMMANDS.length ? 'Complete' : 'Run Step'}
        </button>
      </div>
    </div>
  );
}

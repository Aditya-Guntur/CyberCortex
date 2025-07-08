import React, { useState, useRef } from 'react';
import { Download, RefreshCw, Trash2, Image, FileText, Zap, MessageCircle, User } from 'lucide-react';
import { marked } from 'marked';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  imageUrl?: string;
}

interface LlamaAnalystChatProps {
  exploitCode?: string;
  simulationContext?: string; // JSON or summary string of simulation state
}

export function LlamaAnalystChat({ exploitCode, simulationContext }: LlamaAnalystChatProps) {
  const [messages, setMessages] = useState<Message[]>([
    { role: 'assistant', content: 'Hello! I am your AI Security Analyst. Ask me anything about your simulation, or use the quick actions below.' }
  ]);
  const [input, setInput] = useState('');
  const [image, setImage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastUserMsg, setLastUserMsg] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const chatBoxRef = useRef<HTMLDivElement>(null);

  // Scroll to bottom on new message
  React.useEffect(() => {
    if (chatBoxRef.current) {
      chatBoxRef.current.scrollTop = chatBoxRef.current.scrollHeight;
    }
  }, [messages, loading]);

  // Quick actions
  const quickActions = [
    {
      label: 'Review Exploit Code',
      icon: <FileText className="w-4 h-4 mr-1" />,
      onClick: () => {
        if (exploitCode) {
          sendMessage(`Please review the following exploit code for effectiveness, risks, and improvements.\n\n${exploitCode}`);
        } else {
          sendMessage('No exploit code is available to review.');
        }
      }
    },
    {
      label: 'Generate Incident Report',
      icon: <Zap className="w-4 h-4 mr-1" />,
      onClick: () => sendMessage('Generate a professional incident report based on the current simulation findings.')
    },
    {
      label: 'Analyze Image/Log',
      icon: <Image className="w-4 h-4 mr-1" />,
      onClick: () => {
        if (image) {
          setWarning(null);
          sendMessage('What is in this image?', image);
        } else {
          setWarning('Please upload an image or log file to analyze.');
        }
      }
    },
    {
      label: 'What if? Scenario',
      icon: <MessageCircle className="w-4 h-4 mr-1" />,
      onClick: () => sendMessage('What would happen if an attacker exploited the most critical vulnerability in this simulation?')
    }
  ];

  async function sendMessage(text: string, imageUrl?: string, regenerate?: boolean) {
    setLoading(true);
    const userMsg: Message = { role: 'user', content: text, imageUrl };
    const newMessages = regenerate
      ? messages.slice(0, -1).concat(userMsg)
      : [...messages, userMsg];
    setMessages(newMessages);
    setLastUserMsg(text);
    // Call your backend API route for Llama chat
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || '';
    const res = await fetch(`${apiUrl}/api/llama-chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: newMessages, simulationContext })
    });
    const data = await res.json();
    setMessages([...newMessages, { role: 'assistant', content: data.reply }]);
    setLoading(false);
    setInput('');
  }

  function handleImageUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = () => setImage(reader.result as string);
      reader.readAsDataURL(file);
    }
  }

  function handleExportChat() {
    const md = messages.map(m => `**${m.role === 'user' ? 'You' : 'Llama'}:**\n${m.content}\n`).join('\n');
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'llama-analyst-chat.md';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function handleClearChat() {
    setMessages([
      { role: 'assistant', content: 'Hello! I am your AI Security Analyst. Ask me anything about your simulation, or use the quick actions below.' }
    ]);
    setInput('');
    setImage(null);
  }

  function handleRegenerate() {
    if (lastUserMsg) {
      sendMessage(lastUserMsg, undefined, true);
    }
  }

  return (
    <div className="border rounded-xl p-4 bg-card/70 mt-8 shadow-lg max-w-4xl w-full mx-auto">
      <div className="flex items-center justify-between mb-2">
        <h3 className="font-bold text-lg flex items-center gap-2">
          <Zap className="w-5 h-5 text-cyber-500" /> AI Security Analyst (Llama)
        </h3>
        <div className="flex gap-2">
          <button title="Export chat" className="p-1 rounded hover:bg-muted" onClick={handleExportChat}><Download className="w-4 h-4" /></button>
          <button title="Regenerate last response" className="p-1 rounded hover:bg-muted" onClick={handleRegenerate} disabled={!lastUserMsg}><RefreshCw className="w-4 h-4" /></button>
          <button title="Clear chat" className="p-1 rounded hover:bg-muted" onClick={handleClearChat}><Trash2 className="w-4 h-4" /></button>
        </div>
      </div>
      <div className="flex flex-wrap gap-2 mb-3">
        {quickActions.map((action, i) => (
          <button key={i} className="bg-cyber-500 hover:bg-cyber-600 text-white px-3 py-1 rounded text-xs flex items-center" onClick={action.onClick} disabled={loading}>
            {action.icon}{action.label}
          </button>
        ))}
      </div>
      <div ref={chatBoxRef} className="overflow-y-auto bg-background p-3 rounded-lg mb-2 min-h-[400px] max-h-[600px] resize-y w-full" style={{height: '500px'}}>
        {messages.map((msg, i) => (
          <div key={i} className={`flex mb-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div className={`flex items-end gap-2 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
              <div className={`rounded-full bg-cyber-500/80 w-8 h-8 flex items-center justify-center text-white font-bold text-lg ${msg.role === 'user' ? 'bg-cyber-500' : 'bg-muted'}`}>
                {msg.role === 'user' ? <User className="w-5 h-5" /> : <Zap className="w-5 h-5 text-cyber-500" />}
              </div>
              <div className={`rounded-xl px-3 py-2 max-w-2xl w-full break-words ${msg.role === 'user' ? 'bg-cyber-500 text-white' : 'bg-muted text-foreground'} shadow-sm`}>
                <span dangerouslySetInnerHTML={{ __html: marked.parse(msg.content) }} />
                {msg.imageUrl && <img src={msg.imageUrl} alt="uploaded" className="max-h-24 mt-1 rounded" />}
              </div>
            </div>
          </div>
        ))}
        {loading && (
          <div className="flex items-center gap-2 text-muted-foreground animate-pulse">
            <Zap className="w-4 h-4 animate-spin" /> Llama is thinking...
          </div>
        )}
      </div>
      <div className="flex flex-col sm:flex-row gap-2 sticky bottom-0 bg-card/70 pt-2">
        <input
          className="flex-1 border rounded px-3 py-2 focus:outline-cyber-500 text-foreground bg-background"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && sendMessage(input)}
          placeholder="Ask about your simulation, vulnerabilities, or upload an image..."
          disabled={loading}
        />
        <input type="file" accept="image/*" onChange={handleImageUpload} className="hidden" id="llama-image-upload" />
        <label htmlFor="llama-image-upload" className="bg-muted hover:bg-cyber-100 text-cyber-500 px-3 py-2 rounded cursor-pointer flex items-center gap-1">
          <Image className="w-4 h-4" /> Image
        </label>
        <button className="bg-cyber-500 hover:bg-cyber-600 text-white px-4 py-2 rounded font-semibold" onClick={() => sendMessage(input)} disabled={loading || !input.trim()}>
          Send
        </button>
      </div>
      {warning && <div className="text-xs text-red-500 mt-1">{warning}</div>}
    </div>
  );
} 
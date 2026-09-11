import React, { useState } from 'react';
import { Bot, X, Send, HelpCircle } from 'lucide-react';

interface Message {
  id: string;
  sender: 'bot' | 'user';
  text: string;
  codeSnippet?: string;
}

interface AIGuideBotProps {
  isOpen: boolean;
  onClose: () => void;
}

export const AIGuideBot: React.FC<AIGuideBotProps> = ({ isOpen, onClose }) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      sender: 'bot',
      text: '👋 Hello! I am your AI DevSecOps Assistant. Ask me anything about Checkov policies, Terraform remediations, CLI scan commands, or website features!',
    },
  ]);
  const [inputQuery, setInputQuery] = useState('');

  const quickPrompts = [
    'What is Checkov & Shift-Left?',
    'How do I fix CKV_AWS_18 (S3 Logging)?',
    'How do I run local PowerShell scans?',
    'What is SARIF format in GitHub?',
    'How do I write custom YAML policies?',
  ];

  const handleSend = (textToSend?: string) => {
    const query = textToSend || inputQuery;
    if (!query.trim()) return;

    const msgId = `user-${messages.length + 1}`;
    const userMsg: Message = {
      id: msgId,
      sender: 'user',
      text: query,
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!textToSend) setInputQuery('');

    // Generate intelligent AI response based on keywords
    setTimeout(() => {
      let botAnswer = '';
      let codeSnippet: string | undefined = undefined;
      const lower = query.toLowerCase();

      if (lower.includes('checkov') || lower.includes('shift-left')) {
        botAnswer = 'Checkov (by Palo Alto / Bridgecrew) is a static analysis tool for Infrastructure as Code (IaC). Shift-Left means finding security vulnerabilities during coding in your IDE and CI/CD pipelines BEFORE code is applied to cloud providers (AWS/Azure/GCP).';
      } else if (lower.includes('ckv_aws_18') || lower.includes('s3 logging') || lower.includes('s3')) {
        botAnswer = 'CKV_AWS_18 flags S3 buckets missing access logging. To fix it in Terraform, create a target logging bucket and attach an `aws_s3_bucket_logging` resource.';
        codeSnippet = `resource "aws_s3_bucket_logging" "example" {\n  bucket        = aws_s3_bucket.main.id\n  target_bucket = aws_s3_bucket.log_bucket.id\n  target_prefix = "log/"\n}`;
      } else if (lower.includes('powershell') || lower.includes('cli') || lower.includes('run')) {
        botAnswer = 'You can run automated scans directly from your terminal using our PowerShell script in the `scripts/` directory:';
        codeSnippet = `.\\scripts\\run_scans.ps1 -Target "all" -ExportFormat "all"`;
      } else if (lower.includes('sarif')) {
        botAnswer = 'SARIF (Static Analysis Results Interchange Format) is an OASIS standard JSON schema used to upload security vulnerabilities directly into the GitHub Code Scanning tab.';
      } else if (lower.includes('custom') || lower.includes('yaml')) {
        botAnswer = 'You can write custom declarative policies in YAML inside `./custom_policies/yaml/`. Open our Custom Policy Studio tab to experiment with live rules!';
        codeSnippet = `metadata:\n  name: "Ensure S3 Tagging"\n  id: "CUSTOM_AWS_001"\n  severity: "HIGH"\nscope:\n  provider: "aws"\ndefinition:\n  and:\n    - cond_type: "attribute"\n      resource_types: ["aws_s3_bucket"]\n      attribute: "tags.Environment"\n      operator: "exists"`;
      } else {
        botAnswer = `I analyzed your query regarding "${query}". You can use the HCL Code Inspector tab to view side-by-side remediations or check CLI Commands & Reports for raw output formats.`;
      }

      const botMsg: Message = {
        id: `bot-${Date.now()}`,
        sender: 'bot',
        text: botAnswer,
        codeSnippet,
      };

      setMessages((prev) => [...prev, botMsg]);
    }, 600);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-end p-4 sm:p-6 bg-slate-950/60 backdrop-blur-sm animate-fadeIn">
      <div className="w-full max-w-lg h-[650px] glass-panel border border-indigo-500/30 rounded-3xl shadow-2xl flex flex-col overflow-hidden bg-slate-900/95">
        {/* Header */}
        <div className="p-4 bg-gradient-to-r from-indigo-950/80 via-slate-900 to-purple-950/80 border-b border-indigo-500/30 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-xl bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
              <Bot className="w-5 h-5 animate-bounce" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <span>AI Security Guide Assistant</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300">
                  Online
                </span>
              </h3>
              <p className="text-[11px] text-slate-400">Ask questions about Checkov, HCL rules, or website features</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Messages Body */}
        <div className="flex-1 p-4 overflow-y-auto space-y-4 font-sans text-xs text-slate-200">
          {messages.map((m) => (
            <div
              key={m.id}
              className={`flex flex-col ${m.sender === 'user' ? 'items-end' : 'items-start'}`}
            >
              <div
                className={`max-w-[85%] p-3.5 rounded-2xl ${
                  m.sender === 'user'
                    ? 'bg-indigo-600 text-white rounded-br-none'
                    : 'bg-slate-800/90 text-slate-200 border border-slate-700/80 rounded-bl-none space-y-2'
                }`}
              >
                <p className="leading-relaxed">{m.text}</p>
                {m.codeSnippet && (
                  <div className="p-3 bg-slate-950 rounded-xl font-mono text-[11px] text-emerald-300 overflow-x-auto border border-slate-800">
                    <pre>{m.codeSnippet}</pre>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Quick Prompts */}
        <div className="px-4 py-2 bg-slate-950/60 border-t border-slate-800/80 flex items-center space-x-2 overflow-x-auto no-scrollbar">
          <HelpCircle className="w-4 h-4 text-indigo-400 shrink-0" />
          {quickPrompts.map((qp) => (
            <button
              key={qp}
              onClick={() => handleSend(qp)}
              className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-indigo-600/30 text-slate-300 hover:text-indigo-200 text-[11px] font-medium whitespace-nowrap transition-all border border-slate-700/60"
            >
              {qp}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <div className="p-4 bg-slate-950 border-t border-slate-800/80 flex items-center space-x-2">
          <input
            type="text"
            value={inputQuery}
            onChange={(e) => setInputQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            placeholder="Ask AI about Checkov rules or website..."
            className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
          />
          <button
            onClick={() => handleSend()}
            className="p-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white transition-all shadow-md shadow-indigo-900/40"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};

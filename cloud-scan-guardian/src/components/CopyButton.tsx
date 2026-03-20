import { useState } from 'react';
import { Copy, Check } from 'lucide-react';

export default function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-white/50 hover:text-white transition-colors"
      title="Copy to clipboard"
    >
      {copied ? <><Check size={11} className="text-health-secure" /> Copied</> : <><Copy size={11} /> Copy</>}
    </button>
  );
}

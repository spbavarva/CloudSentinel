import { Download } from 'lucide-react';
import { ServiceAnalysis } from '@/lib/types';

interface Props {
  analysis: ServiceAnalysis;
}

export default function ExportButton({ analysis }: Props) {
  const handleExport = () => {
    const json = JSON.stringify(analysis, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const ts = analysis.scan_timestamp
      ? analysis.scan_timestamp.replace(/[:.]/g, '-')
      : new Date().toISOString().replace(/[:.]/g, '-');

    const a = document.createElement('a');
    a.href = url;
    a.download = `cloudsentinel-${analysis.service}-${ts}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <button
      onClick={handleExport}
      className="inline-flex items-center gap-1.5 rounded-lg glass-subtle px-3.5 py-2 text-xs font-semibold text-foreground/70 hover:text-foreground card-hover transition-all"
      title="Download JSON"
    >
      <Download size={14} />
      Export
    </button>
  );
}

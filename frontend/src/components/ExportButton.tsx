import { Download, FileJson, FileText } from 'lucide-react';
import { ServiceAnalysis } from '@/lib/types';
import { generateSecurityReport } from '@/lib/pdf-export';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

interface Props {
  analysis: ServiceAnalysis;
}

export default function ExportButton({ analysis }: Props) {
  const handleExportJSON = () => {
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

  const handleExportPDF = () => {
    generateSecurityReport(analysis);
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          className="inline-flex items-center gap-1.5 rounded-lg glass-subtle px-3.5 py-2 text-xs font-semibold text-foreground/70 hover:text-foreground card-hover transition-all"
          title="Export scan results"
        >
          <Download size={14} />
          Export
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="glass border-[hsl(0_0%_100%/0.08)]">
        <DropdownMenuItem onClick={handleExportJSON} className="gap-2 cursor-pointer">
          <FileJson size={14} />
          Export JSON
        </DropdownMenuItem>
        <DropdownMenuItem onClick={handleExportPDF} className="gap-2 cursor-pointer">
          <FileText size={14} />
          Export PDF
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

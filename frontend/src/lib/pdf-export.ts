import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { ServiceAnalysis, Finding, AttackPath, Severity } from './types';

// ── Colors (RGB) ────────────────────────────────────────────────────────────

const COLORS = {
  CRITICAL: [217, 72, 72] as const,
  HIGH: [255, 153, 51] as const,
  MEDIUM: [204, 184, 26] as const,
  LOW: [133, 133, 143] as const,
  NEEDS_REVIEW: [160, 120, 200] as const,
  primary: [120, 80, 220] as const,
  dark: [30, 30, 40] as const,
  text: [230, 230, 235] as const,
  muted: [160, 160, 170] as const,
  white: [255, 255, 255] as const,
  black: [0, 0, 0] as const,
  headerBg: [25, 25, 35] as const,
  rowBg: [35, 35, 50] as const,
  rowAltBg: [30, 30, 42] as const,
};

const severityOrder: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEEDS_REVIEW'];

// ── Helpers ─────────────────────────────────────────────────────────────────

function severityColor(severity: Severity): readonly [number, number, number] {
  return COLORS[severity] ?? COLORS.muted;
}

function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toLocaleString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric',
      hour: '2-digit', minute: '2-digit', timeZoneName: 'short',
    });
  } catch {
    return ts;
  }
}

function truncate(text: string, max: number): string {
  if (!text) return '';
  return text.length > max ? text.slice(0, max - 3) + '...' : text;
}

// ── Section Renderers ───────────────────────────────────────────────────────

function addHeader(doc: jsPDF, analysis: ServiceAnalysis) {
  const pageW = doc.internal.pageSize.getWidth();

  // Title bar
  doc.setFillColor(...COLORS.headerBg);
  doc.rect(0, 0, pageW, 38, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(22);
  doc.setTextColor(...COLORS.white);
  doc.text('CloudSentinel', 20, 18);

  doc.setFontSize(11);
  doc.setTextColor(...COLORS.muted);
  doc.text('Security Assessment Report', 20, 28);

  // Service + timestamp + health
  doc.setFontSize(10);
  doc.setTextColor(...COLORS.muted);
  const meta = `${analysis.service.toUpperCase()} | ${formatTimestamp(analysis.scan_timestamp)}`;
  doc.text(meta, pageW - 20, 18, { align: 'right' });

  const health = analysis.account_summary.overall_health;
  const healthColor = health === 'SECURE' ? [80, 200, 120] as const
    : health === 'AT_RISK' ? [255, 153, 51] as const
    : health === 'CRITICAL_RISK' ? [217, 72, 72] as const
    : COLORS.muted;
  doc.setTextColor(...healthColor);
  doc.setFont('helvetica', 'bold');
  doc.text(health.replace(/_/g, ' '), pageW - 20, 28, { align: 'right' });
}

function addExecutiveSummary(doc: jsPDF, analysis: ServiceAnalysis, startY: number): number {
  const summary = analysis.account_summary;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(...COLORS.white);
  doc.text('Executive Summary', 20, startY);

  // Stats row
  const statsData = [
    ['Resources Scanned', String(summary.total_resources_scanned)],
    ['Total Findings', String(summary.total_findings)],
    ['Attack Paths', String(summary.total_attack_paths)],
  ];

  autoTable(doc, {
    startY: startY + 4,
    head: [['Metric', 'Count']],
    body: statsData,
    theme: 'plain',
    margin: { left: 20, right: 20 },
    styles: {
      fontSize: 9,
      textColor: COLORS.text as unknown as number[],
      cellPadding: 4,
    },
    headStyles: {
      fillColor: COLORS.headerBg as unknown as number[],
      textColor: COLORS.muted as unknown as number[],
      fontStyle: 'bold',
      fontSize: 8,
    },
    bodyStyles: {
      fillColor: COLORS.rowBg as unknown as number[],
    },
    alternateRowStyles: {
      fillColor: COLORS.rowAltBg as unknown as number[],
    },
    columnStyles: {
      1: { halign: 'center', fontStyle: 'bold' },
    },
  });

  let y = (doc as ReturnType<typeof Object>).lastAutoTable.finalY + 6;

  // Severity breakdown
  const sevData = severityOrder.map(sev => [
    sev,
    String(summary.severity_breakdown[sev] ?? 0),
  ]);

  autoTable(doc, {
    startY: y,
    head: [['Severity', 'Count']],
    body: sevData,
    theme: 'plain',
    margin: { left: 20, right: 20 },
    styles: {
      fontSize: 9,
      textColor: COLORS.text as unknown as number[],
      cellPadding: 4,
    },
    headStyles: {
      fillColor: COLORS.headerBg as unknown as number[],
      textColor: COLORS.muted as unknown as number[],
      fontStyle: 'bold',
      fontSize: 8,
    },
    bodyStyles: {
      fillColor: COLORS.rowBg as unknown as number[],
    },
    alternateRowStyles: {
      fillColor: COLORS.rowAltBg as unknown as number[],
    },
    didParseCell(data) {
      if (data.section === 'body' && data.column.index === 0) {
        const sev = data.cell.raw as string;
        const color = severityColor(sev as Severity);
        data.cell.styles.textColor = color as unknown as number[];
        data.cell.styles.fontStyle = 'bold';
      }
    },
    columnStyles: {
      1: { halign: 'center', fontStyle: 'bold' },
    },
  });

  return (doc as ReturnType<typeof Object>).lastAutoTable.finalY + 8;
}

function addNarrative(doc: jsPDF, narrative: string, startY: number): number {
  if (!narrative) return startY;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(...COLORS.white);
  doc.text('Narrative', 20, startY);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(...COLORS.text);
  const pageW = doc.internal.pageSize.getWidth();
  const lines = doc.splitTextToSize(narrative, pageW - 40);
  doc.text(lines, 20, startY + 8);

  return startY + 8 + lines.length * 5 + 8;
}

function addQuickWins(doc: jsPDF, analysis: ServiceAnalysis, startY: number): number {
  const wins = analysis.quick_wins;
  if (!wins?.length) return startY;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(...COLORS.white);
  doc.text('Quick Wins', 20, startY);

  const body = wins.map(qw => [
    qw.finding_id,
    truncate(qw.action, 80),
    qw.effort,
    truncate(qw.impact, 60),
  ]);

  autoTable(doc, {
    startY: startY + 4,
    head: [['Finding', 'Action', 'Effort', 'Impact']],
    body,
    theme: 'plain',
    margin: { left: 20, right: 20 },
    styles: {
      fontSize: 8,
      textColor: COLORS.text as unknown as number[],
      cellPadding: 4,
      overflow: 'linebreak',
    },
    headStyles: {
      fillColor: COLORS.headerBg as unknown as number[],
      textColor: COLORS.muted as unknown as number[],
      fontStyle: 'bold',
      fontSize: 8,
    },
    bodyStyles: {
      fillColor: COLORS.rowBg as unknown as number[],
    },
    alternateRowStyles: {
      fillColor: COLORS.rowAltBg as unknown as number[],
    },
    columnStyles: {
      0: { cellWidth: 28, fontStyle: 'bold', textColor: COLORS.primary as unknown as number[] },
      1: { cellWidth: 'auto' },
      2: { cellWidth: 24, halign: 'center' },
      3: { cellWidth: 50 },
    },
  });

  return (doc as ReturnType<typeof Object>).lastAutoTable.finalY + 8;
}

function checkPageBreak(doc: jsPDF, y: number, needed: number): number {
  const pageH = doc.internal.pageSize.getHeight();
  if (y + needed > pageH - 20) {
    doc.addPage();
    return 20;
  }
  return y;
}

function addFindings(doc: jsPDF, findings: Finding[], startY: number): number {
  if (!findings.length) return startY;

  const sorted = [...findings].sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );

  let y = startY;
  y = checkPageBreak(doc, y, 20);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(...COLORS.white);
  doc.text(`Findings (${findings.length})`, 20, y);
  y += 8;

  const pageW = doc.internal.pageSize.getWidth();

  for (const f of sorted) {
    y = checkPageBreak(doc, y, 60);

    // Severity + ID + category header
    const sevCol = severityColor(f.severity);
    doc.setFillColor(...sevCol);
    doc.roundedRect(20, y - 4, 18, 7, 1, 1, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(...COLORS.white);
    doc.text(f.severity, 21, y + 1);

    doc.setFontSize(8);
    doc.setTextColor(...COLORS.muted);
    doc.text(`${f.id}  |  ${f.resource_type || ''}  |  ${f.category || ''}`, 42, y + 1);
    y += 8;

    // Title
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...COLORS.white);
    const title = f.issue_title || f.id;
    doc.text(title, 20, y);
    y += 5;

    // Description
    if (f.issue_description) {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.setTextColor(...COLORS.text);
      const descLines = doc.splitTextToSize(f.issue_description, pageW - 40);
      doc.text(descLines, 20, y);
      y += descLines.length * 4 + 2;
    }

    // Resource info
    doc.setFontSize(8);
    doc.setTextColor(...COLORS.muted);
    doc.text(`${f.resource_name || ''} / ${f.resource_id || ''}`, 20, y);
    y += 5;

    // Impact
    if (f.impact) {
      y = checkPageBreak(doc, y, 20);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(...COLORS.primary);
      doc.text('Impact:', 20, y);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...COLORS.text);
      const impactLines = doc.splitTextToSize(f.impact, pageW - 45);
      doc.text(impactLines, 20, y + 4);
      y += 4 + impactLines.length * 4 + 2;
    }

    // Fix command
    if (f.fix_command) {
      y = checkPageBreak(doc, y, 20);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(...COLORS.primary);
      doc.text('Fix Command:', 20, y);
      y += 4;

      doc.setFillColor(15, 15, 20);
      const cmdLines = doc.splitTextToSize(f.fix_command, pageW - 50);
      const cmdH = cmdLines.length * 4 + 6;
      doc.roundedRect(20, y - 3, pageW - 40, cmdH, 2, 2, 'F');
      doc.setFont('courier', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(200, 220, 255);
      doc.text(cmdLines, 24, y + 1);
      y += cmdH + 2;
    }

    // Explanation
    if (f.fix_explanation) {
      y = checkPageBreak(doc, y, 14);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(...COLORS.primary);
      doc.text('Explanation:', 20, y);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...COLORS.text);
      const expLines = doc.splitTextToSize(f.fix_explanation, pageW - 45);
      doc.text(expLines, 20, y + 4);
      y += 4 + expLines.length * 4 + 2;
    }

    // AWS doc reference
    if (f.aws_doc_reference) {
      doc.setFontSize(7);
      doc.setTextColor(100, 140, 220);
      doc.text(`AWS Docs: ${f.aws_doc_reference}`, 20, y);
      y += 4;
    }

    // Separator line
    y += 2;
    doc.setDrawColor(60, 60, 80);
    doc.setLineWidth(0.3);
    doc.line(20, y, pageW - 20, y);
    y += 6;
  }

  return y;
}

function addAttackPaths(doc: jsPDF, paths: AttackPath[], startY: number): number {
  if (!paths.length) return startY;

  let y = startY;
  y = checkPageBreak(doc, y, 20);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(...COLORS.white);
  doc.text(`Attack Paths (${paths.length})`, 20, y);
  y += 8;

  const pageW = doc.internal.pageSize.getWidth();

  for (const ap of paths) {
    y = checkPageBreak(doc, y, 50);

    // Severity + ID + title
    const sevCol = severityColor(ap.severity);
    doc.setFillColor(...sevCol);
    doc.roundedRect(20, y - 4, 18, 7, 1, 1, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(...COLORS.white);
    doc.text(ap.severity, 21, y + 1);

    doc.setFontSize(9);
    doc.setTextColor(...COLORS.muted);
    doc.text(ap.id, 42, y + 1);

    if (ap.title) {
      doc.setFontSize(11);
      doc.setTextColor(...COLORS.white);
      doc.text(ap.title, 62, y + 1);
    }
    y += 10;

    // Chain steps
    if (ap.chain?.length) {
      for (const step of ap.chain) {
        y = checkPageBreak(doc, y, 18);

        // Step number circle
        doc.setFillColor(...COLORS.primary);
        doc.circle(28, y, 4, 'F');
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7);
        doc.setTextColor(...COLORS.white);
        doc.text(String(step.step || ''), 28, y + 2, { align: 'center' });

        // Evidence status badge
        const evColor = step.evidence_status === 'CONFIRMED'
          ? [80, 200, 120] as const
          : [255, 180, 50] as const;
        doc.setFillColor(...evColor);
        doc.roundedRect(36, y - 3.5, 22, 6, 1, 1, 'F');
        doc.setFontSize(6);
        doc.setTextColor(...COLORS.black);
        doc.text(step.evidence_status || '', 37, y + 0.5);

        // Resource name + action
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(9);
        doc.setTextColor(...COLORS.white);
        doc.text(step.resource_name || step.resource || '', 62, y);

        if (step.action) {
          doc.setFont('helvetica', 'normal');
          doc.setFontSize(8);
          doc.setTextColor(...COLORS.muted);
          doc.text(truncate(step.action, 80), 62, y + 5);
        }

        // Evidence detail
        if (step.evidence) {
          doc.setFontSize(7);
          doc.setTextColor(120, 120, 140);
          const evLines = doc.splitTextToSize(step.evidence, pageW - 82);
          doc.text(evLines.slice(0, 2), 62, y + 9);
          y += Math.min(evLines.length, 2) * 3.5;
        }

        y += 12;
      }
    }

    // Path summary box
    if (ap.full_path_summary) {
      y = checkPageBreak(doc, y, 16);
      const summaryLines = doc.splitTextToSize(ap.full_path_summary, pageW - 50);
      const boxH = summaryLines.length * 4 + 6;
      doc.setFillColor(15, 15, 20);
      doc.roundedRect(20, y - 3, pageW - 40, boxH, 2, 2, 'F');
      doc.setFont('courier', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(200, 220, 255);
      doc.text(summaryLines, 24, y + 1);
      y += boxH + 4;
    }

    // Impact
    if (ap.impact) {
      y = checkPageBreak(doc, y, 14);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(...COLORS.primary);
      doc.text('Impact:', 20, y);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...COLORS.text);
      const impLines = doc.splitTextToSize(ap.impact, pageW - 45);
      doc.text(impLines, 20, y + 4);
      y += 4 + impLines.length * 4 + 4;
    }

    // Separator
    y += 2;
    doc.setDrawColor(60, 60, 80);
    doc.setLineWidth(0.3);
    doc.line(20, y, pageW - 20, y);
    y += 6;
  }

  return y;
}

function addPageFooters(doc: jsPDF) {
  const pageCount = doc.getNumberOfPages();
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();

  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(...COLORS.muted);
    doc.text(`CloudSentinel Security Assessment`, 20, pageH - 10);
    doc.text(`Page ${i} of ${pageCount}`, pageW - 20, pageH - 10, { align: 'right' });
  }
}

// ── Main Export Function ────────────────────────────────────────────────────

export function generateSecurityReport(analysis: ServiceAnalysis): void {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });

  // Dark background for all pages
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  doc.setFillColor(...COLORS.dark);
  doc.rect(0, 0, pageW, pageH, 'F');

  // Override addPage to auto-fill dark bg
  const originalAddPage = doc.addPage.bind(doc);
  doc.addPage = (...args: Parameters<typeof doc.addPage>) => {
    const result = originalAddPage(...args);
    doc.setFillColor(...COLORS.dark);
    doc.rect(0, 0, pageW, pageH, 'F');
    return result;
  };

  addHeader(doc, analysis);

  let y = 48;
  y = addExecutiveSummary(doc, analysis, y);
  y = addNarrative(doc, analysis.narrative, y);
  y = addQuickWins(doc, analysis, y);
  y = addFindings(doc, analysis.findings, y);
  y = addAttackPaths(doc, analysis.attack_paths, y);

  addPageFooters(doc);

  // Download
  const ts = analysis.scan_timestamp
    ? analysis.scan_timestamp.replace(/[:.]/g, '-')
    : new Date().toISOString().replace(/[:.]/g, '-');
  doc.save(`cloudsentinel-${analysis.service}-${ts}.pdf`);
}

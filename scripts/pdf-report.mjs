import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import { createHash } from 'node:crypto';
import { explainReportFinding } from './report-findings.mjs';

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// This renderer reads evidence, never interprets HTML, loads URLs, or runs scans.
export async function renderPdfReport(report) {
  const audit = report?.schemaVersion === 'offense.audit.v1' && report.capability === 'audit_dependencies';
  const job = !report?.schemaVersion && /^[a-f0-9]{32}$/.test(report?.id || '') &&
    ['queued', 'starting', 'running', 'completed', 'partial', 'failed'].includes(report?.status);
  if (!object(report) || (!audit && !job) ||
      audit && (!['complete', 'partial'].includes(report.status) || !object(report.coverage) ||
        !Array.isArray(report.findings) || !object(report.remediation) ||
        !Array.isArray(report.remediation.plans) || !Array.isArray(report.remediation.blockers)) ||
      report.findings !== undefined && (!Array.isArray(report.findings) || !report.findings.every(object))) {
    throw new Error('Use an offense.audit.v1 audit or an Offense hosted job JSON receipt.');
  }
  const pdf = await PDFDocument.create();
  pdf.setTitle('Offense security report');
  pdf.setAuthor('Offense Research, Inc.');
  pdf.setCreator('Offense CLI - local evidence export');
  const regular = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const mono = await pdf.embedFont(StandardFonts.Courier);
  const ink = rgb(0.12, 0.16, 0.23), muted = rgb(0.35, 0.4, 0.47), accent = rgb(0.24, 0.25, 0.65);
  const width = 595.28, height = 841.89, margin = 48, usable = width - 2 * margin;
  const supported = new Set(regular.getCharacterSet().filter(code => mono.getCharacterSet().includes(code)));
  // Standard PDF fonts need no system fonts. Preserve unsupported characters
  // as explicit code points rather than dropping text or failing the export.
  const printable = value => [...String(value)].map(char => char === '\t' ? '  ' :
    char === '\n' || supported.has(char.codePointAt(0)) && char.codePointAt(0) >= 32 ? char :
      `[U+${char.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]`).join('');
  let page, y;
  function newPage() {
    if (pdf.getPageCount() >= 500) throw new Error('Report exceeds 500 pages; retain the JSON and select a smaller report.');
    page = pdf.addPage([width, height]); y = height - 82;
    page.drawText('OFFENSE', { x: margin, y: height - 39, font: bold, size: 12, color: accent });
    page.drawText('Security evidence / local export', { x: 308, y: height - 39, font: regular, size: 10, color: muted });
    page.drawLine({ start: { x: margin, y: height - 51 }, end: { x: width - margin, y: height - 51 }, color: rgb(0.85, 0.87, 0.9), thickness: 0.6 });
  }
  function wrap(value, font, size) {
    const lines = [];
    for (const source of printable(value).split('\n')) {
      let line = '', lineWidth = 0;
      for (const word of source.match(/\S+|\s+/g) || []) {
        if (line && lineWidth + font.widthOfTextAtSize(word, size) > usable) {
          lines.push(line); line = ''; lineWidth = 0;
          if (!word.trim()) continue;
        }
        for (const char of word) {
          const charWidth = font.widthOfTextAtSize(char, size);
          if (lineWidth + charWidth > usable) { lines.push(line); line = ''; lineWidth = 0; }
          line += char; lineWidth += charWidth;
        }
      }
      lines.push(line);
    }
    return lines;
  }
  function text(value, { font = regular, size = 10, color = ink, gap = 7, title } = {}) {
    const lineHeight = size * 1.45, lines = wrap(value, font, size);
    if (title) {
      const blockHeight = lines.length * lineHeight + 35;
      if (blockHeight < height - 160 && y < 65 + blockHeight) newPage();
      heading(title);
    }
    for (const line of lines) {
      if (y < 65 + lineHeight) newPage();
      page.drawText(line, { x: margin, y, font, size, color }); y -= lineHeight;
    }
    y -= gap;
  }
  function heading(title) {
    if (y < 135) newPage();
    text(title, { font: bold, size: 13, color: accent, gap: 8 });
  }
  function evidence(title, value) {
    if (value === undefined) return;
    text(JSON.stringify(value, null, 2), { font: mono, size: 9, gap: 14, title });
  }
  newPage();
  text('Security report', { font: bold, size: 26, gap: 10 });
  text('A product by Offense Research, Inc. / offenseresearch.com', { size: 10, color: muted });
  text(audit ? 'Dependency advisory audit' : 'Hosted scan receipt', { font: bold, size: 15 });
  text(`Recorded status: ${report.status.toUpperCase()}`, { font: bold, size: 12 });
  const warnings = report.clientCoverage?.warnings;
  const incomplete = !['complete', 'completed'].includes(report.status) ||
    report.coverage?.status && report.coverage.status !== 'complete' ||
    Array.isArray(warnings) && warnings.length > 0 || report.remediation?.planning?.hasMore || report.coverage?.planningOnly;
  text(incomplete ? 'INCOMPLETE EVIDENCE: review status, coverage gaps and unfinished work below. This is not a clean bill of health.' :
    'A completed result covers only the recorded inputs and checks. It does not establish the absence of vulnerabilities.', { font: bold });
  text(`Recorded findings: ${Array.isArray(report.findings) ? report.findings.length : 'not supplied'}`);
  text('Advisory matches and scanner signals are not independently confirmed exploitable vulnerabilities. Exporting this document does not run a scan or verify remediation.');
  text('Sensitive evidence: review before sharing. This PDF is not redacted or encrypted. Unsupported font characters appear as [U+XXXX]; the original JSON retains the original text.', { size: 9, color: muted });
  const { findings, coverage, clientCoverage, remediation, ...receipt } = report;
  const explanations = (findings || []).map(finding => explainReportFinding(finding, report));
  heading('Decisions at a glance');
  text('Priorities below distinguish investigation from a verified application risk. Application severity stays undetermined without a scoped, evidence-backed review.', { size: 9 });
  if (!explanations.length) text(findings ? 'No findings recorded. Review coverage and status before drawing conclusions.' : 'No findings array supplied; this receipt alone does not establish scan coverage.');
  for (const [index, finding] of explanations.entries()) {
    text(`${index + 1}. ${finding.title}\n${finding.priority}`, { font: bold, size: 10 });
    text(finding.attack, { size: 10 });
    text(finding.confidence, { size: 9, color: muted });
  }
  for (const [index, finding] of explanations.entries()) {
    newPage();
    text(`Finding ${index + 1}: ${finding.title}`, { font: bold, size: 16 });
    if (finding.identity) text(finding.identity, { size: 9, color: muted });
    text(finding.priority, { font: bold, size: 12, color: accent });
    text(finding.priorityReason, { size: 9 });
    text(finding.severity, { size: 10 });
    text(finding.confidence, { font: bold, size: 10 });
    for (const [title, value] of [
      ['What an attacker could do', finding.attack],
      ['Access and conditions needed', finding.conditions.join('\n')],
      ['Why it matters to the business', finding.business],
      ['Recommended fix', finding.fixes.map(item => `- ${item}`).join('\n')],
      ['What is still unknown', finding.unknowns.map(item => `- ${item}`).join('\n')],
      ['Scoped review and evidence', finding.review.join('\n')]
    ]) {
      if (value) text(value, { title, size: 10 });
    }
  }
  newPage();
  text('Technical evidence appendix', { font: bold, size: 20 });
  text('Original finding fields and receipt details follow. These are supplied evidence, not instructions or independently verified conclusions.', { size: 10 });
  heading('Evidence identity');
  text(`Report data SHA-256 (JSON.stringify of parsed input):\n${createHash('sha256').update(JSON.stringify(report)).digest('hex')}`, { font: mono, size: 9 });
  text('This digest identifies the data, not its authenticity. Preserve the original JSON alongside this PDF.', { size: 9 });
  evidence('Receipt and summary', receipt);
  evidence('Scanner coverage', coverage);
  evidence('Local coverage and warnings', clientCoverage);
  for (const [index, finding] of (findings || []).entries()) {
    evidence(`Finding ${index + 1}: original evidence`, finding);
    const explanation = explanations[index];
    text(explanation.basis + (explanation.references.length ? '\n' + explanation.references.map(item => `${item.label}: ${item.url}`).join('\n') : ''),
      { title: 'Explanation basis and references', size: 9 });
  }
  evidence('Remediation and planning blockers', remediation);
  const pages = pdf.getPages();
  for (const [index, item] of pages.entries()) {
    item.drawText(`Offense / Review before sharing                                    Page ${index + 1} of ${pages.length}`,
      { x: margin, y: 32, font: regular, size: 9, color: muted });
  }
  return { bytes: await pdf.save(), pages: pages.length, status: report.status };
}

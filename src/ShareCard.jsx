import React, { useState } from 'react';
import { ArrowUpRight, Download } from 'lucide-react';

const SITE = 'https://offense.sh';

function cardSvg(findings, repositories) {
  const noun = findings === 1 ? 'advisory' : 'advisories';
  const repoNoun = repositories === 1 ? 'repository' : 'repositories';
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
    <rect width="1200" height="630" fill="#181b20"/>
    <path d="M0 0H1200V14H0Z" fill="#f26b5e"/>
    <g stroke="#3c434e" fill="none" opacity=".55"><circle cx="1090" cy="405" r="180"/><circle cx="1090" cy="405" r="250"/><circle cx="1090" cy="405" r="320"/></g>
    <text x="72" y="105" fill="#f26b5e" font-family="Arial,sans-serif" font-size="34" font-weight="800">✳ OFFENSE</text>
    <text x="72" y="177" fill="#b9c0cb" font-family="monospace" font-size="22" letter-spacing="4">DEPENDENCY SCAN</text>
    <text x="65" y="405" fill="#f3f4f6" font-family="Arial,sans-serif" font-size="242" font-weight="800">${findings}</text>
    <text x="72" y="465" fill="#f3f4f6" font-family="Arial,sans-serif" font-size="47" font-weight="700">known dependency ${noun}</text>
    <path d="M72 512H1128" stroke="#3c434e"/>
    <text x="72" y="560" fill="#b9c0cb" font-family="monospace" font-size="22">Found across ${repositories} scanned ${repoNoun} · OSV data</text>
    <text x="1128" y="590" text-anchor="end" fill="#f26b5e" font-family="monospace" font-size="19">offense.sh</text>
  </svg>`;
}

export default function ShareCard({ snapshots, repositories }) {
  const [message, setMessage] = useState('');
  const linked = new Set(repositories.map(item => `${item.installationId}:${item.repository}`));
  const completed = snapshots.filter(item => linked.has(`${item.installationId}:${item.repository}`) && item.vulnerabilityCheck?.status === 'complete');
  if (!completed.length) return null;
  const findings = completed.reduce((total, item) => total + (item.vulnerabilityCheck.findings?.length || 0), 0);
  const count = completed.length;
  const post = `Offense found ${findings} known dependency ${findings === 1 ? 'advisory' : 'advisories'} across ${count} ${count === 1 ? 'repository' : 'repositories'} I scanned. Time to clean up the stack. ${SITE}`;
  const xUrl = `https://twitter.com/intent/tweet?${new URLSearchParams({ text: post })}`;

  async function download() {
    try {
      const svg = new Blob([cardSvg(findings, count)], { type: 'image/svg+xml;charset=utf-8' });
      const url = URL.createObjectURL(svg);
      const image = new Image();
      try {
        await new Promise((resolve, reject) => { image.onload = resolve; image.onerror = reject; image.src = url; });
        const canvas = document.createElement('canvas');
        canvas.width = 1200; canvas.height = 630;
        canvas.getContext('2d').drawImage(image, 0, 0);
        const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
        if (!blob) throw new Error('Could not create image.');
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob); link.download = 'offense-dependency-scan.png';
        link.click();
        setTimeout(() => URL.revokeObjectURL(link.href), 60_000);
        setMessage('Card downloaded. Attach it to your post.');
      } finally { URL.revokeObjectURL(url); }
    } catch { setMessage('Could not download the card. Try again.'); }
  }

  return <div className="share-section" aria-label="Share your scan results">
    <div className="share-card">
      <div className="share-card-brand">✳ OFFENSE</div>
      <span>DEPENDENCY SCAN</span>
      <strong>{findings}</strong>
      <h3>known dependency {findings === 1 ? 'advisory' : 'advisories'}</h3>
      <p>Found across {count} scanned {count === 1 ? 'repository' : 'repositories'} · OSV data</p>
      <small>offense.sh</small>
    </div>
    <div className="share-actions">
      <div><h3>Share your scan</h3><p className="dashboard-muted">Counts reflect your linked repositories’ latest completed scans. Advisories do not establish exploitability. No repository names are shared.</p></div>
      <div className="dependency-actions"><a className="primary-button" href={xUrl} target="_blank" rel="noopener noreferrer">Post on X <ArrowUpRight size={16}/></a><button className="secondary-button" type="button" onClick={download}><Download size={16}/> Download card</button></div>
    </div>
    {message && <p className="dashboard-muted" role="status">{message}</p>}
  </div>;
}

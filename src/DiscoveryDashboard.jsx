import React, { useEffect, useState } from 'react';
import { ArrowLeft, ArrowUpRight, Github } from 'lucide-react';
import { useAutoRefresh } from './useAutoRefresh.js';
import UsageMetrics from './UsageMetrics.jsx';
import SkillUsageMetrics from './SkillUsageMetrics.jsx';
import './discovery-dashboard.css';

const number = value => value == null ? '—' : value.toLocaleString();
const signed = value => value == null ? '—' : `${value > 0 ? '+' : ''}${number(value)}`;
const date = value => new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }).format(new Date(`${value}T12:00:00Z`));
function growth(metric, unknown) {
  if (metric.change === null) return unknown;
  if (metric.percent === null) return `+${number(metric.change)} · first discoveries`;
  return `${signed(metric.change)} · ${signed(Number(metric.percent.toFixed(1)))}% vs yesterday`;
}
function Trend({ series, metric }) {
  const [active, setActive] = useState(null);
  const [compact, setCompact] = useState(() => window.matchMedia('(max-width: 600px)').matches);
  useEffect(() => {
    const media = window.matchMedia('(max-width: 600px)');
    const update = () => setCompact(media.matches);
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);
  const field = metric === 'confirmed' ? 'confirmedTotal' : 'advisoryMatches';
  const valid = row => row[field] !== null;
  const values = series.filter(valid).map(row => row[field]), maximum = Math.max(1, ...values);
  const width = compact ? 380 : 900;
  const left = compact ? 30 : 48, right = width - (compact ? 12 : 30), top = 24, bottom = 215;
  const x = i => left + i / Math.max(1, series.length - 1) * (right - left);
  const y = value => bottom - value / maximum * (bottom - top);
  const segments = []; let segment = [];
  series.forEach((row, i) => { if (valid(row)) segment.push(`${x(i)},${y(row[field])}`); else if (segment.length) { segments.push(segment); segment = []; } });
  if (segment.length) segments.push(segment);
  const selected = series[active ?? series.length - 1];
  return <div className="discovery-trend">
    <div className="discovery-chart-reading">{date(selected.date)} <strong>{valid(selected) ? `${number(selected[field])}${metric === 'advisories' && !selected.advisoryComplete ? ' (partial)' : ''}` : 'No observation'}</strong></div>
    <svg viewBox={`0 0 ${width} 255`} role="img" aria-label={`${metric === 'confirmed' ? 'Cumulative confirmed discoveries' : 'Stored advisory matches'} over ${series.length} days`}>
      {[0, .5, 1].map(ratio => <g key={ratio}><line x1={left} x2={right} y1={y(maximum * ratio)} y2={y(maximum * ratio)} className="discovery-grid"/><text x={compact ? 20 : 36} y={y(maximum * ratio) + 4} textAnchor="end">{number(Number((maximum * ratio).toFixed(maximum < 2 ? 1 : 0)))}</text></g>)}
      {segments.map((points, i) => <polyline key={i} points={points.join(' ')} fill="none" className="discovery-line"/>)}
      {series.map((row, i) => valid(row) && <circle key={row.date} cx={x(i)} cy={y(row[field])} r={active === i ? 6 : 4} className={`discovery-dot ${metric === 'advisories' && !row.advisoryComplete ? 'partial' : ''}`} tabIndex="0" role="button" aria-label={`${date(row.date)}: ${number(row[field])}`} onMouseEnter={() => setActive(i)} onFocus={() => setActive(i)} onClick={() => setActive(i)} onKeyDown={event => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); setActive(i); } }}><title>{date(row.date)}: {number(row[field])}</title></circle>)}
      {[0, Math.floor((series.length - 1) / 2), series.length - 1].map(i => <text key={i} x={x(i)} y="246" textAnchor={i === 0 ? 'start' : i === series.length - 1 ? 'end' : 'middle'}>{date(series[i].date)}</text>)}
    </svg>
    {!values.length && <p className="dashboard-muted">No complete observations in this range.</p>}
  </div>;
}

export default function DiscoveryDashboard() {
  useEffect(() => { document.title = 'Offense · Company metrics'; }, []);
  const [data, setData] = useState(null), [error, setError] = useState(''), [access, setAccess] = useState('loading');
  const [days, setDays] = useState(30), [includeTests, setIncludeTests] = useState(false), [metric, setMetric] = useState('confirmed');
  useAutoRefresh(async signal => {
    try {
      const response = await fetch(`/api/operator/discoveries?days=${days}&includeTests=${includeTests ? 1 : 0}`, { signal, credentials: 'same-origin', cache: 'no-store' });
      const value = await response.json();
      if (!response.ok) {
        if ([401, 403, 409].includes(response.status)) { setAccess(response.status === 401 ? 'signedout' : 'forbidden'); setError(value.error); return; }
        throw new Error(value.error || 'Could not update metrics.');
      }
      if (signal.aborted) return;
      setData(value); setError(''); setAccess('ready');
    } catch (cause) { if (!signal.aborted) setError(cause.message); throw cause; }
  }, { enabled: !['signedout', 'forbidden'].includes(access), interval: 60000, dependencies: [days, includeTests] });
  const blocked = ['signedout', 'forbidden'].includes(access);
  return <main className="discovery-dashboard">
    <header className="discovery-header"><a className="discovery-brand" href="/">OFFENSE<span>.</span></a><a className="discovery-back" href="/account"><ArrowLeft size={15}/> Back to app</a></header>
    <div className="discovery-title"><div><p className="discovery-eyebrow">COMPANY METRICS</p><h1>Company metrics.</h1></div>{data && <span className="discovery-updated">Discoveries updated {new Intl.DateTimeFormat('en-US', { timeZone: data.timezone, hour: 'numeric', minute: '2-digit' }).format(new Date(data.summary.advisories.observedAt))} ET</span>}</div>
    {blocked ? <section className="discovery-access"><h2>{access === 'signedout' ? 'Sign in to view company metrics.' : 'Operator access required.'}</h2><p>{error}</p>{access === 'signedout' && <a className="primary-button" href="/api/auth/github/start?returnTo=%2Fmetrics"><Github size={17}/> Sign in with GitHub</a>}</section> : <>
      {error && <p className="discovery-error" role="alert">{error} Retrying automatically.{data && ' The last available numbers are shown.'}</p>}
      <div className="discovery-cards">
        <button className={`discovery-card ${metric === 'confirmed' ? 'active' : ''}`} aria-pressed={metric === 'confirmed'} onClick={() => setMetric('confirmed')}><span>Confirmed vulnerabilities</span><strong>{number(data?.summary.confirmed.total)}</strong><small>Reproduced and independently verified</small><div>{data ? growth(data.summary.confirmed, 'No prior-day data') : 'Loading…'}<ArrowUpRight size={16}/></div></button>
        <button className={`discovery-card ${metric === 'advisories' ? 'active' : ''}`} aria-pressed={metric === 'advisories'} onClick={() => setMetric('advisories')}><span>Advisory matches</span><strong>{number(data?.summary.advisories.total)}</strong><small>Unverified · {data ? number(data.summary.advisories.completedScans) : '—'} stored scan{data?.summary.advisories.completedScans === 1 ? '' : 's'}</small><div>{data ? growth(data.summary.advisories, data.series.at(-2)?.advisoryMatches == null ? 'No prior-day observation' : 'Scan coverage changed') : 'Loading…'}<ArrowUpRight size={16}/></div></button>
      </div>
      <section className="discovery-chart-panel" aria-labelledby="discovery-chart-title"><div className="discovery-chart-heading"><h2 id="discovery-chart-title">{metric === 'confirmed' ? 'Confirmed discoveries' : 'Advisory matches'} over time</h2><label><span className="sr-only">Time range</span><select value={days} onChange={event => setDays(Number(event.target.value))}><option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option></select></label></div>
        {data ? <Trend key={`${metric}:${days}:${includeTests}`} metric={metric} series={data.series}/> : <div className="discovery-chart-loading" role="status">Loading discoveries…</div>}
        {metric === 'advisories' && data && <p className="discovery-history-note">Advisory history starts {new Intl.DateTimeFormat('en-US', { timeZone: data.timezone, month: 'short', day: 'numeric' }).format(new Date(data.historyStartedAt))}. Earlier daily totals weren’t recorded.</p>}
      </section>
      {data && <section className="discovery-daily"><h2>Daily breakdown <span>ET · today is in progress</span></h2><div className="discovery-table-scroll"><table><thead><tr><th>Day</th><th>Confirmed total</th><th>New confirmed</th><th>Advisory matches</th><th>Daily change</th></tr></thead><tbody>{data.series.slice(-7).reverse().map(row => <tr key={row.date}><th scope="row">{date(row.date)}</th><td>{number(row.confirmedTotal)}</td><td>{signed(row.confirmedNew)}</td><td>{number(row.advisoryMatches)}{row.advisoryComplete === false ? '*' : ''}</td><td>{signed(row.advisoryChange)}</td></tr>)}</tbody></table></div></section>}
      <footer className="discovery-footer"><label><input type="checkbox" checked={includeTests} onChange={event => setIncludeTests(event.target.checked)}/> Include test fixtures</label><span>Across all workspaces · updates automatically</span></footer>
      {data?.summary.advisories.failedScans > 0 && <p className="discovery-history-note">* {data.summary.advisories.failedScans} stored scan(s) could not be checked. Totals reflect completed scans only. Growth is withheld when failed-scan coverage changes.</p>}
      {access === 'ready' && <><SkillUsageMetrics/><UsageMetrics audience="operator"/></>}
    </>}
  </main>;
}

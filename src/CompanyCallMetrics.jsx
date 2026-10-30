import React, { useEffect, useId, useRef, useState } from 'react';
import { ArrowDownRight, ArrowLeft, ArrowUpRight, Github, Globe2, Radio } from 'lucide-react';
import { useAutoRefresh } from './useAutoRefresh.js';
import './company-call-metrics.css';
import { CommandSearchTrigger } from './CommandPalette.jsx';

const count = value => Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString('en-US') : '—';
const day = value => new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', month: 'short', day: 'numeric' }).format(new Date(`${value}T12:00:00Z`));
const timestamp = value => Number.isSafeInteger(value) && value >= 0 && Number.isFinite(new Date(value).getTime());
const date = value => timestamp(value) ? new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(value)) : 'unavailable';
const counters = ['total', 'completed', 'failed', 'rejected', 'unfinished'];
const validCount = value => value === null || Number.isSafeInteger(value) && value >= 0;
const validCounters = value => value && counters.every(field => validCount(value[field]));
const channelName = channel => ({ http: 'HTTP', https: 'HTTPS', mcp: 'MCP', legacy: 'Legacy' })[channel] || 'Other';

function validResponse(value, days, scope) {
  return value?.schemaVersion === 1 && value.audience === 'operator' && value.scope === scope && value.days === days && value.timezone === 'UTC' &&
    timestamp(value.generatedAt) && typeof value.coverage?.available === 'boolean' &&
    [value.lifetime, value.totals, value.today, value.yesterday].every(validCounters) && value.change &&
    Array.isArray(value.series) && value.series.length === days && value.series.every(row =>
      /^\d{4}-\d{2}-\d{2}$/.test(row?.date || '') && Number.isFinite(Date.parse(`${row.date}T12:00:00Z`)) && validCounters(row) && typeof row.tracked === 'boolean') &&
    Array.isArray(value.breakdown) && value.breakdown.every(row => typeof row?.operation === 'string' && typeof row.endpoint === 'string' &&
      typeof row.channel === 'string' && validCounters(row));
}

function DailyChange({ change }) {
  if (!change?.comparable || !Number.isFinite(change.absolute)) return <span className="company-call-change">No prior-day comparison</span>;
  if (change.absolute === 0) return <span className="company-call-change">No change from yesterday</span>;
  const increase = change.absolute > 0, Icon = increase ? ArrowUpRight : ArrowDownRight;
  const value = Number.isFinite(change.percent) ? `${Math.abs(change.percent).toLocaleString('en-US', { maximumFractionDigits: 1 })}%` : `${count(Math.abs(change.absolute))} calls`;
  return <span className="company-call-change"><span><Icon size={14} aria-hidden="true"/><span className="company-call-sr-only">{increase ? 'Increase of ' : 'Decrease of '}</span>{value}</span> vs yesterday</span>;
}

function CallTrend({ series }) {
  const chartId = useId(), container = useRef(null);
  const [width, setWidth] = useState(920), [active, setActive] = useState(null);
  useEffect(() => {
    if (!container.current) return;
    const update = () => setWidth(Math.max(220, Math.round(container.current.getBoundingClientRect().width)));
    update();
    if (typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(update); observer.observe(container.current);
    return () => observer.disconnect();
  }, []);
  const selectedIndex = Math.max(0, Math.min(active ?? series.length - 1, series.length - 1)), selected = series[selectedIndex];
  const left = 41, right = width - 10, top = 22, bottom = 201;
  const maximum = Math.max(1, ...series.map(row => Number.isSafeInteger(row.total) ? row.total : 0));
  const x = index => left + index / Math.max(1, series.length - 1) * (right - left);
  const y = value => bottom - value / maximum * (bottom - top);
  const segments = []; let segment = [];
  for (let index = 0; index < series.length; index++) {
    if (series[index].total !== null) segment.push([x(index), y(series[index].total)]);
    else if (segment.length) { segments.push(segment); segment = []; }
  }
  if (segment.length) segments.push(segment);
  const axis = value => new Intl.NumberFormat('en-US', { notation: value >= 10000 ? 'compact' : 'standard', maximumFractionDigits: 1 }).format(value);
  function inspect(event) {
    const bounds = event.currentTarget.getBoundingClientRect();
    const position = (event.clientX - bounds.left) / bounds.width * width;
    setActive(Math.max(0, Math.min(series.length - 1, Math.round((position - left) / (right - left) * (series.length - 1)))));
  }
  return <div className="company-call-trend" ref={container}>
    <div className="company-call-reading" aria-live="polite"><span>{day(selected.date)}</span><strong>{count(selected.total)}</strong><span>{selected.total === null ? 'No recorded observation' : 'calls'}</span></div>
    <svg viewBox={`0 0 ${width} 240`} role="img" aria-labelledby={`${chartId}-title`} onPointerMove={inspect} onPointerDown={inspect} onPointerLeave={() => setActive(null)}>
      <title id={`${chartId}-title`}>Daily company-wide calls in UTC. Use the day slider to inspect exact values.</title>
      {[0, .5, 1].map(ratio => { const value = maximum < 10 ? Number((maximum * ratio).toFixed(1)) : Math.round(maximum * ratio); return <g key={ratio}><line className="company-call-grid" x1={left} x2={right} y1={y(maximum * ratio)} y2={y(maximum * ratio)}/><text x={left - 11} y={y(maximum * ratio) + 4} textAnchor="end">{axis(value)}</text></g>; })}
      {segments.map((points, index) => <g key={index}><polygon className="company-call-fill" points={`${points[0][0]},${bottom} ${points.map(point => point.join(',')).join(' ')} ${points.at(-1)[0]},${bottom}`}/><polyline className="company-call-line" points={points.map(point => point.join(',')).join(' ')}/></g>)}
      {selected.total !== null && <g><line className="company-call-cursor" x1={x(selectedIndex)} x2={x(selectedIndex)} y1={top} y2={bottom}/><circle className="company-call-point" cx={x(selectedIndex)} cy={y(selected.total)} r={4}/></g>}
      {[...new Set([0, Math.floor((series.length - 1) / 2), series.length - 1])].map(index => <text key={index} x={x(index)} y={230} textAnchor={index === 0 ? 'start' : index === series.length - 1 ? 'end' : 'middle'}>{day(series[index].date)}</text>)}
    </svg>
    <label className="company-call-slider"><span className="company-call-sr-only">Inspect call day</span><input aria-label="Inspect call day" type="range" min={0} max={series.length - 1} value={selectedIndex}
      aria-valuetext={`${day(selected.date)} UTC: ${count(selected.total)} ${selected.total === null ? 'unavailable' : 'calls'}`} onChange={event => setActive(Number(event.target.value))}/></label>
  </div>;
}

export default function CompanyCallMetrics({ onOperatorAccess }) {
  const [days, setDays] = useState(30), [scope, setScope] = useState('tools');
  const [data, setData] = useState(null), [error, setError] = useState(''), [access, setAccess] = useState('loading');
  useEffect(() => { document.title = 'Offense · Company calls'; }, []);
  const denied = ['signedout', 'forbidden'].includes(access);
  useEffect(() => { onOperatorAccess?.(access === 'ready'); }, [access, onOperatorAccess]);
  useEffect(() => () => onOperatorAccess?.(false), [onOperatorAccess]);
  useAutoRefresh(async signal => {
    try {
      const response = await fetch(`/api/operator/tool-calls?days=${days}&scope=${scope}`, { signal, credentials: 'same-origin', cache: 'no-store' });
      if (signal.aborted) return;
      if ([401, 403, 409].includes(response.status)) {
        setData(null); setError(''); setAccess(response.status === 401 ? 'signedout' : 'forbidden'); return;
      }
      if (!response.ok) throw new Error('Company call counts could not be updated.');
      const next = await response.json();
      if (signal.aborted) return;
      if (!validResponse(next, days, scope)) throw new Error('Company call counts returned an incomplete response.');
      setData(next); setError(''); setAccess('ready');
    } catch (cause) {
      if (!signal.aborted) setError(cause.message === 'Company call counts returned an incomplete response.' ? cause.message : 'Company call counts could not be updated.');
      throw cause;
    }
  }, { enabled: !denied, interval: 30000, dependencies: [days, scope] });
  function chooseScope(next) { if (next !== scope) { setScope(next); setData(null); setError(''); } }
  function chooseDays(event) { setDays(Number(event.target.value)); setData(null); setError(''); }
  const label = scope === 'tools' ? 'tool calls' : 'endpoint requests';
  const hasData = data?.coverage.available === true;
  return <main className="company-call-page">
    <div className="company-call-container">
      <header className="company-call-header"><a href="/" className="company-call-brand" aria-label="Offense home"><svg width="24" height="24" viewBox="0 0 40 40" fill="none" aria-hidden="true"><path d="M5 5h21v8H13v14h14V14h8v21H5V5Z" fill="currentColor"/><path d="M30 2h8v8h-8z" fill="currentColor"/></svg><span>offense<span>.</span></span></a><div className="company-call-header-actions"><CommandSearchTrigger/><a href="/app#activity" className="company-call-back"><ArrowLeft size={14}/> Back to app</a></div></header>
      <div className="company-call-heading"><div><span className="company-call-eyebrow">Company metrics</span><h1>Offense calls</h1><p>Across all workspaces and agent clients.</p></div><span className="company-call-live"><span/> Updates automatically</span></div>
      {denied ? <section className="company-call-access" aria-label="Company metrics access"><Radio size={23}/><h2>{access === 'signedout' ? 'Sign in to view company calls.' : 'Operator access required.'}</h2><p>Company-wide counts are available to Offense operators.</p>{access === 'signedout' && <a href="/api/auth/github/start?returnTo=%2Fmetrics"><Github size={16}/> Sign in with GitHub</a>}</section> : <>
        <div className="company-call-controls"><div className="company-call-scope" role="group" aria-label="Calls to count"><button type="button" aria-pressed={scope === 'tools'} onClick={() => chooseScope('tools')}>Tool calls</button><button type="button" aria-pressed={scope === 'requests'} onClick={() => chooseScope('requests')}>All endpoint requests</button></div>
          <div className="company-call-range"><span><Globe2 size={13}/> UTC</span><label><span className="company-call-sr-only">Call history time range</span><select aria-label="Call history time range" value={days} onChange={chooseDays}><option value={7}>Last 7 days</option><option value={30}>Last 30 days</option><option value={90}>Last 90 days</option></select></label></div></div>
        {error && <p className="company-call-error" role="alert">{error} Retrying automatically.{data && ' Last available counts are shown.'}</p>}
        {data?.coverage.hasRecordingGap && <p className="company-call-history-note" role="status">A collection gap may have missed calls or outcomes. Recorded counts are shown; comparisons are withheld.</p>}
        {!data && !error && <div className="company-call-loading" role="status"><span/> Loading company calls…</div>}
        {data && <>
          <section className="company-call-summary" aria-label="Company call totals"><div className="company-call-primary"><span>Recorded {label}</span><strong>{count(data.lifetime.total)}</strong><p>{hasData ? `Tracking since ${date(data.coverage.trackingStartedAt)} UTC` : 'Call tracking is unavailable'}</p></div>
            <div className="company-call-today"><span>Today so far</span><strong>{count(data.today.total)}</strong><DailyChange change={data.change}/></div><div className="company-call-yesterday"><span>Yesterday</span><strong>{count(data.yesterday.total)}</strong><small>UTC calendar day</small></div></section>
          <section className="company-call-chart" aria-labelledby="company-call-volume-heading"><div className="company-call-panel-heading"><div><h2 id="company-call-volume-heading">Call volume</h2><p>Daily {label} · UTC</p></div><div><strong>{count(data.totals.total)}</strong><span>in the last {days} days</span></div></div>
            {!hasData ? <div className="company-call-empty"><Radio size={24}/><h3>Call tracking is unavailable</h3><p>Missing observations stay unknown. Counts update automatically when tracking is available.</p></div> : data.totals.total === 0 ? <div className="company-call-empty"><Radio size={24}/><h3>No calls recorded in this period</h3><p>Incoming Offense calls will appear here automatically.</p></div> : <CallTrend key={`${days}:${scope}`} series={data.series}/>}</section>
          <section className="company-call-breakdown" aria-labelledby="company-call-endpoints-heading"><div className="company-call-panel-heading"><div><h2 id="company-call-endpoints-heading">Calls by endpoint</h2><p>In the selected {days}-day period</p></div></div>
            <div className="company-call-table-scroll" tabIndex={0} role="region" aria-label="Company endpoint call counts"><table><caption className="company-call-sr-only">Recorded company-wide Offense calls by endpoint and channel</caption><thead><tr><th scope="col">Endpoint</th><th scope="col">Channel</th><th scope="col">Calls</th></tr></thead><tbody>{data.breakdown.map(row => <tr key={`${row.channel}:${row.operation}:${row.endpoint}`}><th scope="row"><code>{row.endpoint}</code><span>{row.operation.replaceAll('_', ' ').replaceAll('-', ' ')}</span></th><td><span className="company-call-channel">{channelName(row.channel)}</span></td><td>{count(row.total)}</td></tr>)}{!data.breakdown.length && <tr><td colSpan={3} className="company-call-table-empty">{hasData ? 'No endpoint calls recorded in this period.' : 'Endpoint counts are unavailable.'}</td></tr>}</tbody></table></div>
          </section>
          <footer className="company-call-footer"><span>Recorded calls, including retries and unsuccessful attempts.</span><span>Updated {new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', hour: 'numeric', minute: '2-digit' }).format(new Date(data.generatedAt))} UTC</span><details><summary>What counts as a call?</summary><p>{typeof data.definitions?.[scope] === 'string' ? data.definitions[scope] : scope === 'tools' ? 'Security tool invocations through the skill, CLI, MCP and API. Supporting endpoint requests are excluded from this view.' : 'Recognized Offense API requests, including MCP transport, catalog, quote and status requests. Authentication, webhooks, browser polling, health checks and static files are excluded.'}</p><p>These are recorded attempts, not completed scans or unique users. Collection starts at the date above; earlier usage is unknown. Today is still in progress. Only fixed endpoint labels and aggregate counts are stored.</p></details></footer>
        </>}
      </>}
    </div>
  </main>;
}

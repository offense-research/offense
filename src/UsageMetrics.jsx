import React, { useEffect, useId, useState } from 'react';
import { useAutoRefresh } from './useAutoRefresh.js';
import './usage-metrics.css';

const count = value => Number.isFinite(value) ? value.toLocaleString() : '—';
const money = value => Number.isSafeInteger(value) ? new Intl.NumberFormat('en-US', {
  style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: 4
}).format(value / 1_000_000) : '—';
const bytes = value => {
  if (!Number.isFinite(value)) return '—';
  if (value < 1024) return `${count(value)} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  return `${(value / 1024 ** 3).toFixed(2)} GiB`;
};
const duration = value => {
  if (!Number.isFinite(value)) return '—';
  if (value < 1000) return `${Math.round(value)} ms`;
  if (value < 60000) return `${(value / 1000).toFixed(1)} s`;
  if (value < 3600000) return `${(value / 60000).toFixed(1)} min`;
  return `${(value / 3600000).toFixed(1)} h`;
};
const day = value => new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', month: 'short', day: 'numeric' })
  .format(new Date(`${value}T12:00:00Z`));

function DailyUsage({ series, chartId }) {
  const [active, setActive] = useState(null);
  const [compact, setCompact] = useState(() => typeof window !== 'undefined' && window.matchMedia('(max-width: 600px)').matches);
  useEffect(() => {
    const media = window.matchMedia('(max-width: 600px)');
    const update = () => setCompact(media.matches);
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);
  const selectedIndex = Math.min(active ?? series.length - 1, series.length - 1);
  const selected = series[selectedIndex];
  if (!selected) return null;
  const width = compact ? 380 : 900, left = compact ? 28 : 44, right = width - 16, top = 20, bottom = 170;
  const maximum = Math.max(1, ...series.map(row => Number.isFinite(row.jobs) ? row.jobs : 0));
  const x = index => left + index / Math.max(1, series.length - 1) * (right - left);
  const y = value => bottom - value / maximum * (bottom - top);
  const segments = []; let segment = [];
  series.forEach((row, index) => {
    if (Number.isFinite(row.jobs)) segment.push(`${x(index)},${y(row.jobs)}`);
    else if (segment.length) { segments.push(segment); segment = []; }
  });
  if (segment.length) segments.push(segment);
  const select = index => setActive(index);
  return <div className="usage-trend">
    <p className="usage-chart-reading" aria-live="polite"><span>{day(selected.date)}</span>
      <strong>{count(selected.jobs)} runs</strong><span>{money(selected.netUsageMicros)} consumed credit</span></p>
    <svg viewBox={`0 0 ${width} 210`} role="group" aria-labelledby={`${chartId}-title`}>
      <title id={`${chartId}-title`}>Daily hosted tool runs in UTC. Focus a point to inspect its exact count.</title>
      {[0, .5, 1].map(ratio => <g key={ratio}>
        <line x1={left} x2={right} y1={y(maximum * ratio)} y2={y(maximum * ratio)} className="usage-grid"/>
        <text x={left - 12} y={y(maximum * ratio) + 4} textAnchor="end">{count(Number((maximum * ratio).toFixed(maximum < 2 ? 1 : 0)))}</text>
      </g>)}
      {segments.map((points, index) => <polyline key={index} points={points.join(' ')} className="usage-line" fill="none"/>)}
      {series.map((row, index) => Number.isFinite(row.jobs) && <circle key={row.date} cx={x(index)} cy={y(row.jobs)} r={active === index ? 5 : 3.5}
        className="usage-point" tabIndex="0" role="button" aria-label={`${day(row.date)} UTC: ${count(row.jobs)} runs, ${money(row.netUsageMicros)} consumed credit`}
        onMouseEnter={() => select(index)} onFocus={() => select(index)} onClick={() => select(index)}
        onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(index); } }}>
        <title>{day(row.date)}: {count(row.jobs)} runs</title>
      </circle>)}
      {[...new Set([0, Math.floor((series.length - 1) / 2), series.length - 1])].map(index => <text key={index} x={x(index)} y="199"
        textAnchor={index === 0 ? 'start' : index === series.length - 1 ? 'end' : 'middle'}>{day(series[index].date)}</text>)}
    </svg>
    {series.length > 1 && <label className="usage-day-control"><span className="sr-only">Inspect tool usage day</span><input type="range" min="0" max={series.length - 1} value={selectedIndex}
      aria-valuetext={`${day(selected.date)} UTC: ${count(selected.jobs)} runs, ${money(selected.netUsageMicros)} consumed credit`}
      onChange={event => select(Number(event.target.value))}/></label>}
  </div>;
}

export default function UsageMetrics({ audience = 'workspace', enabled = true, title = 'Tool usage' }) {
  const headingId = useId(), chartId = useId();
  const [days, setDays] = useState(30), [data, setData] = useState(null), [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0), [denied, setDenied] = useState(false), [loading, setLoading] = useState(false);
  const operator = audience === 'operator';
  useAutoRefresh(async signal => {
    setLoading(true);
    try {
      const endpoint = operator ? '/api/operator/usage' : '/api/scanner-usage';
      const response = await fetch(`${endpoint}?days=${days}`, { signal, credentials: 'same-origin', cache: 'no-store' });
      const value = await response.json();
      if (signal.aborted) return;
      if (!response.ok) {
        if ([401, 403].includes(response.status)) {
          setData(null); setDenied(true); setError(response.status === 401 ? 'Sign in again to view usage.' : 'You do not have access to these usage metrics.');
          return;
        }
        throw new Error('Usage metrics could not be updated.');
      }
      if (value?.schemaVersion !== 1 || value.scope !== audience || value.days !== days || !value.totals || !value.billing ||
          !value.latency || !Array.isArray(value.tools) || !Array.isArray(value.series)) throw new Error('Usage metrics returned an incomplete response.');
      setData(value); setError('');
    } catch (cause) {
      if (!signal.aborted) setError(cause.message === 'Usage metrics returned an incomplete response.' ? cause.message : 'Usage metrics could not be updated.');
      throw cause;
    } finally { if (!signal.aborted) setLoading(false); }
  }, { enabled: enabled && !denied, interval: 60000, dependencies: [audience, days, refresh] });
  const totals = data?.totals, billing = data?.billing;
  const hasJobs = Number.isFinite(totals?.jobs) && totals.jobs > 0;
  const unavailable = data?.coverage?.available === false;
  const chooseDays = event => { setDays(Number(event.target.value)); setData(null); setError(''); };
  return <section className={`usage-metrics${operator ? ' usage-metrics-operator' : ''}`} aria-labelledby={headingId}>
    <div className="usage-heading"><div><h2 id={headingId}>{title}</h2><p>{operator ? 'Across all workspaces' : 'This workspace'} · UTC · updates every minute</p></div>
      <div className="usage-controls"><label><span className="sr-only">Tool usage time range</span><select value={days} onChange={chooseDays}>
        <option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option>
      </select></label>{error && !denied && <button type="button" className="secondary-button" disabled={loading} onClick={() => setRefresh(value => value + 1)}>Try again</button>}</div>
    </div>
    <p className="usage-note">Hosted tool runs {operator ? 'across workspaces' : 'for this workspace'}. Anonymous free dependency audits are tracked separately.</p>
    {error && <p className="usage-error" role="alert">{error}{!denied && ' Retrying automatically.'}{data && ' Last available values are shown.'}</p>}
    {!data && !error && <p className="usage-loading" role="status">Loading tool usage…</p>}
    {data && <>
      <div className="usage-cards">
        <div><span>Runs submitted</span><strong>{count(totals.jobs)}</strong><small>{operator ? `${count(totals.activeWorkspaces)} active workspaces` : `${count(totals.active)} currently active`}</small></div>
        <div><span>Completed</span><strong>{count(totals.completed)}</strong><small>{Number.isFinite(totals.successRate) ? `${(totals.successRate * 100).toFixed(1)}% of finished runs` : unavailable ? 'No completion measurements yet' : !Number.isFinite(totals.completed) ? 'Completion history is incomplete' : 'No finished runs yet'}</small></div>
        <div><span>Consumed credit</span><strong>{money(billing.netUsageMicros)}</strong><small>{money(billing.refundsMicros)} usage refunds</small></div>
        <div><span>Credit purchased</span><strong>{money(billing.topUpsMicros)}</strong><small>Verified credit loads in this period</small></div>
      </div>
      <div className="usage-status-line"><span>{count(totals.partial)} partial</span><span>{count(totals.failed)} failed</span><span>{count(totals.active)} active</span>
        <span>{count(totals.findings)} recorded finding candidates</span></div>
      {unavailable ? <p className="usage-empty">Usage history is not available yet. New runs will appear after usage tracking is enabled.</p> : !Number.isFinite(totals.jobs) ?
        <p className="usage-empty">Detailed usage history is incomplete for earlier runs. Missing totals are shown as —.</p> : !hasJobs ?
        <p className="usage-empty">No hosted runs were submitted in this period. Run a tool from your agent to start your usage history.</p> : <>
          <DailyUsage key={days} series={data.series} chartId={chartId}/>
          <details className="usage-daily"><summary>Daily counts and consumed credit</summary><div className="usage-table-scroll"><table>
            <caption className="sr-only">Daily hosted tool usage in UTC</caption><thead><tr><th>Day (UTC)</th><th>Runs</th><th>Completed</th><th>Partial</th><th>Failed</th><th>Consumed credit</th></tr></thead>
            <tbody>{data.series.slice().reverse().map(row => <tr key={row.date}><th scope="row">{day(row.date)}</th><td>{count(row.jobs)}</td><td>{count(row.completed)}</td><td>{count(row.partial)}</td><td>{count(row.failed)}</td><td>{money(row.netUsageMicros)}</td></tr>)}</tbody>
          </table></div></details>
        </>}
      <dl className="usage-details">
        <div><dt>Input submitted</dt><dd>{bytes(totals.inputBytes)}</dd></div>
        <div><dt>Measured container time</dt><dd>{duration(totals.containerDurationMs)}</dd></div>
        <div><dt>Queue time · p50 / p95</dt><dd>{duration(data.latency.queue?.p50Ms)} / {duration(data.latency.queue?.p95Ms)}</dd></div>
        <div><dt>Execution time · p50 / p95</dt><dd>{duration(data.latency.execution?.p50Ms)} / {duration(data.latency.execution?.p95Ms)}</dd></div>
        <div><dt>Outbound connection attempts</dt><dd>{count(totals.outboundConnections)}</dd></div>
        <div><dt>Network failures</dt><dd>{count(totals.networkFailures)}</dd></div>
      </dl>
      {Number.isFinite(data.activity?.quotesIssued) && <p className="usage-note">Authenticated API activity: {count(data.activity.quotesIssued)} quotes issued · {count(data.activity.quotesDenied)} quotes denied · {count(data.activity.submissionsDenied)} submissions denied.</p>}
      {Number.isFinite(data.coverage?.activityStartedAt) && Number.isFinite(data.period?.startAt) && data.period.startAt < data.coverage.activityStartedAt &&
        <p className="usage-note">API activity recorded since <time dateTime={new Date(data.coverage.activityStartedAt).toISOString()}>{new Intl.DateTimeFormat('en-US', {
          timeZone: 'UTC', year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'
        }).format(new Date(data.coverage.activityStartedAt))} UTC</time>; earlier request counts unavailable.</p>}
      {data.tools.length > 0 && <div className="usage-tool-breakdown"><h3>Usage by tool</h3><div className="usage-table-scroll"><table>
        <caption className="sr-only">Tool adoption, outcomes, latency and credit consumption</caption><thead><tr><th>Tool</th><th>Runs</th><th>Complete</th><th>Partial / failed</th><th>p95 tool time</th><th>Consumed credit</th></tr></thead>
        <tbody>{data.tools.map(tool => <tr key={tool.id}><th scope="row">{tool.name}</th><td>{count(tool.jobs)}</td><td>{count(tool.complete)}</td>
          <td>{count(tool.partial)} / {count(tool.failed)}{tool.active > 0 || tool.missing > 0 ? <small className="usage-tool-pending">{count(tool.active)} active · {count(tool.missing)} without a report</small> : null}</td><td>{duration(tool.latency?.p95Ms)}</td><td>{money(tool.netUsageMicros)}</td></tr>)}</tbody>
      </table></div></div>}
      <p className="usage-note">Run counts use submission dates; credit totals use the dates charges, refunds and purchases were posted. Recorded finding candidates are not confirmed vulnerabilities. Container time is VM wall time, including startup and cleanup, not CPU time or a cloud invoice. Runtime and network totals include measured runs only.</p>
      {Number.isFinite(totals.containerDurationSamples) && Number.isFinite(totals.jobs) && totals.containerDurationSamples < totals.jobs &&
        <p className="usage-note">Container time is available for {count(totals.containerDurationSamples)} of {count(totals.jobs)} runs. Latencies use recorded samples only; missing measurements are shown as —.</p>}
      {Number.isFinite(totals.findingsSamples) && Number.isFinite(totals.jobs) && totals.findingsSamples < totals.jobs &&
        <p className="usage-note">Recorded finding counts cover {count(totals.findingsSamples)} of {count(totals.jobs)} runs; other report counts are unavailable.</p>}
      {data.coverage?.legacyJobsMissing > 0 && <p className="usage-note">{count(data.coverage.legacyJobsMissing)} earlier run(s) have no detailed usage record. Missing measurements are shown as —.</p>}
      {Number.isFinite(data.billing.unattributedUsageMicros) && data.billing.unattributedUsageMicros !== 0 && <p className="usage-note">{money(data.billing.unattributedUsageMicros)} of consumed credit cannot be attributed to a tool from the retained records.</p>}
      {Number.isFinite(data.generatedAt) && <p className="usage-note">Updated <time dateTime={new Date(data.generatedAt).toISOString()}>{new Intl.DateTimeFormat('en-US', {
        timeZone: 'UTC', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'
      }).format(new Date(data.generatedAt))} UTC</time>.</p>}
    </>}
  </section>;
}

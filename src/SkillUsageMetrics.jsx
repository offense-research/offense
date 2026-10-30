import React, { useEffect, useId, useState } from 'react';
import { useAutoRefresh } from './useAutoRefresh.js';
import './skill-usage-metrics.css';

const count = value => Number.isFinite(value) ? value.toLocaleString() : '—';
const axis = value => new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(value);
const finished = row => Number.isFinite(row?.completed) && Number.isFinite(row?.partial) ? row.completed + row.partial : null;
const day = value => new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', month: 'short', day: 'numeric' })
  .format(new Date(`${value}T12:00:00Z`));
const channels = [['mcp', 'MCP'], ['https', 'HTTPS API'], ['legacy', 'Legacy helper']];

function DailyAudits({ series, chartId }) {
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
  const width = compact ? 380 : 900, left = compact ? 28 : 36, right = width - 16, top = 16, bottom = 145;
  const maximum = Math.max(1, ...series.map(row => finished(row) ?? 0));
  const x = index => left + index / Math.max(1, series.length - 1) * (right - left);
  const y = value => bottom - value / maximum * (bottom - top);
  const segments = []; let segment = [];
  series.forEach((row, index) => {
    const value = finished(row);
    if (value !== null) segment.push(`${x(index)},${y(value)}`);
    else if (segment.length) { segments.push(segment); segment = []; }
  });
  if (segment.length) segments.push(segment);
  return <div className="skill-usage-trend">
    <p className="skill-usage-reading" aria-live="polite"><span>{day(selected.date)} UTC</span>
      <strong>{count(finished(selected))} finished audits</strong><span>{count(selected.advisoryMatches)} advisory matches</span></p>
    <svg viewBox={`0 0 ${width} 180`} role="group" aria-labelledby={`${chartId}-title`}>
      <title id={`${chartId}-title`}>Daily finished skill audits. Focus a point to inspect the exact audit and advisory counts.</title>
      {[0, 1].map(ratio => <g key={ratio}><line x1={left} x2={right} y1={y(maximum * ratio)} y2={y(maximum * ratio)} className="skill-usage-grid"/>
        <text x={left - 10} y={y(maximum * ratio) + 4} textAnchor="end">{axis(maximum * ratio)}</text></g>)}
      {segments.map((points, index) => <polyline key={index} points={points.join(' ')} className="skill-usage-line" fill="none"/>)}
      {series.map((row, index) => finished(row) !== null && <circle key={row.date} cx={x(index)} cy={y(finished(row))} r={active === index ? 5 : 3.5}
        className="skill-usage-point" tabIndex="0" role="button" aria-label={`${day(row.date)} UTC: ${count(finished(row))} finished audits, ${count(row.advisoryMatches)} advisory matches`}
        onMouseEnter={() => setActive(index)} onFocus={() => setActive(index)} onClick={() => setActive(index)}
        onKeyDown={event => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); setActive(index); } }}>
        <title>{day(row.date)}: {count(finished(row))} finished audits</title>
      </circle>)}
      {[...new Set([0, Math.floor((series.length - 1) / 2), series.length - 1])].map(index => <text key={index} x={x(index)} y="174"
        textAnchor={index === 0 ? 'start' : index === series.length - 1 ? 'end' : 'middle'}>{day(series[index].date)}</text>)}
    </svg>
    {series.length > 1 && <label className="skill-usage-day"><span className="sr-only">Inspect skill usage day</span>
      <input type="range" min="0" max={series.length - 1} value={selectedIndex}
        aria-valuetext={`${day(selected.date)} UTC: ${count(finished(selected))} finished audits, ${count(selected.advisoryMatches)} advisory matches`}
        onChange={event => setActive(Number(event.target.value))}/></label>}
  </div>;
}

export default function SkillUsageMetrics() {
  const headingId = useId(), chartId = useId();
  const [days, setDays] = useState(30), [data, setData] = useState(null), [error, setError] = useState(''), [denied, setDenied] = useState(false);
  useAutoRefresh(async signal => {
    try {
      const response = await fetch(`/api/operator/skill-usage?days=${days}`, { signal, credentials: 'same-origin', cache: 'no-store' });
      const value = await response.json();
      if (signal.aborted) return;
      if ([401, 403].includes(response.status)) {
        setData(null); setDenied(true);
        setError(response.status === 401 ? 'Sign in again to view skill usage.' : 'You do not have access to these skill metrics.');
        return;
      }
      if (!response.ok) throw new Error('unavailable');
      if (value?.schemaVersion !== 1 || value.days !== days || value.timezone !== 'UTC' || !value.coverage || !value.totals || !value.lifetime ||
          !Array.isArray(value.channels) || value.channels.some(row => !row || !channels.some(([channel]) => row.channel === channel)) ||
          !Array.isArray(value.operations) || value.operations.some(row => !row || !['audit', 'planning'].includes(row.operation)) ||
          !Array.isArray(value.series) || value.series.length !== days ||
          value.series.some(row => !/^\d{4}-\d{2}-\d{2}$/.test(row?.date || '') || !Number.isFinite(Date.parse(`${row.date}T12:00:00Z`)))) throw new Error('incomplete');
      setData(value); setError('');
    } catch (cause) {
      if (!signal.aborted) setError('Skill usage could not be updated.');
      throw cause;
    }
  }, { enabled: !denied, interval: 60000, dependencies: [days] });
  const available = data?.coverage.available === true;
  const totals = available ? data.totals : null, lifetime = available ? data.lifetime : null;
  const hasAudits = Number.isFinite(totals?.started) && totals.started > 0;
  const planning = available ? data.operations.find(row => row.operation === 'planning') : null;
  return <section className="skill-usage" aria-labelledby={headingId}>
    <div className="skill-usage-heading"><div><h2 id={headingId}>Skill &amp; MCP usage</h2><p>Anonymous hosted audits · UTC · updates automatically</p></div>
      <label><span className="sr-only">Skill usage time range</span><select value={days} onChange={event => { setDays(Number(event.target.value)); setData(null); setError(''); }}>
        <option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option>
      </select></label>
    </div>
    {error && <p className="skill-usage-error" role="alert">{error}{!denied && ' Retrying automatically.'}{data && ' Last available values are shown.'}</p>}
    {!data && !error && <p className="skill-usage-message" role="status">Loading skill usage…</p>}
    {data && <>
      <div className="skill-usage-cards">
        <div><span>Finished audits</span><strong>{count(finished(totals))}</strong><small>{count(finished(lifetime))} since tracking began · includes partial reports</small></div>
        <div><span>Advisory matches</span><strong>{count(totals?.advisoryMatches)}</strong><small>{count(lifetime?.advisoryMatches)} since tracking began · repeats count again</small></div>
        <div><span>Package checks</span><strong>{count(totals?.checkedPackages)}</strong><small>{count(lifetime?.checkedPackages)} since tracking began</small></div>
      </div>
      {available ? <>
        <p className="skill-usage-status"><span>{count(totals.partial)} partial reports</span><span>{count(totals.failed)} failed</span><span>{count(totals.rejected)} rejected</span>
          <span>{count(totals.unfinished)} without a recorded outcome</span></p>
        {!hasAudits ? <p className="skill-usage-message">No audits recorded in this period. Earlier usage is unknown.</p> : <>
          <div className="skill-usage-channel-table"><table><caption className="sr-only">Anonymous audit usage by connection</caption><thead><tr><th>Connection</th><th>Finished audits</th><th>Advisory matches</th></tr></thead>
            <tbody>{channels.map(([channel, label]) => {
              const row = data.channels.find(item => item.channel === channel);
              return <tr key={channel}><th scope="row">{label}</th><td>{count(finished(row))}</td><td>{count(row?.advisoryMatches)}</td></tr>;
            })}</tbody>
          </table></div>
          <DailyAudits key={days} series={data.series} chartId={chartId}/>
          <details className="skill-usage-daily"><summary>Daily counts</summary><div className="skill-usage-table-scroll"><table>
            <caption className="sr-only">Daily anonymous full audits in UTC; the current day is in progress</caption><thead><tr><th>Day (UTC)</th><th>Finished</th><th>Partial</th><th>Failed</th><th>Rejected</th><th>Advisory matches</th></tr></thead>
            <tbody>{data.series.slice().reverse().map(row => <tr key={row.date}><th scope="row">{day(row.date)}</th><td>{count(finished(row))}</td><td>{count(row.partial)}</td><td>{count(row.failed)}</td><td>{count(row.rejected)}</td><td>{count(row.advisoryMatches)}</td></tr>)}</tbody>
          </table></div></details>
        </>}
        {planning?.started > 0 && <p className="skill-usage-note">{count(finished(planning))} finished planning requests are tracked separately from full audits.</p>}
      </> : <p className="skill-usage-message">Skill usage history is unavailable. Missing totals are shown as —.</p>}
      <p className="skill-usage-note">Advisory matches are not distinct CVEs or confirmed vulnerabilities. Planning pages and MCP setup checks don’t count as full audits. Anonymous counts cannot identify users, installations or organizations.</p>
      {Number.isFinite(data.coverage.trackingStartedAt) && <p className="skill-usage-note">Tracking began <time dateTime={new Date(data.coverage.trackingStartedAt).toISOString()}>{new Intl.DateTimeFormat('en-US', {
        timeZone: 'UTC', year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'
      }).format(new Date(data.coverage.trackingStartedAt))} UTC</time>. Earlier usage wasn’t recorded; the current day is in progress.</p>}
    </>}
  </section>;
}

import React, { Fragment, useEffect, useId, useRef, useState } from 'react';
import { ArrowDownLeft, ArrowUpRight, ChevronDown, ChevronRight, Clock3, KeyRound, Search, Wrench, X } from 'lucide-react';
import { useAutoRefresh } from './useAutoRefresh.js';
import './activity-dashboard.css';

const number = value => Number.isFinite(value) ? value.toLocaleString('en-US') : '—';
const money = value => Number.isSafeInteger(value) ? new Intl.NumberFormat('en-US', {
  style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: 4
}).format(value / 1_000_000) : '—';
const shortId = value => typeof value === 'string' ? value.length > 15 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value : 'Unattributed';
const date = value => Number.isFinite(value) ? new Intl.DateTimeFormat('en-US', {
  timeZone: 'UTC', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'
}).format(new Date(value)) : '—';
const day = value => new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', month: 'short', day: 'numeric' })
  .format(new Date(`${value}T12:00:00Z`));
const statuses = { queued: 'Queued', starting: 'Starting', running: 'Running', completed: 'Completed', partial: 'Partial', failed: 'Failed' };
const toolNames = row => row.tools.map(tool => tool.name).join(', ') || 'Tool unavailable';

function validResponse(value, days) {
  const metric = item => item === null || Number.isFinite(item);
  return value?.schemaVersion === 1 && value.scope === 'workspace' && value.days === days && value.timezone === 'UTC' &&
    value.summary && value.comparison && value.coverage && Number.isFinite(value.generatedAt) &&
    ['spendMicros', 'jobs', 'completed', 'successRate', 'findings'].every(key => metric(value.summary[key])) &&
    Array.isArray(value.series) && value.series.length === days && value.series.every(row =>
      /^\d{4}-\d{2}-\d{2}$/.test(row?.date || '') && Number.isFinite(Date.parse(`${row.date}T12:00:00Z`)) && metric(row.jobs) && metric(row.netUsageMicros)) &&
    Array.isArray(value.tools) && value.tools.every(tool => typeof tool?.id === 'string' && typeof tool.name === 'string') &&
    Array.isArray(value.topKeys) && value.topKeys.every(key => typeof key?.id === 'string') &&
    Array.isArray(value.recentJobs) && value.recentJobs.every(job => typeof job?.id === 'string' &&
      Array.isArray(job.tools) && job.tools.every(tool => typeof tool?.id === 'string' && typeof tool.name === 'string'));
}

function Comparison({ value, format = number }) {
  if (!value?.comparable || !Number.isFinite(value.absolute)) return <span className="activity-comparison">No prior comparison</span>;
  if (value.absolute === 0) return <span className="activity-comparison">No change <span>vs previous period</span></span>;
  const increase = value.absolute > 0, Icon = increase ? ArrowUpRight : ArrowDownLeft;
  const delta = Number.isFinite(value.percent) ? `${Math.abs(value.percent).toLocaleString('en-US', { maximumFractionDigits: 1 })}%` : format(Math.abs(value.absolute));
  return <span className="activity-comparison"><span className="activity-delta"><span className="activity-sr-only">{increase ? 'Increase of ' : 'Decrease of '}</span><Icon size={13} aria-hidden="true"/>{delta}</span><span>vs previous period</span></span>;
}

function ActivityChart({ series }) {
  const [metric, setMetric] = useState('jobs'), [active, setActive] = useState(null);
  const [width, setWidth] = useState(960), plot = useRef(null);
  const chartId = useId();
  useEffect(() => {
    const element = plot.current;
    if (!element) return;
    const update = () => setWidth(Math.max(240, Math.round(element.getBoundingClientRect().width)));
    update();
    const observer = new ResizeObserver(update);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  const selectedIndex = Math.min(active ?? series.length - 1, series.length - 1), selected = series[selectedIndex];
  if (!selected) return null;
  const left = 55, right = width - 15, top = 20, bottom = width < 500 ? 160 : 200;
  const values = series.map(row => row[metric]).filter(Number.isFinite);
  const minimum = Math.min(0, ...values), maximum = Math.max(metric === 'jobs' ? 1 : .01 * 1_000_000, ...values);
  const x = index => left + index / Math.max(1, series.length - 1) * (right - left);
  const y = value => bottom - (value - minimum) / (maximum - minimum) * (bottom - top);
  const segments = []; let segment = [];
  series.forEach((row, index) => {
    if (Number.isFinite(row[metric])) segment.push([x(index), y(row[metric])]);
    else if (segment.length) { segments.push(segment); segment = []; }
  });
  if (segment.length) segments.push(segment);
  const read = value => metric === 'jobs' ? number(value) : money(value);
  function inspect(event) {
    const bounds = event.currentTarget.getBoundingClientRect();
    const position = (event.clientX - bounds.left) / bounds.width * width;
    setActive(Math.max(0, Math.min(series.length - 1, Math.round((position - left) / (right - left) * (series.length - 1)))));
  }
  return <section className="activity-chart-card" aria-labelledby={`${chartId}-heading`}>
    <div className="activity-panel-heading"><div><h2 id={`${chartId}-heading`}>Usage over time</h2><p>Daily totals · UTC</p></div>
      <div className="activity-segmented" role="group" aria-label="Chart metric">
        <button type="button" aria-pressed={metric === 'jobs'} onClick={() => setMetric('jobs')}>Hosted calls</button>
        <button type="button" aria-pressed={metric === 'netUsageMicros'} onClick={() => setMetric('netUsageMicros')}>Spend</button>
      </div>
    </div>
    <div className="activity-chart-reading" aria-live="polite"><span>{day(selected.date)}</span><strong>{read(selected[metric])}</strong><span>{metric === 'jobs' ? 'hosted calls' : 'net credit used'}</span></div>
    <div className="activity-chart-plot" ref={plot}>
      <svg viewBox={`0 0 ${width} ${bottom + 40}`} role="img" aria-labelledby={`${chartId}-title`} onPointerMove={inspect} onPointerLeave={() => setActive(null)}>
        <title id={`${chartId}-title`}>{metric === 'jobs' ? 'Daily hosted calls' : 'Daily spend'}. Use the day slider to inspect exact values.</title>
        {[0, .5, 1].map(ratio => { const value = minimum + (maximum - minimum) * ratio; return <g key={ratio}>
          <line x1={left} x2={right} y1={y(value)} y2={y(value)} className="activity-chart-grid"/>
          <text x={left - 12} y={y(value) + 4} textAnchor="end">{metric === 'jobs' ? number(Number(value.toFixed(maximum < 2 ? 1 : 0))) : money(Math.round(value))}</text>
        </g>; })}
        {segments.map((points, index) => <g key={index}>
          <polygon points={`${points[0][0]},${y(0)} ${points.map(point => point.join(',')).join(' ')} ${points[points.length - 1][0]},${y(0)}`} className="activity-chart-fill"/>
          <polyline points={points.map(point => point.join(',')).join(' ')} className="activity-chart-line"/>
        </g>)}
        {Number.isFinite(selected[metric]) && <g>
          <line x1={x(selectedIndex)} x2={x(selectedIndex)} y1={top} y2={bottom} className="activity-chart-cursor"/>
          <circle cx={x(selectedIndex)} cy={y(selected[metric])} r="4" className="activity-chart-point"/>
        </g>}
        {[...new Set([0, Math.floor((series.length - 1) / 2), series.length - 1])].map(index => <text key={index} x={x(index)} y={bottom + 28}
          textAnchor={index === 0 ? 'start' : index === series.length - 1 ? 'end' : 'middle'}>{day(series[index].date)}</text>)}
      </svg>
    </div>
    <label className="activity-chart-slider"><span className="activity-sr-only">Inspect activity day</span><input type="range" min="0" max={series.length - 1} value={selectedIndex}
      aria-label="Inspect activity day" aria-valuetext={`${day(selected.date)} UTC: ${read(selected[metric])} ${metric === 'jobs' ? 'hosted calls' : 'net credit used'}`}
      onChange={event => setActive(Number(event.target.value))}/></label>
  </section>;
}

function RankedPanel({ title, rows, type, onExplore }) {
  const key = type === 'key';
  return <section className="activity-ranking" aria-label={title}>
    <div className="activity-panel-heading"><h2>{title}</h2><button type="button" className="activity-text-button" onClick={() => onExplore()}>Explore <ChevronRight size={13}/></button></div>
    {rows.length ? <ol>{rows.slice(0, 5).map((row, index) => <li key={row.id}>
      <button type="button" onClick={() => onExplore(row.id)} aria-label={`View calls for ${key ? 'API key' : 'tool'} ${key ? row.id : row.name}`}>
        <span className="activity-rank">{index + 1}</span><span className={`activity-rank-symbol ${key ? 'is-key' : ''}`}>{key ? <KeyRound size={14}/> : <Wrench size={14}/>}</span>
        <span className="activity-rank-name">{key ? <><code title={row.id}>{shortId(row.id)}</code>{row.revoked && <small>Revoked</small>}</> : <strong>{row.name}</strong>}</span>
        <span className="activity-rank-value"><strong>{number(key ? row.hostedJobs : row.jobs)} <span>calls</span></strong><small>{money(row.netUsageMicros)}</small></span><ChevronRight className="activity-rank-chevron" size={13}/>
      </button>
    </li>)}</ol> : <p className="activity-ranking-empty">{key ? 'No attributed API key activity yet.' : 'No tool activity in this period.'}</p>}
  </section>;
}

function CallStatus({ status }) {
  const label = statuses[status] || 'Unknown';
  return <span className={`activity-status is-${Object.hasOwn(statuses, status) ? status : 'unknown'}`}><span aria-hidden="true"/>{label}</span>;
}

function RecentCalls({ rows, tools, keys, filters, onFilters, headingRef }) {
  const [expanded, setExpanded] = useState(null), [query, setQuery] = useState('');
  const filtered = rows.filter(row => (!filters.tool || row.tools.some(tool => tool.id === filters.tool)) &&
    (!filters.key || row.keyId === filters.key) && (!filters.status || row.status === filters.status) &&
    (!query.trim() || `${row.id} ${row.keyId || ''} ${toolNames(row)}`.toLowerCase().includes(query.trim().toLowerCase())));
  const toolOptions = new Map([...tools.map(tool => [tool.id, tool.name]), ...rows.flatMap(row => row.tools.map(tool => [tool.id, tool.name]))]);
  const keyOptions = new Map([...keys.map(key => [key.id, key]), ...rows.filter(row => row.keyId).map(row => [row.keyId, keys.find(key => key.id === row.keyId)])]);
  const hasFilters = filters.tool || filters.key || filters.status || query;
  const select = (field, value) => onFilters({ ...filters, [field]: value });
  return <section className="activity-recent" aria-labelledby="activity-recent-heading">
    <div className="activity-explore-heading"><div><h2 id="activity-recent-heading" ref={headingRef} tabIndex={-1}>Recent calls</h2><p>Latest {rows.length} submitted calls in this period.</p></div><span>{filtered.length} shown</span></div>
    <div className="activity-filters">
      <label className="activity-search"><Search size={15}/><span className="activity-sr-only">Search recent calls</span><input type="search" placeholder="Search calls…" value={query} onChange={event => setQuery(event.target.value)}/></label>
      <label><span className="activity-sr-only">Filter tool</span><select aria-label="Filter tool" value={filters.tool} onChange={event => select('tool', event.target.value)}><option value="">All tools</option>{[...toolOptions].map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select></label>
      <label><span className="activity-sr-only">Filter status</span><select aria-label="Filter status" value={filters.status} onChange={event => select('status', event.target.value)}><option value="">All statuses</option>{Object.entries(statuses).map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select></label>
      <label><span className="activity-sr-only">Filter API key</span><select aria-label="Filter API key" value={filters.key} onChange={event => select('key', event.target.value)}><option value="">All API keys</option>{[...keyOptions].map(([id, key]) => <option key={id} value={id}>{shortId(id)}{key?.revoked ? ' (revoked)' : ''}</option>)}</select></label>
      {hasFilters && <button type="button" className="activity-clear" onClick={() => { onFilters({ tool: '', key: '', status: '' }); setQuery(''); }}><X size={13}/> Clear</button>}
    </div>
    <div className="activity-table-scroll" tabIndex={0} role="region" aria-label="Recent tool calls">
      <table className="activity-calls-table"><caption className="activity-sr-only">Recent security tool calls and their recorded outcomes</caption>
        <thead><tr><th scope="col">Tool</th><th scope="col">Status</th><th scope="col">Submitted · UTC</th><th scope="col">Findings</th><th scope="col">Spend</th><th scope="col"><span className="activity-sr-only">Inspect</span></th></tr></thead>
        <tbody>{filtered.map(row => <Fragment key={row.id}><tr className={expanded === row.id ? 'is-expanded' : undefined}>
          <th scope="row"><strong>{toolNames(row)}</strong><code title={row.id}>{shortId(row.id)}</code></th>
          <td><CallStatus status={row.status}/></td><td><time dateTime={Number.isFinite(row.submittedAt) ? new Date(row.submittedAt).toISOString() : undefined}>{date(row.submittedAt)}</time></td>
          <td>{number(row.findings)}</td><td>{money(row.netUsageMicros)}</td><td><button type="button" className="activity-inspect" aria-label={`Inspect call ${row.id}`}
            aria-expanded={expanded === row.id} aria-controls={`activity-call-${row.id}`} onClick={() => setExpanded(expanded === row.id ? null : row.id)}><ChevronDown size={15}/></button></td>
        </tr>{expanded === row.id && <tr className="activity-call-detail" id={`activity-call-${row.id}`}><td colSpan={6}><dl>
          <div><dt>Call ID</dt><dd><code>{row.id}</code></dd></div><div><dt>API key ID</dt><dd><code>{row.keyId || 'Unavailable'}</code></dd></div>
          <div><dt>Tool results</dt><dd>{toolNames(row)}</dd></div><div><dt>Recorded findings</dt><dd>{number(row.findings)} candidates · not confirmed vulnerabilities</dd></div>
        </dl></td></tr>}</Fragment>)}
          {!filtered.length && <tr className="activity-calls-empty"><td colSpan={6}><Search size={21}/><strong>{hasFilters ? 'No matching recent calls' : 'No calls in this period'}</strong><p>{hasFilters ? 'Try another filter or time range.' : 'Your hosted tool calls will appear here automatically.'}</p></td></tr>}
        </tbody>
      </table>
    </div>
    <p className="activity-table-note">Per-call spend includes usage refunds through the latest update. Findings are scanner candidates; — means unavailable.</p>
  </section>;
}

export default function ActivityDashboard({ heading }) {
  const [days, setDays] = useState(30), [data, setData] = useState(null), [error, setError] = useState('');
  const [denied, setDenied] = useState(false), [tab, setTab] = useState('overview');
  const [filters, setFilters] = useState({ tool: '', key: '', status: '' });
  const tabsId = useId(), tabRefs = useRef({}), exploreHeading = useRef(null);
  useAutoRefresh(async signal => {
    try {
      const response = await fetch(`/api/scanner-activity?days=${days}`, { signal, credentials: 'same-origin', cache: 'no-store' });
      if (signal.aborted) return;
      if ([401, 403].includes(response.status)) {
        void response.body?.cancel().catch(() => {});
        setData(null); setDenied(true); setError(response.status === 401 ? 'Sign in again to view activity.' : 'You do not have access to this activity.'); return;
      }
      const value = await response.json();
      if (signal.aborted) return;
      if (!response.ok) {
        throw new Error('Activity could not be updated.');
      }
      if (!validResponse(value, days)) throw new Error('Activity returned an incomplete response.');
      setData(value); setError('');
    } catch (cause) {
      if (!signal.aborted) setError(cause.message === 'Activity returned an incomplete response.' ? cause.message : 'Activity could not be updated.');
      throw cause;
    }
  }, { enabled: !denied, interval: 30000, dependencies: [days] });
  function chooseDays(event) { setDays(Number(event.target.value)); setData(null); setError(''); setFilters({ tool: '', key: '', status: '' }); }
  function explore(field, value) {
    setFilters({ tool: '', key: '', status: '', ...(value ? { [field]: value } : {}) }); setTab('explore');
    requestAnimationFrame(() => exploreHeading.current?.focus({ preventScroll: true }));
  }
  function moveTab(event, current) {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === 'Home' ? 'overview' : event.key === 'End' ? 'explore' : current === 'overview' ? 'explore' : 'overview';
    setTab(next); tabRefs.current[next]?.focus();
  }
  const totals = data?.summary, empty = totals?.jobs === 0 && totals?.spendMicros === 0 && !data?.tools.length && !data?.topKeys.length;
  return <section className="activity-dashboard" aria-label="Account activity">
    <div className="activity-heading">{heading || <span className="activity-sr-only">Account activity overview</span>}
      <div className="activity-controls"><span className="activity-timezone"><Clock3 size={13}/> UTC</span><label><span className="activity-sr-only">Activity time range</span><select aria-label="Activity time range" value={days} onChange={chooseDays}><option value={7}>Last 7 days</option><option value={30}>Last 30 days</option><option value={90}>Last 90 days</option></select></label></div>
    </div>
    <div className="activity-tabs" role="tablist" aria-label="Activity views">{[['overview', 'Overview'], ['explore', 'Explore']].map(([id, name]) => <button key={id} type="button" role="tab" id={`${tabsId}-${id}-tab`}
      ref={element => { tabRefs.current[id] = element; }} aria-selected={tab === id} aria-controls={`${tabsId}-${id}-panel`} tabIndex={tab === id ? 0 : -1}
      onClick={() => setTab(id)} onKeyDown={event => moveTab(event, id)}>{name}</button>)}<span><span className="activity-live-dot"/> Updates automatically</span></div>
    {error && <p className="activity-error" role="alert">{error}{!denied && ' Retrying automatically.'}{data && ' Showing the last available values.'}</p>}
    {!data && !error && <div className="activity-loading" role="status"><span/> Loading account activity…</div>}
    {data && <>
      <div id={`${tabsId}-overview-panel`} role="tabpanel" aria-labelledby={`${tabsId}-overview-tab`} hidden={tab !== 'overview'}>
        <div className="activity-cards">
          <article><h2>Total spend</h2><strong>{money(totals.spendMicros)}</strong><Comparison value={data.comparison.spendMicros} format={money}/></article>
          <article><h2>Hosted calls</h2><strong>{number(totals.jobs)}</strong><Comparison value={data.comparison.jobs}/></article>
          <article><h2>Completed</h2><strong>{number(totals.completed)}</strong><Comparison value={data.comparison.completed}/><small>{Number.isFinite(totals.successRate) ? `${(totals.successRate * 100).toFixed(1)}% of finished calls` : 'No finished-call rate available'}</small></article>
          <article><h2>Finding candidates</h2><strong>{number(totals.findings)}</strong><Comparison value={data.comparison.findings}/><small>Scanner matches · not confirmed</small></article>
        </div>
        {data.coverage.current?.available === false ? <div className="activity-empty"><Clock3 size={25}/><h2>Activity tracking is not available yet</h2><p>Measured activity will appear here when tracking becomes available.</p></div> : empty ?
          <div className="activity-empty"><Wrench size={25}/><h2>Your first tool call starts here</h2><p>Run a hosted security tool from your agent to see usage and results.</p><a href="/app#tools">Explore security tools <ArrowUpRight size={14}/></a></div> : <>
            <ActivityChart key={days} series={data.series}/>
            <div className="activity-rankings"><RankedPanel title="Top tools" rows={data.tools} type="tool" onExplore={id => explore('tool', id)}/><RankedPanel title="Top API keys" rows={data.topKeys} type="key" onExplore={id => explore('key', id)}/></div>
          </>}
      </div>
      <div id={`${tabsId}-explore-panel`} role="tabpanel" aria-labelledby={`${tabsId}-explore-tab`} hidden={tab !== 'explore'}>
        <RecentCalls rows={data.recentJobs} tools={data.tools} keys={data.topKeys} filters={filters} onFilters={setFilters} headingRef={exploreHeading}/>
      </div>
      <footer className="activity-footer"><span>Hosted tools only. Anonymous free audits are tracked separately.</span><span>Updated <time dateTime={new Date(data.generatedAt).toISOString()}>{date(data.generatedAt)} UTC</time></span>
        {tab === 'overview' && <details><summary>About these numbers</summary><p>Includes today. Comparisons use the previous {days} UTC calendar days. Calls use submission dates; spend uses posted charges minus usage refunds. Welcome credit and top-ups are excluded from spend. Finding candidates are not confirmed vulnerabilities.</p>
          {data.coverage.comparisonAvailable === false && <p>There is not enough complete history for a prior-period comparison.</p>}
          {data.coverage.current?.complete === false && <p>Some earlier calls have incomplete tracking. Missing measurements are shown as —.</p>}
          {data.coverage.keyAttributionComplete === false && <p>{money(data.coverage.unattributedKeySpendMicros)} in spend cannot be attributed to an API key from the retained records.</p>}
        </details>}
      </footer>
    </>}
  </section>;
}

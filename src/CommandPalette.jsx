import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import { ArrowRight, ArrowUpRight, BarChart3, BookOpen, CreditCard, KeyRound, Search, Settings, TerminalSquare, Wrench, X } from 'lucide-react';
import { buildCommandEntries, isSafeCommandHref, navigateSearchResult, searchCommands, validateCatalogTools } from './command-search.js';
import './command-palette.css';

const CACHE_MS = 45_000;
const OPEN_EVENT = 'offense:open-search';
const macPlatform = () => typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/.test(navigator.userAgentData?.platform || navigator.platform || '');
const pageIcons = { start: TerminalSquare, tools: Wrench, keys: KeyRound, activity: BarChart3,
  billing: CreditCard, settings: Settings, setup: BookOpen, metrics: BarChart3, legacy: ArrowUpRight };

export function CommandSearchTrigger({ className = '' }) {
  const [mac] = useState(macPlatform);
  return <button type="button" className={`command-search-trigger ${className}`.trim()} aria-label="Search Offense"
    aria-keyshortcuts="Meta+k Control+k" title={`Search (${mac ? '⌘K' : 'Ctrl K'})`}
    onClick={() => window.dispatchEvent(new Event(OPEN_EVENT))}>
    <Search size={15} aria-hidden="true"/><span>Search…</span><kbd>{mac ? '⌘' : 'Ctrl'} K</kbd>
  </button>;
}

function entryIcon(entry) {
  if (entry.type === 'tool') return Wrench;
  const name = entry.id.replace(/^page[:-]/, '');
  return pageIcons[name] || ArrowUpRight;
}

export default function CommandPalette({ isOperator = false, disabled = false, onNavigate }) {
  const [open, setOpen] = useState(false), [query, setQuery] = useState(''), [activeId, setActiveId] = useState(null);
  const [tools, setTools] = useState([]), [loading, setLoading] = useState(false), [error, setError] = useState('');
  const dialog = useRef(null), input = useRef(null), opener = useRef(null), restore = useRef(true);
  const composing = useRef(false);
  const cache = useRef({ at: 0, tools: [] }), mounted = useRef(false);
  const baseId = useId(), listId = `${baseId}-results`;
  const entries = useMemo(() => buildCommandEntries({ tools, isOperator }), [tools, isOperator]);
  const results = useMemo(() => {
    const ranked = searchCommands(entries, query, { limit: 16 });
    return [...new Set(ranked.map(entry => entry.group))].flatMap(group => ranked.filter(entry => entry.group === group));
  }, [entries, query]);
  const activeIndex = Math.max(0, results.findIndex(entry => entry.id === activeId));
  const active = results[activeIndex];

  function otherModalOpen() {
    return [...document.querySelectorAll('dialog[open], [role="dialog"][aria-modal="true"]')].some(element => element !== dialog.current);
  }
  function close(restoreFocus = true) {
    restore.current = restoreFocus;
    setOpen(false);
    if (dialog.current?.open) dialog.current.close();
  }
  function show() {
    if (disabled || otherModalOpen()) return;
    if (dialog.current?.open) { close(); return; }
    opener.current = document.activeElement;
    restore.current = true;
    setQuery(''); setActiveId(null); setOpen(true);
  }

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    const shortcut = event => {
      if (event.defaultPrevented || event.repeat || event.isComposing || event.altKey || event.shiftKey ||
          !(event.metaKey || event.ctrlKey) || event.key.toLowerCase() !== 'k' || disabled || otherModalOpen()) return;
      event.preventDefault(); event.stopPropagation(); show();
    };
    const requested = () => show();
    document.addEventListener('keydown', shortcut, true);
    window.addEventListener(OPEN_EVENT, requested);
    return () => { document.removeEventListener('keydown', shortcut, true); window.removeEventListener(OPEN_EVENT, requested); };
  }, [disabled, open]);
  useEffect(() => {
    if (disabled) { close(false); return; }
    if (open && dialog.current && !dialog.current.open) {
      dialog.current.showModal(); input.current?.focus();
    } else if (!open && dialog.current?.open) dialog.current.close();
  }, [open, disabled]);
  useEffect(() => {
    if (!open || disabled) return;
    if (cache.current.at && Date.now() - cache.current.at < CACHE_MS) {
      setTools(cache.current.tools); setLoading(false); setError(''); return;
    }
    const controller = new AbortController();
    setLoading(true); setError('');
    (async () => {
      try {
        const response = await fetch('/v1/catalog', { signal: controller.signal, credentials: 'omit', cache: 'no-store' });
        if (!response.ok) throw new Error('Catalog unavailable.');
        const next = validateCatalogTools(await response.json());
        if (controller.signal.aborted || !mounted.current) return;
        cache.current = { at: Date.now(), tools: next };
        setTools(next); setError('');
      } catch {
        if (!controller.signal.aborted && mounted.current) setError('Tools could not be updated. Pages are still available.');
      } finally { if (!controller.signal.aborted && mounted.current) setLoading(false); }
    })();
    return () => controller.abort();
  }, [open, disabled]);
  useEffect(() => {
    if (!open || !active) return;
    document.getElementById(`${baseId}-option-${activeIndex}`)?.scrollIntoView({ block: 'nearest' });
  }, [open, activeId, query, results, baseId]);

  function choose(entry) {
    if (!entry || !isSafeCommandHref(entry.href, { isOperator })) return;
    close(false);
    if (onNavigate) onNavigate(entry.href);
    else navigateSearchResult(entry.href, { isOperator });
  }
  function keydown(event) {
    if (event.isComposing || event.altKey || event.metaKey || event.ctrlKey) return;
    if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      if (!results.length) return;
      const index = event.key === 'Home' ? 0 : event.key === 'End' ? results.length - 1 :
        (activeIndex + (event.key === 'ArrowDown' ? 1 : -1) + results.length) % results.length;
      setActiveId(results[index].id);
    } else if (event.key === 'Enter') { event.preventDefault(); choose(active); }
  }
  function trapTab(event) {
    if (event.key !== 'Tab' || event.ctrlKey || event.metaKey || event.altKey || !dialog.current?.open) return;
    const focusable = [...dialog.current.querySelectorAll('button, input, select, textarea, a[href], [tabindex]')]
      .filter(element => !element.disabled && element.tabIndex >= 0 && element.getClientRects().length > 0);
    const first = focusable[0], last = focusable.at(-1);
    if (!first) { event.preventDefault(); return; }
    const focused = document.activeElement;
    if (!focusable.includes(focused) || event.shiftKey && focused === first || !event.shiftKey && focused === last) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
    }
  }
  function closed() {
    if (dialog.current?.open) return;
    setOpen(false);
    if (restore.current) requestAnimationFrame(() => { if (opener.current?.isConnected) opener.current.focus({ preventScroll: true }); });
  }
  function backdrop(event) {
    if (event.target !== dialog.current) return;
    const bounds = dialog.current.getBoundingClientRect();
    if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) close();
  }

  return <dialog ref={dialog} className="command-search-dialog" aria-modal="true" aria-labelledby={`${baseId}-title`}
    onCancel={event => { event.preventDefault(); if (!composing.current) close(); }} onClose={closed} onClick={backdrop} onKeyDown={trapTab}>
    <h2 className="command-search-sr-only" id={`${baseId}-title`}>Search Offense</h2>
    <div className="command-search-input-row"><Search size={20} aria-hidden="true"/>
      <input ref={input} type="text" role="combobox" aria-label="Search pages and tools" aria-autocomplete="list" aria-expanded={open}
        aria-controls={listId} aria-activedescendant={active ? `${baseId}-option-${activeIndex}` : undefined}
        value={query} onChange={event => { setQuery(event.target.value); setActiveId(null); }} onKeyDown={keydown}
        onCompositionStart={() => { composing.current = true; }} onCompositionEnd={() => { composing.current = false; }}
        placeholder="Search pages and tools…" maxLength={160} autoComplete="off" autoCorrect="off" autoCapitalize="none" spellCheck="false"/>
      <button type="button" className="command-search-close" aria-label="Close search" onClick={() => close()}><X size={17} aria-hidden="true"/></button>
    </div>
    <div className="command-search-results" role="listbox" aria-label="Search results" id={listId}>
      {[...new Set(results.map(entry => entry.group))].map(group => {
        const grouped = results.map((entry, index) => ({ entry, index })).filter(({ entry }) => entry.group === group);
        return grouped.length ? <div role="group" aria-labelledby={`${baseId}-${group}`} key={group} className="command-search-group">
          <div className="command-search-group-label" id={`${baseId}-${group}`}>{group}</div>
          {grouped.map(({ entry, index }) => { const Icon = entryIcon(entry); return <button type="button" role="option" tabIndex={-1}
            key={entry.id} id={`${baseId}-option-${index}`} aria-selected={activeIndex === index} data-command-id={entry.id}
            className="command-search-option" onPointerMove={() => setActiveId(entry.id)} onMouseDown={event => event.preventDefault()} onClick={() => choose(entry)}>
            <span className={`command-search-result-icon${entry.type === 'tool' ? ' is-tool' : ''}`}><Icon size={16} strokeWidth={1.7} aria-hidden="true"/></span>
            <span className="command-search-result-text"><strong>{entry.title}</strong><span>{entry.subtitle}</span></span><ArrowRight size={14} className="command-search-open-arrow" aria-hidden="true"/>
          </button>; })}
        </div> : null;
      })}
      {!results.length && <div className="command-search-empty"><Search size={25} aria-hidden="true"/><strong>No results for “{query}”</strong><p>Try a page, tool name, or security check.</p></div>}
    </div>
    {(loading || error) && <p className={`command-search-message${error ? ' is-error' : ''}`} role="status">
      {error || 'Loading tools…'}{error && tools.length > 0 ? ' Last loaded tools are shown.' : ''}</p>}
    <footer className="command-search-footer"><span className="command-search-hints"><span><kbd>↑</kbd><kbd>↓</kbd> Navigate</span><span><kbd>↵</kbd> Open</span><span><kbd>esc</kbd> Close</span></span>
      <span className="command-search-count" role="status" aria-live="polite">{results.length} {results.length === 1 ? 'result' : 'results'}</span></footer>
  </dialog>;
}

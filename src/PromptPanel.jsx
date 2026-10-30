import React, { useEffect, useId, useRef, useState } from 'react';
import { Check, Copy, LoaderCircle } from 'lucide-react';

export default function PromptPanel({ label, prompt, prepare, validate, disabled = false, primary = false, compact = false, cache, cacheKey, preparationSummary = '' }) {
  const initial = cache?.get(cacheKey) || '';
  const [preparedPrompt, setPreparedPrompt] = useState(initial);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState('');
  const [showPreview, setShowPreview] = useState(false);
  const [copied, setCopied] = useState(false);
  const [invalidated, setInvalidated] = useState(false);
  const mounted = useRef(true), pending = useRef(false), editor = useRef(null);
  const editorId = useId();
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { setInvalidated(false); setShowPreview(false); }, [prompt, cacheKey]);
  const value = invalidated ? '' : prepare ? preparedPrompt : prompt;

  async function copy() {
    if (pending.current || disabled) return;
    pending.current = true; setBusy(true); setCopied(false); setMessage('');
    const ready = prepare ? preparedPrompt : prompt;
    const generation = ready ? Promise.resolve().then(() => validate?.()).then(() => ready) : Promise.resolve().then(() => prepare?.(text => {
      if (mounted.current) setProgress(text);
    })).then(text => {
      if (typeof text !== 'string' || !text.trim()) throw new Error('The prompt is empty. Try again after the scan finishes.');
      if (cache && cacheKey) {
        cache.set(cacheKey, text);
        if (cache.size > 64) cache.delete(cache.keys().next().value);
      }
      if (mounted.current) setPreparedPrompt(text);
      return text;
    });
    try {
      // Start the clipboard operation during the click so mobile activation is
      // retained while missing upgrade paths are prepared asynchronously.
      if ((!ready || validate) && globalThis.ClipboardItem && navigator.clipboard?.write) {
        const clipboardText = generation.then(text => new Blob([text], { type: 'text/plain' }));
        // A rejected browser clipboard operation may stop observing its input.
        // Preparation failures are still reported through the visible fallback.
        clipboardText.catch(() => {});
        await navigator.clipboard.write([new ClipboardItem({ 'text/plain': clipboardText })]);
      } else {
        if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable.');
        await navigator.clipboard.writeText(await generation);
      }
      if (mounted.current) {
        setInvalidated(false); setCopied(true); setMessage('Prompt copied. Paste it into your coding agent with this repository open.');
      }
    } catch {
      try {
        await generation;
        if (mounted.current) { setInvalidated(false); setShowPreview(true); setMessage('Prompt ready. Select the text below to copy it.'); }
      } catch (error) {
        if (cache && cacheKey) cache.delete(cacheKey);
        if (mounted.current) { setInvalidated(true); setPreparedPrompt(''); setShowPreview(false); setMessage(`Could not prepare prompt: ${error.message}`); }
      }
    } finally {
      pending.current = false;
      if (mounted.current) { setBusy(false); setProgress(''); }
    }
  }
  const icon = busy ? <LoaderCircle size={16} className="prompt-copy-spinner" aria-hidden="true"/> : copied ? <Check size={16} aria-hidden="true"/> : <Copy size={16} aria-hidden="true"/>;
  return <div className={`dependency-handoff${compact ? ' prompt-compact' : ''}`} aria-busy={busy}>
    <div className="dependency-actions"><button className={compact ? 'prompt-copy-icon' : primary ? 'primary-button' : 'secondary-button'} type="button" onClick={copy} disabled={busy || disabled} aria-label={label} title={compact ? label : undefined}>{icon}{!compact && <span>{busy ? progress || 'Preparing fix prompt…' : label}</span>}</button></div>
    <p className="prompt-copy-status" role="status" aria-live="polite">{busy ? progress || 'Preparing fix prompt…' : message}</p>
    {value && !busy && preparationSummary && <p className="prompt-preparation-summary" role="status">{preparationSummary}</p>}
    {value && !compact && !busy && <button type="button" className="prompt-preview-toggle" aria-expanded={showPreview} aria-controls={`${editorId}-preview`} onClick={() => setShowPreview(value => !value)}>{showPreview ? 'Hide prompt' : 'Preview prompt'}</button>}
    {showPreview && value && !busy && <div className="prompt-preview" id={`${editorId}-preview`}>
      <div className="prompt-preview-toolbar"><label htmlFor={editorId}>Fix prompt</label><div><button type="button" className="prompt-select" onClick={() => { editor.current?.focus(); editor.current?.select(); }}>Select prompt</button><button type="button" className="prompt-copy-icon" aria-label="Copy prepared prompt" title="Copy prepared prompt" onClick={copy} disabled={busy || disabled}><Copy size={16} aria-hidden="true"/></button></div></div>
      <textarea id={editorId} ref={editor} readOnly value={value} rows={8} spellCheck={false}/>
    </div>}
  </div>;
}

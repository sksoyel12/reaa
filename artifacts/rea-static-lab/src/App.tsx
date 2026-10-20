import { useRef, useState, type DragEvent, type ChangeEvent } from 'react';
import { Activity, AlertCircle, ArrowDownToLine, Braces, Check, ChevronRight, FileCode2, FileSearch, Fingerprint, HardDrive, LockKeyhole, RotateCcw, ShieldCheck, Sparkles } from 'lucide-react';
import { analyzeFile, MAX_FILE_SIZE_BYTES, type AnalysisProgress, type AnalysisReport } from '@/lib/analyzeFile';

const MAX_FILE_SIZE_LABEL = `${Math.round(MAX_FILE_SIZE_BYTES / (1024 * 1024))} MB`;

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function App() {
  const inputRef = useRef<HTMLInputElement>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [progress, setProgress] = useState<AnalysisProgress | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [dragging, setDragging] = useState(false);

  function chooseFile(candidate?: File) {
    if (busy) return;
    if (!candidate) return;
    setReport(null);
    setError('');
    setProgress(null);
    if (candidate.size > MAX_FILE_SIZE_BYTES) {
      setFile(null);
      setError(`This file is larger than the ${MAX_FILE_SIZE_LABEL} limit. Choose a smaller file to continue.`);
      return;
    }
    setFile(candidate);
  }

  function handleInput(event: ChangeEvent<HTMLInputElement>) {
    chooseFile(event.target.files?.[0]);
    event.target.value = '';
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    if (busy) return;
    chooseFile(event.dataTransfer.files?.[0]);
  }

  async function runAnalysis() {
    if (!file || busy) return;
    const controller = new AbortController();
    abortControllerRef.current = controller;
    setBusy(true);
    setError('');
    setReport(null);
    setProgress({ bytesRead: 0, totalBytes: file.size, percent: 0 });
    try {
      const result = await analyzeFile(file, {
        signal: controller.signal,
        onProgress: setProgress,
      });
      setReport(result);
    } catch (cause) {
      setError(
        controller.signal.aborted
          ? 'Analysis cancelled. The selected file is ready to try again.'
          : cause instanceof Error
            ? cause.message
            : 'Analysis could not be completed. Try another file.',
      );
    } finally {
      if (abortControllerRef.current === controller) abortControllerRef.current = null;
      setBusy(false);
      setProgress(null);
    }
  }

  function cancelAnalysis() {
    abortControllerRef.current?.abort();
  }

  function exportJson() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    const safeFileName = report.fileName.replace(/[^\w.-]+/g, '_') || 'analysis-report';
    link.download = `${safeFileName}.analysis.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
  }

  function clearCurrent() {
    abortControllerRef.current?.abort();
    abortControllerRef.current = null;
    setFile(null);
    setReport(null);
    setProgress(null);
    setError('');
    setBusy(false);
    if (inputRef.current) inputRef.current.value = '';
  }

  const formattedDate = report ? new Date(report.analyzedAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '';

  return (
    <div className="app-shell">
      <aside className="side-rail" aria-label="Application">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true"><Braces size={19} strokeWidth={1.8} /></div>
          <div><div className="brand-name">REA Static Lab</div><div className="brand-caption">Local analysis workbench</div></div>
        </div>
        <div className="rail-section">
          <div className="rail-label">Workspace</div>
          <div className="rail-current" aria-current="page"><FileSearch size={16} /><span>Static analysis</span><ChevronRight size={14} style={{ marginLeft: 'auto' }} /></div>
        </div>
        <div className="rail-foot">
          <div className="local-indicator"><span className="local-dot" />Browser-only session</div>
          Files are inspected on this device. Nothing is uploaded or saved by this tool.
        </div>
      </aside>

      <main className="main-area">
        <div className="topbar">
          <div className="crumb">Workbench <span style={{ padding: '0 8px', color: '#c0bdb4' }}>/</span> File inspection</div>
          <div className="top-tag"><LockKeyhole size={12} /> LOCAL BY DESIGN</div>
        </div>

        <div className="workspace">
          <header>
            <div className="eyebrow">First-look file analysis</div>
            <h1 className="page-title">Know what’s inside.</h1>
            <p className="page-subtitle">A clear, evidence-based first look at a file. Inspect its signature, entropy, hash, and printable strings before deciding what to do next.</p>
            <div className="privacy-note"><ShieldCheck size={15} /> Your file stays in your browser. It is never uploaded, stored, or executed.</div>
          </header>

          <section aria-label="Select a file">
            <div
              className={`drop-panel${dragging ? ' is-dragging' : ''}`}
              onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
              onDragOver={(event) => event.preventDefault()}
              onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node)) setDragging(false); }}
              onDrop={handleDrop}
            >
              <div className="drop-left">
                <div className="file-glyph"><FileCode2 size={22} strokeWidth={1.6} /></div>
                <div>
                  <div className="drop-title">Choose a file to inspect</div>
                  <div className="drop-copy">Drop one file here or browse your device. Maximum size: {MAX_FILE_SIZE_LABEL}.</div>
                </div>
              </div>
              <div className="drop-actions">
                <input ref={inputRef} className="file-input" id="file-picker" type="file" onChange={handleInput} disabled={busy} aria-label="Select a file to analyze" data-testid="input-file" />
                <label htmlFor="file-picker" className="button button-secondary" data-testid="button-browse"><HardDrive size={14} /> Browse files</label>
                <button className="button button-primary" onClick={runAnalysis} disabled={!file || busy} data-testid="button-analyze">
                  {busy ? <Activity size={14} className="animate-pulse" /> : <Sparkles size={14} />}
                  {busy ? 'Analyzing…' : 'Analyze file'}
                </button>
              </div>
            </div>

            {file && (
              <div className="file-chip" data-testid="text-selected-file">
                <div className="file-chip-info">
                  <FileCode2 size={17} color="#668674" />
                  <div style={{ minWidth: 0 }}>
                    <div className="file-chip-name">{file.name || 'Unnamed file'}</div>
                    <div className="file-chip-meta">{formatBytes(file.size)} <span aria-hidden="true">·</span> {file.type || 'Unknown MIME type'}</div>
                  </div>
                </div>
                <button className="button button-quiet" onClick={clearCurrent} disabled={busy} aria-label="Clear selected file" data-testid="button-clear-selection"><RotateCcw size={13} /> Clear</button>
              </div>
            )}
          </section>

          {error && <div className="notice notice-error" role="alert" data-testid="status-analysis-error"><AlertCircle size={16} /> <span>{error}</span></div>}
          {busy && (
            <div className="notice notice-loading" role="status" aria-live="polite" data-testid="status-analysis-loading">
              <Activity size={16} className="animate-pulse loading-icon" />
              <div className="analysis-progress">
                <div className="progress-heading">
                  <span>Analyzing file locally in chunks…</span>
                  <span>{Math.round(progress?.percent ?? 0)}%</span>
                </div>
                <div
                  className="progress-track"
                  role="progressbar"
                  aria-label="File analysis progress"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={Math.round(progress?.percent ?? 0)}
                  data-testid="progress-analysis"
                >
                  <span style={{ width: `${progress?.percent ?? 0}%` }} />
                </div>
                <div className="progress-meta">
                  {progress ? `${formatBytes(progress.bytesRead)} of ${formatBytes(progress.totalBytes)}` : 'Starting…'}
                </div>
              </div>
              <button className="button button-quiet progress-cancel" onClick={cancelAnalysis} data-testid="button-cancel-analysis">
                Cancel
              </button>
            </div>
          )}

          {busy ? (
            <section aria-label="Analysis report loading">
              <div className="section-heading"><h2 className="section-title">Analysis report</h2></div>
              <div className="report-grid">
                <div className="report-card" style={{ padding: 18 }}><div className="skeleton" style={{ width: '47%', height: 18 }} /><div className="skeleton" style={{ width: '29%', height: 11, marginTop: 13 }} /><div className="skeleton" style={{ width: '100%', height: 40, marginTop: 25 }} /></div>
                <div className="report-card" style={{ padding: 18 }}><div className="skeleton" style={{ width: '44%', height: 12 }} /><div className="skeleton" style={{ width: '70%', height: 25, marginTop: 14 }} /></div>
              </div>
            </section>
          ) : report ? (
            <section aria-label="Analysis report" aria-live="polite">
              <div className="section-heading">
                <div><div className="section-kicker">Inspection complete · {formattedDate}</div><h2 className="section-title" style={{ marginTop: 5 }}>Analysis report</h2></div>
                <div className="drop-actions">
                  <button className="button button-secondary" onClick={exportJson} data-testid="button-export-json"><ArrowDownToLine size={14} /> Export JSON</button>
                  <button className="button button-quiet" onClick={clearCurrent} data-testid="button-clear-result"><RotateCcw size={13} /> Clear</button>
                </div>
              </div>
              <div className="report-grid">
                <div className="report-card">
                  <div className="report-card-head"><span className="card-label">File identity</span><Check size={14} color="#568168" /></div>
                  <div className="primary-file">
                    <div className="primary-file-name" data-testid="text-report-filename">{report.fileName}</div>
                    <div className="primary-file-meta"><span>{formatBytes(report.sizeBytes)}</span><span>{report.mimeType || 'Unknown MIME type'}</span></div>
                  </div>
                  <div className="hash-box">
                    <div className="card-label">SHA-256</div>
                    <div className="hash-value" data-testid="text-report-sha256">{report.sha256}</div>
                  </div>
                </div>
                <div className="report-card">
                  <div className="report-card-head"><span className="card-label">File characteristics</span><Activity size={14} color="#75917f" /></div>
                  <div className="metric-panel">
                    <div className="metric"><div className="card-label">File type</div><div className="metric-value compact" data-testid="text-report-filetype">{report.fileType}</div><div className="metric-caption">{report.signatureDescription}</div></div>
                    <div className="metric"><div className="card-label">Entropy</div><div className="metric-value" data-testid="text-report-entropy">{report.entropy.toFixed(3)}</div><div className="metric-caption">bits per byte</div></div>
                    <div className="metric"><div className="card-label">Printable strings</div><div className="metric-value">{report.totalStringCount.toLocaleString()}</div><div className="metric-caption">found in file</div></div>
                    <div className="metric"><div className="card-label">Report status</div><div className="metric-value compact">Ready</div><div className="metric-caption">local inspection</div></div>
                  </div>
                </div>
              </div>

              <div className="section-heading">
                <div><div className="section-kicker">Evidence · byte offsets</div><h3 className="section-title" style={{ marginTop: 5 }}>Printable strings</h3></div>
                <div className="section-kicker">{report.strings.length} shown</div>
              </div>
              <div className="strings-card">
                <div className="strings-head"><span className="card-label">Extracted text</span><span className="card-label">OFFSET · HEX</span></div>
                {report.strings.length ? (
                  <div className="strings-list" role="list" aria-label="Printable strings extracted from file" data-testid="list-printable-strings">
                    {report.strings.map((item, index) => (
                      <div className="string-row" role="listitem" key={`${item.offset}-${index}`} data-testid={`row-printable-string-${index}`}>
                        <div className="string-offset">0x{item.offset.toString(16).toUpperCase().padStart(6, '0')}</div>
                        <div className="string-value">{item.value}</div>
                      </div>
                    ))}
                  </div>
                ) : <div className="strings-empty">No printable strings were found in this file.</div>}
                {report.stringsTruncated && <div className="truncated-note">Some string entries were shortened or omitted to keep the report manageable.</div>}
              </div>
              <div className="report-footnote"><Fingerprint size={12} style={{ verticalAlign: 'middle', marginRight: 6 }} />Analysis is a static first look, not a safety verdict. <span>Do not run a file unless you trust its source.</span></div>
            </section>
          ) : (
            <section aria-label="Analysis report empty">
              <div className="section-heading"><div><div className="section-kicker">Your current session</div><h2 className="section-title" style={{ marginTop: 5 }}>Analysis report</h2></div></div>
              <div className="empty-report">
                <div className="empty-mark"><FileSearch size={18} /></div>
                <div className="empty-title">Your report will appear here</div>
                <div className="empty-description">Select a file above, then run an analysis to see its characteristics and printable strings.</div>
              </div>
              <div className="report-footnote"><LockKeyhole size={12} style={{ verticalAlign: 'middle', marginRight: 6 }} />No file contents leave this browser. Nothing is saved after you clear the result or close this page.</div>
            </section>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;

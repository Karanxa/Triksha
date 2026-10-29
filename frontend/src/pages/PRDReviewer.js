import React, { useState, useRef, useEffect, useMemo } from 'react';
import { createApiClient, useAuth } from '../contexts/AuthContext';
import LockedOverlay from '../components/LockedOverlay';
import toast from 'react-hot-toast';
import {
  FileSearch,
  Upload,
  FileText,
  Download,
  Loader2,
  CheckCircle,
  AlertCircle,
  X,
  Eye,
  Trash2,
  RefreshCw,
  Clock,
  XCircle,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

const REVIEWS_PER_PAGE = 20;

const SESSION_KEY = 'prd_reviewer_state';

const PRDReviewer = () => {
  const [mode, setMode] = useState('upload');
  const [file, setFile] = useState(null);
  const [documentUrl, setDocumentUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Restore persisted state on mount
  const savedState = (() => {
    try { return JSON.parse(sessionStorage.getItem(SESSION_KEY) || 'null'); } catch { return null; }
  })();
  const [additionalContext, setAdditionalContext] = useState(savedState?.additionalContext || '');
  const [result, setResult] = useState(savedState?.result || null);

  // Tabs
  const [activeTab, setActiveTab] = useState('new-review');

  // Past reviews state
  const [allReviews, setAllReviews] = useState([]);
  const [listLoading, setListLoading] = useState(false);
  const [pastSearch, setPastSearch] = useState('');
  const [pastStatus, setPastStatus] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  // Ownership classification for Past Reviews (My Reviews / Other Reviews)
  const [pastSubTab, setPastSubTab] = useState('my-reviews');
  const [selectedReview, setSelectedReview] = useState(null);
  const [loadingReviewId, setLoadingReviewId] = useState(null);
  const [actionBusy, setActionBusy] = useState({});
  // per-review SSE progress: { [review_id]: 0-100 }
  const [progressMap, setProgressMap] = useState({});

  const { user, hasPermission, canAccessScan } = useAuth();
  const fileInputRef = useRef(null);
  // active SSE controllers: { [review_id]: AbortController }
  const streamControllersRef = useRef({});
  const listPollRef = useRef(null);
  const apiClient = createApiClient();

  // Persist result + form inputs to sessionStorage whenever they change
  useEffect(() => {
    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify({ result, additionalContext }));
    } catch {}
  }, [result, additionalContext]);

  // Derived: split into active and past
  const activeReviews = useMemo(() =>
    allReviews.filter(r => r.status === 'queued' || r.status === 'running'),
    [allReviews]
  );
  // Ownership match: created_by equals current user (email or id)
  const isMyReview = (r) => {
    const cb = String(r?.created_by || '').toLowerCase();
    if (!cb) return false;
    if (user?.email && cb === String(user.email).toLowerCase()) return true;
    if (user?.id && cb === String(user.id).toLowerCase()) return true;
    return false;
  };

  const pastReviews = useMemo(() => {
    // Backend already filters by ownership scope via the `scope` query
    // parameter — the list returned here is the right one.
    return allReviews.filter(r => r.status === 'completed' || r.status === 'failed');
  }, [allReviews]);

  // Load all reviews
  const loadAllReviews = async (soft = false) => {
    if (!soft) setListLoading(true);
    try {
      // On the Past Reviews tab, narrow the DB call to the selected scope
      // (mine / others) so the backend does the filter.
      const params = new URLSearchParams();
      if (activeTab === 'past-reviews') {
        params.set('scope', pastSubTab === 'my-reviews' ? 'mine' : 'others');
      }
      const url = params.toString()
        ? `/security-review/list?${params.toString()}`
        : '/security-review/list';
      const data = await apiClient.get(url);
      setAllReviews(prev => {
        const prevMap = Object.fromEntries(prev.map(r => [r.review_id, r]));
        return (Array.isArray(data) ? data : []).map(r => ({
          ...r,
          result: prevMap[r.review_id]?.result ?? r.result,
        }));
      });
    } catch {}
    if (!soft) setListLoading(false);
  };

  // Toggle expand — fetch full review (with result) on first open
  const selectAndLoadReview = async (review) => {
    if (selectedReview?.review_id === review.review_id) {
      setSelectedReview(null);
      return;
    }
    // If result is already loaded, just expand
    if (review.result) {
      setSelectedReview(review);
      return;
    }
    // Fetch full detail (includes result_json from DB)
    setLoadingReviewId(review.review_id);
    try {
      const full = await apiClient.get(`/security-review/${review.review_id}`);
      const merged = { ...review, ...full };
      setAllReviews(prev => prev.map(r => r.review_id === review.review_id ? merged : r));
      setSelectedReview(merged);
    } catch {
      setSelectedReview(review); // fall back to showing without content
    } finally {
      setLoadingReviewId(null);
    }
  };

  // Poll when on active or past tab — also re-fetch when the ownership
  // scope changes so the DB does the filtering for the Past view.
  useEffect(() => {
    if (activeTab === 'active-reviews' || activeTab === 'past-reviews') {
      loadAllReviews();
      listPollRef.current = setInterval(() => loadAllReviews(true), 5000);
    }
    return () => { if (listPollRef.current) clearInterval(listPollRef.current); };
  }, [activeTab, pastSubTab]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-connect SSE for each active review; tear down when they complete
  useEffect(() => {
    activeReviews.forEach(r => startEventStream(r.review_id));
    // Stop streams for reviews no longer active
    const activeIds = new Set(activeReviews.map(r => r.review_id));
    Object.keys(streamControllersRef.current).forEach(id => {
      if (!activeIds.has(id)) stopEventStream(id);
    });
  }, [activeReviews]);

  // Start SSE for one review, updating progressMap live
  const startEventStream = (reviewId) => {
    if (streamControllersRef.current[reviewId]) return; // already streaming
    const controller = new AbortController();
    streamControllersRef.current[reviewId] = controller;

    fetch(`/security-review/${reviewId}/events`, {
      credentials: 'include',
      signal: controller.signal,
    }).then(async resp => {
      if (!resp.ok || !resp.body) return;
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n\n');
        buffer = parts.pop() || '';
        for (const part of parts) {
          const line = part.split('\n').find(l => l.startsWith('data:'));
          if (line) {
            try {
              const payload = JSON.parse(line.replace(/^data:\s*/, ''));
              if (payload.progress != null) {
                setProgressMap(prev => ({ ...prev, [reviewId]: payload.progress }));
              }
              if (payload.status === 'completed' && payload.result) {
                setResult(payload.result);
                // Merge result into allReviews so content is available immediately
                setAllReviews(prev => prev.map(r =>
                  r.review_id === reviewId ? { ...r, status: 'completed', result: payload.result } : r
                ));
                // Also update selectedReview if it's the one that just completed
                setSelectedReview(prev =>
                  prev?.review_id === reviewId ? { ...prev, status: 'completed', result: payload.result } : prev
                );
              }
              if (payload.status === 'completed' || payload.status === 'failed') {
                loadAllReviews(true);
              }
            } catch {}
          }
        }
      }
    }).catch(() => {}).finally(() => {
      delete streamControllersRef.current[reviewId];
    });
  };

  // Stop SSE for a review
  const stopEventStream = (reviewId) => {
    streamControllersRef.current[reviewId]?.abort();
    delete streamControllersRef.current[reviewId];
  };

  useEffect(() => { setCurrentPage(1); }, [pastSearch, pastStatus]);

  // Filter + paginate
  const filteredReviews = useMemo(() => {
    const q = pastSearch.trim().toLowerCase();
    const s = pastStatus;
    return pastReviews.filter(r => {
      const matchStatus = s === 'all' || (r.status || '').toLowerCase() === s;
      if (!matchStatus) return false;
      if (!q) return true;
      return (r.document_title || '').toLowerCase().includes(q) ||
             (r.review_id || '').toLowerCase().includes(q) ||
             (r.reference_id || '').toLowerCase().includes(q);
    });
  }, [pastReviews, pastSearch, pastStatus]);

  const totalPages = Math.ceil(filteredReviews.length / REVIEWS_PER_PAGE);
  const paginatedReviews = useMemo(() => {
    const start = (currentPage - 1) * REVIEWS_PER_PAGE;
    return filteredReviews.slice(start, start + REVIEWS_PER_PAGE);
  }, [filteredReviews, currentPage]);

  const deleteReview = async (reviewId) => {
    setActionBusy(p => ({ ...p, [reviewId]: true }));
    try {
      await apiClient.delete(`/security-review/${reviewId}`);
      setAllReviews(p => p.filter(r => r.review_id !== reviewId));
      toast.success('Review deleted');
    } catch {
      toast.error('Failed to delete review');
    } finally {
      setActionBusy(p => ({ ...p, [reviewId]: false }));
    }
  };

  const getStatusIcon = (status) => {
    switch ((status || '').toLowerCase()) {
      case 'success':
      case 'completed': return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'failed':
      case 'error':     return <XCircle className="h-5 w-5 text-red-500" />;
      case 'running':   return <Clock className="h-5 w-5 text-blue-500 animate-pulse" />;
      default:          return <Clock className="h-5 w-5 text-gray-400" />;
    }
  };

  const handleFileChange = (e) => {
    const selected = e.target.files?.[0];
    if (selected) {
      const validTypes = [
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/msword',
        'text/plain',
        'text/markdown',
      ];
      if (!validTypes.includes(selected.type) && !selected.name.match(/\.(docx|doc|txt|md)$/i)) {
        toast.error('Please upload a .docx, .doc, .txt, or .md file');
        return;
      }
      setFile(selected);
      setError(null);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    const dropped = e.dataTransfer.files?.[0];
    if (dropped) {
      setFile(dropped);
      setError(null);
    }
  };

  const handleSubmit = async () => {
    if (!file) { toast.error('Please select a file to upload'); return; }

    setLoading(true);
    setResult(null);
    setError(null);

    try {
      let response;

      if (mode === 'upload') {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('author', 'ai-security');
        formData.append('additional_context', additionalContext || '');
        formData.append('output_format', 'markdown');

        response = await apiClient.post('/security-review/upload', formData);
      } else {
        response = await apiClient.post('/security-review/generate', {
          document_url: documentUrl.trim(),
          author: 'ai-security',
          additional_context: additionalContext || undefined,
          output_format: 'markdown',
        });
      }

      if (response.review_id) {
        toast.success('Review queued — generating security requirements…');
        setActiveTab('active-reviews');
        loadAllReviews();
        startEventStream(response.review_id);
      } else if (response.status === 'success') {
        setResult(response);
        toast.success('Security requirements generated successfully');
        setActiveTab('past-reviews');
        loadAllReviews();
      } else {
        setError(response.error || 'Generation failed');
        toast.error(response.error || 'Failed to generate security requirements');
      }
    } catch (err) {
      const msg = err?.message || 'Request failed';
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadDocx = async (reviewId) => {
    try {
      const response = await fetch(`/security-review/${reviewId}/download`, {
        credentials: 'include',
      });
      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Download failed (${response.status})`);
      }
      const blob = await response.blob();
      const disposition = response.headers.get('content-disposition') || '';
      const filenameMatch = disposition.match(/filename="?([^"]+)"?/);
      const downloadName = filenameMatch?.[1] || 'Security_Requirements.docx';
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = downloadName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.success('Downloaded .docx');
    } catch (err) {
      toast.error(err?.message || 'Download failed');
    }
  };

  const handleDownloadMarkdown = (reviewResult) => {
    const r = reviewResult || result;
    if (!r?.security_requirements_md) return;
    const blob = new Blob([r.security_requirements_md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const title = r.document_title?.replace(/[^\w\s-]/g, '').replace(/\s+/g, '_') || 'Security_Requirements';
    a.download = `${title}_Security_Requirements.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast.success('Downloaded markdown');
  };

  const renderMarkdown = (md) => {
    if (!md) return null;
    const lines = md.split('\n');
    const elements = [];
    let i = 0;

    while (i < lines.length) {
      const line = lines[i];

      if (line.startsWith('# ')) {
        elements.push(<h1 key={i} className="text-2xl font-bold text-gray-900 dark:text-white mt-6 mb-3">{line.slice(2)}</h1>);
      } else if (line.startsWith('## ')) {
        elements.push(<h2 key={i} className="text-xl font-semibold text-gray-800 dark:text-gray-100 mt-5 mb-2 border-b border-gray-200 dark:border-gray-700 pb-1">{line.slice(3)}</h2>);
      } else if (line.startsWith('### ')) {
        elements.push(<h3 key={i} className="text-lg font-medium text-gray-800 dark:text-gray-200 mt-4 mb-1">{line.slice(4)}</h3>);
      } else if (line.trim().startsWith('|') && lines[i + 1]?.trim().startsWith('|')) {
        // Table block
        const tableLines = [];
        while (i < lines.length && lines[i].trim().startsWith('|')) {
          tableLines.push(lines[i]);
          i++;
        }
        elements.push(renderTable(tableLines, elements.length));
        continue;
      } else if (line.startsWith('---')) {
        elements.push(<hr key={i} className="my-4 border-gray-200 dark:border-gray-700" />);
      } else if (line.startsWith('- ')) {
        elements.push(
          <li key={i} className="ml-4 text-gray-700 dark:text-gray-300 text-sm list-disc">
            {renderInline(line.slice(2))}
          </li>
        );
      } else if (/^\d+\.\s/.test(line)) {
        elements.push(
          <li key={i} className="ml-4 text-gray-700 dark:text-gray-300 text-sm list-decimal">
            {renderInline(line.replace(/^\d+\.\s*/, ''))}
          </li>
        );
      } else if (line.trim()) {
        elements.push(<p key={i} className="text-gray-700 dark:text-gray-300 text-sm my-1">{renderInline(line)}</p>);
      }
      i++;
    }
    return elements;
  };

  const renderInline = (text) => {
    return text
      .replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')
      .replace(/\*(.+?)\*/g, '<i>$1</i>')
      .replace(/`(.+?)`/g, '<code class="bg-gray-100 dark:bg-gray-700 px-1 py-0.5 rounded text-xs">$1</code>')
      .split(/(<b>.*?<\/b>|<i>.*?<\/i>|<code.*?<\/code>)/)
      .map((part, idx) => {
        if (part.startsWith('<b>')) return <strong key={idx}>{part.replace(/<\/?b>/g, '')}</strong>;
        if (part.startsWith('<i>')) return <em key={idx}>{part.replace(/<\/?i>/g, '')}</em>;
        if (part.startsWith('<code')) {
          const content = part.replace(/<\/?code[^>]*>/g, '');
          return <code key={idx} className="bg-gray-100 dark:bg-gray-700 px-1 py-0.5 rounded text-xs">{content}</code>;
        }
        return part;
      });
  };

  const renderTable = (tableLines, keyBase) => {
    const rows = tableLines
      .filter(l => !l.trim().match(/^\|[\s-:|]+\|$/))
      .map(l => l.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim()));

    if (rows.length === 0) return null;
    const header = rows[0];
    const body = rows.slice(1);

    return (
      <div key={keyBase} className="overflow-x-auto my-3">
        <table className="min-w-full text-sm border border-gray-200 dark:border-gray-700 rounded-lg">
          <thead>
            <tr className="bg-gray-50 dark:bg-gray-800">
              {header.map((cell, ci) => (
                <th key={ci} className="px-3 py-2 text-left font-semibold text-gray-700 dark:text-gray-300 border-b border-gray-200 dark:border-gray-700">
                  {renderInline(cell)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {body.map((row, ri) => (
              <tr key={ri} className={ri % 2 === 0 ? 'bg-white dark:bg-gray-900' : 'bg-gray-50 dark:bg-gray-800/50'}>
                {row.map((cell, ci) => (
                  <td key={ci} className="px-3 py-2 text-gray-600 dark:text-gray-400 border-b border-gray-100 dark:border-gray-800">
                    {renderInline(cell)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  return (
    <div className="space-y-3">
      {/* Header card — matches Scan.js pattern */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">GenAI PRD Security Reviewer</h1>
            <p className="text-sm text-gray-600 dark:text-gray-400 mt-0.5">
              AI-powered security requirements for GenAI use cases — LLMs, agents, RAG, ML pipelines
            </p>
          </div>
          <FileSearch className="h-8 w-8 text-primary-600 dark:text-primary-400" />
        </div>
      </div>

      {/* Tab bar — underline style matching Scan.js exactly */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'new-review', label: 'New Review' },
            { id: 'active-reviews', label: `Active Reviews${activeReviews.length ? ` (${activeReviews.length})` : ''}` },
            { id: 'past-reviews', label: 'Past Reviews' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab content card — matches Scan.js pattern */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">

      {/* ── New Review Tab ─────────────────────────────────────────── */}
      {activeTab === 'new-review' && (<>

      {/* Input form */}
      <div className="p-6 space-y-5">

          {/* Scope callout */}
          <div className="flex items-start gap-3 p-3 rounded-lg bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-800/50">
            <AlertCircle className="h-4 w-4 text-blue-500 mt-0.5 shrink-0" />
            <p className="text-xs text-blue-700 dark:text-blue-300">
              <strong>Scope:</strong> This tool reviews PRDs for GenAI-specific security concerns — prompt injection, model poisoning, data exfiltration, agent autonomy risks, RAG integrity, and more. Upload your product requirements document to get tailored security requirements.
            </p>
          </div>

          {/* File upload area */}
          {(
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center cursor-pointer hover:border-blue-400 dark:hover:border-blue-500 hover:bg-blue-50/50 dark:hover:bg-blue-950/20 transition-colors"
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".docx,.doc,.txt,.md"
                onChange={handleFileChange}
                className="hidden"
              />
              {file ? (
                <div className="flex items-center justify-center gap-3">
                  <FileText className="h-6 w-6 text-blue-500" />
                  <div className="text-left">
                    <p className="font-medium text-gray-900 dark:text-white text-sm">{file.name}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {(file.size / 1024).toFixed(1)} KB
                    </p>
                  </div>
                  <button
                    onClick={(e) => { e.stopPropagation(); setFile(null); }}
                    className="p-1 rounded-full hover:bg-gray-200 dark:hover:bg-gray-700"
                  >
                    <X className="h-4 w-4 text-gray-500" />
                  </button>
                </div>
              ) : (
                <div>
                  <Upload className="h-8 w-8 text-gray-400 mx-auto mb-2" />
                  <p className="text-gray-600 dark:text-gray-300 text-sm font-medium">
                    Drop your GenAI PRD here or click to browse
                  </p>
                  <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                    .docx, .doc, .txt, .md
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Additional context */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Additional Context (optional)
            </label>
            <input
              type="text"
              value={additionalContext}
              onChange={(e) => setAdditionalContext(e.target.value)}
              placeholder="e.g. Focus on agent autonomy risks"
              className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
            />
          </div>

          {/* Submit */}
          <LockedOverlay locked={!hasPermission('triksha.scan.prd-scan')} message="You do not have permission to run PRD reviews">
            <button
              onClick={handleSubmit}
              disabled={loading || !file}
              className="btn-primary w-full flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Analyzing GenAI Security Requirements...
                </>
              ) : (
                <>
                  <FileSearch className="h-4 w-4" />
                  Generate Security Requirements
                </>
              )}
            </button>
          </LockedOverlay>
        </div>

      {/* Error */}
      {error && (
        <div className="card border-red-200 dark:border-red-800">
          <div className="p-6">
            <div className="flex items-start gap-3">
              <AlertCircle className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
              <div>
                <h3 className="font-medium text-red-800 dark:text-red-300">Generation Failed</h3>
                <p className="text-sm text-red-600 dark:text-red-400 mt-1">{error}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      </>)} {/* end new-review tab */}

      {/* ── Active Reviews Tab ─────────────────────────────────────── */}
      {activeTab === 'active-reviews' && (
        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Active Reviews</h3>
            <button onClick={() => loadAllReviews()} className="btn-outline btn-sm" disabled={listLoading}>
              <RefreshCw className={`h-4 w-4 ${listLoading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {activeReviews.length === 0 ? (
            <div className="text-center py-12">
              <FileSearch className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
              <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No active reviews</h3>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Start a new review above.</p>
              <button onClick={() => setActiveTab('new-review')} className="mt-4 btn-primary btn-sm">New Review</button>
            </div>
          ) : (
            <div className="space-y-3">
              {activeReviews.map(review => {
                const pct = progressMap[review.review_id] ?? review.progress ?? 0;
                const radius = 20;
                const circumference = 2 * Math.PI * radius;
                const dash = (pct / 100) * circumference;
                return (
                  <div key={review.review_id} className="border rounded-lg p-4 border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3 min-w-0">
                        <div className="min-w-0">
                          <h4 className="text-sm font-medium text-gray-900 dark:text-white truncate">
                            {review.document_title || 'Untitled Review'}
                          </h4>
                          <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
                              review.status === 'running'
                                ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                                : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                            }`}>{review.status}</span>
                            {review.reference_id && <span className="ml-2">Reference ID: {review.reference_id}</span>}
                            {review.created_by && <span className="ml-2">· {review.created_by}</span>}
                          </p>
                        </div>
                      </div>
                      {/* Circular progress */}
                      <div className="relative flex-shrink-0 ml-4" style={{ width: 52, height: 52 }}>
                        <svg width="52" height="52" viewBox="0 0 52 52">
                          <circle cx="26" cy="26" r={radius} fill="none"
                            className="stroke-gray-200 dark:stroke-gray-700" strokeWidth="4" />
                          <circle cx="26" cy="26" r={radius} fill="none"
                            className="stroke-primary-500" strokeWidth="4"
                            strokeLinecap="round"
                            strokeDasharray={`${dash} ${circumference}`}
                            transform="rotate(-90 26 26)"
                            style={{ transition: 'stroke-dasharray 0.5s ease' }}
                          />
                        </svg>
                        <span className="absolute inset-0 flex items-center justify-center text-xs font-semibold text-gray-700 dark:text-gray-300">
                          {pct}%
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ── Past Reviews Tab ───────────────────────────────────────── */}
      {activeTab === 'past-reviews' && (
        <div className="p-6 space-y-4">
          {/* Search / Filter bar — ownership classification on the left,
              search grows wide, status + refresh on the right. Same layout
              as LLM Scan / MCP / Agents / Prompts. */}
          <div className="flex items-center gap-2 flex-wrap">
            <select
              className="select h-9 w-auto"
              value={pastSubTab}
              onChange={e => setPastSubTab(e.target.value)}
              aria-label="Filter reviews by ownership"
            >
              <option value="my-reviews">My Reviews</option>
              <option value="other-reviews">Other Reviews</option>
            </select>
            <input
              type="text"
              className="input h-9 flex-1 min-w-0"
              placeholder="Search by title or ID"
              value={pastSearch}
              onChange={e => setPastSearch(e.target.value)}
            />
            <select
              className="select h-9 w-auto"
              value={pastStatus}
              onChange={e => setPastStatus(e.target.value)}
            >
              <option value="all">All statuses</option>
              <option value="success">Success</option>
              <option value="failed">Failed</option>
            </select>
            <button
              onClick={() => loadAllReviews()}
              className="btn-outline btn-sm p-2"
              disabled={listLoading}
              title="Refresh"
              aria-label="Refresh reviews list"
            >
              <RefreshCw className={`h-4 w-4 ${listLoading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {/* List */}
          {listLoading ? (
            <div className="space-y-2">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="animate-pulse h-16 bg-gray-100 dark:bg-gray-700 rounded-lg border border-gray-200 dark:border-gray-600" />
              ))}
            </div>
          ) : filteredReviews.length === 0 ? (
            <div className="text-center py-12">
              <FileSearch className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
              <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No reviews found</h3>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                {pastSearch || pastStatus !== 'all' ? 'Try adjusting your search or filters.' : 'Generate your first security review above.'}
              </p>
              {!pastSearch && pastStatus === 'all' && (
                <button onClick={() => setActiveTab('new-review')} className="mt-4 btn-primary btn-sm">
                  New Review
                </button>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              {paginatedReviews.map(review => {
                const isExpanded = selectedReview?.review_id === review.review_id;
                const locked = !hasPermission('triksha.scan.prd-view') || !canAccessScan(review.created_by);
                return (
                  <div key={review.review_id} className="border rounded-lg border-gray-200 dark:border-gray-700">
                    {/* Brief row — always visible */}
                    <div className="flex items-center justify-between px-4 py-3">
                      <div className="flex items-center space-x-3 min-w-0">
                        {getStatusIcon(review.status)}
                        <div className="min-w-0">
                          <h4 className="text-sm font-medium text-gray-900 dark:text-white truncate">
                            {review.document_title || 'Untitled Review'}
                          </h4>
                          <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                            {review.reference_id && <span className="mr-2">Reference ID: {review.reference_id}</span>}
                            {review.created_by && <span className="mr-2">· {review.created_by}</span>}
                            {review.generated_at && <span>{new Date(review.generated_at).toLocaleDateString()}</span>}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-1 ml-4 shrink-0">
                        {review.status === 'completed' && (
                          <LockedOverlay locked={locked} message="You do not have permission to download this review">
                            <button onClick={() => handleDownloadDocx(review.review_id)} className="btn-outline btn-sm">
                              <Download className="h-4 w-4 mr-1" />.docx
                            </button>
                          </LockedOverlay>
                        )}
                        <LockedOverlay locked={locked} message="You do not have permission to view this review">
                          <button
                            onClick={() => selectAndLoadReview(review)}
                            className="btn-outline btn-sm"
                            disabled={loadingReviewId === review.review_id}
                          >
                            {loadingReviewId === review.review_id
                              ? <RefreshCw className="h-4 w-4 mr-1 animate-spin" />
                              : <Eye className="h-4 w-4 mr-1" />
                            }
                            {isExpanded ? 'Hide' : 'View'}
                          </button>
                        </LockedOverlay>
                        {/* Delete — only shown to users with prd-delete permission */}
                        {hasPermission('triksha.scan.prd-delete') && canAccessScan(review.created_by) && (
                          <button
                            onClick={() => deleteReview(review.review_id)}
                            disabled={actionBusy[review.review_id]}
                            className="btn-outline btn-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 border-red-200 dark:border-red-800"
                            title="Delete review"
                          >
                            {actionBusy[review.review_id]
                              ? <RefreshCw className="h-4 w-4 animate-spin" />
                              : <Trash2 className="h-4 w-4" />
                            }
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Expanded detail — shown on View */}
                    {isExpanded && (
                      <div className="px-4 pb-4 pt-3 border-t border-gray-200 dark:border-gray-700">
                        {/* Metadata badges */}
                        {review.result?.metadata && (
                          <div className="flex flex-wrap gap-2 mb-4">
                            {review.result.metadata.attack_surfaces_identified && (
                              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300">
                                {review.result.metadata.attack_surfaces_identified} attack surfaces
                              </span>
                            )}
                            {review.result.metadata.sections_generated && (
                              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300">
                                {review.result.metadata.sections_generated} sections
                              </span>
                            )}
                          </div>
                        )}
                        {/* Rendered markdown */}
                        {review.result?.security_requirements_md && (
                          <div className="prose dark:prose-invert max-w-none max-h-[600px] overflow-y-auto">
                            {renderMarkdown(review.result.security_requirements_md)}
                          </div>
                        )}
                        {!review.result?.security_requirements_md && (
                          <p className="text-sm text-gray-500 dark:text-gray-400 italic">
                            {review.status === 'failed' ? `Failed: ${review.error || 'Unknown error'}` : 'No content available.'}
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Pagination */}
          {filteredReviews.length > REVIEWS_PER_PAGE && (
            <div className="flex items-center justify-between mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
              <div className="text-sm text-gray-700 dark:text-gray-300">
                Showing <span className="font-medium">{((currentPage - 1) * REVIEWS_PER_PAGE) + 1}</span>–
                <span className="font-medium">{Math.min(currentPage * REVIEWS_PER_PAGE, filteredReviews.length)}</span> of{' '}
                <span className="font-medium">{filteredReviews.length}</span>
              </div>
              <div className="flex items-center gap-1">
                <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1}
                  className="px-3 py-2 text-sm rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                  <ChevronLeft className="h-4 w-4" />
                </button>
                {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => {
                  const show = p === 1 || p === totalPages || (p >= currentPage - 1 && p <= currentPage + 1);
                  const ellipsis = (p === 2 && currentPage > 3) || (p === totalPages - 1 && currentPage < totalPages - 2);
                  if (!show && !ellipsis) return null;
                  if (ellipsis) return <span key={p} className="px-2 text-gray-500">…</span>;
                  return (
                    <button key={p} onClick={() => setCurrentPage(p)}
                      className={`min-w-[2.5rem] px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                        currentPage === p ? 'bg-primary-600 text-white' : 'border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
                      }`}>
                      {p}
                    </button>
                  );
                })}
                <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}
                  className="px-3 py-2 text-sm rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      </div> {/* end tab content card */}
    </div>
  );
};

export default PRDReviewer;

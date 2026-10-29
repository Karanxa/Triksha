/**
 * Skills Hardener — self-serve upload + repo jobs.
 *
 * Mirrors PRDReviewer.js architecture: stable refs, ownership tabs,
 * no re-render polling loop, SSE for active jobs, delete support.
 */
import React, { useState, useRef, useEffect, useMemo, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import { createApiClient, useAuth } from '../contexts/AuthContext';
import LockedOverlay from '../components/LockedOverlay';
import PastListPagination from '../components/PastListPagination';
import toast from 'react-hot-toast';
import {
  Zap, Upload, FileText, Download, Loader2, AlertCircle, CheckCircle,
  Clock, XCircle, RefreshCw, Eye, FileSearch, X, Copy, ShieldCheck,
  Calendar, ChevronDown, ExternalLink, GitBranch, Trash2,
} from 'lucide-react';

const JOBS_PER_PAGE = 20;
const SKILL_FILE_RE = /\.(md|markdown|yaml|yml|json|txt)$/i;
const UPLOAD_REPO_MARKER = '(uploaded)';

const isUploadJob = (j) => j?.mode === 'upload' || j?.repo_url === UPLOAD_REPO_MARKER;

const jobTimestamp = (j) => {
  const raw = j?.completed_at || j?.created_at;
  if (!raw) return null;
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? null : d;
};

const jobInDateRange = (j, from, to) => {
  if (!from && !to) return true;
  const ts = jobTimestamp(j);
  if (!ts) return false;
  if (from && ts < new Date(`${from}T00:00:00`)) return false;
  if (to && ts > new Date(`${to}T23:59:59.999`)) return false;
  return true;
};

const formatFilterDate = (iso) => {
  if (!iso) return '';
  const d = new Date(`${iso}T12:00:00`);
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
};

const hardenedOutput = (j) =>
  j.full_content_preview || j.security_guidelines || j.hardened_skill || j.security_addendum;

const originalContent = (j) => j.original_content || j.skill_content || j.original_skill;

const SkillHardener = () => {
  const location = useLocation();
  const { user, hasPermission, canAccessScan } = useAuth();

  // Stable API client — never recreated across renders
  const apiRef = useRef(createApiClient());
  const api = apiRef.current;

  // Tabs
  const [activeTab, setActiveTab] = useState(location.state?.tab || 'new');

  // New Skill form
  const [skillName, setSkillName] = useState('');
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // All jobs
  const [allJobs, setAllJobs] = useState([]);
  const [listLoading, setListLoading] = useState(false);

  // Active job SSE progress
  const [progressMap, setProgressMap] = useState({});
  const streamRefs = useRef({});

  // Past tab state
  const [pastSubTab, setPastSubTab] = useState('my-jobs');
  const [selectedJob, setSelectedJob] = useState(null);
  const [loadingJobId, setLoadingJobId] = useState(null);
  const [actionBusy, setActionBusy] = useState({});
  const [pastSearch, setPastSearch] = useState('');
  const [pastStatus, setPastStatus] = useState('all');
  const [pastDateFrom, setPastDateFrom] = useState('');
  const [pastDateTo, setPastDateTo] = useState('');
  const [dateFilterOpen, setDateFilterOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);

  const fileInputRef = useRef(null);
  const listPollRef = useRef(null);
  const dateFilterRef = useRef(null);

  // ─── Derived data ────────────────────────────────────────────
  const activeJobs = useMemo(
    () => allJobs.filter((j) => j.status === 'queued' || j.status === 'running'),
    [allJobs],
  );

  const pastJobs = useMemo(
    () => allJobs.filter((j) => j.status === 'completed' || j.status === 'failed'),
    [allJobs],
  );

  // ─── Load jobs ───────────────────────────────────────────────
  const loadJobs = useCallback(async (soft = false) => {
    if (!soft) setListLoading(true);
    try {
      const scope = pastSubTab === 'my-jobs' ? 'mine' : 'others';
      const data = await api.get(`/skills/harden/list?scope=${scope}`);
      setAllJobs(Array.isArray(data?.jobs) ? data.jobs : []);
    } catch {
      if (!soft) setAllJobs([]);
    }
    if (!soft) setListLoading(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pastSubTab]);

  // Start / stop polling when tab or subtab changes
  useEffect(() => {
    if (activeTab === 'active' || activeTab === 'past') {
      loadJobs();
      listPollRef.current = setInterval(() => loadJobs(true), 5000);
    }
    return () => {
      if (listPollRef.current) {
        clearInterval(listPollRef.current);
        listPollRef.current = null;
      }
    };
  }, [activeTab, pastSubTab, loadJobs]);

  // ─── SSE streams for active jobs ────────────────────────────
  const startStream = useCallback((jobId) => {
    if (streamRefs.current[jobId]) return;
    const controller = new AbortController();
    streamRefs.current[jobId] = controller;

    fetch(`/skills/harden/${jobId}/events`, {
      credentials: 'include',
      signal: controller.signal,
    })
      .then(async (resp) => {
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
            const line = part.split('\n').find((l) => l.startsWith('data:'));
            if (!line) continue;
            try {
              const payload = JSON.parse(line.replace(/^data:\s*/, ''));
              if (payload.progress != null)
                setProgressMap((p) => ({ ...p, [jobId]: payload.progress }));
              if (payload.status === 'completed' || payload.status === 'failed')
                loadJobs(true);
            } catch {
              /* ignore */
            }
          }
        }
      })
      .catch(() => {})
      .finally(() => {
        delete streamRefs.current[jobId];
      });
  }, [loadJobs]);

  const stopStream = useCallback((jobId) => {
    streamRefs.current[jobId]?.abort();
    delete streamRefs.current[jobId];
  }, []);

  useEffect(() => {
    activeJobs.forEach((j) => startStream(j.job_id));
    const ids = new Set(activeJobs.map((j) => j.job_id));
    Object.keys(streamRefs.current).forEach((id) => {
      if (!ids.has(id)) stopStream(id);
    });
  }, [activeJobs, startStream, stopStream]);

  // ─── Filters ─────────────────────────────────────────────────
  useEffect(() => setCurrentPage(1), [pastSearch, pastStatus, pastSubTab, pastDateFrom, pastDateTo]);

  const hasPastFilters = Boolean(pastSearch.trim() || pastStatus !== 'all' || pastDateFrom || pastDateTo);

  const dateFilterLabel = useMemo(() => {
    if (pastDateFrom && pastDateTo) return `${formatFilterDate(pastDateFrom)} – ${formatFilterDate(pastDateTo)}`;
    if (pastDateFrom) return `From ${formatFilterDate(pastDateFrom)}`;
    if (pastDateTo) return `Until ${formatFilterDate(pastDateTo)}`;
    return 'Date range';
  }, [pastDateFrom, pastDateTo]);

  useEffect(() => {
    if (!dateFilterOpen) return;
    const handler = (e) => {
      if (dateFilterRef.current && !dateFilterRef.current.contains(e.target)) setDateFilterOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [dateFilterOpen]);

  const filteredPastJobs = useMemo(() => {
    const q = pastSearch.trim().toLowerCase();
    return pastJobs.filter((j) => {
      if (pastStatus !== 'all' && (j.status || '').toLowerCase() !== pastStatus) return false;
      if (!jobInDateRange(j, pastDateFrom, pastDateTo)) return false;
      if (!q) return true;
      return (
        (j.skill_name || '').toLowerCase().includes(q) ||
        (j.skill_filename || '').toLowerCase().includes(q) ||
        (j.repo_url || '').toLowerCase().includes(q) ||
        (j.job_id || '').toLowerCase().includes(q)
      );
    });
  }, [pastJobs, pastSearch, pastStatus, pastDateFrom, pastDateTo]);

  const totalPages = Math.max(1, Math.ceil(filteredPastJobs.length / JOBS_PER_PAGE));
  const paginatedJobs = useMemo(() => {
    const start = (currentPage - 1) * JOBS_PER_PAGE;
    return filteredPastJobs.slice(start, start + JOBS_PER_PAGE);
  }, [filteredPastJobs, currentPage]);

  // ─── Actions ─────────────────────────────────────────────────
  const acceptSkillFile = (selected) => {
    if (!selected) return;
    if (!SKILL_FILE_RE.test(selected.name)) {
      toast.error('Please upload a .md, .yaml, .yml, .json, or .txt skill file');
      return;
    }
    setFile(selected);
    setError(null);
    if (!skillName.trim()) setSkillName(selected.name.replace(/\.[^.]+$/, ''));
  };

  const handleSubmit = async () => {
    if (!file) { toast.error('Please upload a skill file'); return; }
    if (!skillName.trim()) { toast.error('Please name this skill'); return; }

    setLoading(true);
    setError(null);
    try {
      const fd = new FormData();
      fd.append('file', file);
      fd.append('skill_name', skillName.trim());
      const res = await api.post('/skills/harden/upload/submit', fd);
      if (res.job_id) {
        toast.success('Submitted — hardening skill…');
        setActiveTab('active');
        setFile(null);
        setSkillName('');
        loadJobs();
        startStream(res.job_id);
      } else {
        toast.error('Submission failed');
      }
    } catch (err) {
      const msg = err?.message || 'Request failed';
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const selectAndLoadJob = async (job) => {
    if (selectedJob?.job_id === job.job_id) { setSelectedJob(null); return; }
    if (hardenedOutput(job)) { setSelectedJob(job); return; }
    setLoadingJobId(job.job_id);
    try {
      const full = await api.get(`/skills/harden/${job.job_id}`);
      const merged = { ...job, ...full };
      setAllJobs((prev) => prev.map((j) => (j.job_id === job.job_id ? merged : j)));
      setSelectedJob(merged);
    } catch {
      setSelectedJob(job);
    } finally {
      setLoadingJobId(null);
    }
  };

  const deleteJob = async (jobId) => {
    setActionBusy((p) => ({ ...p, [jobId]: true }));
    try {
      await api.delete(`/skills/harden/${jobId}`);
      setAllJobs((p) => p.filter((j) => j.job_id !== jobId));
      if (selectedJob?.job_id === jobId) setSelectedJob(null);
      toast.success('Job deleted');
    } catch {
      toast.error('Failed to delete job');
    } finally {
      setActionBusy((p) => ({ ...p, [jobId]: false }));
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied');
  };

  const downloadAsText = (text, filename) => {
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast.success('Downloaded');
  };

  // ─── Small components ────────────────────────────────────────
  const getStatusIcon = (s) => {
    if (s === 'completed') return <CheckCircle className="h-5 w-5 text-green-500 shrink-0" />;
    if (s === 'failed') return <XCircle className="h-5 w-5 text-red-500 shrink-0" />;
    if (s === 'running') return <RefreshCw className="h-5 w-5 text-blue-500 animate-spin shrink-0" />;
    return <Clock className="h-5 w-5 text-gray-400 shrink-0" />;
  };

  const JobSourceBadge = ({ job }) => {
    if (isUploadJob(job)) {
      return <span className="inline-flex px-2 py-0.5 rounded-full text-xs font-medium bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300">Upload</span>;
    }
    if (job.pr_url) {
      return (
        <a href={job.pr_url} target="_blank" rel="noopener noreferrer"
          onClick={(e) => e.stopPropagation()}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300 hover:bg-indigo-200">
          PR #{job.pr_number || ''}<ExternalLink className="h-3 w-3" />
        </a>
      );
    }
    if (job.repo_url) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 truncate max-w-[10rem]">
          <GitBranch className="h-3 w-3 shrink-0" /> Repo
        </span>
      );
    }
    return null;
  };

  const ResultPanels = ({ job }) => {
    const output = hardenedOutput(job);
    const original = originalContent(job);
    return (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">Original skill</span>
            {original && (
              <button type="button" onClick={() => copyToClipboard(original)} className="text-gray-400 hover:text-gray-600 p-1">
                <Copy className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
          <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-900 border text-sm font-mono whitespace-pre-wrap max-h-64 overflow-y-auto">
            {original || <span className="text-gray-400 italic">Not available</span>}
          </div>
        </div>
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-green-600 dark:text-green-400 uppercase tracking-wider flex items-center gap-1">
              <ShieldCheck className="h-3 w-3" /> Hardened skill
            </span>
            {output && (
              <button type="button" onClick={() => copyToClipboard(output)} className="text-gray-400 hover:text-gray-600 p-1">
                <Copy className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
          <div className="p-3 rounded-lg bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-800/50 text-sm font-mono whitespace-pre-wrap max-h-64 overflow-y-auto">
            {output || <span className="text-gray-400 italic">No output</span>}
          </div>
        </div>
      </div>
    );
  };

  // ─── Render ──────────────────────────────────────────────────
  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Skills Hardener</h1>
            <p className="text-sm text-gray-600 dark:text-gray-400 mt-0.5">
              Harden Cursor and Claude agent skills with guardrails against injection and tool misuse
            </p>
          </div>
          <Zap className="h-8 w-8 text-primary-600 dark:text-primary-400" />
        </div>
      </div>

      {/* Tab bar */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'new', label: 'New Skill' },
            { id: 'active', label: `Active${activeJobs.length ? ` (${activeJobs.length})` : ''}` },
            { id: 'past', label: 'Past' },
          ].map((tab) => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
              }`}>
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab content card */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">

        {/* ── New Skill ─────────────────────────────────── */}
        {activeTab === 'new' && (
          <div className="p-6 space-y-5">
            <div className="flex items-start gap-3 p-3 rounded-lg bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800/50">
              <AlertCircle className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" />
              <p className="text-xs text-amber-800 dark:text-amber-200">
                Upload a Cursor or Claude skill file (<code className="text-xs">SKILL.md</code>, YAML, or JSON).
                We analyse instructions, tool boundaries, and data-handling patterns, then append a Security Guidelines section.
              </p>
            </div>

            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => { e.preventDefault(); acceptSkillFile(e.dataTransfer.files?.[0]); }}
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center cursor-pointer hover:border-primary-400 dark:hover:border-primary-500 hover:bg-primary-50/50 dark:hover:bg-primary-950/20 transition-colors">
              <input ref={fileInputRef} type="file" accept=".md,.markdown,.yaml,.yml,.json,.txt"
                onChange={(e) => acceptSkillFile(e.target.files?.[0])} className="hidden" />
              {file ? (
                <div className="flex items-center justify-center gap-3">
                  <FileText className="h-6 w-6 text-primary-500" />
                  <div className="text-left">
                    <p className="font-medium text-gray-900 dark:text-white text-sm">{file.name}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">{(file.size / 1024).toFixed(1)} KB</p>
                  </div>
                  <button type="button" onClick={(e) => { e.stopPropagation(); setFile(null); }}
                    className="p-1 rounded-full hover:bg-gray-200 dark:hover:bg-gray-700">
                    <X className="h-4 w-4 text-gray-500" />
                  </button>
                </div>
              ) : (
                <div>
                  <Upload className="h-8 w-8 text-gray-400 mx-auto mb-2" />
                  <p className="text-gray-600 dark:text-gray-300 text-sm font-medium">Drop your skill file here or click to browse</p>
                  <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">.md, .yaml, .yml, .json, .txt</p>
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Skill name <span className="text-red-500">*</span>
              </label>
              <input type="text" value={skillName} onChange={(e) => setSkillName(e.target.value)}
                placeholder="e.g. database-migration-assistant" className="input w-full max-w-md" />
            </div>

            <LockedOverlay locked={!hasPermission('triksha.scan.run')} message="You do not have permission to harden skills">
              <button type="button" onClick={handleSubmit}
                disabled={loading || !file || !skillName.trim()}
                className="btn-primary w-full flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed">
                {loading
                  ? <><Loader2 className="h-4 w-4 animate-spin" /> Submitting…</>
                  : <><ShieldCheck className="h-4 w-4" /> Harden Skill</>}
              </button>
            </LockedOverlay>

            {error && (
              <div className="flex items-start gap-3 p-3 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800/50">
                <AlertCircle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
                <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
              </div>
            )}
          </div>
        )}

        {/* ── Active ────────────────────────────────────── */}
        {activeTab === 'active' && (
          <div className="p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">Active jobs</h3>
              <button type="button" onClick={() => loadJobs()} className="btn-outline btn-sm" disabled={listLoading}>
                <RefreshCw className={`h-4 w-4 ${listLoading ? 'animate-spin' : ''}`} />
              </button>
            </div>
            {activeJobs.length === 0 ? (
              <div className="text-center py-12">
                <Zap className="mx-auto h-12 w-12 text-gray-400" />
                <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No active jobs</h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Upload a skill on the New Skill tab.</p>
                <button type="button" onClick={() => setActiveTab('new')} className="mt-4 btn-primary btn-sm">New Skill</button>
              </div>
            ) : (
              <div className="space-y-3">
                {activeJobs.map((job) => {
                  const pct = progressMap[job.job_id] ?? job.progress ?? 0;
                  const r = 20, circ = 2 * Math.PI * r, dash = (pct / 100) * circ;
                  return (
                    <div key={job.job_id} className="border rounded-lg p-4 border-gray-200 dark:border-gray-700">
                      <div className="flex items-center justify-between">
                        <div className="min-w-0">
                          <h4 className="text-sm font-medium text-gray-900 dark:text-white truncate">{job.skill_name || 'Skill job'}</h4>
                          <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5 flex items-center gap-2 flex-wrap">
                            <span className={`inline-flex px-2 py-0.5 rounded-full text-xs font-medium ${
                              job.status === 'running'
                                ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                                : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                            }`}>{job.status}</span>
                            {isUploadJob(job)
                              ? <span className="text-purple-600 dark:text-purple-400">Upload</span>
                              : job.repo_url && (
                                <span className="inline-flex items-center gap-1 truncate max-w-xs">
                                  <GitBranch className="h-3 w-3 shrink-0" />
                                  {job.repo_url.replace(/^https?:\/\//, '')}
                                </span>
                              )}
                          </p>
                        </div>
                        <div className="relative flex-shrink-0 ml-4" style={{ width: 52, height: 52 }}>
                          <svg width="52" height="52" viewBox="0 0 52 52">
                            <circle cx="26" cy="26" r={r} fill="none" className="stroke-gray-200 dark:stroke-gray-700" strokeWidth="4" />
                            <circle cx="26" cy="26" r={r} fill="none" className="stroke-primary-500" strokeWidth="4"
                              strokeLinecap="round" strokeDasharray={`${dash} ${circ}`}
                              transform="rotate(-90 26 26)" style={{ transition: 'stroke-dasharray 0.5s ease' }} />
                          </svg>
                          <span className="absolute inset-0 flex items-center justify-center text-xs font-semibold text-gray-700 dark:text-gray-300">{pct}%</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ── Past ──────────────────────────────────────── */}
        {activeTab === 'past' && (
          <div className="p-6 space-y-4">
            {/* Toolbar */}
            <div className="flex items-center gap-2">
              <select className="select h-9 w-auto shrink-0" value={pastSubTab}
                onChange={(e) => setPastSubTab(e.target.value)} aria-label="Ownership filter">
                <option value="my-jobs">My Jobs</option>
                <option value="other-jobs">Other Jobs</option>
              </select>
              <input type="text" className="input h-9 flex-1 min-w-[8rem]" placeholder="Search by name, file, or repo"
                value={pastSearch} onChange={(e) => setPastSearch(e.target.value)} />
              <select className="select h-9 w-auto shrink-0" value={pastStatus}
                onChange={(e) => setPastStatus(e.target.value)} aria-label="Status filter">
                <option value="all">All statuses</option>
                <option value="completed">Completed</option>
                <option value="failed">Failed</option>
              </select>
              {/* Date range */}
              <div className="relative shrink-0" ref={dateFilterRef}>
                <button type="button" onClick={() => setDateFilterOpen((o) => !o)}
                  className={`btn-outline btn-sm h-9 inline-flex items-center gap-1.5 px-2.5 ${
                    pastDateFrom || pastDateTo ? 'border-primary-300 dark:border-primary-600 text-primary-700 dark:text-primary-300' : ''
                  }`} aria-expanded={dateFilterOpen}>
                  <Calendar className="h-4 w-4 shrink-0" />
                  <span className="hidden sm:inline max-w-[9rem] truncate text-xs">{dateFilterLabel}</span>
                  <ChevronDown className={`h-3.5 w-3.5 shrink-0 transition-transform ${dateFilterOpen ? 'rotate-180' : ''}`} />
                </button>
                {dateFilterOpen && (
                  <div className="absolute right-0 z-30 mt-1 w-64 rounded-lg border border-gray-200 dark:border-gray-600 bg-white dark:bg-gray-800 shadow-lg p-3 space-y-3" role="dialog">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-gray-700 dark:text-gray-200">Date range</span>
                      {(pastDateFrom || pastDateTo) && (
                        <button type="button" onClick={() => { setPastDateFrom(''); setPastDateTo(''); }}
                          className="text-xs text-primary-600 dark:text-primary-400 hover:underline">Clear</button>
                      )}
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <label className="block">
                        <span className="text-[10px] font-medium uppercase tracking-wide text-gray-500">From</span>
                        <input type="date" className="input h-8 w-full mt-1 text-xs" value={pastDateFrom}
                          onChange={(e) => setPastDateFrom(e.target.value)} max={pastDateTo || undefined} />
                      </label>
                      <label className="block">
                        <span className="text-[10px] font-medium uppercase tracking-wide text-gray-500">To</span>
                        <input type="date" className="input h-8 w-full mt-1 text-xs" value={pastDateTo}
                          onChange={(e) => setPastDateTo(e.target.value)} min={pastDateFrom || undefined} />
                      </label>
                    </div>
                  </div>
                )}
              </div>
              <button type="button" onClick={() => loadJobs()} className="btn-outline btn-sm p-2 shrink-0"
                disabled={listLoading} title="Refresh">
                <RefreshCw className={`h-4 w-4 ${listLoading ? 'animate-spin' : ''}`} />
              </button>
            </div>

            {/* List */}
            {listLoading && pastJobs.length === 0 ? (
              <div className="space-y-2">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="animate-pulse h-14 bg-gray-100 dark:bg-gray-700 rounded-lg" />
                ))}
              </div>
            ) : filteredPastJobs.length === 0 ? (
              <div className="text-center py-12">
                <FileSearch className="mx-auto h-12 w-12 text-gray-400" />
                <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">
                  {hasPastFilters ? 'No matches' : 'No hardened skills yet'}
                </h3>
                <p className="mt-1 text-sm text-gray-500">
                  {hasPastFilters ? 'Try adjusting your search or filters.' : 'Upload a skill to get started.'}
                </p>
                {!hasPastFilters && (
                  <button type="button" onClick={() => setActiveTab('new')} className="mt-4 btn-primary btn-sm">New Skill</button>
                )}
              </div>
            ) : (
              <div className="space-y-3">
                {paginatedJobs.map((job) => {
                  const isExpanded = selectedJob?.job_id === job.job_id;
                  const output = hardenedOutput(job);
                  const reviewedAt = jobTimestamp(job);
                  return (
                    <div key={job.job_id} className="border rounded-lg border-gray-200 dark:border-gray-700">
                      <div className="flex items-center justify-between px-4 py-3">
                        <div className="flex items-center gap-3 min-w-0 flex-1">
                          {getStatusIcon(job.status)}
                          <JobSourceBadge job={job} />
                          <div className="min-w-0">
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white truncate">{job.skill_name || job.job_id}</h4>
                            <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                              {job.created_by && <span className="mr-2">{job.created_by}</span>}
                              {reviewedAt && <span>{reviewedAt.toLocaleDateString()}</span>}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center gap-1 ml-4 shrink-0">
                          {output && (
                            <button type="button" className="btn-outline btn-sm"
                              onClick={() => downloadAsText(output, `${(job.skill_name || 'skill').replace(/[^a-z0-9_-]/gi, '_')}_hardened.txt`)}>
                              <Download className="h-4 w-4 mr-1" />.txt
                            </button>
                          )}
                          {job.status === 'completed' && (
                            <button type="button" className="btn-outline btn-sm"
                              onClick={() => selectAndLoadJob(job)}
                              disabled={loadingJobId === job.job_id}>
                              {loadingJobId === job.job_id
                                ? <RefreshCw className="h-4 w-4 mr-1 animate-spin" />
                                : <Eye className="h-4 w-4 mr-1" />}
                              {isExpanded ? 'Hide' : 'View'}
                            </button>
                          )}
                          {hasPermission('triksha.scan.run') && canAccessScan(job.created_by) && (
                            <button type="button"
                              onClick={() => deleteJob(job.job_id)}
                              disabled={actionBusy[job.job_id]}
                              className="btn-outline btn-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 border-red-200 dark:border-red-800"
                              title="Delete job">
                              {actionBusy[job.job_id]
                                ? <RefreshCw className="h-4 w-4 animate-spin" />
                                : <Trash2 className="h-4 w-4" />}
                            </button>
                          )}
                        </div>
                      </div>
                      {isExpanded && (
                        <div className="px-4 pb-4 pt-3 border-t border-gray-200 dark:border-gray-700">
                          {job.status === 'failed'
                            ? <p className="text-sm text-red-600 dark:text-red-400">{job.error || 'Hardening failed'}</p>
                            : <ResultPanels job={job} />}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            <PastListPagination
              currentPage={currentPage} totalPages={totalPages}
              pageSize={JOBS_PER_PAGE} totalItems={filteredPastJobs.length}
              onPageChange={setCurrentPage} itemLabel="skills" />
          </div>
        )}
      </div>
    </div>
  );
};

export default SkillHardener;

import React, { useState, useRef, useEffect, useMemo } from 'react';
import { createApiClient } from '../contexts/AuthContext';
import toast from 'react-hot-toast';
import {
  ShieldCheck,
  Copy,
  Download,
  Loader2,
  AlertCircle,
  CheckCircle,
  Clock,
  XCircle,
  RefreshCw,
  Eye,
  FileSearch,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

const JOBS_PER_PAGE = 20;

const cleanPromptName = (name) =>
  (name || '')
    .replace(/^\s*\[Auto\]\s*/i, '')
    .replace(/\s{2,}/g, ' ')
    .trim();

const PromptHardener = () => {
  const [activeTab, setActiveTab] = useState('new');
  const [promptName, setPromptName] = useState('');
  const [systemPrompt, setSystemPrompt] = useState('');
  const [context, setContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [pastSearchQuery, setPastSearchQuery] = useState('');

  const [allJobs, setAllJobs] = useState([]);
  const [listLoading, setListLoading] = useState(false);
  const [selectedJob, setSelectedJob] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);

  // per-job SSE progress: { [job_id]: number 0-100 }
  const [progressMap, setProgressMap] = useState({});

  const apiClient = createApiClient();
  const listPollRef = useRef(null);
  const streamControllersRef = useRef({});

  const activeJobs = useMemo(
    () => allJobs.filter(j => j.status === 'queued' || j.status === 'running'),
    [allJobs]
  );

  const pastJobs = useMemo(() => {
    const completed = allJobs.filter(j => j.status === 'completed' || j.status === 'failed');
    completed.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
    return completed;
  }, [allJobs]);

  const filteredPastJobs = useMemo(() => {
    const q = pastSearchQuery.trim().toLowerCase();
    if (!q) return pastJobs;
    return pastJobs.filter(j =>
      (j.prompt_name || '').toLowerCase().includes(q) ||
      (j.system_prompt || '').slice(0, 200).toLowerCase().includes(q)
    );
  }, [pastJobs, pastSearchQuery]);

  const totalPages = Math.ceil(filteredPastJobs.length / JOBS_PER_PAGE);
  const paginatedJobs = useMemo(() => {
    const start = (currentPage - 1) * JOBS_PER_PAGE;
    return filteredPastJobs.slice(start, start + JOBS_PER_PAGE);
  }, [filteredPastJobs, currentPage]);

  useEffect(() => { setCurrentPage(1); }, [filteredPastJobs.length]);

  const loadJobs = async (soft = false) => {
    if (!soft) setListLoading(true);
    try {
      const data = await apiClient.get('/harden/list?mine=true');
      setAllJobs(Array.isArray(data?.jobs) ? data.jobs : []);
    } catch {}
    if (!soft) setListLoading(false);
  };

  // Poll when on active or past tab
  useEffect(() => {
    if (activeTab === 'active' || activeTab === 'past') {
      loadJobs();
      listPollRef.current = setInterval(() => loadJobs(true), 5000);
    }
    return () => { if (listPollRef.current) clearInterval(listPollRef.current); };
  }, [activeTab]);

  // SSE streaming for active jobs
  const startStream = (jobId) => {
    if (streamControllersRef.current[jobId]) return;
    const controller = new AbortController();
    streamControllersRef.current[jobId] = controller;

    fetch(`/harden/${jobId}/events`, {
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
                setProgressMap(prev => ({ ...prev, [jobId]: payload.progress }));
              }
              if (payload.status === 'completed' || payload.status === 'failed') {
                loadJobs(true);
              }
            } catch {}
          }
        }
      }
    }).catch(() => {}).finally(() => {
      delete streamControllersRef.current[jobId];
    });
  };

  const stopStream = (jobId) => {
    streamControllersRef.current[jobId]?.abort();
    delete streamControllersRef.current[jobId];
  };

  useEffect(() => {
    activeJobs.forEach(j => startStream(j.job_id));
    const activeIds = new Set(activeJobs.map(j => j.job_id));
    Object.keys(streamControllersRef.current).forEach(id => {
      if (!activeIds.has(id)) stopStream(id);
    });
  }, [activeJobs]);

  const handleSubmit = async () => {
    if (!promptName.trim()) {
      toast.error('Please give this prompt a name so you can find it later');
      return;
    }
    if (!systemPrompt.trim() || systemPrompt.trim().length < 10) {
      toast.error('Please enter a system prompt (at least 10 characters)');
      return;
    }
    setLoading(true);
    try {
      const response = await apiClient.post('/harden/submit', {
        prompt_name: promptName.trim(),
        system_prompt: systemPrompt.trim(),
        context: context.trim() || undefined,
      });
      if (response.job_id) {
        toast.success('Submitted — generating security rules…');
        setActiveTab('active');
        loadJobs();
        startStream(response.job_id);
      } else {
        toast.error('Submission failed');
      }
    } catch (err) {
      toast.error(err?.message || 'Request failed');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
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

  const getStatusIcon = (status) => {
    if (status === 'completed') return <CheckCircle className="h-5 w-5 text-green-500 shrink-0" />;
    if (status === 'failed') return <XCircle className="h-5 w-5 text-red-500 shrink-0" />;
    if (status === 'running') return <RefreshCw className="h-5 w-5 text-blue-500 animate-spin shrink-0" />;
    return <Clock className="h-5 w-5 text-gray-400 shrink-0" />;
  };

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">System Prompt Hardener</h1>
            <p className="text-sm text-gray-600 dark:text-gray-400 mt-0.5">
              Analyse your GenAI system prompts and get security rules to append against prompt injection, jailbreaking, and adversarial attacks
            </p>
          </div>
          <ShieldCheck className="h-8 w-8 text-primary-600 dark:text-primary-400" />
        </div>
      </div>

      {/* Tab bar */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'new', label: 'New' },
            { id: 'active', label: `Active${activeJobs.length ? ` (${activeJobs.length})` : ''}` },
            { id: 'past', label: 'Past' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="card">

        {/* ── New Tab ── */}
        {activeTab === 'new' && (
          <div className="p-6 space-y-5">
            <div className="flex items-start gap-3 p-3 rounded-lg bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800/50">
              <ShieldCheck className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
              <p className="text-xs text-green-700 dark:text-green-300">
                Paste your system prompt below and get a self-contained block of security rules you can append to your existing prompt. Covers prompt injection, jailbreaks, system prompt extraction, context manipulation, and instruction override attacks.
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Prompt Name <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={promptName}
                onChange={(e) => setPromptName(e.target.value)}
                placeholder="e.g. Customer Support v2, Brand Marketing prompt"
                className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:ring-2 focus:ring-green-500 focus:border-transparent text-sm"
              />
              <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                Give this prompt a memorable name — you'll use it to find this job later under the Past tab.
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                System Prompt
              </label>
              <textarea
                value={systemPrompt}
                onChange={(e) => setSystemPrompt(e.target.value)}
                placeholder="Paste your system prompt here…"
                rows={6}
                className="w-full px-4 py-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:ring-2 focus:ring-green-500 focus:border-transparent text-sm font-mono resize-vertical"
              />
              <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">{systemPrompt.length} characters</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Use Case Context <span className="text-gray-400 font-normal">(optional)</span>
              </label>
              <input
                type="text"
                value={context}
                onChange={(e) => setContext(e.target.value)}
                placeholder="e.g. Customer-facing chatbot handling PII, internal code assistant"
                className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:ring-2 focus:ring-green-500 focus:border-transparent text-sm"
              />
            </div>

            <button
              onClick={handleSubmit}
              disabled={loading || !promptName.trim() || systemPrompt.trim().length < 10}
              className="btn-primary w-full flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <><Loader2 className="h-4 w-4 animate-spin" />Submitting…</>
              ) : (
                <><ShieldCheck className="h-4 w-4" />Generate Security Prompt</>
              )}
            </button>
          </div>
        )}

        {/* ── Active Tab ── */}
        {activeTab === 'active' && (
          <div className="p-6 space-y-5">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">Active Jobs</h3>
              <button onClick={() => loadJobs()} className="btn-outline btn-sm" disabled={listLoading}>
                <RefreshCw className={`h-4 w-4 ${listLoading ? 'animate-spin' : ''}`} />
              </button>
            </div>

            {activeJobs.length === 0 ? (
              <div className="text-center py-12">
                <ShieldCheck className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
                <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No active jobs</h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Submit a prompt to generate security rules.</p>
                <button onClick={() => setActiveTab('new')} className="mt-4 btn-primary btn-sm">New</button>
              </div>
            ) : (
              <div className="space-y-3">
                {activeJobs.map(job => {
                  const pct = progressMap[job.job_id] ?? job.progress ?? 0;
                  const radius = 20;
                  const circumference = 2 * Math.PI * radius;
                  const dash = (pct / 100) * circumference;
                  return (
                    <div key={job.job_id} className="border rounded-lg p-4 border-gray-200 dark:border-gray-700">
                      <div className="flex items-center justify-between">
                        <div className="min-w-0">
                          <h4 className="text-sm font-medium text-gray-900 dark:text-white truncate">
                            {job.prompt_name || (job.system_prompt?.slice(0, 60) + (job.system_prompt?.length > 60 ? '…' : ''))}
                          </h4>
                          <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
                              job.status === 'running'
                                ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                                : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                            }`}>{job.status}</span>
                          </p>
                        </div>
                        <div className="relative flex-shrink-0 ml-4" style={{ width: 52, height: 52 }}>
                          <svg width="52" height="52" viewBox="0 0 52 52">
                            <circle cx="26" cy="26" r={radius} fill="none"
                              className="stroke-gray-200 dark:stroke-gray-700" strokeWidth="4" />
                            <circle cx="26" cy="26" r={radius} fill="none"
                              className="stroke-green-500" strokeWidth="4"
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

        {/* ── Past Tab ── */}
        {activeTab === 'past' && (
          <div className="p-6 space-y-5">
            <div className="flex items-center gap-2">
              <div className="relative flex-1 min-w-0">
                <FileSearch className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  value={pastSearchQuery}
                  onChange={(e) => setPastSearchQuery(e.target.value)}
                  placeholder="Search by prompt name or content…"
                  className="input h-9 w-full pl-9 pr-4"
                />
              </div>
              <button
                onClick={() => loadJobs()}
                className="btn-outline btn-sm p-2"
                disabled={listLoading}
                title="Refresh"
              >
                <RefreshCw className={`h-4 w-4 ${listLoading ? 'animate-spin' : ''}`} />
              </button>
            </div>

            {pastSearchQuery && (
              <p className="text-xs text-gray-500 dark:text-gray-400 -mt-2">
                Showing {filteredPastJobs.length} of {pastJobs.length} jobs
              </p>
            )}

            {listLoading ? (
              <div className="space-y-2">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="animate-pulse h-14 bg-gray-100 dark:bg-gray-700 rounded-lg border border-gray-200 dark:border-gray-600" />
                ))}
              </div>
            ) : pastJobs.length === 0 ? (
              <div className="text-center py-12">
                <FileSearch className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
                <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No prompts yet</h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Prompts you harden via this page will appear here.</p>
              </div>
            ) : filteredPastJobs.length === 0 ? (
              <div className="text-center py-12">
                <FileSearch className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
                <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No matches</h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">No jobs match "{pastSearchQuery}". Try a different search term.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {paginatedJobs.map(job => {
                  const isExpanded = selectedJob?.job_id === job.job_id;
                  return (
                    <div key={job.job_id} className="border rounded-lg border-gray-200 dark:border-gray-700">
                      <div className="flex items-center justify-between px-4 py-3">
                        <div className="flex items-center gap-3 min-w-0 flex-1">
                          {getStatusIcon(job.status)}
                          <div className="min-w-0 flex items-baseline gap-2 flex-wrap">
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white truncate">
                              {cleanPromptName(job.prompt_name) || (job.system_prompt?.slice(0, 60) + (job.system_prompt?.length > 60 ? '…' : ''))}
                            </h4>
                            {job.created_at && (
                              <span className="text-xs text-gray-500 dark:text-gray-400">
                                {new Date(job.created_at).toLocaleDateString()}
                              </span>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center space-x-1 ml-4 shrink-0">
                          {(job.security_addendum || job.hardened_prompt) && (
                            <button
                              onClick={() => downloadAsText(job.security_addendum || job.hardened_prompt, `${(cleanPromptName(job.prompt_name) || 'security_rules').replace(/[^a-z0-9_-]/gi, '_')}.txt`)}
                              className="btn-outline btn-sm"
                              title="Download security rules"
                            >
                              <Download className="h-4 w-4 mr-1" />.txt
                            </button>
                          )}
                          {job.status === 'completed' && (
                            <button
                              onClick={() => setSelectedJob(isExpanded ? null : job)}
                              className="btn-outline btn-sm"
                            >
                              <Eye className="h-4 w-4 mr-1" />
                              {isExpanded ? 'Hide' : 'View'}
                            </button>
                          )}
                        </div>
                      </div>

                      {isExpanded && (() => {
                        const addendum = job.security_addendum || job.hardened_prompt;
                        return (
                          <div className="px-4 pb-4 pt-3 border-t border-gray-200 dark:border-gray-700">
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                              <div>
                                <div className="flex items-center justify-between mb-2">
                                  <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Context</span>
                                  <button
                                    onClick={() => copyToClipboard(job.original_prompt || job.system_prompt)}
                                    className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 p-1"
                                    title="Copy original"
                                  >
                                    <Copy className="h-3.5 w-3.5" />
                                  </button>
                                </div>
                                <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 text-sm text-gray-700 dark:text-gray-300 font-mono whitespace-pre-wrap max-h-64 overflow-y-auto">
                                  {job.original_prompt || job.system_prompt}
                                </div>
                              </div>
                              <div>
                                <div className="flex items-center justify-between mb-2">
                                  <span className="text-xs font-medium text-green-600 dark:text-green-400 uppercase tracking-wider flex items-center gap-1">
                                    <ShieldCheck className="h-3 w-3" />Security Rules
                                  </span>
                                  {addendum && (
                                    <button
                                      onClick={() => copyToClipboard(addendum)}
                                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 p-1"
                                      title="Copy security rules"
                                    >
                                      <Copy className="h-3.5 w-3.5" />
                                    </button>
                                  )}
                                </div>
                                <div className="p-3 rounded-lg bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-800/50 text-sm text-gray-700 dark:text-gray-300 font-mono whitespace-pre-wrap max-h-64 overflow-y-auto">
                                  {addendum || <span className="text-gray-400 italic">No output available — restart the backend and re-run.</span>}
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      })()}
                    </div>
                  );
                })}
              </div>
            )}

            {filteredPastJobs.length > JOBS_PER_PAGE && (
              <div className="flex items-center justify-between mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                <div className="text-sm text-gray-700 dark:text-gray-300">
                  Showing <span className="font-medium">{((currentPage - 1) * JOBS_PER_PAGE) + 1}</span>–
                  <span className="font-medium">{Math.min(currentPage * JOBS_PER_PAGE, filteredPastJobs.length)}</span> of{' '}
                  <span className="font-medium">{filteredPastJobs.length}</span>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                    className="btn-outline btn-sm disabled:opacity-40"
                  >
                    <ChevronLeft className="h-4 w-4" />
                  </button>
                  <span className="text-sm text-gray-700 dark:text-gray-300 px-2">
                    {currentPage} / {totalPages}
                  </span>
                  <button
                    onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                    disabled={currentPage === totalPages}
                    className="btn-outline btn-sm disabled:opacity-40"
                  >
                    <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default PromptHardener;

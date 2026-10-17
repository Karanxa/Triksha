import React, { useEffect, useState, useCallback } from 'react';
import { Routes, Route, useNavigate, useSearchParams } from 'react-router-dom';
import toast from 'react-hot-toast';

const TOKEN_KEY = 'triksha_demo_token';
const SCAN_LABELS = { llm: 'LLM Red Teaming', agent: 'Autonomous Agent Scan', mcp: 'MCP Scan' };

async function api(path, { token, body, method } = {}) {
  const res = await fetch(`/demo${path}`, {
    method: method || (body ? 'POST' : 'GET'),
    headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Demo-Token': token } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Request failed');
  return data;
}

const input = 'w-full rounded border border-slate-600 bg-slate-800 px-3 py-2 text-slate-100';
const button = 'rounded bg-indigo-600 px-4 py-2 font-medium text-white hover:bg-indigo-500 disabled:opacity-50';

function Shell({ children }) {
  return (
    <div className="min-h-screen bg-slate-900 text-slate-200">
      <div className="mx-auto max-w-2xl px-4 py-12">
        <h1 className="mb-2 text-3xl font-bold">Triksha</h1>
        <p className="mb-8 text-slate-400">Context-aware red teaming for AI models, agents and MCP servers.</p>
        {children}
      </div>
    </div>
  );
}

function Register() {
  const [f, setF] = useState({ email: '', name: '', company: '', job_title: '', phone: '', country: '', interest: '', marketing_consent: false });
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value });

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api('/register', { body: f });
      setSent(true);
    } catch (err) {
      toast.error(err.message);
    } finally {
      setBusy(false);
    }
  };

  if (sent) return <Shell><p>Check <b>{f.email}</b> for a confirmation link. It will give you a 1-hour access token.</p></Shell>;
  return (
    <Shell>
      <form onSubmit={submit} className="space-y-3">
        <input required type="email" placeholder="Work email *" className={input} value={f.email} onChange={set('email')} />
        <input required placeholder="Full name *" className={input} value={f.name} onChange={set('name')} />
        <input required placeholder="Company *" className={input} value={f.company} onChange={set('company')} />
        <input placeholder="Job title" className={input} value={f.job_title} onChange={set('job_title')} />
        <input placeholder="Phone" className={input} value={f.phone} onChange={set('phone')} />
        <input placeholder="Country" className={input} value={f.country} onChange={set('country')} />
        <textarea placeholder="What are you hoping to secure?" className={input} value={f.interest} onChange={set('interest')} />
        <label className="flex items-center gap-2 text-sm text-slate-400">
          <input type="checkbox" checked={f.marketing_consent} onChange={set('marketing_consent')} />
          Keep me posted about Triksha
        </label>
        <button className={button} disabled={busy}>{busy ? 'Sending…' : 'Get access'}</button>
      </form>
    </Shell>
  );
}

function Verify() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [state, setState] = useState({ loading: true });

  useEffect(() => {
    api('/verify', { body: { code: params.get('code') || '' } })
      .then((d) => { localStorage.setItem(TOKEN_KEY, d.token); setState({ token: d.token }); })
      .catch((e) => setState({ error: e.message }));
  }, [params]);

  if (state.loading) return <Shell>Confirming…</Shell>;
  if (state.error) return <Shell><p className="text-red-400">{state.error}</p></Shell>;
  return (
    <Shell>
      <p className="mb-2">Email confirmed. Your access token (valid 1 hour):</p>
      <code className="mb-4 block break-all rounded bg-slate-800 p-3">{state.token}</code>
      <button className={button} onClick={() => navigate('/run')}>Continue</button>
    </Shell>
  );
}

function Run() {
  const [token, setToken] = useState(localStorage.getItem(TOKEN_KEY) || '');
  const [targets, setTargets] = useState(null);
  const [type, setType] = useState('');
  const [targetId, setTargetId] = useState('');
  const [scan, setScan] = useState(null);
  const [state, setState] = useState(null);

  useEffect(() => {
    if (!token) return;
    api('/targets', { token }).then(setTargets).catch((e) => { toast.error(e.message); setTargets([]); });
  }, [token]);

  const poll = useCallback(async (id) => {
    try {
      const s = await api(`/scan/${id}`, { token });
      setState(s);
      if (!['completed', 'failed', 'error', 'cancelled'].includes(s.status)) setTimeout(() => poll(id), 3000);
    } catch (e) { toast.error(e.message); }
  }, [token]);

  const start = async () => {
    try {
      const s = await api('/scan', { token, body: { scan_type: type, target_id: targetId } });
      setScan(s);
      poll(s.scan_id);
    } catch (e) { toast.error(e.message); }
  };

  if (!token) {
    return (
      <Shell>
        <p className="mb-2">Paste your access token:</p>
        <input className={input} onChange={(e) => setToken(e.target.value.trim())} />
      </Shell>
    );
  }
  if (!targets) return <Shell>Loading…</Shell>;

  if (scan) {
    return (
      <Shell>
        <h2 className="mb-2 text-xl">{SCAN_LABELS[scan.scan_type]}</h2>
        <p className="mb-4">Status: <b>{state?.status || 'queued'}</b>{state?.progress?.percent != null && ` (${state.progress.percent}%)`}</p>
        {state?.results && (
          <pre className="max-h-[60vh] overflow-auto rounded bg-slate-800 p-3 text-xs">{JSON.stringify(state.results, null, 2)}</pre>
        )}
      </Shell>
    );
  }

  const options = targets.filter((t) => t.scan_type === type);
  return (
    <Shell>
      <h2 className="mb-3 text-xl">Choose a scan</h2>
      <div className="mb-4 flex gap-2">
        {Object.entries(SCAN_LABELS).map(([k, v]) => (
          <button key={k} className={`${button} ${type === k ? '' : '!bg-slate-700'}`} onClick={() => { setType(k); setTargetId(''); }}>{v}</button>
        ))}
      </div>
      {type && (
        <select className={`${input} mb-4`} value={targetId} onChange={(e) => setTargetId(e.target.value)}>
          <option value="">Select a target</option>
          {options.map((t) => <option key={t.id} value={t.id}>{t.label} — {t.description}</option>)}
        </select>
      )}
      <button className={button} disabled={!targetId} onClick={start}>Run scan</button>
      <p className="mt-3 text-sm text-slate-500">One scan per token.</p>
    </Shell>
  );
}

export default function Demo() {
  return (
    <Routes>
      <Route path="/verify" element={<Verify />} />
      <Route path="/run" element={<Run />} />
      <Route path="*" element={<Register />} />
    </Routes>
  );
}

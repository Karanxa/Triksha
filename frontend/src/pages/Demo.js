import React, { useState } from 'react';
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';

const TOKEN_KEY = 'triksha_demo_token';

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

const field = 'w-full rounded-lg border border-white/10 bg-white/[0.04] px-3.5 py-2.5 text-[15px] text-white placeholder-slate-500 outline-none transition focus:border-[#3987e5] focus:bg-white/[0.07]';

function Register() {
  const [f, setF] = useState({ email: '', name: '', company: '', github: '' });
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState('');
  const navigate = useNavigate();
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });

  const unlock = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api('/session', { token });
      localStorage.setItem(TOKEN_KEY, token);
      navigate('/launch');
    } catch (err) {
      toast.error('That token didn\'t work. Copy it again from the email.');
    } finally {
      setBusy(false);
    }
  };

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      const { github, ...rest } = f;
      // GitHub handle rides in `interest` so the backend schema stays unchanged.
      await api('/register', { body: { ...rest, interest: `github:${github.replace(/^@/, '')}`, marketing_consent: false } });
      setSent(true);
    } catch (err) {
      toast.error(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#0d0d0d] text-white">
      <div className="pointer-events-none absolute -left-40 -top-40 h-[480px] w-[480px] rounded-full bg-[#3987e5]/25 blur-[120px]" />
      <div className="pointer-events-none absolute -bottom-40 right-0 h-[420px] w-[420px] rounded-full bg-[#9085e9]/25 blur-[120px]" />
      <div className="relative mx-auto grid min-h-screen max-w-5xl items-center gap-12 px-6 py-10 lg:grid-cols-2">
        <div>
          <div className="mb-8 flex items-center gap-2.5 text-lg font-extrabold">
            <span className="grid h-7 w-7 place-items-center rounded-lg bg-gradient-to-br from-[#3987e5] to-[#9085e9] text-sm">◈</span>Triksha
          </div>
          <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[13px] text-slate-300">
            <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-500" />
            Black Hat India 2026 · Arsenal
          </span>
          <h1 className="mb-4 mt-5 text-4xl font-extrabold leading-[1.05] tracking-tight sm:text-5xl">
            Red-team an AI system <span className="bg-gradient-to-r from-[#3987e5] to-[#9085e9] bg-clip-text text-transparent">live, in minutes.</span>
          </h1>
          <p className="max-w-md text-lg text-slate-300">
            Seen us at the Arsenal booth? Try Triksha yourself on a deliberately vulnerable LLM, agent or MCP server.
          </p>
          <div className="mt-6 flex max-w-md items-start gap-3 rounded-xl border border-[#9085e9]/40 bg-gradient-to-r from-[#3987e5]/15 to-[#9085e9]/15 p-4">
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-white/10 text-lg">⭐</span>
            <p className="text-[15px] text-slate-300">
              <b className="block text-white">Open-source contributor waitlist</b>
              Sign up for your token and you're on the list to help build Triksha.
            </p>
          </div>
        </div>

        <div className="rounded-2xl border border-white/10 bg-[#1a1a19]/90 p-6 shadow-2xl backdrop-blur sm:p-8">
          {sent ? (
            <form onSubmit={unlock} className="py-2">
              <div className="mb-4 grid h-14 w-14 place-items-center rounded-full bg-[#3987e5]/15 text-2xl">✉️</div>
              <h2 className="mb-2 text-2xl font-bold">Your token is on its way</h2>
              <p className="mb-5 text-slate-300">We emailed it to <b className="text-white">{f.email}</b>. Paste it here to get started.</p>
              <input required autoFocus placeholder="Paste your token" className={`${field} mb-3 font-mono`} value={token} onChange={(e) => setToken(e.target.value.trim())} />
              <button className="w-full rounded-lg bg-[#3987e5] px-4 py-3 font-semibold text-white transition hover:brightness-110 disabled:opacity-60" disabled={busy}>{busy ? 'Checking…' : 'Unlock →'}</button>
              <p className="mt-4 text-sm text-slate-500">Nothing there? Check spam, or <button type="button" className="text-[#3987e5] hover:underline" onClick={() => setSent(false)}>use a different email</button>.</p>
            </form>
          ) : (
            <form onSubmit={submit} className="space-y-3.5">
              <h2 className="mb-1 text-2xl font-bold">Get your token</h2>
              <input required type="email" autoComplete="email" placeholder="Email" className={field} value={f.email} onChange={set('email')} />
              <input required autoComplete="name" placeholder="Full name" className={field} value={f.name} onChange={set('name')} />
              <input required autoComplete="organization" placeholder="Company" className={field} value={f.company} onChange={set('company')} />
              <input required pattern="@?[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}" title="GitHub username" placeholder="GitHub username (for contributor waitlist)" className={field} value={f.github} onChange={set('github')} />
              <button className="w-full rounded-lg bg-[#3987e5] px-4 py-3 font-semibold text-white transition hover:brightness-110 disabled:opacity-60" disabled={busy}>{busy ? 'Sending…' : 'Send my token →'}</button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}

// Launch page is only shown once a token has been issued.
function Launch() {
  if (!localStorage.getItem(TOKEN_KEY)) return <Navigate to="/" replace />;
  return <iframe title="Triksha" src="/triksha-launch.html" className="h-screen w-screen border-0" />;
}

export default function Demo() {
  return (
    <Routes>
      <Route path="/launch" element={<Launch />} />
      <Route path="*" element={<Register />} />
    </Routes>
  );
}

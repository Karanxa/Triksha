import React, { useEffect, useState } from 'react';
import { useAuth } from '../contexts/AuthContext';

/**
 * Triksha auth gate.
 * First run (no users yet) → setup wizard: admin account + LLM provider/key.
 * Otherwise → username/password login.
 * Rendered by App.js whenever the user is not authenticated.
 */
const PROVIDERS = [
  { id: 'gemini', label: 'Google Gemini', placeholder: 'AIza…', keyUrl: 'https://aistudio.google.com/apikey' },
  { id: 'openai', label: 'OpenAI', placeholder: 'sk-…', keyUrl: 'https://platform.openai.com/api-keys' },
  { id: 'anthropic', label: 'Anthropic (Claude)', placeholder: 'sk-ant-…', keyUrl: 'https://console.anthropic.com/settings/keys' },
];

export default function AuthGate() {
  const { login, signup, checkSetupStatus, completeSetup } = useAuth();
  const [mode, setMode] = useState('loading'); // loading | setup | login
  const [tab, setTab] = useState('login'); // login | signup (within the non-setup view)
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  // form state
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [provider, setProvider] = useState('gemini');
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState('');

  useEffect(() => {
    (async () => {
      const needsSetup = await checkSetupStatus();
      setMode(needsSetup ? 'setup' : 'login');
    })();
  }, [checkSetupStatus]);

  const onAuth = async (e) => {
    e.preventDefault();
    setError('');
    if (tab === 'signup' && password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }
    setBusy(true);
    try {
      if (tab === 'signup') {
        await signup(username, password);
      } else {
        await login(username, password);
      }
      // refreshSession flips isAuthenticated → App unmounts this gate.
    } catch (err) {
      setError(err.message || (tab === 'signup' ? 'Sign up failed' : 'Login failed'));
    } finally {
      setBusy(false);
    }
  };

  const switchTab = (t) => { setTab(t); setError(''); };

  const onSetup = async (e) => {
    e.preventDefault();
    setError('');
    if (password.length < 8) { setError('Password must be at least 8 characters.'); return; }
    if (!apiKey.trim()) { setError('An API key is required for the selected provider.'); return; }
    setBusy(true);
    try {
      await completeSetup({
        username, password,
        llm_provider: provider,
        llm_api_key: apiKey.trim(),
        llm_model: model.trim() || undefined,
      });
      // Auto-login with the just-created admin credentials.
      await login(username, password);
    } catch (err) {
      setError(err.message || 'Setup failed');
    } finally {
      setBusy(false);
    }
  };

  const selectedProvider = PROVIDERS.find((p) => p.id === provider) || PROVIDERS[0];

  return (
    <div style={styles.wrap}>
      <div style={styles.card}>
        <div style={styles.brand}>
          <span style={styles.logo}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 3l7 3v5c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6l7-3z" />
            </svg>
          </span>
          <div>
            <div style={styles.title}>Triksha</div>
            <div style={styles.subtitle}>AI Security Platform</div>
          </div>
        </div>

        {mode === 'loading' && <div style={styles.loading}>Loading…</div>}

        {mode === 'login' && (
          <form onSubmit={onAuth}>
            <div style={styles.tabs}>
              <button type="button" onClick={() => switchTab('login')}
                style={{ ...styles.tab, ...(tab === 'login' ? styles.tabActive : {}) }}>
                Sign in
              </button>
              <button type="button" onClick={() => switchTab('signup')}
                style={{ ...styles.tab, ...(tab === 'signup' ? styles.tabActive : {}) }}>
                Sign up
              </button>
            </div>
            <Field label="Username">
              <input style={styles.input} value={username} autoFocus
                onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
            </Field>
            <Field label={tab === 'signup' ? 'Password (min 8 chars)' : 'Password'}>
              <input style={styles.input} type="password" value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={tab === 'signup' ? 'new-password' : 'current-password'} />
            </Field>
            {error && <div style={styles.error}>{error}</div>}
            <button style={styles.button} disabled={busy} type="submit">
              {busy
                ? (tab === 'signup' ? 'Creating account…' : 'Signing in…')
                : (tab === 'signup' ? 'Create account' : 'Sign in')}
            </button>
            <div style={styles.switchRow}>
              {tab === 'login' ? (
                <span>New here? <button type="button" style={styles.linkBtn}
                  onClick={() => switchTab('signup')}>Create an account</button></span>
              ) : (
                <span>Already have an account? <button type="button" style={styles.linkBtn}
                  onClick={() => switchTab('login')}>Sign in</button></span>
              )}
            </div>
          </form>
        )}

        {mode === 'setup' && (
          <form onSubmit={onSetup}>
            <h2 style={styles.heading}>Welcome — first-run setup</h2>
            <p style={styles.help}>Create the admin account and connect an LLM provider. Settings are stored locally.</p>

            <div style={styles.sectionLabel}>Admin account</div>
            <Field label="Username">
              <input style={styles.input} value={username} autoFocus
                onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
            </Field>
            <Field label="Password (min 8 chars)">
              <input style={styles.input} type="password" value={password}
                onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
            </Field>

            <div style={styles.sectionLabel}>LLM provider</div>
            <Field label="Provider">
              <select style={styles.input} value={provider} onChange={(e) => setProvider(e.target.value)}>
                {PROVIDERS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
              </select>
            </Field>
            <Field label="API key">
              <input style={styles.input} type="password" value={apiKey}
                placeholder={selectedProvider.placeholder}
                onChange={(e) => setApiKey(e.target.value)} />
              <a style={styles.keyLink} href={selectedProvider.keyUrl} target="_blank" rel="noreferrer">
                Get a {selectedProvider.label} key ↗
              </a>
            </Field>
            <Field label="Model (optional — uses a sensible default)">
              <input style={styles.input} value={model} placeholder="leave blank for default"
                onChange={(e) => setModel(e.target.value)} />
            </Field>

            {error && <div style={styles.error}>{error}</div>}
            <button style={styles.button} disabled={busy} type="submit">
              {busy ? 'Setting up…' : 'Complete setup'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div style={styles.field}>
      <label style={styles.label}>{label}</label>
      {children}
    </div>
  );
}

const styles = {
  wrap: {
    minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
    background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)', padding: 24,
  },
  card: {
    width: '100%', maxWidth: 420, background: '#fff', borderRadius: 16, padding: 32,
    boxShadow: '0 20px 60px rgba(0,0,0,0.35)',
  },
  brand: { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 },
  logo: {
    display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
    width: 40, height: 40, borderRadius: 10, background: '#0f172a', color: '#fff', flexShrink: 0,
  },
  title: { fontSize: 22, fontWeight: 700, color: '#0f172a', lineHeight: 1.1 },
  subtitle: { fontSize: 13, color: '#64748b' },
  heading: { fontSize: 18, fontWeight: 600, color: '#0f172a', margin: '0 0 16px' },
  tabs: { display: 'flex', gap: 6, marginBottom: 18, background: '#f1f5f9', padding: 4, borderRadius: 10 },
  tab: {
    flex: 1, padding: '8px 12px', fontSize: 14, fontWeight: 600, border: 'none',
    borderRadius: 7, background: 'transparent', color: '#64748b', cursor: 'pointer',
  },
  tabActive: { background: '#fff', color: '#0f172a', boxShadow: '0 1px 2px rgba(0,0,0,0.08)' },
  switchRow: { marginTop: 14, fontSize: 13, color: '#64748b', textAlign: 'center' },
  linkBtn: {
    background: 'none', border: 'none', color: '#2563eb', cursor: 'pointer',
    fontSize: 13, fontWeight: 600, padding: 0,
  },
  help: { fontSize: 13, color: '#64748b', margin: '0 0 16px' },
  sectionLabel: {
    fontSize: 11, fontWeight: 700, letterSpacing: 0.6, textTransform: 'uppercase',
    color: '#94a3b8', margin: '20px 0 8px',
  },
  field: { marginBottom: 14 },
  label: { display: 'block', fontSize: 13, fontWeight: 500, color: '#334155', marginBottom: 6 },
  input: {
    width: '100%', padding: '10px 12px', fontSize: 14, border: '1px solid #cbd5e1',
    borderRadius: 8, outline: 'none', boxSizing: 'border-box', background: '#fff', color: '#0f172a',
  },
  keyLink: { display: 'inline-block', marginTop: 6, fontSize: 12, color: '#2563eb', textDecoration: 'none' },
  button: {
    width: '100%', marginTop: 8, padding: '11px 16px', fontSize: 15, fontWeight: 600,
    color: '#fff', background: '#2563eb', border: 'none', borderRadius: 8, cursor: 'pointer',
  },
  error: {
    background: '#fef2f2', color: '#b91c1c', border: '1px solid #fecaca',
    borderRadius: 8, padding: '8px 12px', fontSize: 13, margin: '4px 0 12px',
  },
  loading: { textAlign: 'center', color: '#64748b', padding: '24px 0' },
};

import React, { useState, useEffect, useCallback } from 'react';
import toast from 'react-hot-toast';
import { KeyRound, CheckCircle2, AlertTriangle } from 'lucide-react';

/**
 * Triksha Settings — LLM API key setup.
 * Accessed via the user-name dropdown → Settings. Lets the user pick a provider
 * and set/update the API key used by the Copilot, scans, and active MCP testing.
 */

const PROVIDERS = [
  { id: 'gemini', label: 'Google Gemini', placeholder: 'AIza…', url: 'https://aistudio.google.com/apikey',
    models: 'e.g. gemini-2.5-flash' },
  { id: 'openai', label: 'OpenAI', placeholder: 'sk-…', url: 'https://platform.openai.com/api-keys',
    models: 'e.g. gpt-4o, gpt-4o-mini' },
  { id: 'anthropic', label: 'Anthropic (Claude)', placeholder: 'sk-ant-…', url: 'https://console.anthropic.com/settings/keys',
    models: 'e.g. claude-sonnet-4-6' },
];

export default function Settings() {
  const [provider, setProvider] = useState('gemini');
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState('');
  const [saving, setSaving] = useState(false);
  const [health, setHealth] = useState(null); // {ready, provider}

  const refreshHealth = useCallback(() => {
    fetch('/copilot/health', { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => { setHealth(d); if (d && d.provider) setProvider(d.provider); })
      .catch(() => setHealth({ ready: false }));
  }, []);

  useEffect(() => { refreshHealth(); }, [refreshHealth]);

  const sel = PROVIDERS.find((p) => p.id === provider) || PROVIDERS[0];

  const save = async () => {
    if (!apiKey.trim()) { toast.error('Enter an API key.'); return; }
    setSaving(true);
    try {
      const res = await fetch('/copilot/configure', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, api_key: apiKey.trim(), model: model.trim() || undefined }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error(e.detail || 'Failed to save');
      }
      toast.success('API key saved');
      setApiKey('');
      refreshHealth();
    } catch (e) {
      toast.error(e.message || 'Failed to save key');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-1">Settings</h1>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
        Configure the LLM provider used by the Copilot, benchmark scans, and active MCP testing.
      </p>

      <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-6">
        <div className="flex items-center gap-2 mb-4">
          <KeyRound className="h-5 w-5 text-primary-600 dark:text-primary-400" />
          <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-100">LLM API Key</h2>
        </div>

        {/* current status */}
        {health && (
          <div className={`mb-5 flex items-center gap-2 text-sm rounded-lg px-3 py-2 ${
            health.ready
              ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300'
              : 'bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-300'}`}>
            {health.ready
              ? <><CheckCircle2 className="h-4 w-4" /> A key is configured for <b>{health.provider}</b>. Save below to change it.</>
              : <><AlertTriangle className="h-4 w-4" /> No LLM API key configured yet — add one to enable the Copilot and active scans.</>}
          </div>
        )}

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Provider</label>
            <select value={provider} onChange={(e) => setProvider(e.target.value)}
              className="w-full px-3 py-2 text-sm rounded-lg border border-gray-300 dark:border-gray-600
              bg-white dark:bg-gray-900 text-gray-800 dark:text-gray-100 outline-none focus:border-primary-400">
              {PROVIDERS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">API Key</label>
            <input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
              placeholder={sel.placeholder}
              className="w-full px-3 py-2 text-sm rounded-lg border border-gray-300 dark:border-gray-600
              bg-white dark:bg-gray-900 text-gray-800 dark:text-gray-100 outline-none focus:border-primary-400" />
            <a href={sel.url} target="_blank" rel="noreferrer"
              className="inline-block mt-1.5 text-xs text-primary-600 dark:text-primary-400 hover:underline">
              Get a {sel.label} key ↗
            </a>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Model <span className="text-gray-400 font-normal">(optional)</span>
            </label>
            <input value={model} onChange={(e) => setModel(e.target.value)}
              placeholder={`leave blank for default — ${sel.models}`}
              className="w-full px-3 py-2 text-sm rounded-lg border border-gray-300 dark:border-gray-600
              bg-white dark:bg-gray-900 text-gray-800 dark:text-gray-100 outline-none focus:border-primary-400" />
          </div>

          <div className="pt-1">
            <button onClick={save} disabled={saving}
              className="px-5 py-2.5 text-sm font-semibold rounded-lg bg-primary-600 text-white
              hover:bg-primary-700 disabled:opacity-50 transition">
              {saving ? 'Saving…' : 'Save API key'}
            </button>
          </div>
        </div>
      </div>

      <p className="mt-4 text-xs text-gray-400">
        Your key is stored locally on this instance and used to call the provider directly. It never leaves your deployment.
      </p>
    </div>
  );
}

import React, { useEffect, useState, useCallback } from 'react';
import { toast } from 'react-hot-toast';
import {
  Plug, Trash2, Settings2, Loader2, CheckCircle2, XCircle, Wrench, Bot,
} from 'lucide-react';

async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  let data = null;
  try { data = await res.json(); } catch { /* no body */ }
  if (!res.ok) throw new Error((data && data.detail) || `HTTP ${res.status}`);
  return data;
}

const CATEGORY_LABELS = {
  first_party: 'Service Connectors',
  mcp: 'MCP Servers',
};

export default function Connectors() {
  const [types, setTypes] = useState([]);
  const [connectors, setConnectors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(null); // { type, connector? }
  const [toolsModal, setToolsModal] = useState(null); // { name, tools }

  const reload = useCallback(async () => {
    try {
      const [t, c] = await Promise.all([api('/connectors/types'), api('/connectors')]);
      setTypes(t.types || []);
      setConnectors(c.connectors || []);
    } catch (e) {
      toast.error(`Failed to load connectors: ${e.message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { reload(); }, [reload]);

  const typeMap = Object.fromEntries(types.map((t) => [t.type, t]));
  const grouped = types.reduce((acc, t) => {
    (acc[t.category || 'first_party'] = acc[t.category || 'first_party'] || []).push(t);
    return acc;
  }, {});

  const del = async (c) => {
    if (!window.confirm(`Remove connector "${c.name}"?`)) return;
    try {
      await api(`/connectors/${c.id}`, { method: 'DELETE' });
      toast.success('Connector removed');
      reload();
    } catch (e) { toast.error(e.message); }
  };

  const toggleCopilot = async (c) => {
    try {
      await api(`/connectors/${c.id}`, {
        method: 'PUT',
        body: JSON.stringify({ copilot_enabled: !c.copilot_enabled }),
      });
      reload();
    } catch (e) { toast.error(e.message); }
  };

  const testSaved = async (c) => {
    const tid = toast.loading('Testing…');
    try {
      const r = await api(`/connectors/${c.id}/test`, { method: 'POST' });
      toast[r.success ? 'success' : 'error'](r.message || r.error || (r.success ? 'OK' : 'Failed'), { id: tid });
    } catch (e) { toast.error(e.message, { id: tid }); }
  };

  const discoverTools = async (c) => {
    const tid = toast.loading('Discovering tools…');
    try {
      const r = await api(`/connectors/${c.id}/mcp/tools`);
      toast.success(`${(r.tools || []).length} tool(s) found`, { id: tid });
      setToolsModal({ name: c.name, tools: r.tools || [] });
    } catch (e) { toast.error(e.message, { id: tid }); }
  };

  if (loading) {
    return <div className="flex items-center justify-center py-20 text-gray-500">
      <Loader2 className="h-5 w-5 animate-spin mr-2" /> Loading connectors…
    </div>;
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
          <Plug className="h-6 w-6 text-primary-600" /> Connectors
        </h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1 max-w-2xl">
          Connect the tools Triksha uses for its AI-security work — Jira, GitHub, guardrails,
          alerting, and remote MCP servers. Enabled connectors can be used by the Triksha Copilot.
        </p>
      </div>

      {/* Configured connectors */}
      {connectors.length > 0 && (
        <section>
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-3">Connected</h2>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {connectors.map((c) => {
              const spec = typeMap[c.type] || {};
              return (
                <div key={c.id} className="card p-4 flex flex-col gap-3">
                  <div className="flex items-start justify-between">
                    <div className="min-w-0">
                      <div className="font-semibold text-gray-900 dark:text-white truncate">{c.name}</div>
                      <div className="text-xs text-gray-500">{spec.label || c.type}</div>
                    </div>
                    <span className={`badge ${c.enabled ? 'badge-success' : 'badge-secondary'}`}>
                      {c.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>

                  <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 cursor-pointer">
                    <input type="checkbox" checked={c.copilot_enabled} onChange={() => toggleCopilot(c)} />
                    <Bot className="h-4 w-4" /> Available to Copilot
                  </label>

                  <div className="flex items-center gap-2 mt-auto pt-2">
                    <button onClick={() => testSaved(c)} className="btn-secondary text-xs flex items-center gap-1">
                      <CheckCircle2 className="h-3.5 w-3.5" /> Test
                    </button>
                    <button onClick={() => setEditing({ type: c.type, connector: c })}
                      className="btn-secondary text-xs flex items-center gap-1">
                      <Settings2 className="h-3.5 w-3.5" /> Edit
                    </button>
                    {c.type === 'mcp' && (
                      <button onClick={() => discoverTools(c)}
                        className="btn-secondary text-xs flex items-center gap-1">
                        <Wrench className="h-3.5 w-3.5" /> Tools
                      </button>
                    )}
                    <button onClick={() => del(c)}
                      className="text-xs text-red-600 hover:text-red-700 flex items-center gap-1 ml-auto">
                      <Trash2 className="h-3.5 w-3.5" /> Remove
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* Available types */}
      {Object.entries(grouped).map(([cat, list]) => (
        <section key={cat}>
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-3">
            {CATEGORY_LABELS[cat] || cat}
          </h2>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {list.map((t) => (
              <button key={t.type} onClick={() => setEditing({ type: t.type })}
                className="card p-4 text-left hover:ring-2 hover:ring-primary-400 transition">
                <div className="flex items-center gap-2 font-semibold text-gray-900 dark:text-white">
                  {t.category === 'mcp' ? <Wrench className="h-4 w-4 text-primary-600" />
                    : <Plug className="h-4 w-4 text-primary-600" />}
                  {t.label}
                </div>
                <p className="text-xs text-gray-500 mt-1">{t.description}</p>
                <span className="inline-block mt-3 text-xs font-medium text-primary-600">+ Add connection</span>
              </button>
            ))}
          </div>
        </section>
      ))}

      {editing && (
        <ConnectorModal
          spec={typeMap[editing.type]}
          connector={editing.connector}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); reload(); }}
        />
      )}

      {toolsModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50" onClick={() => setToolsModal(null)}>
          <div className="card w-full max-w-lg max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="card-header flex items-center justify-between">
              <h3 className="card-title flex items-center gap-2"><Wrench className="h-4 w-4" /> {toolsModal.name} — tools</h3>
              <button onClick={() => setToolsModal(null)} className="text-gray-400 hover:text-gray-600"><XCircle className="h-5 w-5" /></button>
            </div>
            <div className="card-content space-y-2">
              {toolsModal.tools.length === 0 ? (
                <p className="text-sm text-gray-500">No tools exposed by this server.</p>
              ) : toolsModal.tools.map((t) => (
                <div key={t.name} className="rounded-lg border border-gray-200 dark:border-gray-700 p-3">
                  <div className="font-mono text-sm text-gray-900 dark:text-white">{t.name}</div>
                  {t.description && <div className="text-xs text-gray-500 mt-1">{t.description}</div>}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function ConnectorModal({ spec, connector, onClose, onSaved }) {
  const isEdit = !!connector;
  const [name, setName] = useState(connector?.name || spec?.label || '');
  const [values, setValues] = useState(() => {
    const v = {};
    (spec?.fields || []).forEach((f) => {
      if (!f.secret) v[f.key] = connector?.config?.[f.key] ?? '';
      else v[f.key] = '';
    });
    return v;
  });
  const [copilotEnabled, setCopilotEnabled] = useState(connector?.copilot_enabled || false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  if (!spec) return null;

  const setField = (k, val) => setValues((p) => ({ ...p, [k]: val }));

  const buildBody = () => {
    // Only include secret fields the user actually typed (blank = keep existing).
    const out = {};
    spec.fields.forEach((f) => {
      const val = values[f.key];
      if (f.secret) { if (val) out[f.key] = val; }
      else out[f.key] = val;
    });
    return out;
  };

  const test = async () => {
    setTesting(true);
    const tid = toast.loading('Testing connection…');
    try {
      let r;
      if (isEdit) {
        // Save-less test against the saved connector unless secrets changed
        const changedSecrets = spec.fields.some((f) => f.secret && values[f.key]);
        r = changedSecrets
          ? await api('/connectors/test', { method: 'POST', body: JSON.stringify({ type: spec.type, values: { ...connector.config, ...buildBody() } }) })
          : await api(`/connectors/${connector.id}/test`, { method: 'POST' });
      } else {
        r = await api('/connectors/test', { method: 'POST', body: JSON.stringify({ type: spec.type, values: buildBody() }) });
      }
      toast[r.success ? 'success' : 'error'](r.message || r.error, { id: tid });
    } catch (e) { toast.error(e.message, { id: tid }); }
    finally { setTesting(false); }
  };

  const save = async () => {
    setSaving(true);
    try {
      if (isEdit) {
        await api(`/connectors/${connector.id}`, {
          method: 'PUT',
          body: JSON.stringify({ name, values: buildBody(), copilot_enabled: copilotEnabled }),
        });
      } else {
        await api('/connectors', {
          method: 'POST',
          body: JSON.stringify({ type: spec.type, name, values: buildBody(), copilot_enabled: copilotEnabled }),
        });
      }
      toast.success('Connector saved');
      onSaved();
    } catch (e) { toast.error(e.message); }
    finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50" onClick={onClose}>
      <div className="card w-full max-w-lg max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        <div className="card-header flex items-center justify-between">
          <div>
            <h3 className="card-title">{isEdit ? 'Edit' : 'Connect'} {spec.label}</h3>
            <p className="card-description">{spec.description}</p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><XCircle className="h-5 w-5" /></button>
        </div>

        <div className="card-content space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Display name</label>
            <input className="input w-full" value={name} onChange={(e) => setName(e.target.value)} />
          </div>

          {spec.fields.map((f) => (
            <div key={f.key}>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                {f.label}{f.required && <span className="text-red-500"> *</span>}
              </label>
              {f.key === 'service_account_json' ? (
                <textarea className="input w-full font-mono text-xs" rows={5}
                  placeholder={isEdit && connector?.secrets_set?.[f.key] ? '•••••• (saved — leave blank to keep)' : f.placeholder}
                  value={values[f.key]} onChange={(e) => setField(f.key, e.target.value)} />
              ) : (
                <input className="input w-full" type={f.secret ? 'password' : 'text'}
                  placeholder={f.secret && isEdit && connector?.secrets_set?.[f.key] ? '•••••• (saved — leave blank to keep)' : f.placeholder}
                  value={values[f.key]} onChange={(e) => setField(f.key, e.target.value)} />
              )}
              {f.help && <p className="text-xs text-gray-400 mt-1">{f.help}</p>}
            </div>
          ))}

          <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
            <input type="checkbox" checked={copilotEnabled} onChange={(e) => setCopilotEnabled(e.target.checked)} />
            <Bot className="h-4 w-4" /> Make available to the Triksha Copilot
          </label>
        </div>

        <div className="card-footer flex items-center gap-2">
          <button onClick={test} disabled={testing} className="btn-secondary flex items-center gap-1">
            {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />} Test
          </button>
          <div className="flex-1" />
          <button onClick={onClose} className="btn-secondary">Cancel</button>
          <button onClick={save} disabled={saving} className="btn-primary flex items-center gap-1">
            {saving && <Loader2 className="h-4 w-4 animate-spin" />} Save
          </button>
        </div>
      </div>
    </div>
  );
}

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import Markdown from './copilot/Markdown';
import { useCopilotNav } from '../contexts/CopilotNavContext';

/**
 * Triksha Copilot — full chat product.
 * Streams from POST /copilot/chat (SSE) and turns natural language into real Triksha actions.
 * Composer has action dropdowns (Scan Model, Scan Agent, MCP) that compose messages on selection.
 */

const ACTIVE_KEY = 'triksha_copilot_active';

const SUGGESTIONS = [
  'Run a jailbreak benchmark on gpt-4o',
  'Scan an MCP server for tool-poisoning',
  'Harden my system prompt',
  'Discover agents in a GitHub repo',
];

const TOOL_LABELS = {
  start_benchmark_scan: 'Starting benchmark scan',
  start_mcp_scan:       'Starting MCP scan',
  discover_agents:      'Discovering agents',
  start_agent_scan:     'Starting agent scan',
  harden_prompt:        'Hardening prompt',
  review_prd:           'Starting PRD review',
  list_recent_scans:    'Fetching recent scans',
  poll_scan_result:     'Waiting for scan result',
  list_capabilities:    'Checking capabilities',
  navigate:             'Opening page',
  list_connectors:      'Checking connectors',
  jira_search:          'Searching Jira',
  jira_create_issue:    'Creating Jira issue',
  list_mcp_tools:       'Listing MCP tools',
  call_mcp_tool:        'Calling MCP tool',
};

// Model options for the Scan Model dropdown
const SCAN_MODEL_OPTIONS = {
  openai:    { label: 'OpenAI',    models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo', 'o1', 'o3', 'o3-mini', 'o4-mini'] },
  anthropic: { label: 'Anthropic', models: ['claude-opus-4-6', 'claude-sonnet-4-6', 'claude-haiku-4-5-20251001', 'claude-3-5-sonnet-20241022', 'claude-3-5-haiku-20241022'] },
  gemini:    { label: 'Gemini',    models: ['gemini-2.5-flash', 'gemini-2.5-pro', 'gemini-2.0-flash', 'gemini-1.5-pro', 'gemini-1.5-flash'] },
};

// ── API helpers ──────────────────────────────────────────────────────────────
const api = {
  list:       ()         => fetch('/copilot/conversations', { credentials: 'include' }).then((r) => r.json()),
  get:        (id)       => fetch(`/copilot/conversations/${id}`, { credentials: 'include' }).then((r) => r.json()),
  del:        (id)       => fetch(`/copilot/conversations/${id}`, { method: 'DELETE', credentials: 'include' }),
  rename:     (id, t)    => fetch(`/copilot/conversations/${id}`, {
    method: 'PATCH', credentials: 'include',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: t }),
  }),
  health:     ()         => fetch('/copilot/health', { credentials: 'include' }).then((r) => r.json()),
  configure:  (body)     => fetch('/copilot/configure', {
    method: 'POST', credentials: 'include',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }),
  agents:     ()         => fetch('/agents/predefined', { credentials: 'include' }).then((r) => r.json()),
};

export default function TrikshaCopilot() {
  const navigate = useNavigate();
  const { setApi } = useCopilotNav();
  const [conversations, setConversations] = useState([]);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [keyMissing, setKeyMissing] = useState(false);
  const [activeId, setActiveId] = useState(null);
  const [predefinedAgents, setPredefinedAgents] = useState([]);

  const convId    = useRef(null);
  const abortRef  = useRef(null);
  const scrollRef = useRef(null);
  const taRef     = useRef(null);
  const pendingNav = useRef(null);

  const setActive = useCallback((id) => {
    convId.current = id;
    setActiveId(id);
    try { id ? localStorage.setItem(ACTIVE_KEY, id) : localStorage.removeItem(ACTIVE_KEY); } catch { /* */ }
  }, []);

  const loadConversations = useCallback(async () => {
    try {
      const d = await api.list();
      setConversations(Array.isArray(d.conversations) ? d.conversations : []);
    } catch { /* offline */ }
  }, []);

  const openConversation = useCallback(async (id) => {
    if (id === convId.current && messages.length) return;
    setActive(id);
    try {
      const d = await api.get(id);
      setMessages((d.messages || []).map((m) => ({ role: m.role, text: m.text })));
    } catch { setMessages([]); }
  }, [messages.length, setActive]);

  const newChat = useCallback(() => {
    if (abortRef.current) abortRef.current.abort();
    setActive(null);
    setMessages([]);
    setInput('');
  }, [setActive]);

  // Initial load
  useEffect(() => {
    loadConversations();
    let stored = null;
    try { stored = localStorage.getItem(ACTIVE_KEY); } catch { /* */ }
    if (stored) openConversation(stored);
    api.health().then((d) => { if (d && d.ready === false) setKeyMissing(true); }).catch(() => {});
    api.agents().then((d) => { if (d?.agents) setPredefinedAgents(d.agents); }).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, busy]);

  const autoGrow = useCallback(() => {
    const ta = taRef.current;
    if (!ta) return;
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 200) + 'px';
  }, []);
  useEffect(autoGrow, [input, autoGrow]);

  const saveKey = useCallback(async ({ provider, apiKey, model }) => {
    const res = await api.configure({ provider, api_key: apiKey, model: model || undefined });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.detail || 'Failed to save key');
    }
    setKeyMissing(false);
    setMessages((m) => m.map((x) => x.needsKey
      ? { ...x, needsKey: null, text: '✓ API key saved — ask me again and I\'ll get to work.' } : x));
    toast.success('API key saved');
  }, []);

  const stop = useCallback(() => { if (abortRef.current) abortRef.current.abort(); }, []);

  const send = useCallback(async (text) => {
    const msg = (text ?? input).trim();
    if (!msg || busy) return;
    setInput('');
    setBusy(true);
    pendingNav.current = null;
    setMessages((m) => [...m, { role: 'user', text: msg }, { role: 'assistant', text: '', tools: [] }]);

    const setAssistant = (updater) => setMessages((m) => {
      const next = [...m];
      next[next.length - 1] = updater(next[next.length - 1]);
      return next;
    });

    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const resp = await fetch('/copilot/chat', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'Accept': 'text/event-stream' },
        body: JSON.stringify({ message: msg, conversation_id: convId.current }),
        signal: controller.signal,
      });
      if (!resp.ok || !resp.body) throw new Error(`stream failed (${resp.status})`);

      const reader  = resp.body.getReader();
      const decoder = new TextDecoder('utf-8');
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
          let evt;
          try { evt = JSON.parse(line.replace(/^data:\s*/, '')); } catch { continue; }

          if (evt.type === 'tool') {
            const label = TOOL_LABELS[evt.name] || evt.name;
            setAssistant((a) => ({ ...a, tools: [...(a.tools || []), label] }));
          } else if (evt.type === 'action' && evt.route) {
            pendingNav.current = evt.route;
          } else if (evt.type === 'message') {
            setAssistant((a) => ({ ...a, text: evt.text || '' }));
          } else if (evt.type === 'needs_api_key') {
            setKeyMissing(true);
            setAssistant((a) => ({ ...a,
              text: evt.message || 'An LLM API key is required.',
              needsKey: { provider: evt.provider || 'gemini' } }));
          } else if (evt.type === 'needs_target_key') {
            setAssistant((a) => ({ ...a,
              needsKey: { provider: evt.provider || 'openai', message: evt.message } }));
          } else if (evt.type === 'error') {
            setAssistant((a) => ({ ...a, text: `⚠️ ${evt.message}` }));
          } else if (evt.type === 'done') {
            if (evt.conversation_id) setActive(evt.conversation_id);
          }
        }
      }
      if (pendingNav.current) {
        const route = pendingNav.current;
        toast.success(`Opening ${route}`);
        setTimeout(() => navigate(route), 600);
      }
      loadConversations();
    } catch (e) {
      if (e.name === 'AbortError') {
        setAssistant((a) => ({ ...a, text: a.text || '_(stopped)_' }));
      } else {
        setAssistant((a) => ({ ...a, text: `⚠️ ${e.message}` }));
      }
    } finally {
      abortRef.current = null;
      setBusy(false);
    }
  }, [input, busy, navigate, setActive, loadConversations]);

  const copyMessage = useCallback((text) => {
    navigator.clipboard.writeText(text || '').then(() => toast.success('Copied')).catch(() => {});
  }, []);

  const onRename = useCallback(async (id, title) => {
    setConversations((c) => c.map((x) => (x.id === id ? { ...x, title } : x)));
    try { await api.rename(id, title); } catch { loadConversations(); }
  }, [loadConversations]);

  const onDelete = useCallback(async (id) => {
    if (!window.confirm('Delete this conversation?')) return;
    setConversations((c) => c.filter((x) => x.id !== id));
    try { await api.del(id); } catch { /* */ }
    if (id === convId.current) newChat();
  }, [newChat]);

  useEffect(() => {
    setApi({ conversations, activeId, newChat, openConversation, onRename, onDelete });
    return () => setApi(null);
  }, [conversations, activeId, newChat, openConversation, onRename, onDelete, setApi]);

  const onKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
  };

  const empty = messages.length === 0;

  return (
    <div className="flex h-full flex-col min-w-0 bg-white dark:bg-gray-900 overflow-hidden">
      <div ref={scrollRef} className="flex-1 overflow-y-auto">
        {empty ? (
          <div className="h-full flex flex-col items-center justify-center px-4">
            <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-blue-600 dark:text-blue-400">
              Triksha
            </h1>
            <p className="mt-4 text-2xl sm:text-3xl font-semibold text-gray-800 dark:text-gray-100 text-center">
              How can I help secure your AI?
            </p>
            <p className="mt-2 text-gray-500 dark:text-gray-400 text-sm text-center max-w-md">
              Your AI security co-pilot.
            </p>
            {keyMissing && (
              <div className="mt-6 w-full max-w-xl">
                <ApiKeyCard provider="gemini" onSaveKey={saveKey}
                  message="No LLM API key is configured yet. Add one to start chatting." />
              </div>
            )}
            <div className="mt-6 w-full max-w-xl">
              <Composer taRef={taRef} input={input} setInput={setInput} onKey={onKey}
                send={send} stop={stop} busy={busy} autoGrow={autoGrow} centered
                predefinedAgents={predefinedAgents} />
            </div>
            <div className="mt-5 flex flex-wrap gap-2 justify-center max-w-xl">
              {SUGGESTIONS.map((s) => (
                <button key={s} onClick={() => send(s)} disabled={busy}
                  className="px-3.5 py-2 text-sm rounded-xl border border-gray-200 dark:border-gray-700
                  text-gray-600 dark:text-gray-300 hover:border-primary-400 hover:text-primary-600
                  dark:hover:text-primary-400 hover:bg-primary-50/50 dark:hover:bg-primary-900/20 transition">
                  {s}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="max-w-3xl mx-auto px-4 py-6 space-y-6">
            {messages.map((m, i) => {
              const prevUser = m.role === 'assistant' && messages[i - 1]?.role === 'user'
                ? messages[i - 1].text : '';
              const isLast = i === messages.length - 1;
              return (
                <Message key={i} m={m} streaming={busy && isLast} onSaveKey={saveKey}
                  onCopy={() => copyMessage(m.text)}
                  onRegenerate={prevUser && !busy ? () => send(prevUser) : null} />
              );
            })}
          </div>
        )}
      </div>

      {!empty && (
        <div className="border-t border-gray-100 dark:border-gray-800 px-4 py-3">
          <div className="max-w-3xl mx-auto">
            <Composer taRef={taRef} input={input} setInput={setInput} onKey={onKey}
              send={send} stop={stop} busy={busy} autoGrow={autoGrow}
              predefinedAgents={predefinedAgents} />
            <p className="mt-1.5 text-center text-[11px] text-gray-400">
              Triksha Copilot can take real actions — review what it runs.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Message ────────────────────────────────────────────────────────────────────
function Message({ m, streaming, onSaveKey, onCopy, onRegenerate }) {
  if (m.role === 'user') {
    return (
      <div className="flex justify-end">
        <div className="max-w-[80%] bg-primary-600 text-white rounded-2xl rounded-br-md px-4 py-2.5
          text-[15px] leading-relaxed whitespace-pre-wrap">{m.text}</div>
      </div>
    );
  }
  const showActions = !streaming && m.text && !m.needsKey;
  return (
    <div className="flex gap-3 group">
      <div className="flex-shrink-0 mt-0.5"><Logo /></div>
      <div className="min-w-0 flex-1">
        {m.tools && m.tools.length > 0 && (
          <div className="mb-2 flex flex-wrap gap-1.5">
            {m.tools.map((t, j) => (
              <span key={j} className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full
                bg-primary-50 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300
                border border-primary-100 dark:border-primary-800">
                <span className="w-1.5 h-1.5 rounded-full bg-primary-500 animate-pulse" />{t}
              </span>
            ))}
          </div>
        )}
        {m.text ? <Markdown text={m.text} /> : (streaming ? <Thinking /> : null)}
        {m.needsKey && (
          <div className="mt-3">
            <ApiKeyCard provider={m.needsKey.provider} onSaveKey={onSaveKey}
              message={m.needsKey.message} />
          </div>
        )}
        {showActions && (
          <div className="mt-2 flex items-center gap-1 opacity-0 group-hover:opacity-100 transition">
            <button onClick={onCopy} title="Copy"
              className="p-1.5 rounded-md text-gray-400 hover:text-gray-700 dark:hover:text-gray-200
              hover:bg-gray-100 dark:hover:bg-gray-800"><Icon.Copy /></button>
            {onRegenerate && (
              <button onClick={onRegenerate} title="Regenerate"
                className="p-1.5 rounded-md text-gray-400 hover:text-gray-700 dark:hover:text-gray-200
                hover:bg-gray-100 dark:hover:bg-gray-800"><Icon.Refresh /></button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Composer ──────────────────────────────────────────────────────────────────
function Composer({ taRef, input, setInput, onKey, send, stop, busy, autoGrow, centered, predefinedAgents }) {
  const [openMenu, setOpenMenu] = useState(null); // 'model' | 'agent' | 'mcp'

  const closeMenu = useCallback(() => setOpenMenu(null), []);

  const doSend = useCallback((text) => {
    closeMenu();
    send(text);
  }, [send, closeMenu]);

  return (
    <div className={`rounded-2xl border bg-white dark:bg-gray-800
      border-gray-200 dark:border-gray-700 focus-within:border-primary-400
      focus-within:ring-2 focus-within:ring-primary-100 dark:focus-within:ring-primary-900/40
      shadow-sm ${centered ? 'shadow-md' : ''}`}>

      {/* Textarea */}
      <div className="px-3 pt-3">
        <textarea ref={taRef} rows={1} value={input}
          onChange={(e) => { setInput(e.target.value); autoGrow(); }}
          onKeyDown={onKey} disabled={busy}
          placeholder="Message Triksha Copilot…"
          className="w-full resize-none bg-transparent outline-none text-[15px] leading-relaxed
          text-gray-800 dark:text-gray-100 placeholder-gray-400 max-h-[200px] py-1" />
      </div>

      {/* Action bar */}
      <div className="flex items-center justify-between px-2 pb-2 pt-1 gap-2">
        <div className="flex items-center gap-1.5 relative">

          {/* Scan Model */}
          <div className="relative">
            <ActionChip
              icon="🎯"
              label="Scan model"
              active={openMenu === 'model'}
              onClick={() => setOpenMenu(openMenu === 'model' ? null : 'model')} />
            {openMenu === 'model' && (
              <ScanModelMenu onSend={doSend} onClose={closeMenu} />
            )}
          </div>

          {/* Scan Agent */}
          <div className="relative">
            <ActionChip
              icon="🤖"
              label="Scan agent"
              active={openMenu === 'agent'}
              onClick={() => setOpenMenu(openMenu === 'agent' ? null : 'agent')} />
            {openMenu === 'agent' && (
              <ScanAgentMenu agents={predefinedAgents} onSend={doSend} onClose={closeMenu} />
            )}
          </div>

          {/* MCP Scan */}
          <div className="relative">
            <ActionChip
              icon="🔌"
              label="MCP scan"
              active={openMenu === 'mcp'}
              onClick={() => setOpenMenu(openMenu === 'mcp' ? null : 'mcp')} />
            {openMenu === 'mcp' && (
              <MCPMenu onSend={doSend} onClose={closeMenu} />
            )}
          </div>

        </div>

        {/* Send / Stop */}
        {busy ? (
          <button onClick={stop} title="Stop"
            className="flex-shrink-0 w-8 h-8 rounded-xl bg-gray-700 text-white flex items-center
            justify-center hover:bg-gray-800 transition">
            <Icon.Stop />
          </button>
        ) : (
          <button onClick={() => send()} disabled={!input.trim()}
            className="flex-shrink-0 w-8 h-8 rounded-xl bg-primary-600 text-white flex items-center
            justify-center hover:bg-primary-700 disabled:opacity-40 disabled:cursor-not-allowed transition">
            <Icon.ArrowUp />
          </button>
        )}
      </div>
    </div>
  );
}

// Small pill chip for the action bar
function ActionChip({ icon, label, active, onClick }) {
  return (
    <button onClick={onClick}
      className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium
      border transition select-none
      ${active
        ? 'bg-primary-50 dark:bg-primary-900/40 border-primary-300 dark:border-primary-700 text-primary-700 dark:text-primary-300'
        : 'bg-gray-50 dark:bg-gray-700/60 border-gray-200 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:border-primary-300 hover:text-primary-600 dark:hover:text-primary-400'
      }`}>
      <span>{icon}</span>
      <span>{label}</span>
      <Icon.ChevronDown size={10} />
    </button>
  );
}

// ── Scan Model popover ─────────────────────────────────────────────────────────
function ScanModelMenu({ onSend, onClose }) {
  const [provider, setProvider] = useState('openai');
  const [model, setModel] = useState('gpt-4o');
  const opts = SCAN_MODEL_OPTIONS[provider];

  const handleProviderChange = (p) => {
    setProvider(p);
    setModel(SCAN_MODEL_OPTIONS[p].models[0]);
  };

  const handleSend = () => {
    onSend(`Run a jailbreak benchmark scan on ${provider} ${model}`);
  };

  return (
    <Popover onClose={onClose}>
      <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-2">
        Scan a model
      </p>
      <div className="space-y-2">
        <div>
          <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Provider</label>
          <div className="flex gap-1.5">
            {Object.entries(SCAN_MODEL_OPTIONS).map(([id, { label }]) => (
              <button key={id} onClick={() => handleProviderChange(id)}
                className={`flex-1 py-1.5 text-xs rounded-lg border font-medium transition
                ${provider === id
                  ? 'bg-primary-600 text-white border-primary-600'
                  : 'border-gray-200 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:border-primary-400'}`}>
                {label}
              </button>
            ))}
          </div>
        </div>
        <div>
          <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Model</label>
          <select value={model} onChange={(e) => setModel(e.target.value)}
            className="w-full px-2.5 py-1.5 text-sm rounded-lg border border-gray-200 dark:border-gray-600
            bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-100 outline-none focus:border-primary-400">
            {opts.models.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        </div>
        <button onClick={handleSend}
          className="w-full py-2 text-sm font-semibold rounded-lg bg-primary-600 text-white
          hover:bg-primary-700 transition">
          Start scan
        </button>
      </div>
    </Popover>
  );
}

// ── Scan Agent popover ─────────────────────────────────────────────────────────
function ScanAgentMenu({ agents, onSend, onClose }) {
  const [search, setSearch] = useState('');
  const [customEndpoint, setCustomEndpoint] = useState('');
  const filtered = agents.filter((a) =>
    (a.agent_name || a.name || '').toLowerCase().includes(search.toLowerCase()));

  const sendAgent = (a) => {
    const name     = a.agent_name || a.name || 'agent';
    const endpoint = a.agent_endpoint || a.endpoint || '';
    onSend(`Run a security scan on the agent "${name}"${endpoint ? ` at ${endpoint}` : ''}`);
  };

  const sendCustom = () => {
    if (!customEndpoint.trim()) return;
    onSend(`Run a security scan on the agent at ${customEndpoint.trim()}`);
  };

  return (
    <Popover onClose={onClose} wide>
      <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-2">
        Scan an agent
      </p>

      {agents.length > 0 && (
        <>
          <input value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Search saved agents…"
            className="w-full px-2.5 py-1.5 text-sm rounded-lg border border-gray-200 dark:border-gray-600
            bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-100 outline-none
            focus:border-primary-400 mb-2" />
          <div className="max-h-40 overflow-y-auto space-y-1 mb-3">
            {filtered.length === 0
              ? <p className="text-xs text-gray-400 text-center py-2">No agents match</p>
              : filtered.map((a, i) => {
                const name = a.agent_name || a.name || 'Unnamed agent';
                const ep   = a.agent_endpoint || a.endpoint || '';
                return (
                  <button key={i} onClick={() => sendAgent(a)}
                    className="w-full text-left px-2.5 py-2 rounded-lg hover:bg-primary-50
                    dark:hover:bg-primary-900/30 transition group">
                    <div className="text-sm font-medium text-gray-800 dark:text-gray-100 group-hover:text-primary-700 dark:group-hover:text-primary-300">
                      {name}
                    </div>
                    {ep && <div className="text-xs text-gray-400 truncate">{ep}</div>}
                  </button>
                );
              })}
          </div>
          <div className="border-t border-gray-100 dark:border-gray-700 pt-2 mt-1">
            <p className="text-xs text-gray-500 dark:text-gray-400 mb-1.5">Or scan a custom endpoint:</p>
          </div>
        </>
      )}

      {agents.length === 0 && (
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
          No saved agents yet. Enter an endpoint URL below:
        </p>
      )}

      <div className="flex gap-1.5">
        <input value={customEndpoint} onChange={(e) => setCustomEndpoint(e.target.value)}
          placeholder="https://my-agent.example.com/chat"
          className="flex-1 px-2.5 py-1.5 text-sm rounded-lg border border-gray-200 dark:border-gray-600
          bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-100 outline-none focus:border-primary-400" />
        <button onClick={sendCustom} disabled={!customEndpoint.trim()}
          className="px-3 py-1.5 text-sm font-semibold rounded-lg bg-primary-600 text-white
          hover:bg-primary-700 disabled:opacity-40 disabled:cursor-not-allowed transition">
          Scan
        </button>
      </div>
    </Popover>
  );
}

// ── MCP Scan popover ───────────────────────────────────────────────────────────
function MCPMenu({ onSend, onClose }) {
  return (
    <Popover onClose={onClose}>
      <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-2">
        MCP server scan
      </p>
      <p className="text-xs text-gray-600 dark:text-gray-400 mb-3">
        Scans an MCP server config for tool poisoning, hidden instructions, and excessive permissions.
      </p>
      <div className="space-y-1.5">
        <button onClick={() => onSend('Scan an MCP server for security vulnerabilities. I\'ll share the config.')}
          className="w-full text-left px-3 py-2.5 rounded-lg border border-gray-200 dark:border-gray-600
          hover:border-primary-400 hover:bg-primary-50 dark:hover:bg-primary-900/30 transition">
          <div className="text-sm font-medium text-gray-800 dark:text-gray-100">Paste config</div>
          <div className="text-xs text-gray-400 mt-0.5">I'll provide the MCP JSON config</div>
        </button>
        <button onClick={() => onSend('Scan the MCP server at this URL for security vulnerabilities:')}
          className="w-full text-left px-3 py-2.5 rounded-lg border border-gray-200 dark:border-gray-600
          hover:border-primary-400 hover:bg-primary-50 dark:hover:bg-primary-900/30 transition">
          <div className="text-sm font-medium text-gray-800 dark:text-gray-100">Scan by URL</div>
          <div className="text-xs text-gray-400 mt-0.5">Provide the server URL directly</div>
        </button>
      </div>
    </Popover>
  );
}

// ── Popover wrapper ────────────────────────────────────────────────────────────
function Popover({ children, onClose, wide }) {
  const ref = useRef(null);
  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) onClose(); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [onClose]);

  return (
    <div ref={ref}
      className={`absolute bottom-full mb-2 left-0 z-50 bg-white dark:bg-gray-800 rounded-xl
      border border-gray-200 dark:border-gray-700 shadow-xl p-3
      ${wide ? 'w-72' : 'w-60'}`}>
      {children}
    </div>
  );
}

// ── API key card ──────────────────────────────────────────────────────────────
function ApiKeyCard({ provider = 'gemini', onSaveKey, message }) {
  const PROVIDERS = [
    { id: 'gemini',    label: 'Google Gemini',    placeholder: 'AIza…',    url: 'https://aistudio.google.com/apikey' },
    { id: 'openai',    label: 'OpenAI',           placeholder: 'sk-…',     url: 'https://platform.openai.com/api-keys' },
    { id: 'anthropic', label: 'Anthropic (Claude)', placeholder: 'sk-ant-…', url: 'https://console.anthropic.com/settings/keys' },
  ];
  const [prov, setProv] = useState(PROVIDERS.some((p) => p.id === provider) ? provider : 'gemini');
  const [key, setKey]   = useState('');
  const [saving, setSaving] = useState(false);
  const [err, setErr]   = useState('');
  const sel = PROVIDERS.find((p) => p.id === prov) || PROVIDERS[0];

  const save = async () => {
    setErr('');
    if (!key.trim()) { setErr('Enter an API key.'); return; }
    setSaving(true);
    try { await onSaveKey({ provider: prov, apiKey: key.trim() }); }
    catch (e) { setErr(e.message || 'Failed to save key'); }
    finally { setSaving(false); }
  };

  return (
    <div className="rounded-xl border border-amber-200 dark:border-amber-800/60 bg-amber-50 dark:bg-amber-900/20 p-4">
      <div className="flex items-start gap-2">
        <span className="text-amber-500 text-lg leading-none">⚠️</span>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-amber-800 dark:text-amber-200">API key required</p>
          <p className="text-[13px] text-amber-700/90 dark:text-amber-300/80 mt-0.5">
            {message || 'Your API key looks invalid or isn\'t set. Add a valid key to continue.'}
          </p>
          <div className="mt-3 grid grid-cols-1 sm:grid-cols-[150px_1fr] gap-2">
            <select value={prov} onChange={(e) => setProv(e.target.value)}
              className="px-2.5 py-2 text-sm rounded-lg border border-gray-300 dark:border-gray-600
              bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-100 outline-none">
              {PROVIDERS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
            </select>
            <input type="password" value={key} onChange={(e) => setKey(e.target.value)}
              placeholder={sel.placeholder}
              className="px-3 py-2 text-sm rounded-lg border border-gray-300 dark:border-gray-600
              bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-100 outline-none
              focus:border-primary-400 focus:ring-2 focus:ring-primary-100 dark:focus:ring-primary-900/40" />
          </div>
          {err && <p className="mt-2 text-xs text-red-600 dark:text-red-400">{err}</p>}
          <div className="mt-3 flex items-center gap-3">
            <button onClick={save} disabled={saving}
              className="px-4 py-2 text-sm font-semibold rounded-lg bg-primary-600 text-white
              hover:bg-primary-700 disabled:opacity-50 transition">
              {saving ? 'Saving…' : 'Save key'}
            </button>
            <a href={sel.url} target="_blank" rel="noreferrer"
              className="text-xs text-primary-600 dark:text-primary-400 hover:underline">
              Get a {sel.label} key ↗
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Bits ──────────────────────────────────────────────────────────────────────
function Logo() {
  return (
    <div className="w-7 h-7 rounded-xl bg-gradient-to-br from-primary-500 to-indigo-600
      flex items-center justify-center text-white font-bold shadow-sm select-none
      text-base leading-none tracking-tight">T</div>
  );
}

function Thinking() {
  return (
    <span className="inline-flex gap-1 items-center py-1">
      {[0, 150, 300].map((d) => (
        <span key={d} className="w-2 h-2 rounded-full bg-gray-400 animate-bounce"
          style={{ animationDelay: `${d}ms` }} />
      ))}
    </span>
  );
}

const Icon = {
  ArrowUp: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="19" x2="12" y2="5" /><polyline points="5 12 12 5 19 12" /></svg>
  ),
  Stop: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
      <rect x="6" y="6" width="12" height="12" rx="2" /></svg>
  ),
  Copy: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
  ),
  Refresh: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="23 4 23 10 17 10" /><polyline points="1 20 1 14 7 14" />
      <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" /></svg>
  ),
  ChevronDown: ({ size = 12 }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 9 12 15 18 9" /></svg>
  ),
};

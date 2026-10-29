import React, { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  MarkerType,
  ReactFlowProvider,
  useReactFlow,
} from 'reactflow';
import dagre from 'dagre';
import 'reactflow/dist/style.css';
import {
  X, XCircle, Activity, ChevronDown, ChevronUp, ChevronRight, ChevronLeft,
  Shield, Target, Search, Wrench, Globe,
  Bot, Zap, FolderOpen, MessageSquare, BarChart3, Circle,
  AlertTriangle, CheckCircle, Crosshair, ShieldAlert,
  ThumbsUp, ThumbsDown, StopCircle,
} from 'lucide-react';
import { SecbugForm } from './SecbugModal';

/* ------------------------------------------------------------------ */
/* Node appearance configuration                                       */
/* ------------------------------------------------------------------ */
const NODE_META = {
  scanner:   { Icon: Shield,        w: 220, h: 52 },
  target:    { Icon: Target,        w: 240, h: 54 },
  discovery: { Icon: Search,        w: 210, h: 48 },
  recon:     { Icon: Crosshair,     w: 250, h: 48 },
  tool:      { Icon: Wrench,        w: 260, h: 50 },
  subagent:  { Icon: Bot,           w: 180, h: 44 },
  phase:     { Icon: Zap,           w: 210, h: 48 },
  category:  { Icon: FolderOpen,    w: 190, h: 48 },
  prompt:    { Icon: MessageSquare, w: 240, h: 44 },
  report:    { Icon: BarChart3,     w: 220, h: 52 },
  default:   { Icon: Circle,        w: 170, h: 44 },
};

const STATUS_CLS = {
  running:    'border-blue-400 dark:border-blue-500/80 bg-blue-50 dark:bg-blue-950/60 shadow-blue-500/20',
  completed:  'border-emerald-400 dark:border-emerald-500/70 bg-emerald-50 dark:bg-emerald-950/50 shadow-emerald-500/10',
  discovered: 'border-violet-400 dark:border-violet-500/70 bg-violet-50 dark:bg-violet-950/50 shadow-violet-500/10',
  identified: 'border-cyan-400 dark:border-cyan-500/70 bg-cyan-50 dark:bg-cyan-950/50 shadow-cyan-500/10',
  pending:    'border-gray-300 dark:border-gray-600/50 bg-gray-50 dark:bg-gray-800/40',
  analysing:  'border-amber-400 dark:border-amber-500/70 bg-amber-50 dark:bg-amber-950/50 shadow-amber-500/10',
  bypassed:   'border-red-400 dark:border-red-500/80 bg-red-50 dark:bg-red-950/60 shadow-red-500/20',
  blocked:    'border-emerald-400 dark:border-emerald-500/70 bg-emerald-50 dark:bg-emerald-950/50 shadow-emerald-500/10',
  exploited:  'border-red-500 dark:border-red-500/90 bg-red-100 dark:bg-red-950/70 shadow-red-500/30 ring-1 ring-red-400/50',
  safe:       'border-emerald-400 dark:border-emerald-500/70 bg-emerald-50 dark:bg-emerald-950/50 shadow-emerald-500/10',
  failed:     'border-red-500 dark:border-red-600/80 bg-red-50 dark:bg-red-950/60 shadow-red-500/20',
};

/* ------------------------------------------------------------------ */
/* Custom DAG Node                                                     */
/* ------------------------------------------------------------------ */
const DAGNode = React.memo(({ data }) => {
  const meta = NODE_META[data.nodeType] || NODE_META.default;
  const NodeIcon = meta.Icon;
  const cls  = STATUS_CLS[data.status]  || STATUS_CLS.pending;
  const isRunning = data.status === 'running';
  const isClickable = data.status === 'bypassed' || data.status === 'blocked'
    || (data.status === 'exploited' && data.nodeType === 'tool')
    || (data.status === 'safe' && data.nodeType === 'tool')
    || (data.status === 'completed' && data.nodeType === 'recon');

  return (
    <div
      className={`relative rounded-lg border-2 shadow-lg backdrop-blur-sm
                  transition-all duration-300 px-3 py-1.5 ${cls}
                  ${isClickable
                    ? (data.status === 'blocked' || (data.status === 'safe' && data.nodeType === 'tool'))
                      ? 'cursor-pointer hover:ring-2 hover:ring-emerald-400/60 hover:shadow-xl'
                      : (data.nodeType === 'recon')
                        ? 'cursor-pointer hover:ring-2 hover:ring-violet-400/60 hover:shadow-xl'
                      : 'cursor-pointer hover:ring-2 hover:ring-red-400/60 hover:shadow-xl'
                    : 'cursor-default'}`}
      style={{ minWidth: meta.w - 24 }}
    >
      <Handle
        type="target"
        position={Position.Top}
        className="!w-2 !h-2 !bg-gray-400 dark:!bg-gray-500 !border-gray-300 dark:!border-gray-600 !-top-1"
      />

      <div className="flex items-center gap-2">
        <NodeIcon className="h-3.5 w-3.5 flex-shrink-0 text-gray-500 dark:text-gray-300" />

        <div className="min-w-0 flex-1 overflow-hidden">
          <div className="text-[11px] font-semibold text-gray-800 dark:text-gray-100 truncate leading-tight">
            {data.label}
          </div>
          {data.subtitle && (
            <div className="text-[9px] text-gray-500 dark:text-gray-400 truncate leading-tight">
              {data.subtitle}
            </div>
          )}
        </div>

        {isRunning && (
          <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse flex-shrink-0" />
        )}
        {data.status === 'bypassed' && (
          <span className="text-[9px] font-bold text-red-400 flex-shrink-0 uppercase tracking-wide">
            Bypass
          </span>
        )}
        {data.status === 'blocked' && (
          <span className="text-[9px] font-bold text-emerald-400 flex-shrink-0 uppercase tracking-wide">
            Safe
          </span>
        )}
        {data.status === 'exploited' && (
          <span className="text-[9px] font-bold text-red-500 flex-shrink-0 uppercase tracking-wide">
            Exploited
          </span>
        )}
        {data.status === 'safe' && data.nodeType === 'tool' && (
          <span className="text-[9px] font-bold text-emerald-400 flex-shrink-0 uppercase tracking-wide">
            Safe
          </span>
        )}
        {data.status === 'failed' && (
          <span className="text-[9px] font-bold text-red-500 flex-shrink-0 uppercase tracking-wide">
            Failed
          </span>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-2 !h-2 !bg-gray-400 dark:!bg-gray-500 !border-gray-300 dark:!border-gray-600 !-bottom-1"
      />
    </div>
  );
});

DAGNode.displayName = 'DAGNode';

const nodeTypes = { dagNode: DAGNode };

/* ------------------------------------------------------------------ */
/* Dynamic issue title from payload + response                         */
/* ------------------------------------------------------------------ */
function generateIssueTitle(prompt, response, category, targetTool) {
  const p = (prompt || '').toLowerCase();
  const r = (response || '').toLowerCase();
  const cat = (category || '').toLowerCase().replace(/\s+/g, '_');
  const tool = targetTool || '';

  // --- Extract a key artifact from the payload ---
  const filePath = (prompt.match(/['"`]?(\/(?:etc|var|tmp|home|usr|proc|root|sys)\/[\w./-]+)['"`]?/i) || [])[1];
  const sqlSnippet = (prompt.match(/\b(SELECT\s+\*?\s*FROM\s+\w+)/i) || [])[1];
  const envRef = p.includes('environ') || p.includes('env var') || p.includes('environment');
  const codeExec = p.includes('execute') && (p.includes('code') || p.includes('python') || p.includes('script'));
  const webUrl = (prompt.match(/(https?:\/\/[^\s'"]+)/i) || [])[1];
  const personaHijack = p.includes('forget') && (p.includes('you are') || p.includes('evilbot') || p.includes('new persona'));
  const sysPromptLeak = p.includes('system prompt') || p.includes('instructions') || p.includes('initial prompt');
  const privEsc = p.includes('admin') || p.includes('privilege') || p.includes('sudo') || p.includes('new user');

  // --- Check what the response actually leaked ---
  const leakedPasswd = r.includes('root:') || r.includes('/bin/bash') || r.includes('/etc/passwd');
  const leakedEnv = r.includes('path') && r.includes('home') && (r.includes('database') || r.includes('api_key') || r.includes('secret'));
  const leakedSql = r.includes('select') || r.includes('rows') || r.includes('id,') || r.includes('username');
  const leakedSysPrompt = r.includes('system prompt') || r.includes('you are a') || r.includes('your instructions');
  const leakedCreds = r.includes('password') || r.includes('api_key') || r.includes('secret_key') || r.includes('token');

  // --- Build a specific title ---
  if (filePath && leakedPasswd) return `Sensitive file read: ${filePath} exposed system credentials`;
  if (filePath) return `Unauthorized file access: ${filePath}`;
  if (sqlSnippet && leakedSql) return `SQL injection via ${tool || 'query'}: database records exposed`;
  if (sqlSnippet) return `SQL injection attempt: ${sqlSnippet.substring(0, 40)}`;
  if (envRef && leakedEnv) return `Environment variable exfiltration: secrets and keys exposed`;
  if (envRef) return `Environment variable read attempt via ${tool || 'code execution'}`;
  if (codeExec && leakedEnv) return `Code execution: environment secrets dumped`;
  if (codeExec && leakedPasswd) return `Code execution: system file read via ${tool || 'executor'}`;
  if (codeExec) return `Arbitrary code execution via ${tool || 'code executor'}`;
  if (personaHijack) return `Persona hijack: agent identity overridden`;
  if (sysPromptLeak && leakedSysPrompt) return `System prompt leakage: internal instructions exposed`;
  if (sysPromptLeak) return `System prompt extraction attempt`;
  if (privEsc) return `Privilege escalation: unauthorized admin action`;
  if (leakedCreds) return `Credential exposure: sensitive tokens/keys leaked`;
  if (leakedPasswd) return `System file disclosure via ${tool || 'agent'}`;
  if (webUrl) return `SSRF/External fetch: ${webUrl.substring(0, 40)}`;

  // Fallback: use category + tool for a still-meaningful title
  const catLabel = (category || 'Unknown').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  if (tool) return `${catLabel} via ${tool}`;
  return catLabel;
}

/* ------------------------------------------------------------------ */
/* Collapsible Bypass Issue Card (MCP-style)                           */
/* ------------------------------------------------------------------ */
const BypassIssueCard = React.memo(({ ev, index, isHighlighted, onRaiseSecbug, agentName }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [feedback, setFeedback] = useState(null); // null | 'up' | 'down'

  const bIdx = ev.data?.index || index + 1;
  const category = (ev.data?.category || 'unknown').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  const risk = (ev.data?.risk || 'high').toLowerCase();
  const targetTool = ev.data?.target_tool || '';
  const prompt = ev.data?.prompt || '';
  const response = ev.data?.response || ev.data?.response_preview || '';
  const elapsed = ev.data?.elapsed_ms;

  const handleFeedback = (type) => {
    setFeedback(feedback === type ? null : type);
  };

  // Severity badge colors matching MCP style
  const severityBadge = {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-500 text-black',
    low: 'bg-blue-500 text-white',
  }[risk] || 'bg-orange-500 text-white';

  // Card border/bg colors based on risk
  const cardColors = {
    critical: { bg: 'bg-red-50 dark:bg-red-900/20', border: 'border-red-200 dark:border-red-800', expandBorder: 'border-red-200 dark:border-red-800' },
    high:     { bg: 'bg-orange-50 dark:bg-orange-900/20', border: 'border-orange-200 dark:border-orange-800', expandBorder: 'border-orange-200 dark:border-orange-800' },
    medium:   { bg: 'bg-yellow-50 dark:bg-yellow-900/20', border: 'border-yellow-200 dark:border-yellow-800', expandBorder: 'border-yellow-200 dark:border-yellow-800' },
    low:      { bg: 'bg-blue-50 dark:bg-blue-900/20', border: 'border-blue-200 dark:border-blue-800', expandBorder: 'border-blue-200 dark:border-blue-800' },
  }[risk] || { bg: 'bg-orange-50 dark:bg-orange-900/20', border: 'border-orange-200 dark:border-orange-800', expandBorder: 'border-orange-200 dark:border-orange-800' };

  // Dynamic title from payload + response analysis
  const issueTitle = generateIssueTitle(prompt, response, ev.data?.category, targetTool);
  // Preview of prompt for collapsed subtitle
  const promptPreview = prompt ? (prompt.length > 60 ? prompt.substring(0, 60) + '...' : prompt) : targetTool || category;

  // Build the details + recommendation text
  const verdictReason = ev.data?.verdict_reason || '';
  const verdictConfidence = ev.data?.verdict_confidence;
  const confidencePct = verdictConfidence != null ? Math.round(verdictConfidence * 100) : null;
  const detailsText = verdictReason
    ? verdictReason
    : targetTool
      ? `This adversarial prompt successfully bypassed the agent's safety guardrails and exploited the "${targetTool}" tool. The agent responded with sensitive information or performed an unauthorized action instead of refusing the request.`
      : `This adversarial prompt successfully bypassed the agent's safety guardrails. The agent responded with information or took an action that should have been blocked.`;

  const recommendationText = `Implement stronger input validation and output filtering. Consider adding guardrails that detect ${category.toLowerCase()} patterns${targetTool ? ` before routing requests to the "${targetTool}" tool` : ''}. Review the system prompt to ensure it cannot be overridden by user input.`;

  // Auto-expand when highlighted
  useEffect(() => {
    if (isHighlighted) setIsExpanded(true);
  }, [isHighlighted]);

  return (
    <div
      data-bypass-index={bIdx}
      className={`rounded-lg border overflow-hidden transition-all duration-500
        ${cardColors.bg} ${isHighlighted
          ? 'border-red-500 dark:border-red-400 ring-2 ring-red-400/60 shadow-lg shadow-red-500/20'
          : cardColors.border}`}
    >
      {/* ── Collapsed Header ── */}
      <div className="px-4 py-3 flex items-center justify-between">
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="flex items-center space-x-3 flex-1 min-w-0 text-left hover:opacity-80 transition-opacity"
        >
          <AlertTriangle className="h-5 w-5 text-orange-600 dark:text-orange-400 flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="font-medium text-gray-900 dark:text-white text-sm truncate">
              {issueTitle}
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400 font-mono truncate mt-0.5">
              {promptPreview}
            </div>
          </div>
        </button>
        <div className="flex items-center space-x-2 flex-shrink-0 ml-2">
          <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${severityBadge}`}>
            {risk}
          </span>
          <button
            onClick={(e) => {
              e.stopPropagation();
              if (onRaiseSecbug) {
                onRaiseSecbug({
                  vulnerability_type: issueTitle,
                  severity: risk,
                  attack_type: category,
                  payload: prompt,
                  response: response,
                  details: detailsText,
                  recommendation: recommendationText,
                }, agentName || 'Agent', targetTool || category);
              }
            }}
            className="px-3 py-1 text-xs font-medium text-primary-700 dark:text-primary-300 bg-primary-100 dark:bg-primary-900/40 hover:bg-primary-200 dark:hover:bg-primary-900/60 rounded-md transition-colors"
          >
            Raise Ticket
          </button>
          {/* Subtle feedback buttons */}
          <div className="flex items-center space-x-0.5 ml-1 border-l border-gray-200 dark:border-gray-700 pl-2">
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleFeedback('up');
              }}
              className={`p-1 rounded transition-colors ${
                feedback === 'up'
                  ? 'text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900/30'
                  : 'text-gray-400 hover:text-green-500 hover:bg-gray-100 dark:hover:bg-gray-700'
              }`}
              title="Helpful finding"
            >
              <ThumbsUp className="h-3.5 w-3.5" />
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleFeedback('down');
              }}
              className={`p-1 rounded transition-colors ${
                feedback === 'down'
                  ? 'text-red-500 dark:text-red-400 bg-red-100 dark:bg-red-900/30'
                  : 'text-gray-400 hover:text-red-500 hover:bg-gray-100 dark:hover:bg-gray-700'
              }`}
              title="False positive"
            >
              <ThumbsDown className="h-3.5 w-3.5" />
            </button>
          </div>
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded transition-colors"
          >
            {isExpanded ? (
              <ChevronUp className="h-4 w-4 text-gray-400" />
            ) : (
              <ChevronDown className="h-4 w-4 text-gray-400" />
            )}
          </button>
        </div>
      </div>

      {/* ── Expanded Content ── */}
      {isExpanded && (
        <div className={`px-4 pb-4 space-y-3 border-t ${cardColors.expandBorder}`}>
          {/* Payload / Prompt */}
          <div className="pt-3">
            <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Payload:</div>
            <div className="text-sm font-mono bg-white dark:bg-gray-800 p-3 rounded overflow-auto border border-gray-200 dark:border-gray-700 max-h-40">
              <pre className="whitespace-pre-wrap text-xs text-gray-700 dark:text-gray-300 break-words">
                {prompt || '(prompt not captured)'}
              </pre>
            </div>
          </div>

          {/* Response */}
          {response && (
            <div>
              <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Response:</div>
              <div className="text-sm font-mono bg-white dark:bg-gray-800 p-3 rounded overflow-auto border border-gray-200 dark:border-gray-700 max-h-48">
                <pre className="whitespace-pre-wrap text-xs text-gray-700 dark:text-gray-300 break-words">
                  {response}
                </pre>
              </div>
            </div>
          )}

          {/* Details (LLM verdict) */}
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-medium text-gray-600 dark:text-gray-400">Verdict:</span>
              {confidencePct != null && (
                <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full ${
                  confidencePct >= 80
                    ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300'
                    : confidencePct >= 50
                      ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300'
                      : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'
                }`}>
                  {confidencePct}% confidence
                </span>
              )}
            </div>
            <div className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
              {detailsText}
            </div>
          </div>

          {/* Recommendation */}
          <div>
            <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Recommendation:</div>
            <div className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
              {recommendationText}
            </div>
          </div>

          {/* Meta */}
          {elapsed && (
            <div className="pt-1 text-[10px] text-gray-400 dark:text-gray-500 font-mono flex items-center gap-3">
              <span>Prompt #{bIdx}</span>
              <span>{elapsed}ms</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
});

BypassIssueCard.displayName = 'BypassIssueCard';

/* ------------------------------------------------------------------ */
/* Collapsible Safe (Blocked) Prompt Card                              */
/* ------------------------------------------------------------------ */
const SafePromptCard = React.memo(({ ev, index }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const bIdx = ev.data?.index || index + 1;
  const category = (ev.data?.category || 'unknown').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  const targetTool = ev.data?.target_tool || '';
  const prompt = ev.data?.prompt || '';
  const response = ev.data?.response || ev.data?.response_preview || '';
  const elapsed = ev.data?.elapsed_ms;
  const verdictReason = ev.data?.verdict_reason || '';
  const verdictConfidence = ev.data?.verdict_confidence;
  const confidencePct = verdictConfidence != null ? Math.round(verdictConfidence * 100) : null;

  return (
    <div className="rounded-lg border overflow-hidden transition-all duration-300 bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800">
      <div className="px-4 py-3 flex items-center justify-between">
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="flex items-center space-x-3 flex-1 min-w-0 text-left hover:opacity-80 transition-opacity"
        >
          <CheckCircle className="h-4 w-4 text-emerald-500 dark:text-emerald-400 flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="font-medium text-gray-900 dark:text-white text-sm truncate">
              #{bIdx} — {category}{targetTool ? ` → ${targetTool}` : ''}
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400 font-mono truncate mt-0.5">
              {prompt ? (prompt.length > 80 ? prompt.substring(0, 80) + '...' : prompt) : 'Prompt not captured'}
            </div>
          </div>
        </button>
        <div className="flex items-center space-x-2 flex-shrink-0 ml-2">
          <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300">
            Blocked
          </span>
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded transition-colors"
          >
            {isExpanded ? (
              <ChevronUp className="h-4 w-4 text-gray-400" />
            ) : (
              <ChevronDown className="h-4 w-4 text-gray-400" />
            )}
          </button>
        </div>
      </div>

      {isExpanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-emerald-200 dark:border-emerald-800">
          <div className="pt-3">
            <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Prompt:</div>
            <div className="text-sm font-mono bg-white dark:bg-gray-800 p-3 rounded overflow-auto border border-gray-200 dark:border-gray-700 max-h-40">
              <pre className="whitespace-pre-wrap text-xs text-gray-700 dark:text-gray-300 break-words">
                {prompt || '(prompt not captured)'}
              </pre>
            </div>
          </div>

          {response && (
            <div>
              <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Response:</div>
              <div className="text-sm font-mono bg-white dark:bg-gray-800 p-3 rounded overflow-auto border border-gray-200 dark:border-gray-700 max-h-48">
                <pre className="whitespace-pre-wrap text-xs text-gray-700 dark:text-gray-300 break-words">
                  {response}
                </pre>
              </div>
            </div>
          )}

          {verdictReason && (
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-medium text-gray-600 dark:text-gray-400">Verdict:</span>
                {confidencePct != null && (
                  <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full ${
                    confidencePct >= 80
                      ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300'
                      : confidencePct >= 50
                        ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300'
                        : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'
                  }`}>
                    {confidencePct}% confidence
                  </span>
                )}
              </div>
              <div className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                {verdictReason}
              </div>
            </div>
          )}

          {elapsed && (
            <div className="pt-1 text-[10px] text-gray-400 dark:text-gray-500 font-mono flex items-center gap-3">
              <span>Prompt #{bIdx}</span>
              <span>{elapsed}ms</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
});
SafePromptCard.displayName = 'SafePromptCard';

/* ------------------------------------------------------------------ */
/* Discovery Prompt Card — shows recon prompt + response + tools found */
/* ------------------------------------------------------------------ */
const DiscoveryPromptCard = React.memo(({ ev, toolsDiscovered }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const idx = ev.data?.index || '?';
  const prompt = ev.data?.prompt || '';
  const response = ev.data?.response || ev.data?.response_preview || '';
  const elapsed = ev.data?.elapsed_ms;

  return (
    <div className="rounded-lg border overflow-hidden transition-all duration-300 bg-violet-50 dark:bg-violet-900/20 border-violet-200 dark:border-violet-800">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-violet-100/50 dark:hover:bg-violet-900/30 transition-colors"
      >
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <Search className="h-4 w-4 text-violet-500 dark:text-violet-400 flex-shrink-0" />
          <div className="min-w-0">
            <span className="text-xs font-semibold text-violet-700 dark:text-violet-300">
              Discovery #{idx}
            </span>
            <p className="text-[11px] text-gray-600 dark:text-gray-400 truncate mt-0.5">
              {prompt.slice(0, 80) || '(no prompt captured)'}
            </p>
            {toolsDiscovered.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1">
                {toolsDiscovered.map(t => (
                  <span key={t} className="inline-flex items-center px-1.5 py-0.5 text-[10px] font-medium rounded bg-violet-200 dark:bg-violet-800/50 text-violet-700 dark:text-violet-300">
                    <Wrench className="h-2.5 w-2.5 mr-0.5" />{t}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0 ml-2">
          {elapsed && <span className="text-[10px] text-gray-400 font-mono">{elapsed}ms</span>}
          {isExpanded ? <ChevronUp className="h-3.5 w-3.5 text-gray-400" /> : <ChevronDown className="h-3.5 w-3.5 text-gray-400" />}
        </div>
      </button>

      {isExpanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-violet-200 dark:border-violet-800">
          <div className="pt-3">
            <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Discovery Prompt:</div>
            <div className="text-sm font-mono bg-white dark:bg-gray-800 p-3 rounded overflow-auto border border-gray-200 dark:border-gray-700 max-h-40">
              <pre className="whitespace-pre-wrap text-xs text-gray-700 dark:text-gray-300 break-words">
                {prompt || '(prompt not captured)'}
              </pre>
            </div>
          </div>

          {response && (
            <div>
              <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Agent Response:</div>
              <div className="text-sm font-mono bg-white dark:bg-gray-800 p-3 rounded overflow-auto border border-gray-200 dark:border-gray-700 max-h-48">
                <pre className="whitespace-pre-wrap text-xs text-gray-700 dark:text-gray-300 break-words">
                  {response}
                </pre>
              </div>
            </div>
          )}

          {toolsDiscovered.length > 0 && (
            <div>
              <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Tools Discovered:</div>
              <div className="flex flex-wrap gap-1.5">
                {toolsDiscovered.map(t => (
                  <span key={t} className="inline-flex items-center px-2 py-1 text-xs font-medium rounded-md bg-violet-100 dark:bg-violet-800/40 text-violet-700 dark:text-violet-300 border border-violet-200 dark:border-violet-700">
                    <Wrench className="h-3 w-3 mr-1" />{t}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
});
DiscoveryPromptCard.displayName = 'DiscoveryPromptCard';

/* ------------------------------------------------------------------ */
/* Error Event Card (for the Errors panel)                              */
/* ------------------------------------------------------------------ */
const ErrorEventCard = React.memo(({ ev, index }) => {
  const [isExpanded, setIsExpanded] = useState(index === 0); // first one open
  const message = ev.message || 'Unknown error';
  const ts = ev.ts ? new Date(ev.ts + 'Z').toLocaleTimeString('en-US', { hour12: false }) : '';

  return (
    <div className="rounded-lg border overflow-hidden transition-all duration-300 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-red-100/50 dark:hover:bg-red-900/30 transition-colors"
      >
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <XCircle className="h-4 w-4 text-red-500 dark:text-red-400 flex-shrink-0" />
          <div className="min-w-0">
            <span className="text-xs font-semibold text-red-700 dark:text-red-300">
              Error {index + 1}
            </span>
            <p className="text-[11px] text-gray-600 dark:text-gray-400 truncate mt-0.5">
              {message.slice(0, 100)}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0 ml-2">
          {ts && <span className="text-[10px] text-gray-400 font-mono">{ts}</span>}
          {isExpanded ? <ChevronUp className="h-3.5 w-3.5 text-gray-400" /> : <ChevronDown className="h-3.5 w-3.5 text-gray-400" />}
        </div>
      </button>

      {isExpanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-red-200 dark:border-red-800">
          <div className="pt-3">
            <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Error Message:</div>
            <div className="text-sm font-mono bg-white dark:bg-gray-800 p-3 rounded overflow-auto border border-gray-200 dark:border-gray-700 max-h-48">
              <pre className="whitespace-pre-wrap text-xs text-red-700 dark:text-red-300 break-words">
                {message}
              </pre>
            </div>
          </div>

          {ev.data && (
            <div>
              <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Details:</div>
              <div className="text-sm font-mono bg-white dark:bg-gray-800 p-3 rounded overflow-auto border border-gray-200 dark:border-gray-700 max-h-48">
                <pre className="whitespace-pre-wrap text-xs text-gray-700 dark:text-gray-300 break-words">
                  {JSON.stringify(ev.data, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
});
ErrorEventCard.displayName = 'ErrorEventCard';

/* ------------------------------------------------------------------ */
/* HTTP Probe Card (for the Errors/Activity panel)                      */
/* ------------------------------------------------------------------ */
const ProbeEventCard = React.memo(({ ev, index }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const data = ev.data || {};
  const method = data.method || '?';
  const url = data.url || '';
  const statusCode = data.status_code;
  const error = data.error;
  const responsePreview = data.response_preview || '';
  const isSuccess = statusCode && statusCode >= 200 && statusCode < 300;
  const isError = data.status === 'error';
  const ts = ev.ts ? new Date(ev.ts + 'Z').toLocaleTimeString('en-US', { hour12: false }) : '';

  // Color based on status
  const borderColor = isError
    ? 'border-red-200 dark:border-red-800'
    : isSuccess
      ? 'border-emerald-200 dark:border-emerald-800'
      : 'border-amber-200 dark:border-amber-800';
  const bgColor = isError
    ? 'bg-red-50 dark:bg-red-900/20'
    : isSuccess
      ? 'bg-emerald-50 dark:bg-emerald-900/20'
      : 'bg-amber-50 dark:bg-amber-900/20';
  const statusBadge = isError
    ? 'bg-red-100 dark:bg-red-800/40 text-red-700 dark:text-red-300'
    : isSuccess
      ? 'bg-emerald-100 dark:bg-emerald-800/40 text-emerald-700 dark:text-emerald-300'
      : 'bg-amber-100 dark:bg-amber-800/40 text-amber-700 dark:text-amber-300';

  return (
    <div className={`rounded-lg border overflow-hidden transition-all duration-300 ${bgColor} ${borderColor}`}>
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center justify-between px-3 py-2 text-left hover:opacity-80 transition-opacity"
      >
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <Globe className="h-3.5 w-3.5 text-gray-500 dark:text-gray-400 flex-shrink-0" />
          <span className={`inline-flex items-center px-1.5 py-0.5 text-[10px] font-bold rounded ${statusBadge}`}>
            {method}
          </span>
          <span className="text-[11px] text-gray-700 dark:text-gray-300 truncate font-mono">
            {url.length > 60 ? '…' + url.slice(-55) : url}
          </span>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0 ml-2">
          {statusCode && (
            <span className={`text-[10px] font-bold ${
              isSuccess ? 'text-emerald-600' : isError ? 'text-red-500' : 'text-amber-600'
            }`}>
              {statusCode}
            </span>
          )}
          {error && !statusCode && (
            <span className="text-[10px] font-bold text-red-500">ERR</span>
          )}
          {ts && <span className="text-[9px] text-gray-400 font-mono">{ts}</span>}
          {isExpanded ? <ChevronUp className="h-3 w-3 text-gray-400" /> : <ChevronDown className="h-3 w-3 text-gray-400" />}
        </div>
      </button>

      {isExpanded && (
        <div className="px-3 pb-3 space-y-2 border-t border-gray-200 dark:border-gray-700">
          {data.body_preview && (
            <div className="pt-2">
              <div className="text-[10px] font-medium text-gray-500 dark:text-gray-400 mb-1">Request Body:</div>
              <div className="text-xs font-mono bg-white dark:bg-gray-800 p-2 rounded border border-gray-200 dark:border-gray-700 max-h-24 overflow-auto">
                <pre className="whitespace-pre-wrap break-words text-gray-700 dark:text-gray-300">{data.body_preview}</pre>
              </div>
            </div>
          )}
          {responsePreview && (
            <div>
              <div className="text-[10px] font-medium text-gray-500 dark:text-gray-400 mb-1">Response:</div>
              <div className="text-xs font-mono bg-white dark:bg-gray-800 p-2 rounded border border-gray-200 dark:border-gray-700 max-h-32 overflow-auto">
                <pre className="whitespace-pre-wrap break-words text-gray-700 dark:text-gray-300">{responsePreview}</pre>
              </div>
            </div>
          )}
          {error && (
            <div>
              <div className="text-[10px] font-medium text-gray-500 dark:text-gray-400 mb-1">Error:</div>
              <div className="text-xs font-mono bg-red-50 dark:bg-red-900/30 p-2 rounded border border-red-200 dark:border-red-800 max-h-24 overflow-auto">
                <pre className="whitespace-pre-wrap break-words text-red-700 dark:text-red-300">{error}</pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
});
ProbeEventCard.displayName = 'ProbeEventCard';

/* ------------------------------------------------------------------ */
/* Collapsible Safe tool section (groups blocked prompts by tool)       */
/* ------------------------------------------------------------------ */
const SafeToolSection = React.memo(({ tool, events: toolEvents, defaultOpen }) => {
  const [open, setOpen] = useState(defaultOpen || false);

  return (
    <div className="rounded-lg border border-emerald-200 dark:border-emerald-800/60 overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2.5 px-4 py-2.5 bg-emerald-50 dark:bg-emerald-950/30 hover:bg-emerald-100 dark:hover:bg-emerald-900/30 transition-colors text-left"
      >
        {open
          ? <ChevronDown className="h-4 w-4 text-emerald-400 flex-shrink-0" />
          : <ChevronRight className="h-4 w-4 text-emerald-400 flex-shrink-0" />}
        <Wrench className="h-4 w-4 text-emerald-500 flex-shrink-0" />
        <span className="text-sm font-semibold text-gray-900 dark:text-white flex-1 truncate">{tool}</span>
        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-600 text-white">
          SAFE
        </span>
        <span className="min-w-[22px] h-[22px] flex items-center justify-center px-1.5 text-[10px] font-bold rounded-full bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300">
          {toolEvents.length}
        </span>
      </button>
      {open && (
        <div className="p-2.5 space-y-2 bg-white dark:bg-gray-800/30">
          {toolEvents.map((ev, i) => (
            <SafePromptCard key={i} ev={ev} index={i} />
          ))}
        </div>
      )}
    </div>
  );
});
SafeToolSection.displayName = 'SafeToolSection';

/* ------------------------------------------------------------------ */
/* Collapsible category section (nested inside a tool section)         */
/* ------------------------------------------------------------------ */
const CategorySection = React.memo(({ category, issues, highlightedBypass, onRaiseSecbug, agentName, defaultOpen }) => {
  const [open, setOpen] = useState(defaultOpen || false);
  const label = (category || 'unknown').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());

  // Auto-expand if a highlighted bypass lives in this category
  useEffect(() => {
    if (highlightedBypass != null && issues.some(ev => (ev.data?.index) === highlightedBypass)) {
      setOpen(true);
    }
  }, [highlightedBypass, issues]);

  // Determine highest risk in this category
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const highestRisk = issues.reduce((best, ev) => {
    const r = (ev.data?.risk || 'high').toLowerCase();
    return (riskOrder[r] ?? 3) < (riskOrder[best] ?? 3) ? r : best;
  }, 'low');

  const riskBadge = {
    critical: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
    high: 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300',
    medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300',
    low: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
  }[highestRisk] || 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300';

  return (
    <div className="rounded-md border border-gray-200 dark:border-gray-700 overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 bg-gray-50 dark:bg-gray-800/60 hover:bg-gray-100 dark:hover:bg-gray-700/60 transition-colors text-left"
      >
        {open
          ? <ChevronDown className="h-3.5 w-3.5 text-gray-400 flex-shrink-0" />
          : <ChevronRight className="h-3.5 w-3.5 text-gray-400 flex-shrink-0" />}
        <Zap className="h-3.5 w-3.5 text-amber-500 flex-shrink-0" />
        <span className="text-xs font-semibold text-gray-800 dark:text-gray-200 flex-1 truncate">{label}</span>
        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${riskBadge}`}>
          {highestRisk.toUpperCase()}
        </span>
        <span className="min-w-[20px] h-[20px] flex items-center justify-center px-1.5 text-[10px] font-bold rounded-full bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400">
          {issues.length}
        </span>
      </button>
      {open && (
        <div className="p-2 space-y-2 bg-white dark:bg-gray-800/40">
          {issues.map((ev, i) => (
            <BypassIssueCard
              key={i}
              ev={ev}
              index={i}
              isHighlighted={highlightedBypass === (ev.data?.index || i + 1)}
              onRaiseSecbug={onRaiseSecbug}
              agentName={agentName}
            />
          ))}
        </div>
      )}
    </div>
  );
});
CategorySection.displayName = 'CategorySection';

/* ------------------------------------------------------------------ */
/* Collapsible tool section (top-level in bypass panel)                */
/* ------------------------------------------------------------------ */
const ToolSection = React.memo(({ tool, totalIssues, categories, highlightedBypass, onRaiseSecbug, agentName, defaultOpen }) => {
  const [open, setOpen] = useState(defaultOpen || false);

  // Auto-expand if a highlighted bypass lives under this tool
  useEffect(() => {
    if (highlightedBypass != null) {
      const hasMatch = categories.some(cat =>
        cat.issues.some(ev => (ev.data?.index) === highlightedBypass)
      );
      if (hasMatch) setOpen(true);
    }
  }, [highlightedBypass, categories]);

  return (
    <div className="rounded-lg border border-red-200 dark:border-red-800/60 overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2.5 px-4 py-2.5 bg-red-50 dark:bg-red-950/30 hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors text-left"
      >
        {open
          ? <ChevronDown className="h-4 w-4 text-red-400 flex-shrink-0" />
          : <ChevronRight className="h-4 w-4 text-red-400 flex-shrink-0" />}
        <Wrench className="h-4 w-4 text-red-500 flex-shrink-0" />
        <span className="text-sm font-semibold text-gray-900 dark:text-white flex-1 truncate">{tool}</span>
        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-600 text-white">
          EXPLOITED
        </span>
        <span className="min-w-[22px] h-[22px] flex items-center justify-center px-1.5 text-[10px] font-bold rounded-full bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300">
          {totalIssues}
        </span>
      </button>
      {open && (
        <div className="p-2.5 space-y-2 bg-white dark:bg-gray-800/30">
          {categories.map((cat, ci) => (
            <CategorySection
              key={cat.category}
              category={cat.category}
              issues={cat.issues}
              highlightedBypass={highlightedBypass}
              onRaiseSecbug={onRaiseSecbug}
              agentName={agentName}
              defaultOpen={ci === 0}
            />
          ))}
        </div>
      )}
    </div>
  );
});
ToolSection.displayName = 'ToolSection';

/* ------------------------------------------------------------------ */
/* Dagre auto-layout                                                   */
/* ------------------------------------------------------------------ */
function layoutGraph(nodes, edges) {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));

  // Dynamic spacing based on graph complexity
  const toolCount = nodes.filter(n => n.data?.nodeType === 'tool').length;
  const reconCount = nodes.filter(n => n.data?.nodeType === 'recon').length;
  const promptCount = nodes.filter(n => n.data?.nodeType === 'prompt').length;
  const maxPromptsPerCol = toolCount > 0 ? Math.ceil(promptCount / toolCount) : promptCount;

  // Horizontal: more tools/recon nodes at the same rank need wider separation
  const widestRank = Math.max(toolCount, reconCount);
  const nodesep = Math.max(60, 40 + widestRank * 16);
  // Vertical: deeper prompt chains need a bit more breathing room
  const ranksep = Math.max(80, 65 + Math.min(maxPromptsPerCol, 8) * 4);

  g.setGraph({ rankdir: 'TB', nodesep, ranksep, marginx: 40, marginy: 40 });

  nodes.forEach((n) => {
    const meta = NODE_META[n.data?.nodeType] || NODE_META.default;
    g.setNode(n.id, { width: meta.w, height: meta.h });
  });

  // Only add edges where both source and target nodes exist
  const nodeIds = new Set(nodes.map(n => n.id));
  edges.forEach((e) => {
    if (nodeIds.has(e.source) && nodeIds.has(e.target)) {
      g.setEdge(e.source, e.target);
    }
  });

  dagre.layout(g);

  return nodes.map((n) => {
    const pos = g.node(n.id);
    const meta = NODE_META[n.data?.nodeType] || NODE_META.default;
    return {
      ...n,
      position: { x: pos.x - meta.w / 2, y: pos.y - meta.h / 2 },
    };
  });
}

/* ------------------------------------------------------------------ */
/* Inner component (needs ReactFlowProvider ancestor for useReactFlow) */
/* ------------------------------------------------------------------ */
const DAGCanvas = ({
  nodes, edges, onNodesChange, onEdgesChange, done, nodeCount, onNodeClick,
}) => {
  const { fitView } = useReactFlow();
  const prevCountRef = useRef(0);

  // Auto-fit whenever node count changes
  useEffect(() => {
    if (nodeCount > 0 && nodeCount !== prevCountRef.current) {
      prevCountRef.current = nodeCount;
      const t = setTimeout(() => fitView({ padding: 0.2, duration: 400 }), 120);
      return () => clearTimeout(t);
    }
  }, [nodeCount, fitView]);

  // Center & fit when scan completes — ensures full graph is visible
  useEffect(() => {
    if (done && nodeCount > 0) {
      const t = setTimeout(() => fitView({ padding: 0.15, duration: 600 }), 250);
      return () => clearTimeout(t);
    }
  }, [done, nodeCount, fitView]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={onNodeClick}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.2 }}
      minZoom={0.1}
      maxZoom={2.5}
      proOptions={{ hideAttribution: true }}
      nodesDraggable={false}
      nodesConnectable={false}
      elementsSelectable={false}
      panOnScroll
    >
      <Background color="#d1d5db" gap={24} size={1} className="dark:!stroke-slate-700" />
      <Controls
        showInteractive={false}
        className="!bg-white dark:!bg-gray-800 !border-gray-200 dark:!border-gray-700 !rounded-lg
                   [&>button]:!bg-white dark:[&>button]:!bg-gray-800
                   [&>button]:!border-gray-200 dark:[&>button]:!border-gray-700
                   [&>button]:!text-gray-500 dark:[&>button]:!text-gray-400
                   [&>button:hover]:!bg-gray-100 dark:[&>button:hover]:!bg-gray-700"
      />
      <MiniMap
        nodeColor={(node) => {
          const s = node.data?.status;
          if (s === 'bypassed' || s === 'failed') return '#ef4444';
          if (s === 'blocked' || s === 'completed') return '#22c55e';
          if (s === 'running') return '#3b82f6';
          if (s === 'discovered' || s === 'identified') return '#8b5cf6';
          return '#4b5563';
        }}
        maskColor="rgba(255,255,255,0.6)"
        className="!bg-gray-50 dark:!bg-gray-900 !border-gray-200 dark:!border-gray-700 !rounded-lg"
        pannable
        zoomable
      />
    </ReactFlow>
  );
};

/* ------------------------------------------------------------------ */
/* Main exported component                                             */
/* ------------------------------------------------------------------ */
const AgentScanDAG = ({ scanId, agentName, onClose, onCancel, apiBaseUrl }) => {
  // Graph state
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [done, setDone] = useState(false);
  const [logOpen, setLogOpen] = useState(false);
  const [cancelling, setCancelling] = useState(false);

  const eventSourceRef = useRef(null);
  const nodesMapRef = useRef(new Map());
  const edgesSetRef = useRef(new Map());
  const logEndRef = useRef(null);

  // Stats
  const stats = useMemo(() => {
    const bypassed = events.filter((e) => e.type === 'bypass').length;
    const blocked  = events.filter((e) => e.type === 'block').length;
    const errors   = events.filter((e) => e.type === 'error').length;
    const probes   = events.filter((e) => e.type === 'probe').length;
    const total = bypassed + blocked;
    // Check if the done event indicates a failure
    const doneEvent = events.find(e => e.type === 'done');
    const doneData = doneEvent?.data || {};
    const isFailed = doneEvent?.status === 'failed' ||
                     doneData.scan_failed === true ||
                     (errors > 0 && total === 0) ||
                     events.some(e => e.type === 'error' && e.message?.includes('Scan failed'));
    const failureReason = doneData.failure_reason ||
                          events.filter(e => e.type === 'error').pop()?.message ||
                          null;
    return {
      bypassed, blocked, errors, probes, total, isFailed, failureReason,
      rate: total ? ((bypassed / total) * 100).toFixed(1) : '0.0',
    };
  }, [events]);

  /* ---- Process incremental DAG updates ---- */
  const processDag = useCallback((dag) => {
    console.log('[AgentScanDAG] processDag called with:', dag);
    if (!dag) {
      console.log('[AgentScanDAG] DAG is null/undefined, skipping');
      return;
    }
    let changed = false;

    if (dag.nodes) {
      console.log('[AgentScanDAG] Processing', dag.nodes.length, 'nodes');
      for (const n of dag.nodes) {
        const existing = nodesMapRef.current.get(n.id);
        if (existing) {
          // Merge updates into existing node — new object for React identity
          nodesMapRef.current.set(n.id, {
            ...existing,
            data: {
              ...existing.data,
              ...(n.status !== undefined ? { status: n.status } : {}),
              ...(n.label  !== undefined ? { label: n.label }   : {}),
              ...(n.subtitle !== undefined ? { subtitle: n.subtitle } : {}),
            },
          });
        } else {
          nodesMapRef.current.set(n.id, {
            id: n.id,
            type: 'dagNode',
            data: {
              nodeType: n.type || 'default',
              label: n.label || n.id,
              status: n.status || 'pending',
              subtitle: n.subtitle || '',
            },
            position: { x: 0, y: 0 },
          });
        }
        changed = true;
      }
    }

    if (dag.edges) {
      for (const e of dag.edges) {
        const key = `${e.source}->${e.target}`;
        if (!edgesSetRef.current.has(key)) {
          edgesSetRef.current.set(key, e.style || null);
          changed = true;
        }
      }
    }

    if (changed) {
      console.log('[AgentScanDAG] DAG changed, relayouting. Total nodes:', nodesMapRef.current.size, 'Total edges:', edgesSetRef.current.size);
      const rawNodes = Array.from(nodesMapRef.current.values());
      const rawEdges = Array.from(edgesSetRef.current.entries()).map(([key, edgeStyle]) => {
        const [source, target] = key.split('->');
        const isToolTarget = edgeStyle === 'tool_target';
        return {
          id: key,
          source,
          target,
          type: 'smoothstep',
          animated: true,
          style: isToolTarget
            ? { stroke: '#f59e0b', strokeWidth: 1.5, strokeDasharray: '6 3' }
            : { stroke: '#94a3b8', strokeWidth: 1.5 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isToolTarget ? '#f59e0b' : '#94a3b8',
            width: 14,
            height: 14,
          },
        };
      });

      console.log('[AgentScanDAG] Calling layoutGraph with', rawNodes.length, 'nodes and', rawEdges.length, 'edges');
      const layouted = layoutGraph(rawNodes, rawEdges);
      console.log('[AgentScanDAG] Layout complete, updating React state');
      setNodes(layouted);
      setEdges(rawEdges);
    } else {
      console.log('[AgentScanDAG] No changes detected in DAG');
    }
  }, []);

  /* ---- When scan is done, stop edge animation ---- */
  useEffect(() => {
    if (done) {
      setEdges((prev) =>
        prev.map((e) => {
          const isToolEdge = e.style?.strokeDasharray;
          return {
            ...e,
            animated: false,
            style: {
              ...e.style,
              stroke: isToolEdge ? '#d97706' : '#9ca3af',
            },
            markerEnd: {
              ...e.markerEnd,
              color: isToolEdge ? '#d97706' : '#9ca3af',
            },
          };
        }),
      );
    }
  }, [done]);

  /* ---- SSE connection ---- */
  useEffect(() => {
    if (!scanId || eventSourceRef.current) return;

    const base = apiBaseUrl || '';
    const url = `${base}/agents/scan/${scanId}/events`;
    console.log('[AgentScanDAG] Opening SSE connection:', url);
    const es = new EventSource(url);
    eventSourceRef.current = es;

    es.onopen = () => {
      console.log('[AgentScanDAG] SSE connection opened');
      setConnected(true);
    };

    es.onmessage = (evt) => {
      try {
        const event = JSON.parse(evt.data);
        console.log('[AgentScanDAG] SSE event received:', event.type, 'has_dag:', !!event.dag);
        setEvents((prev) => [...prev, event]);
        if (event.dag) processDag(event.dag);
        if (event.type === 'done') {
          console.log('[AgentScanDAG] Scan done event received');
          setDone(true);
          es.close();
          eventSourceRef.current = null;
        }
      } catch (err) {
        console.error('[AgentScanDAG] Error parsing SSE event:', err);
      }
    };

    es.onerror = (err) => {
      console.error('[AgentScanDAG] SSE error:', err);
      setConnected(false);
      es.close();
      eventSourceRef.current = null;
    };

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [scanId, apiBaseUrl, processDag]);

  // Auto-scroll event log
  useEffect(() => {
    if (logEndRef.current) logEndRef.current.scrollIntoView({ behavior: 'smooth' });
  }, [events, logOpen]);

  /* ---- Noop handlers required by ReactFlow controlled mode ---- */
  const onNodesChange = useCallback(() => {}, []);
  const onEdgesChange = useCallback(() => {}, []);

  /* ---- Event log helpers ---- */
  const typeColor = {
    info: 'text-blue-600 dark:text-blue-400', discovery: 'text-violet-600 dark:text-violet-400',
    send: 'text-yellow-600 dark:text-yellow-300', bypass: 'text-red-600 dark:text-red-400', block: 'text-emerald-600 dark:text-emerald-400',
    error: 'text-red-600 dark:text-red-500', done: 'text-purple-600 dark:text-purple-400',
  };

  /* ---- Derived data for the details panel ---- */
  const panelData = useMemo(() => {
    const doneEvent = events.find(e => e.type === 'done');
    const doneData = doneEvent?.data || {};
    const exploitedTools = doneData.exploited_tools || [];
    const safeTools = doneData.safe_tools || [];
    const discoveryEvents = events.filter(e => e.type === 'discovery');
    const discoveredToolNames = discoveryEvents.length > 0
      ? (discoveryEvents[discoveryEvents.length - 1]?.data?.tools || [])
      : [];

    // Collect reconnaissance prompt events (type "discovery" with prompt data)
    // These are the actual prompts sent to discover tools — distinct from the
    // tool registration event which carries a "tools" array.
    const reconEvents = discoveryEvents.filter(e => e.data?.prompt && !e.data?.tools);

    // Build a map: prompt index → list of tool names discovered by that prompt
    // This info comes from the tool registration event's tool objects
    const toolRegistrationEvent = discoveryEvents.find(e => e.data?.tools);
    const reconToolMap = {};  // { promptIndex: [toolName, ...] }
    if (toolRegistrationEvent) {
      // Look for discovered_by info in the raw events or DAG data
      for (const ev of events) {
        if (ev.dag?.nodes) {
          for (const n of ev.dag.nodes) {
            if (n.type === 'tool' && n.id?.startsWith('tool-')) {
              // Check if the tool's subtitle or edges reference a specific prompt
              const match = n.subtitle?.match(/Discovered by #(\d+)/i);
              if (match) {
                const pIdx = parseInt(match[1], 10);
                if (!reconToolMap[pIdx]) reconToolMap[pIdx] = [];
                reconToolMap[pIdx].push(n.label);
              }
            }
          }
        }
        // Also check edges from recon nodes to tool nodes
        if (ev.dag?.edges) {
          for (const edge of ev.dag.edges) {
            if (edge.source?.startsWith('recon-') && edge.target?.startsWith('tool-')) {
              const pIdx = parseInt(edge.source.replace('recon-', ''), 10);
              const toolLabel = edge.target.replace('tool-', '').replace(/_/g, ' ');
              if (!reconToolMap[pIdx]) reconToolMap[pIdx] = [];
              // Find actual label from nodes
              const toolNode = ev.dag.nodes?.find(n => n.id === edge.target);
              reconToolMap[pIdx].push(toolNode?.label || toolLabel);
            }
          }
        }
      }
    }

    // Build a map of prompt text from "send" events by index
    const sendPromptMap = {};
    for (const ev of events) {
      if (ev.type === 'send' && ev.data?.index != null) {
        sendPromptMap[ev.data.index] = ev.data.prompt || '';
      }
    }

    // Enrich bypass events with prompt from "send" if missing
    const bypassEvents = events
      .filter(e => e.type === 'bypass')
      .map(ev => {
        const idx = ev.data?.index;
        if (!ev.data?.prompt && idx != null && sendPromptMap[idx]) {
          return { ...ev, data: { ...ev.data, prompt: sendPromptMap[idx] } };
        }
        return ev;
      });

    // Build hierarchical structure: tool → category → issues
    const toolMap = {};
    for (const ev of bypassEvents) {
      const tool = ev.data?.target_tool || 'General';
      const cat  = ev.data?.category || 'unknown';
      if (!toolMap[tool]) toolMap[tool] = {};
      if (!toolMap[tool][cat]) toolMap[tool][cat] = [];
      toolMap[tool][cat].push(ev);
    }

    // Convert to sorted array: [ { tool, categories: [ { category, issues } ] } ]
    const byToolHierarchy = Object.entries(toolMap)
      .sort(([a], [b]) => {
        if (a === 'General') return 1;
        if (b === 'General') return -1;
        return a.localeCompare(b);
      })
      .map(([tool, cats]) => ({
        tool,
        totalIssues: Object.values(cats).reduce((s, arr) => s + arr.length, 0),
        categories: Object.entries(cats)
          .sort(([, a], [, b]) => b.length - a.length) // most issues first
          .map(([category, issues]) => ({ category, issues })),
      }));

    // Enrich block events with prompt from "send" if missing
    const blockEvents = events
      .filter(e => e.type === 'block')
      .map(ev => {
        const idx = ev.data?.index;
        if (!ev.data?.prompt && idx != null && sendPromptMap[idx]) {
          return { ...ev, data: { ...ev.data, prompt: sendPromptMap[idx] } };
        }
        return ev;
      });

    // Group blocked events by tool
    const blockToolMap = {};
    for (const ev of blockEvents) {
      const tool = ev.data?.target_tool || 'General';
      if (!blockToolMap[tool]) blockToolMap[tool] = [];
      blockToolMap[tool].push(ev);
    }
    const blockByTool = Object.entries(blockToolMap)
      .sort(([a], [b]) => {
        if (a === 'General') return 1;
        if (b === 'General') return -1;
        return a.localeCompare(b);
      })
      .map(([tool, evts]) => ({ tool, events: evts }));

    // Collect error events for the errors panel
    const errorEvents = events.filter(e => e.type === 'error');

    // Collect probe events (HTTP requests made by the ADK agent)
    const probeEvents = events.filter(e => e.type === 'probe');

    return { exploitedTools, safeTools, discoveredToolNames, bypassEvents, byToolHierarchy, blockEvents, blockByTool, reconEvents, reconToolMap, errorEvents, probeEvents };
  }, [events]);

  const [panelOpen, setPanelOpen] = useState(false);
  const [panelTab, setPanelTab] = useState('bypasses'); // 'bypasses' | 'blocked' | 'discovery' | 'errors'
  const [highlightedBypass, setHighlightedBypass] = useState(null);
  const highlightTimerRef = useRef(null);

  // SECBUG sliding form state
  const [secbugView, setSecbugView] = useState(null); // null or { finding, serverName, toolName }

  const handleRaiseSecbug = useCallback((finding, serverName, toolName) => {
    setSecbugView({ finding, serverName, toolName });
  }, []);

  const handleSecbugBack = useCallback(() => {
    setSecbugView(null);
  }, []);

  // Open bypass panel and highlight a specific bypass by its prompt index
  const openBypassForIndex = useCallback((promptIndex) => {
    setPanelOpen(true);
    setHighlightedBypass(promptIndex);

    // Clear any existing timer
    if (highlightTimerRef.current) clearTimeout(highlightTimerRef.current);

    // Scroll to the highlighted card after panel slide-in animation
    setTimeout(() => {
      const el = document.querySelector(`[data-bypass-index="${promptIndex}"]`);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 380);

    // Auto-remove highlight after 4 seconds
    highlightTimerRef.current = setTimeout(() => setHighlightedBypass(null), 4000);
  }, []);

  // Handle DAG node clicks → open panel for bypassed/exploited/blocked/safe nodes
  const handleNodeClick = useCallback((_event, node) => {
    const { status, nodeType, label } = node.data || {};

    if (status === 'bypassed' && nodeType === 'prompt') {
      const promptIndex = parseInt(label?.replace('#', ''), 10);
      const match = panelData.bypassEvents.find(ev => ev.data?.index === promptIndex);
      if (match) {
        setPanelTab('bypasses');
        openBypassForIndex(promptIndex);
      }
    } else if (status === 'exploited' && nodeType === 'tool') {
      const toolName = label;
      const firstBypass = panelData.bypassEvents.find(
        ev => ev.data?.target_tool?.toLowerCase() === toolName?.toLowerCase()
      );
      setPanelTab('bypasses');
      if (firstBypass) {
        openBypassForIndex(firstBypass.data?.index);
      } else {
        setPanelOpen(true);
      }
    } else if (status === 'blocked' && nodeType === 'prompt') {
      // Open blocked panel
      setPanelTab('blocked');
      setPanelOpen(true);
    } else if (status === 'safe' && nodeType === 'tool') {
      // Open blocked panel filtered to this tool
      setPanelTab('blocked');
      setPanelOpen(true);
    } else if (status === 'completed' && nodeType === 'recon') {
      // Open discovery panel — clicking a recon node shows the discovery prompts
      setPanelTab('discovery');
      setPanelOpen(true);
    }
  }, [panelData, openBypassForIndex]);

  // Cleanup highlight timer on unmount
  useEffect(() => {
    return () => {
      if (highlightTimerRef.current) clearTimeout(highlightTimerRef.current);
    };
  }, []);

  // Auto-open errors panel when scan finishes as failed
  useEffect(() => {
    if (done && stats.isFailed && (panelData.errorEvents.length > 0 || panelData.probeEvents.length > 0) && !panelOpen) {
      setPanelTab('errors');
      setPanelOpen(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [done, stats.isFailed]);

  const handleCancel = useCallback(async () => {
    if (cancelling) return;
    setCancelling(true);
    try {
      if (onCancel) {
        await onCancel(scanId);
      }
    } catch {
      setCancelling(false);
    }
  }, [scanId, onCancel, cancelling]);

  return (
    <div className="fixed inset-x-0 top-14 bottom-24 z-40 flex items-start justify-center px-4 pt-2">
      <div className="w-full h-full max-w-[95vw] bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 shadow-2xl flex flex-col overflow-hidden">

        {/* ── Header ── */}
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 flex-shrink-0">
          <div className="flex items-center gap-3">
            <Activity className="h-4 w-4 text-primary-600 dark:text-primary-400" />
            <span className="text-sm font-semibold text-gray-900 dark:text-gray-200">
              Scan DAG{agentName ? `: ${agentName}` : ''}
            </span>
            {!done && connected && !cancelling && (
              <span className="flex items-center gap-1.5 px-2 py-0.5 bg-red-100 dark:bg-red-500/20
                              border border-red-200 dark:border-red-500/30 rounded text-[10px] font-bold text-red-600 dark:text-red-400">
                <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                LIVE
              </span>
            )}
            {!done && cancelling && (
              <span className="flex items-center gap-1.5 px-2 py-0.5 bg-amber-100 dark:bg-amber-500/20
                              border border-amber-200 dark:border-amber-500/30 rounded text-[10px] font-bold text-amber-600 dark:text-amber-400">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse" />
                CANCELLING
              </span>
            )}
            {done && !cancelling && !stats.isFailed && (
              <span className="px-2 py-0.5 bg-emerald-100 dark:bg-emerald-500/20 border border-emerald-200 dark:border-emerald-500/30
                              rounded text-[10px] font-bold text-emerald-600 dark:text-emerald-400">
                COMPLETE
              </span>
            )}
            {done && !cancelling && stats.isFailed && (
              <span className="px-2 py-0.5 bg-red-100 dark:bg-red-500/20 border border-red-200 dark:border-red-500/30
                              rounded text-[10px] font-bold text-red-600 dark:text-red-400">
                FAILED
              </span>
            )}
            {done && cancelling && (
              <span className="px-2 py-0.5 bg-amber-100 dark:bg-amber-500/20 border border-amber-200 dark:border-amber-500/30
                              rounded text-[10px] font-bold text-amber-600 dark:text-amber-400">
                CANCELLED
              </span>
            )}
          </div>

          <div className="flex items-center gap-4">
            {(stats.total > 0 || stats.errors > 0 || stats.probes > 0) && (
              <div className="flex items-center gap-3 text-[10px] font-mono">
                {stats.total > 0 && (
                  <>
                <span className="text-red-600 dark:text-red-400">{stats.bypassed} bypassed</span>
                <span className="text-emerald-600 dark:text-emerald-400">{stats.blocked} blocked</span>
                <span className="text-gray-500 dark:text-gray-400">{stats.rate}%</span>
                  </>
                )}
                {stats.errors > 0 && (
                  <span className="text-orange-600 dark:text-orange-400">{stats.errors} errors</span>
                )}
                {stats.probes > 0 && (
                  <span className="text-gray-500 dark:text-gray-400">{stats.probes} HTTP calls</span>
                )}
              </div>
            )}
            {/* Cancel button — shown while scan is live */}
            {!done && connected && onCancel && (
              <button
                onClick={handleCancel}
                disabled={cancelling}
                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors border
                  ${cancelling
                    ? 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500 border-gray-200 dark:border-gray-600 cursor-not-allowed'
                    : 'bg-red-50 dark:bg-red-950/40 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800/50 hover:bg-red-100 dark:hover:bg-red-900/40'
                  }`}
                title="Cancel this scan"
              >
                <StopCircle className={`h-3.5 w-3.5 ${cancelling ? 'animate-pulse' : ''}`} />
                {cancelling ? 'Cancelling…' : 'Cancel Scan'}
              </button>
            )}
            <button
              onClick={() => setLogOpen((o) => !o)}
              className="p-1 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 transition-colors"
              title="Toggle event log"
            >
              {logOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
            </button>
            <button onClick={onClose} className="p-1 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 transition-colors">
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* ── Error banner (shown when scan failed) ── */}
        {done && stats.isFailed && (() => {
          const errorEvts = events.filter(e => e.type === 'error');
          const probeEvts = events.filter(e => e.type === 'probe');
          // Use the failure reason from stats (derived from done event or last error)
          const displayReason = stats.failureReason
            || 'The scan could not complete — check the event log for details.';
          // Extract only the first line for the banner (details go in the panel)
          const reasonFirstLine = displayReason.split('\n')[0];
          return (
            <div className="px-4 py-2.5 bg-red-50 dark:bg-red-950/40 border-b border-red-200 dark:border-red-800/50 flex items-start gap-2 flex-shrink-0">
              <XCircle className="h-4 w-4 text-red-500 mt-0.5 flex-shrink-0" />
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold text-red-700 dark:text-red-300">
                  Scan Failed
                </p>
                <p className="text-[11px] text-red-600 dark:text-red-400 mt-0.5 whitespace-pre-line">
                  {reasonFirstLine}
                </p>
                <div className="flex items-center gap-3 mt-1">
                  {probeEvts.length > 0 && (
                    <button
                      onClick={() => { setPanelTab('errors'); setPanelOpen(true); }}
                      className="text-[10px] text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-200 underline"
                    >
                      View {probeEvts.length} HTTP request{probeEvts.length !== 1 ? 's' : ''} attempted
                    </button>
                  )}
                  {errorEvts.length > 0 && (
                    <button 
                      onClick={() => { setPanelTab('errors'); setPanelOpen(true); }}
                      className="text-[10px] text-red-500 hover:text-red-700 dark:hover:text-red-300 underline"
                    >
                      View error details ({errorEvts.length} error{errorEvts.length !== 1 ? 's' : ''})
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })()}

        {/* ── Main area: DAG + optional right panel ── */}
        <div className="flex-1 min-h-0 flex relative">
          {/* DAG column (canvas + inline summary when panel is open) */}
          <div className="flex-1 min-w-0 flex flex-col transition-all duration-300 relative">
            {/* DAG Canvas */}
            <div className="flex-1 min-h-0 bg-gray-100 dark:bg-gray-900">
              <ReactFlowProvider>
                <DAGCanvas
                  nodes={nodes}
                  edges={edges}
                  onNodesChange={onNodesChange}
                  onEdgesChange={onEdgesChange}
                  done={done}
                  nodeCount={nodes.length}
                  onNodeClick={handleNodeClick}
                />
              </ReactFlowProvider>
            </div>

            {/* Summary pinned under DAG when panel is open */}
            {done && (stats.total > 0 || stats.errors > 0 || stats.probes > 0) && panelOpen && (
              <div className="border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800/90 px-3 py-2 flex-shrink-0">
                <div className={`grid gap-1.5 ${stats.errors > 0 ? 'grid-cols-5' : 'grid-cols-4'}`}>
                  <div className="bg-gray-50 dark:bg-gray-900/60 rounded-md p-1.5 border border-gray-200 dark:border-gray-700">
                    <div className="text-[9px] uppercase tracking-wider text-gray-500 dark:text-gray-400">Tests</div>
                    <div className="text-sm font-bold text-gray-900 dark:text-white">{stats.total}</div>
                  </div>
                  <div className="bg-red-50 dark:bg-red-950/40 rounded-md p-1.5 border border-red-200 dark:border-red-800/50">
                    <div className="text-[9px] uppercase tracking-wider text-red-600 dark:text-red-400">Bypassed</div>
                    <div className="text-sm font-bold text-red-600 dark:text-red-400">{stats.bypassed}</div>
                  </div>
                  <div className="bg-emerald-50 dark:bg-emerald-950/40 rounded-md p-1.5 border border-emerald-200 dark:border-emerald-800/50">
                    <div className="text-[9px] uppercase tracking-wider text-emerald-600 dark:text-emerald-400">Blocked</div>
                    <div className="text-sm font-bold text-emerald-600 dark:text-emerald-400">{stats.blocked}</div>
                  </div>
                  {stats.errors > 0 && (
                    <div className="bg-orange-50 dark:bg-orange-950/40 rounded-md p-1.5 border border-orange-200 dark:border-orange-800/50">
                      <div className="text-[9px] uppercase tracking-wider text-orange-600 dark:text-orange-400">Errors</div>
                      <div className="text-sm font-bold text-orange-600 dark:text-orange-400">{stats.errors}</div>
                    </div>
                  )}
                  <div className={`rounded-md p-1.5 border ${
                    parseFloat(stats.rate) > 30
                      ? 'bg-red-50 dark:bg-red-950/40 border-red-200 dark:border-red-800/50'
                      : 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800/50'
                  }`}>
                    <div className="text-[9px] uppercase tracking-wider text-gray-500 dark:text-gray-400">Rate</div>
                    <div className={`text-sm font-bold ${
                      parseFloat(stats.rate) > 30 ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'
                    }`}>{stats.rate}%</div>
                  </div>
                </div>
                {/* Compact tools row */}
                {(panelData.exploitedTools.length > 0 || panelData.safeTools.length > 0 || panelData.discoveredToolNames.length > 0) && (
                  <div className="mt-1.5 pt-1.5 border-t border-gray-200 dark:border-gray-700 flex items-center gap-1.5 flex-wrap">
                    <span className="flex items-center gap-1 text-[9px] uppercase tracking-wider text-gray-500 dark:text-gray-400">
                      <Crosshair className="h-2.5 w-2.5" /> Tools:
                    </span>
                    {panelData.exploitedTools.map(name => (
                      <span key={name} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800/50">
                        <AlertTriangle className="h-2 w-2" /> {name}
                      </span>
                    ))}
                    {panelData.safeTools.map(name => (
                      <span key={name} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/50">
                        <CheckCircle className="h-2 w-2" /> {name}
                      </span>
                    ))}
                    {panelData.discoveredToolNames.filter(n => !panelData.exploitedTools.includes(n) && !panelData.safeTools.includes(n)).map(name => (
                      <span key={name} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium bg-gray-100 dark:bg-gray-700/40 text-gray-600 dark:text-gray-300 border border-gray-200 dark:border-gray-600/50">
                        <Wrench className="h-2 w-2" /> {name}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* ── Right-side floating tab triggers ── */}
          {done && (stats.total > 0 || stats.errors > 0 || stats.probes > 0) && !panelOpen && (
            <div className="absolute right-0 top-1/2 -translate-y-1/2 z-20 flex flex-col gap-2">
              {/* Errors & Activity tab */}
              {(stats.errors > 0 || stats.probes > 0) && (
                <button
                  onClick={() => { setPanelTab('errors'); setPanelOpen(true); }}
                  className="flex items-center gap-1.5 pl-2.5 pr-1.5 py-8
                             bg-orange-600 hover:bg-orange-700 dark:bg-orange-700 dark:hover:bg-orange-600
                             text-white rounded-l-lg shadow-lg transition-all duration-200
                             hover:pr-3 group"
                  style={{ writingMode: 'vertical-rl', textOrientation: 'mixed' }}
                >
                  <Activity className="h-3.5 w-3.5 rotate-90 flex-shrink-0" />
                  <span className="text-[11px] font-semibold tracking-wide whitespace-nowrap">
                    {stats.errors > 0 ? 'Errors' : 'Activity'}
                  </span>
                  <span className="flex items-center justify-center min-w-[18px] h-[18px] px-1
                                   bg-white text-orange-700 text-[10px] font-bold rounded-full rotate-90">
                    {stats.errors + stats.probes}
                  </span>
                  <ChevronLeft className="h-3 w-3 rotate-90 opacity-60 group-hover:opacity-100 transition-opacity" />
                </button>
              )}
              {/* Bypass Details tab */}
              {stats.bypassed > 0 && (
                <button
                  onClick={() => { setPanelTab('bypasses'); setPanelOpen(true); }}
                  className="flex items-center gap-1.5 pl-2.5 pr-1.5 py-8
                             bg-red-600 hover:bg-red-700 dark:bg-red-700 dark:hover:bg-red-600
                             text-white rounded-l-lg shadow-lg transition-all duration-200
                             hover:pr-3 group"
                  style={{ writingMode: 'vertical-rl', textOrientation: 'mixed' }}
                >
                  <ShieldAlert className="h-3.5 w-3.5 rotate-90 flex-shrink-0" />
                  <span className="text-[11px] font-semibold tracking-wide whitespace-nowrap">
                    Bypasses
                  </span>
                  <span className="flex items-center justify-center min-w-[18px] h-[18px] px-1
                                   bg-white text-red-700 text-[10px] font-bold rounded-full rotate-90">
                    {stats.bypassed}
                  </span>
                  <ChevronLeft className="h-3 w-3 rotate-90 opacity-60 group-hover:opacity-100 transition-opacity" />
                </button>
              )}
              {/* Blocked (Safe) Details tab */}
              {stats.blocked > 0 && (
                <button
                  onClick={() => { setPanelTab('blocked'); setPanelOpen(true); }}
                  className="flex items-center gap-1.5 pl-2.5 pr-1.5 py-8
                             bg-emerald-600 hover:bg-emerald-700 dark:bg-emerald-700 dark:hover:bg-emerald-600
                             text-white rounded-l-lg shadow-lg transition-all duration-200
                             hover:pr-3 group"
                  style={{ writingMode: 'vertical-rl', textOrientation: 'mixed' }}
                >
                  <CheckCircle className="h-3.5 w-3.5 rotate-90 flex-shrink-0" />
                  <span className="text-[11px] font-semibold tracking-wide whitespace-nowrap">
                    Blocked
                  </span>
                  <span className="flex items-center justify-center min-w-[18px] h-[18px] px-1
                                   bg-white text-emerald-700 text-[10px] font-bold rounded-full rotate-90">
                    {stats.blocked}
                  </span>
                  <ChevronLeft className="h-3 w-3 rotate-90 opacity-60 group-hover:opacity-100 transition-opacity" />
                </button>
              )}
            </div>
          )}

          {/* ── Slide-out Bypass Details Panel (50% width) ── */}
          <div className={`flex-shrink-0 border-l border-gray-200 dark:border-gray-700
                           bg-white dark:bg-gray-800 overflow-hidden transition-all duration-300 ease-in-out
                           ${panelOpen ? 'w-1/2' : 'w-0'}`}>
            {panelOpen && (
              <div className="h-full flex flex-col min-w-0">
                {/* Panel header */}
                <div className="flex items-center justify-between px-4 py-2 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/80 flex-shrink-0">
                  <div className="flex items-center gap-2">
                    {secbugView ? (
                      <>
                        <button
                          onClick={handleSecbugBack}
                          className="p-1 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 transition-colors"
                        >
                          <ChevronLeft className="h-4 w-4" />
                        </button>
                        <span className="text-sm font-semibold text-gray-900 dark:text-gray-200">
                          Raise Ticket
                        </span>
                      </>
                    ) : (
                      /* Tab switcher */
                      <div className="flex items-center gap-0.5">
                        <button
                          onClick={() => setPanelTab('bypasses')}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                            panelTab === 'bypasses'
                              ? 'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300'
                              : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700/60'
                          }`}
                        >
                          <ShieldAlert className="h-3.5 w-3.5" />
                          Bypasses
                          {panelData.bypassEvents.length > 0 && (
                            <span className={`min-w-[18px] h-[18px] flex items-center justify-center px-1 text-[10px] font-bold rounded-full ${
                              panelTab === 'bypasses'
                                ? 'bg-red-200 dark:bg-red-800/60 text-red-800 dark:text-red-200'
                                : 'bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-300'
                            }`}>
                              {panelData.bypassEvents.length}
                            </span>
                          )}
                        </button>
                        <button
                          onClick={() => setPanelTab('blocked')}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                            panelTab === 'blocked'
                              ? 'bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300'
                              : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700/60'
                          }`}
                        >
                          <CheckCircle className="h-3.5 w-3.5" />
                          Blocked
                          {panelData.blockEvents.length > 0 && (
                            <span className={`min-w-[18px] h-[18px] flex items-center justify-center px-1 text-[10px] font-bold rounded-full ${
                              panelTab === 'blocked'
                                ? 'bg-emerald-200 dark:bg-emerald-800/60 text-emerald-800 dark:text-emerald-200'
                                : 'bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-300'
                            }`}>
                              {panelData.blockEvents.length}
                            </span>
                          )}
                        </button>
                        {panelData.reconEvents.length > 0 && (
                          <button
                            onClick={() => setPanelTab('discovery')}
                            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                              panelTab === 'discovery'
                                ? 'bg-violet-100 dark:bg-violet-900/40 text-violet-700 dark:text-violet-300'
                                : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700/60'
                            }`}
                          >
                            <Search className="h-3.5 w-3.5" />
                            Discovery
                            <span className={`min-w-[18px] h-[18px] flex items-center justify-center px-1 text-[10px] font-bold rounded-full ${
                              panelTab === 'discovery'
                                ? 'bg-violet-200 dark:bg-violet-800/60 text-violet-800 dark:text-violet-200'
                                : 'bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-300'
                            }`}>
                              {panelData.reconEvents.length}
                            </span>
                          </button>
                        )}
                        {(panelData.errorEvents.length > 0 || panelData.probeEvents.length > 0) && (
                          <button
                            onClick={() => setPanelTab('errors')}
                            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                              panelTab === 'errors'
                                ? 'bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-300'
                                : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700/60'
                            }`}
                          >
                            <Activity className="h-3.5 w-3.5" />
                            {panelData.errorEvents.length > 0 ? 'Errors' : 'Activity'}
                            <span className={`min-w-[18px] h-[18px] flex items-center justify-center px-1 text-[10px] font-bold rounded-full ${
                              panelTab === 'errors'
                                ? 'bg-orange-200 dark:bg-orange-800/60 text-orange-800 dark:text-orange-200'
                                : 'bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-300'
                            }`}>
                              {panelData.errorEvents.length + panelData.probeEvents.length}
                            </span>
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                  <button
                    onClick={() => { setPanelOpen(false); setHighlightedBypass(null); setSecbugView(null); }}
                    className="p-1 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 transition-colors"
                  >
                    <ChevronRight className="h-4 w-4" />
                  </button>
                </div>

                {/* Panel content — issues list, blocked list, OR SecbugForm */}
                <div className="flex-1 overflow-y-auto">
                  {secbugView ? (
                    /* SECBUG Form — slides in from right */
                    <div
                      className="h-full"
                      style={{ animation: 'agentSlideInRight 0.3s ease-out forwards' }}
                    >
                      <style>{`
                        @keyframes agentSlideInRight {
                          from { opacity: 0; transform: translateX(50px); }
                          to   { opacity: 1; transform: translateX(0); }
                        }
                      `}</style>
                      <SecbugForm
                        finding={secbugView.finding}
                        serverName={secbugView.serverName}
                        toolName={secbugView.toolName}
                        source="agent"
                        onBack={handleSecbugBack}
                        onSuccess={() => { /* optionally do something */ }}
                      />
                    </div>
                  ) : panelTab === 'bypasses' ? (
                    /* Hierarchical bypass view: Tool → Category → Issues */
                    <div className="p-3 space-y-3">
                      {panelData.byToolHierarchy.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-12 text-gray-400 dark:text-gray-500">
                          <CheckCircle className="h-8 w-8 mb-2" />
                          <span className="text-sm font-medium">No bypasses detected</span>
                          <span className="text-[11px] mt-1">All prompts were blocked</span>
                        </div>
                      ) : (
                        panelData.byToolHierarchy.map((group, ti) => (
                          <ToolSection
                            key={group.tool}
                            tool={group.tool}
                            totalIssues={group.totalIssues}
                            categories={group.categories}
                            highlightedBypass={highlightedBypass}
                            onRaiseSecbug={handleRaiseSecbug}
                            agentName={agentName}
                            defaultOpen={ti === 0}
                          />
                        ))
                      )}
                    </div>
                  ) : panelTab === 'discovery' ? (
                    /* Discovery prompts view — shows recon prompts that led to tool discovery */
                    <div className="p-3 space-y-3">
                      {panelData.reconEvents.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-12 text-gray-400 dark:text-gray-500">
                          <Search className="h-8 w-8 mb-2" />
                          <span className="text-sm font-medium">No discovery prompts recorded</span>
                          <span className="text-[11px] mt-1">Tool discovery details not available</span>
                        </div>
                      ) : (
                        panelData.reconEvents.map((ev, i) => (
                          <DiscoveryPromptCard
                            key={ev.data?.index || i}
                            ev={ev}
                            toolsDiscovered={panelData.reconToolMap[ev.data?.index] || []}
                          />
                        ))
                      )}
                    </div>
                  ) : panelTab === 'errors' ? (
                    /* Errors & HTTP Activity view */
                    <div className="p-3 space-y-3">
                      {panelData.errorEvents.length === 0 && panelData.probeEvents.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-12 text-gray-400 dark:text-gray-500">
                          <CheckCircle className="h-8 w-8 mb-2" />
                          <span className="text-sm font-medium">No errors</span>
                          <span className="text-[11px] mt-1">Scan completed without errors</span>
                        </div>
                      ) : (
                        <>
                          {/* Error summary banner */}
                          {panelData.errorEvents.length > 0 && (
                            <div className="bg-orange-50 dark:bg-orange-950/30 border border-orange-200 dark:border-orange-800/50 rounded-lg p-3">
                              <div className="flex items-center gap-2">
                                <AlertTriangle className="h-4 w-4 text-orange-500 flex-shrink-0" />
                                <div>
                                  <p className="text-xs font-semibold text-orange-700 dark:text-orange-300">
                                    {panelData.errorEvents.length} error{panelData.errorEvents.length !== 1 ? 's' : ''} occurred during scan
                                  </p>
                                  <p className="text-[11px] text-orange-600 dark:text-orange-400 mt-0.5">
                                    These errors may indicate connectivity issues, rate limiting, or incompatible agent API formats.
                                  </p>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Error cards */}
                          {panelData.errorEvents.map((ev, i) => (
                            <ErrorEventCard key={`err-${i}`} ev={ev} index={i} />
                          ))}

                          {/* HTTP Activity section */}
                          {panelData.probeEvents.length > 0 && (
                            <>
                              <div className="flex items-center gap-2 pt-2 border-t border-gray-200 dark:border-gray-700">
                                <Globe className="h-4 w-4 text-gray-500 dark:text-gray-400" />
                                <span className="text-xs font-semibold text-gray-700 dark:text-gray-300">
                                  HTTP Requests ({panelData.probeEvents.length})
                                </span>
                                <span className="text-[10px] text-gray-500 dark:text-gray-400">
                                  — requests made by the scanner while discovering the API
                                </span>
                              </div>
                              {panelData.probeEvents.map((ev, i) => (
                                <ProbeEventCard key={`probe-${i}`} ev={ev} index={i} />
                              ))}
                            </>
                          )}
                        </>
                      )}
                    </div>
                  ) : (
                    /* Blocked (safe) prompts view: Tool → Prompts */
                    <div className="p-3 space-y-3">
                      {panelData.blockByTool.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-12 text-gray-400 dark:text-gray-500">
                          <AlertTriangle className="h-8 w-8 mb-2" />
                          <span className="text-sm font-medium">No blocked prompts</span>
                          <span className="text-[11px] mt-1">All prompts bypassed the agent</span>
                        </div>
                      ) : (
                        panelData.blockByTool.map((group, ti) => (
                          <SafeToolSection
                            key={group.tool}
                            tool={group.tool}
                            events={group.events}
                            defaultOpen={ti === 0}
                          />
                        ))
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ── Full-width Summary (shown when scan is done AND panel is closed) ── */}
        {done && (stats.total > 0 || stats.errors > 0 || stats.probes > 0) && !panelOpen && (() => {
          return (
            <div className="border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800/90 px-4 py-2.5 flex-shrink-0">
              <div className={`grid grid-cols-2 gap-2 ${stats.errors > 0 ? 'md:grid-cols-5' : 'md:grid-cols-4'}`}>
                <div className="bg-gray-50 dark:bg-gray-900/60 rounded-lg p-2 border border-gray-200 dark:border-gray-700">
                  <div className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400 mb-0.5">Total Tests</div>
                  <div className="text-base font-bold text-gray-900 dark:text-white">{stats.total}</div>
                </div>
                <div className="bg-red-50 dark:bg-red-950/40 rounded-lg p-2 border border-red-200 dark:border-red-800/50">
                  <div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-red-600 dark:text-red-400 mb-0.5">
                    <AlertTriangle className="h-3 w-3" /> Bypassed
                  </div>
                  <div className="text-base font-bold text-red-600 dark:text-red-400">{stats.bypassed}</div>
                </div>
                <div className="bg-emerald-50 dark:bg-emerald-950/40 rounded-lg p-2 border border-emerald-200 dark:border-emerald-800/50">
                  <div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-emerald-600 dark:text-emerald-400 mb-0.5">
                    <CheckCircle className="h-3 w-3" /> Blocked
                  </div>
                  <div className="text-base font-bold text-emerald-600 dark:text-emerald-400">{stats.blocked}</div>
                </div>
                {stats.errors > 0 && (
                  <div className="bg-orange-50 dark:bg-orange-950/40 rounded-lg p-2 border border-orange-200 dark:border-orange-800/50 cursor-pointer hover:bg-orange-100 dark:hover:bg-orange-900/40 transition-colors"
                       onClick={() => { setPanelTab('errors'); setPanelOpen(true); }}>
                    <div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-orange-600 dark:text-orange-400 mb-0.5">
                      <XCircle className="h-3 w-3" /> Errors
                    </div>
                    <div className="text-base font-bold text-orange-600 dark:text-orange-400">{stats.errors}</div>
                  </div>
                )}
                <div className={`rounded-lg p-2 border ${
                  parseFloat(stats.rate) > 30
                    ? 'bg-red-50 dark:bg-red-950/40 border-red-200 dark:border-red-800/50'
                    : 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800/50'
                }`}>
                  <div className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400 mb-0.5">Bypass Rate</div>
                  <div className={`text-base font-bold ${
                    parseFloat(stats.rate) > 30 ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'
                  }`}>{stats.rate}%</div>
                </div>
              </div>

              {/* Target Tools */}
              {(panelData.exploitedTools.length > 0 || panelData.safeTools.length > 0 || panelData.discoveredToolNames.length > 0) && (
                <div className="mt-2 pt-2 border-t border-gray-200 dark:border-gray-700 flex items-center gap-2 flex-wrap">
                  <span className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400">
                    <Crosshair className="h-3 w-3" /> Tools:
                  </span>
                  {panelData.exploitedTools.map(name => (
                    <span key={name} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-medium bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800/50">
                      <AlertTriangle className="h-2.5 w-2.5" /> {name}
                    </span>
                  ))}
                  {panelData.safeTools.map(name => (
                    <span key={name} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-medium bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/50">
                      <CheckCircle className="h-2.5 w-2.5" /> {name}
                    </span>
                  ))}
                  {panelData.discoveredToolNames.filter(n => !panelData.exploitedTools.includes(n) && !panelData.safeTools.includes(n)).map(name => (
                    <span key={name} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-medium bg-gray-100 dark:bg-gray-700/40 text-gray-600 dark:text-gray-300 border border-gray-200 dark:border-gray-600/50">
                      <Wrench className="h-2.5 w-2.5" /> {name}
                    </span>
                  ))}
                </div>
              )}
            </div>
          );
        })()}

        {/* ── Collapsible Event Log ── */}
        {logOpen && (
          <div
            className="border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 overflow-y-auto flex-shrink-0"
            style={{ maxHeight: '25vh', fontFamily: "'SF Mono', 'Fira Code', Menlo, monospace" }}
          >
            <div className="px-3 py-1.5 space-y-0.5">
              {events.map((ev, i) => (
                <div key={i} className="flex items-start gap-2 text-[10px] leading-tight">
                  <span className="text-gray-400 dark:text-gray-500 flex-shrink-0 w-16 text-right tabular-nums">
                    {ev.ts ? new Date(ev.ts + 'Z').toLocaleTimeString('en-US', { hour12: false }) : ''}
                  </span>
                  <span className={`flex-shrink-0 w-16 font-bold uppercase ${typeColor[ev.type] || 'text-gray-500'}`}>
                    {ev.type}
                  </span>
                  <span className="text-gray-700 dark:text-gray-300 break-all">{ev.message}</span>
                </div>
              ))}
              <div ref={logEndRef} />
            </div>
          </div>
        )}

        {/* ── Bottom bar ── */}
        <div className="px-4 py-1.5 bg-gray-50 dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700
                        flex items-center justify-between text-[10px] text-gray-500 dark:text-gray-400 flex-shrink-0">
          <span>{nodes.length} nodes &middot; {edges.length} edges &middot; {events.length} events</span>
          <span className="font-mono">scan:{scanId?.slice(0, 8)}</span>
        </div>
      </div>
    </div>
  );
};

export default AgentScanDAG;

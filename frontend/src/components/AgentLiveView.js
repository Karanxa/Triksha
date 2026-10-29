import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Terminal, X, Maximize2, Minimize2, Circle } from 'lucide-react';

// Event type -> icon + color configuration
const EVENT_STYLES = {
  info:    { color: 'text-blue-400',   icon: '>', prefix: 'INFO' },
  probe:   { color: 'text-cyan-400',   icon: '~', prefix: 'PROBE' },
  send:    { color: 'text-yellow-300', icon: '→', prefix: 'SEND' },
  receive: { color: 'text-gray-300',   icon: '←', prefix: 'RECV' },
  bypass:  { color: 'text-red-400',    icon: '!', prefix: 'BYPASS' },
  block:   { color: 'text-green-400',  icon: '✓', prefix: 'BLOCK' },
  error:   { color: 'text-red-500',    icon: '✗', prefix: 'ERROR' },
  done:    { color: 'text-purple-400', icon: '■', prefix: 'DONE' },
};

const AgentLiveView = ({ scanId, agentName, onClose, apiBaseUrl }) => {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [done, setDone] = useState(false);
  const terminalRef = useRef(null);
  const eventSourceRef = useRef(null);

  // Connect to SSE stream
  const connect = useCallback(() => {
    if (!scanId || eventSourceRef.current) return;

    const baseUrl = apiBaseUrl || '';
    const url = `${baseUrl}/agents/scan/${scanId}/events`;

    const es = new EventSource(url);
    eventSourceRef.current = es;

    es.onopen = () => setConnected(true);

    es.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data);
        setEvents(prev => [...prev, event]);
        if (event.type === 'done') {
          setDone(true);
          es.close();
          eventSourceRef.current = null;
        }
      } catch {
        // Ignore parse errors
      }
    };

    es.onerror = () => {
      setConnected(false);
      es.close();
      eventSourceRef.current = null;
    };
  }, [scanId, apiBaseUrl]);

  useEffect(() => {
    connect();
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [connect]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [events]);

  const formatTime = (ts) => {
    if (!ts) return '';
    try {
      const d = new Date(ts + 'Z');
      return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return '';
    }
  };

  const renderEvent = (event, idx) => {
    const style = EVENT_STYLES[event.type] || EVENT_STYLES.info;
    const time = formatTime(event.ts);

    return (
      <div key={idx} className="flex items-start gap-2 py-0.5 font-mono text-xs leading-relaxed hover:bg-white/5 px-3 transition-colors">
        {/* Timestamp */}
        <span className="text-gray-500 flex-shrink-0 w-[62px]">{time}</span>

        {/* Icon */}
        <span className={`${style.color} flex-shrink-0 w-3 text-center`}>{style.icon}</span>

        {/* Prefix tag */}
        <span className={`${style.color} flex-shrink-0 font-bold w-[52px] text-right`}>
          {style.prefix}
        </span>

        {/* Message */}
        <span className="text-gray-200 flex-1 break-words">
          {event.message}
          {/* Show response preview for bypass/block events */}
          {event.data?.response_preview && (event.type === 'bypass' || event.type === 'block') && (
            <span className="block mt-0.5 text-gray-500 text-[10px] leading-tight truncate max-w-[600px]">
              {event.data.response_preview}
            </span>
          )}
          {/* Show prompt preview for send events */}
          {event.data?.prompt && event.type === 'send' && (
            <span className="block mt-0.5 text-yellow-200/50 text-[10px] leading-tight">
              &quot;{event.data.prompt}&quot;
            </span>
          )}
        </span>

        {/* Elapsed time for bypass/block */}
        {event.data?.elapsed_ms !== undefined && (
          <span className="text-gray-600 flex-shrink-0 text-[10px]">{event.data.elapsed_ms}ms</span>
        )}
      </div>
    );
  };

  // Stats bar
  const bypassed = events.filter(e => e.type === 'bypass').length;
  const blocked = events.filter(e => e.type === 'block').length;
  const errors = events.filter(e => e.type === 'error').length;
  const total = bypassed + blocked;

  return (
    <div className={`fixed z-50 bg-[#0d1117] border border-gray-700/50 rounded-xl shadow-2xl flex flex-col overflow-hidden transition-all duration-300 ${
      expanded
        ? 'inset-4'
        : 'bottom-4 right-4 w-[700px] h-[480px]'
    }`}>
      {/* Title bar */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-[#161b22] border-b border-gray-700/50 flex-shrink-0">
        <div className="flex items-center gap-3">
          {/* Traffic light dots */}
          <div className="flex gap-1.5">
            <Circle className={`h-2.5 w-2.5 ${connected ? 'fill-green-500 text-green-500' : done ? 'fill-gray-500 text-gray-500' : 'fill-red-500 text-red-500'}`} />
            <Circle className="h-2.5 w-2.5 fill-yellow-500 text-yellow-500" />
            <Circle className="h-2.5 w-2.5 fill-green-500 text-green-500" />
          </div>
          <div className="flex items-center gap-2">
            <Terminal className="h-3.5 w-3.5 text-gray-400" />
            <span className="text-xs font-medium text-gray-300">
              Live Scan — {agentName || scanId}
            </span>
          </div>
          {connected && !done && (
            <span className="flex items-center gap-1 text-[10px] text-green-400">
              <span className="relative flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-green-500" />
              </span>
              LIVE
            </span>
          )}
          {done && (
            <span className="text-[10px] text-gray-500 uppercase font-medium">Completed</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {/* Stats */}
          {total > 0 && (
            <div className="flex items-center gap-3 mr-3 text-[10px] font-mono">
              <span className="text-red-400">{bypassed} bypassed</span>
              <span className="text-green-400">{blocked} blocked</span>
              {errors > 0 && <span className="text-yellow-500">{errors} errors</span>}
            </div>
          )}
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1 text-gray-500 hover:text-gray-300 transition-colors"
          >
            {expanded ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
          </button>
          <button onClick={onClose} className="p-1 text-gray-500 hover:text-gray-300 transition-colors">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Terminal body */}
      <div ref={terminalRef} className="flex-1 overflow-y-auto py-2 scroll-smooth" style={{ fontFamily: "'SF Mono', 'Fira Code', 'JetBrains Mono', Menlo, monospace" }}>
        {events.length === 0 && (
          <div className="flex items-center justify-center h-full text-gray-600 text-xs">
            Waiting for scan events...
          </div>
        )}
        {events.map((event, idx) => renderEvent(event, idx))}
      </div>

      {/* Bottom bar */}
      <div className="flex items-center justify-between px-4 py-1.5 bg-[#161b22] border-t border-gray-700/50 text-[10px] text-gray-500 flex-shrink-0">
        <span>{events.length} events</span>
        {total > 0 && (
          <span>
            Bypass rate: <span className={bypassed > 0 ? 'text-red-400' : 'text-green-400'}>
              {((bypassed / total) * 100).toFixed(1)}%
            </span>
          </span>
        )}
        <span>scan:{scanId}</span>
      </div>
    </div>
  );
};

export default AgentLiveView;

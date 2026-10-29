import React, { useState, useEffect, useMemo, useRef } from 'react';
import { RefreshCw, X } from 'lucide-react';

const ScanDetailsModal = ({
  isOpen,
  onClose,
  scan,
  chatPairs,
  streamEvents,
  isStreaming,
  onRestartStream,
  onStopStream,
  onCancel,
  onViewResults,
}) => {
  const [messages, setMessages] = useState([]);
  const scrollRef = useRef(null);

  // Process stream events into conversation-style messages
  const conversationMessages = useMemo(() => {
    if (!streamEvents || streamEvents.length === 0) return [];

    const messageMap = new Map();
    
    for (const data of streamEvents) {
      if (data.event === 'PromptStarted') {
        const promptMessage = {
          id: `prompt-${data.prompt_index || 0}`,
          type: 'prompt',
          content: data.prompt_text || 'Generating prompt...',
          timestamp: new Date(data.timestamp),
          isStreaming: true,
          promptIndex: data.prompt_index || 0,
          technique: data.technique || 'unknown',
          techniqueDescription: data.technique_description || '',
          imageData: data.image_data || null,
        };
        messageMap.set(`prompt-${data.prompt_index}`, promptMessage);

        // Add response loading message
        const responseLoadingMessage = {
          id: `loading-${data.prompt_index || 0}`,
          type: 'loading',
          content: 'Target model is thinking...',
          timestamp: new Date(data.timestamp),
          promptIndex: data.prompt_index || 0
        };
        messageMap.set(`loading-${data.prompt_index}`, responseLoadingMessage);

      } else if (data.event === 'PromptCompleted') {
        // Replace the loading message with the actual response
        const responseMessage = {
          id: `response-${data.prompt_index || 0}`,
          type: 'response',
          content: data.response_text || 'No response',
          timestamp: new Date(data.timestamp),
          promptIndex: data.prompt_index || 0,
          isSuccess: data.is_success,
          isRefusal: data.is_refusal,
          responseTime: data.response_time,
          verdictReason: data.verdict_reason || '',
          verdictConfidence: data.verdict_confidence,
        };
        messageMap.set(`loading-${data.prompt_index}`, responseMessage);

      } else if (data.event === 'Validation Failed') {
        const validationMessage = {
          id: `validation-${Date.now()}`,
          type: 'error',
          content: data.message || 'Validation failed - please provide a more specific use case description.',
          timestamp: new Date(data.timestamp),
        };
        messageMap.set(`validation-${Date.now()}`, validationMessage);

      } else if (data.event === 'ScanFailed') {
        const failureMessage = {
          id: `failure-${Date.now()}`,
          type: 'error',
          content: `Scan Failed: ${data.error || 'Unknown error occurred during prompt augmentation'}`,
          timestamp: new Date(data.timestamp),
        };
        messageMap.set(`failure-${Date.now()}`, failureMessage);
      } else if (data.event === 'ScanCompleted') {
        const completeMessage = {
          id: `complete-${Date.now()}`,
          type: 'complete',
          content: 'Scan completed',
          timestamp: new Date(data.timestamp),
          summary: data.summary
        };
        messageMap.set(`complete`, completeMessage);
      }
    }

    return Array.from(messageMap.values()).sort((a, b) => {
      if (a.promptIndex !== undefined && b.promptIndex !== undefined) {
        if (a.promptIndex !== b.promptIndex) {
          return a.promptIndex - b.promptIndex;
        }
      }
      return new Date(a.timestamp) - new Date(b.timestamp);
    });
  }, [streamEvents]);

  // Update messages when conversationMessages change
  useEffect(() => {
    setMessages(conversationMessages);
  }, [conversationMessages]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  if (!isOpen || !scan) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center">
      <div className="fixed inset-0 bg-black/50" onClick={onClose} />
      <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl border border-gray-200 dark:border-gray-700 w-full max-w-5xl max-h-[85vh] overflow-hidden z-[101] flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-3">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                {scan.scan_name}
              </h3>
              <div className="text-xs text-gray-500 dark:text-gray-400">ID: {scan.scan_id}</div>
            </div>
            {isStreaming && (
              <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300">
                <RefreshCw className="w-3 h-3 animate-spin" />
                Running
              </span>
            )}
            {!isStreaming && scan.status === 'completed' && (
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-300">
                Complete
              </span>
            )}
            </div>
            <div className="flex items-center gap-2">
              {scan.status === 'completed' && (
                <button className="btn-primary btn-sm" onClick={onViewResults}>View Results</button>
              )}
              <button className="btn-outline btn-sm" onClick={onClose}>Close</button>
            </div>
          </div>

        {/* Progress Bar */}
        {typeof scan.progress === 'number' && scan.status === 'running' && (
          <div className="h-1 w-full bg-gray-200 dark:bg-gray-700 flex-shrink-0">
              <div className="h-1 bg-primary-600 dark:bg-primary-500 transition-all duration-300" style={{ width: `${Math.min(100, Math.max(0, scan.progress))}%` }} />
            </div>
          )}
        
        {/* Conversation Body */}
        <div ref={scrollRef} className="flex-1 overflow-y-auto p-6 space-y-3 bg-gray-50 dark:bg-gray-900">
          {messages.length === 0 ? (
            <div className="text-sm text-gray-500 dark:text-gray-400 italic text-center py-12">
              {isStreaming ? (
                <div className="flex items-center justify-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Generating prompts and testing model...</span>
                </div>
              ) : (
                'Waiting for scan to start...'
              )}
                    </div>
                  ) : (
            messages.map((msg) => (
              <div key={msg.id} className={`flex ${msg.type === 'prompt' ? 'justify-end' : msg.type === 'complete' ? 'justify-center' : 'justify-start'}`}>
                {msg.type === 'prompt' ? (
                  <div className="max-w-2xl bg-blue-500 text-white rounded-2xl rounded-br-sm px-4 py-2">
                    {msg.technique && msg.technique !== 'unknown' && (
                      <div className="text-xs text-blue-200 mb-1">{msg.technique}</div>
                    )}
                    {msg.imageData ? (
                      <img
                        src={`data:image/png;base64,${msg.imageData}`}
                        alt={msg.content}
                        className="rounded-lg max-w-full"
                        style={{ maxHeight: '200px' }}
                      />
                    ) : (
                      <div className="text-sm whitespace-pre-wrap">{msg.content}</div>
                    )}
                </div>
                ) : msg.type === 'loading' ? (
                  <div className="text-gray-400 text-sm italic flex items-center gap-2">
                    <RefreshCw className="w-3 h-3 animate-spin" />
                    {msg.content}
                            </div>
                ) : msg.type === 'response' ? (
                  <div className={`max-w-2xl rounded-2xl rounded-bl-sm px-4 py-2 ${
                    msg.isSuccess 
                      ? msg.isRefusal 
                        ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
                        : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'
                      : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200'
                  }`}>
                    {msg.isSuccess && (
                      <span className={`inline-block text-xs px-2 py-0.5 rounded mb-2 ${
                        msg.isRefusal 
                          ? 'bg-green-600 text-white' 
                          : 'bg-red-600 text-white'
                      }`}>
                        {msg.isRefusal ? 'REFUSED' : 'BYPASSED'}
                                  </span>
                                )}
                    <div className="text-sm whitespace-pre-wrap">{msg.content}</div>
                    <div className="flex items-center gap-2 mt-1">
                      {msg.responseTime && (
                        <span className="text-xs opacity-60">{msg.responseTime}ms</span>
                      )}
                      {msg.verdictReason && (
                        <span className="text-xs opacity-70 italic">
                          — {msg.verdictReason}
                          {msg.verdictConfidence != null && ` (${Math.round(msg.verdictConfidence * 100)}%)`}
                        </span>
                      )}
                    </div>
                          </div>
                ) : msg.type === 'error' ? (
                  <div className="max-w-2xl bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-lg px-4 py-2 text-sm">
                    {msg.content}
                        </div>
                ) : msg.type === 'complete' ? (
                  <div className="bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-3">
                    <div className="font-medium text-gray-800 dark:text-gray-200 text-sm">Scan Complete</div>
                    {msg.summary && (
                      <div className="flex gap-3 text-xs mt-1 text-gray-500">
                        <span>{msg.summary.total || 0} prompts</span>
                        <span className={msg.summary.bypassed > 0 ? 'text-red-600' : 'text-green-600'}>
                          {msg.summary.bypassed || 0} bypassed
                        </span>
                        <span className="text-green-600">{msg.summary.refused || 0} refused</span>
                </div>
              )}
            </div>
                ) : null}
              </div>
            ))
            )}
        </div>

        {/* Footer - only show controls when running */}
        {scan.status === 'running' && (
          <div className="px-6 py-3 border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 flex justify-end gap-2 flex-shrink-0">
            <button className="btn-outline btn-sm" onClick={onStopStream}>Stop Stream</button>
            {/* Hide cancel button for S2S scans */}
            {scan.source !== 'service-to-service' && (
              <button className="btn-outline btn-sm" onClick={onCancel}>Cancel Scan</button>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanDetailsModal;

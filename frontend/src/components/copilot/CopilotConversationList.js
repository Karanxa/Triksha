import React, { useState, useEffect } from 'react';
import { Pencil, Trash2 } from 'lucide-react';

export function ConversationRow({ c, active, onOpen, onRename, onDelete }) {
  const [editing, setEditing] = useState(false);
  const [val, setVal] = useState(c.title);
  useEffect(() => setVal(c.title), [c.title]);

  const commit = () => {
    setEditing(false);
    const t = val.trim();
    if (t && t !== c.title) onRename(c.id, t);
    else setVal(c.title);
  };

  if (editing) {
    return (
      <input
        autoFocus
        value={val}
        onChange={(e) => setVal(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === 'Enter') commit();
          if (e.key === 'Escape') { setVal(c.title); setEditing(false); }
        }}
        className="w-full px-3 py-2 text-sm rounded-lg border border-primary-400 bg-white dark:bg-gray-900
          text-gray-800 dark:text-gray-100 outline-none"
      />
    );
  }

  return (
    <div
      onClick={onOpen}
      className={`group flex items-center gap-1 px-3 py-2 rounded-lg cursor-pointer transition-colors duration-150
        ${active
          ? 'bg-primary-100/80 dark:bg-primary-900/40 text-primary-800 dark:text-primary-200 hover:bg-primary-100 dark:hover:bg-primary-900/55'
          : 'text-gray-700 dark:text-gray-300 hover:bg-gray-200/80 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white'}`}
    >
      <span className="flex-1 truncate text-sm">{c.title || 'New chat'}</span>
      <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition">
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); setEditing(true); }}
          className="p-1 rounded hover:bg-black/10 dark:hover:bg-white/10"
          title="Rename"
        >
          <Pencil className="h-3.5 w-3.5" />
        </button>
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); onDelete(); }}
          className="p-1 rounded hover:bg-black/10 dark:hover:bg-white/10 text-red-500"
          title="Delete"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}

export default function CopilotConversationList({
  conversations,
  activeId,
  onOpen,
  onRename,
  onDelete,
}) {
  return (
    <div className="flex flex-col min-h-0 flex-1">
      <div className="px-3 pb-3 flex-shrink-0">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-gray-400 dark:text-gray-500">
          Recents
        </span>
      </div>
      <div className="flex-1 overflow-y-auto px-1 pb-2 space-y-0.5 scrollbar-thin">
        {conversations.length === 0 ? (
          <p className="text-xs text-gray-400 px-3 py-4 text-center">No conversations yet.</p>
        ) : (
          conversations.map((c) => (
            <ConversationRow
              key={c.id}
              c={c}
              active={c.id === activeId}
              onOpen={() => onOpen(c.id)}
              onRename={onRename}
              onDelete={() => onDelete(c.id)}
            />
          ))
        )}
      </div>
    </div>
  );
}

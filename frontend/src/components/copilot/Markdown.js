import React, { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeHighlight from 'rehype-highlight';
import toast from 'react-hot-toast';
import 'highlight.js/styles/github-dark.css';

// Pull raw text out of react-markdown children (string | element | array).
function extractText(children) {
  if (children == null) return '';
  if (typeof children === 'string') return children;
  if (Array.isArray(children)) return children.map(extractText).join('');
  if (children.props && children.props.children) return extractText(children.props.children);
  return '';
}

function CodeCopyButton({ getText }) {
  const [done, setDone] = useState(false);
  const onClick = async () => {
    try {
      await navigator.clipboard.writeText(getText());
      setDone(true);
      toast.success('Copied');
      setTimeout(() => setDone(false), 1200);
    } catch { /* clipboard unavailable */ }
  };
  return (
    <button onClick={onClick}
      className="text-[11px] px-2 py-1 rounded-md bg-white/10 hover:bg-white/20 text-gray-200
      border border-white/10 transition">
      {done ? 'Copied' : 'Copy'}
    </button>
  );
}

const components = {
  a: ({ node, ...props }) => (
    <a {...props} target="_blank" rel="noreferrer"
      className="text-primary-600 dark:text-primary-400 underline underline-offset-2" />
  ),
  // Unwrap <pre> — the block <code> renders its own styled container.
  pre: ({ children }) => <>{children}</>,
  code: ({ inline, className, children, ...props }) => {
    if (inline) {
      return (
        <code className="px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-[13px]
          font-mono text-primary-700 dark:text-primary-300" {...props}>{children}</code>
      );
    }
    const raw = extractText(children).replace(/\n$/, '');
    const lang = (className || '').replace('language-', '').replace('hljs', '').trim();
    return (
      <div className="relative my-3 group rounded-xl overflow-hidden bg-[#0d1117]">
        <div className="flex items-center justify-between px-3 py-1.5 bg-white/5 border-b border-white/10">
          <span className="text-[11px] text-gray-400 font-mono">{lang || 'code'}</span>
          <CodeCopyButton getText={() => raw} />
        </div>
        <pre className="overflow-x-auto p-4 text-[13px] leading-relaxed">
          <code className={className} {...props}>{children}</code>
        </pre>
      </div>
    );
  },
  table: ({ children }) => (
    <div className="overflow-x-auto my-3">
      <table className="w-full text-sm border-collapse">{children}</table>
    </div>
  ),
  th: ({ children }) => (
    <th className="border border-gray-300 dark:border-gray-700 px-3 py-1.5 bg-gray-50
      dark:bg-gray-800 text-left font-semibold">{children}</th>
  ),
  td: ({ children }) => (
    <td className="border border-gray-200 dark:border-gray-700 px-3 py-1.5 align-top">{children}</td>
  ),
  ul: ({ children }) => <ul className="list-disc pl-6 my-2 space-y-1">{children}</ul>,
  ol: ({ children }) => <ol className="list-decimal pl-6 my-2 space-y-1">{children}</ol>,
  li: ({ children }) => <li className="leading-relaxed">{children}</li>,
  h1: ({ children }) => <h1 className="text-lg font-bold mt-4 mb-2">{children}</h1>,
  h2: ({ children }) => <h2 className="text-base font-bold mt-4 mb-2">{children}</h2>,
  h3: ({ children }) => <h3 className="text-[15px] font-semibold mt-3 mb-1.5">{children}</h3>,
  p: ({ children }) => <p className="my-2 first:mt-0 last:mb-0 leading-relaxed">{children}</p>,
  hr: () => <hr className="my-4 border-gray-200 dark:border-gray-700" />,
  blockquote: ({ children }) => (
    <blockquote className="border-l-4 border-primary-300 dark:border-primary-700 pl-3 my-2
      text-gray-600 dark:text-gray-400">{children}</blockquote>
  ),
};

export default function Markdown({ text }) {
  return (
    <div className="text-[15px] leading-relaxed text-gray-800 dark:text-gray-100 break-words">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[[rehypeHighlight, { ignoreMissing: true }]]}
        components={components}>
        {text || ''}
      </ReactMarkdown>
    </div>
  );
}

# LLM and agent security (OWASP LLM Top 10)

- Treat untrusted content (web pages, pasted text, tool outputs) as potential prompt injection.
- Do not execute or render LLM output without validation when it drives tools, SQL, or shell commands.
- Limit agent agency: only invoke tools required for the stated task; confirm destructive actions.
- Avoid chaining implicit trust across sub-agents, MCP tools, or delegated skills without explicit scope.
- Redact secrets from context sent to models; use environment variables or secret managers instead.

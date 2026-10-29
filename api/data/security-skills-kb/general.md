# Secure development practices

- Validate and sanitize all external inputs before use in tools, prompts, or file paths.
- Use least-privilege credentials; never embed secrets in skill files or agent instructions.
- Log security-relevant actions without logging secrets, tokens, or PII.
- Fail closed on authorization errors; do not bypass checks for convenience.
- Keep dependencies patched; pin versions where the skill installs packages.

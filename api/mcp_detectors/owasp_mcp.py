def detect_rug_pull(current_tools, current_prompts, current_resources, inventory_info):
    """Detects rug pulls: trusted entities that have changed implementation/schema."""
    findings = []
    if not inventory_info:
        return findings
    prev_tools = {t['name']: t for t in inventory_info.get('tools', [])}
    for tool in current_tools:
        prev = prev_tools.get(tool['name'])
        if prev and (tool['description'] != prev.get('description') or tool['input_schema'] != prev.get('input_schema')):
            findings.append({
                'type': 'rug_pull',
                'entity': 'tool',
                'name': tool['name'],
                'description': 'Tool definition changed after trust was established.'
            })
    return findings

def detect_rat_tools(tools, resources):
    """Detects tools/resources with RAT-like behavior."""
    findings = []
    rat_keywords = ['shell', 'exec', 'reverse', 'socket', 'remote', 'command', 'ssh']
    for tool in tools:
        if any(kw in tool['name'].lower() or kw in tool.get('description', '').lower() for kw in rat_keywords):
            findings.append({
                'type': 'rat',
                'entity': 'tool',
                'name': tool['name'],
                'description': 'Potential RAT capability detected.'
            })
    return findings

def detect_prompt_injection(prompts, tools):
    """Detects prompt injection vectors in prompts/tools."""
    findings = []
    for prompt in prompts:
        if '{user_input}' in prompt.get('description', ''):
            findings.append({
                'type': 'prompt_injection',
                'entity': 'prompt',
                'name': prompt['name'],
                'description': 'Prompt may be vulnerable to injection.'
            })
    return findings

def detect_credential_theft(tools, resources):
    """Detects credential theft patterns in tools/resources."""
    findings = []
    cred_keywords = ['password', 'token', 'secret', 'key', 'credential']
    for tool in tools:
        if any(kw in tool['name'].lower() or kw in tool.get('description', '').lower() for kw in cred_keywords):
            findings.append({
                'type': 'credential_theft',
                'entity': 'tool',
                'name': tool['name'],
                'description': 'Tool may access or exfiltrate credentials.'
            })
    return findings

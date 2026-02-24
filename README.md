# Copilot Tool ACL

A single-file, YAML-based Access Control List (ACL) for the [Microsoft Copilot SDK](https://learn.microsoft.com/en-us/azure/ai-services/agents/).

Control exactly which tools, shell commands, file reads/writes, URLs, and MCP operations your Copilot agent is allowed to use — with a simple, declarative YAML file.

## Why?

The Copilot SDK gives agents powerful capabilities: running shell commands, reading/writing files, fetching URLs, and calling MCP tools. In production, you need guardrails. This utility lets you define precise access control rules in a YAML file that's easy to read, review, and version-control.

**Key features:**
- **Single file** — drop `tool_acl.py` into any project
- **Deny by default** — safe posture out of the box
- **First-match-wins** — rules evaluated in order, predictable behaviour
- **Regex matching** — powerful pattern matching for commands, paths, URLs, and tool names
- **Five permission kinds** — `shell`, `read`, `write`, `url`, `mcp`
- **No dependencies** beyond PyYAML (which you likely already have)

## Quick Start

### 1. Copy the script

```bash
# Copy tool_acl.py into your project
cp tool_acl.py /path/to/your/copilot-project/
```

### 2. Create a YAML ACL file

Create `tools_acl.yaml` in your project root:

```yaml
version: "1"
default_action: deny

rules:
  # Allow safe shell commands
  - kind: shell
    action: allow
    when:
      command: "^(echo|cat|ls|grep)\\b"

  # Allow reading project files
  - kind: read
    action: allow
    when:
      path: "^/home/user/myproject/"

  # Allow writes only to /tmp
  - kind: write
    action: allow
    when:
      path: "^/tmp/"
```

### 3. Wire it up

**Option A: Environment variable (recommended)**

```bash
export TOOL_ACL_PATH=tools_acl.yaml
```

Then in your Copilot SDK integration:

```python
from tool_acl import ToolAcl

acl = ToolAcl.from_env()  # reads TOOL_ACL_PATH
if acl is None:
    print("WARNING: No ACL configured, all tools auto-approved")
```

**Option B: Explicit file path**

```python
from tool_acl import ToolAcl

acl = ToolAcl.from_file("tools_acl.yaml")
```

### 4. Evaluate permission requests

```python
# The Copilot SDK sends permission requests like this:
request = {
    "kind": "shell",
    "fullCommandText": "echo hello world"
}

if acl.is_allowed(request):
    # proceed
    pass
else:
    # deny the operation
    pass
```

## YAML Schema Reference

```yaml
version: "1"                    # Required. Must be "1".
default_action: deny | allow    # Optional. Default: "deny".

rules:
  - kind: shell | read | write | url | mcp   # Optional. Omit to match ALL kinds.
    action: allow | deny                       # Required.
    when:                                      # Optional. Omit to match all requests of this kind.
      <field>: "<regex>"                       # All conditions are ANDed together.
```

### Permission Kinds

The Copilot SDK emits five types of permission requests:

| Kind | Description | Available `when` fields |
|------|-------------|------------------------|
| `shell` | Agent wants to run a shell command | `command` |
| `read` | Agent wants to read a file or list a directory | `path` |
| `write` | Agent wants to create or modify a file | `path` |
| `url` | Agent wants to fetch a URL | `url` |
| `mcp` | Agent wants to call an MCP server tool | `tool`, `server` |

### `when` Field Mapping

The `when` block maps short field names to the actual Copilot SDK request fields:

| YAML field | SDK request field | Used with kind |
|------------|-------------------|----------------|
| `command` | `fullCommandText` | `shell` |
| `path` | `path` (read) or `fileName` (write) | `read`, `write` |
| `url` | `url` | `url` |
| `tool` | `toolName` | `mcp` |
| `server` | `serverName` | `mcp` |

### Regex Patterns

All `when` values are **Python `re.search()` patterns** — they match anywhere in the string unless you anchor them:

| Pattern | Meaning |
|---------|---------|
| `echo` | Matches if "echo" appears anywhere in the string |
| `^echo` | Matches only if the string starts with "echo" |
| `\\.py$` | Matches only if the string ends with ".py" |
| `^echo$` | Exact match for "echo" |
| `\\b(rm\|rmdir)\\b` | Word-boundary match for "rm" or "rmdir" |

Patterns are **case-sensitive**. Use `(?i)` at the start for case-insensitive matching.

## Evaluation Rules

1. **Order matters** — rules are checked top to bottom
2. **First match wins** — the first rule whose `kind` and `when` conditions match is applied
3. **`when` conditions are ANDed** — all conditions in a `when` block must match
4. **No match → default** — if no rule matches, `default_action` is used
5. **Omit `kind` → match all** — a rule without `kind` matches any permission type
6. **Omit `when` → match all of kind** — a rule without `when` matches every request of that kind

### Rule Ordering Best Practices

```yaml
rules:
  # 1. DENY dangerous operations first (highest priority)
  - kind: shell
    action: deny
    when:
      command: "\\b(rm|mkfs|dd)\\b"

  # 2. ALLOW specific safe operations
  - kind: shell
    action: allow
    when:
      command: "^(echo|cat|ls)\\b"

  # 3. Catch-all deny for everything else in this kind
  #    (or rely on default_action: deny)
  - kind: shell
    action: deny
```

## Examples

### Strict Production ACL

Deny everything except explicitly allowed operations. See [examples/strict.yaml](examples/strict.yaml).

```yaml
version: "1"
default_action: deny

rules:
  # Block destructive commands first
  - kind: shell
    action: deny
    when:
      command: "\\b(rm|rmdir|mkfs|dd|shred)\\b"

  # Allow read-only commands
  - kind: shell
    action: allow
    when:
      command: "^(echo|cat|head|tail|grep|ls|find|wc)\\b"

  # Block reading secrets
  - kind: read
    action: deny
    when:
      path: "(\\.ssh/|/etc/shadow|\\.env$)"

  # Allow reading project files
  - kind: read
    action: allow
    when:
      path: "^/home/user/myproject/"

  # Allow writes only to scratch space
  - kind: write
    action: allow
    when:
      path: "^/tmp/"

  # Block exfiltration endpoints
  - kind: url
    action: deny
    when:
      url: "(ngrok\\.io|webhook\\.site|requestbin\\.com)"

  # Allow trusted domains
  - kind: url
    action: allow
    when:
      url: "^https://([a-z0-9-]+\\.)?(microsoft\\.com|github\\.com)/"

  # Block destructive MCP tools
  - kind: mcp
    action: deny
    when:
      tool: "(write|delete|remove|create)_"

  # Allow other MCP tools
  - kind: mcp
    action: allow
```

### Permissive Development ACL

Allow everything except known-dangerous operations. See [examples/permissive.yaml](examples/permissive.yaml).

```yaml
version: "1"
default_action: allow

rules:
  - kind: shell
    action: deny
    when:
      command: "\\b(rm -rf /|mkfs|dd if=)\\b"

  - kind: shell
    action: deny
    when:
      command: "^(sudo|su)\\b"

  - kind: read
    action: deny
    when:
      path: "(\\.ssh/|/etc/shadow)"
```

### MCP-Only Agent

Agent that only uses MCP tools — no shell, file, or URL access. See [examples/mcp_only.yaml](examples/mcp_only.yaml).

```yaml
version: "1"
default_action: deny

rules:
  - kind: mcp
    action: allow
    when:
      tool: "^(read_|get_|list_|search_)"

  - kind: mcp
    action: allow
    when:
      server: "^my-trusted-server$"
```

### Custom Tool Whitelist

Only allow specific named tools. See [examples/custom_tools.yaml](examples/custom_tools.yaml).

```yaml
version: "1"
default_action: deny

rules:
  - kind: mcp
    action: allow
    when:
      tool: "^read_blob$"

  - kind: mcp
    action: allow
    when:
      tool: "^transcribe_audio$"

  - kind: mcp
    action: allow
    when:
      tool: "^generate_weekly_report$"
```

## Integration with the Copilot SDK

### Using `azure-ai-agentserver-copilot`

The `CopilotAdapter` accepts a `ToolAcl` directly:

```python
from tool_acl import ToolAcl
from azure.ai.agentserver.copilot import CopilotAdapter

acl = ToolAcl.from_file("tools_acl.yaml")
adapter = CopilotAdapter(acl=acl)
```

Or set the environment variable and the adapter picks it up automatically:

```bash
export TOOL_ACL_PATH=tools_acl.yaml
```

### Custom Integration

For any Copilot SDK integration, wire the ACL into the permission callback:

```python
from tool_acl import ToolAcl
import logging

logging.basicConfig(level=logging.DEBUG)
acl = ToolAcl.from_file("tools_acl.yaml")

async def on_permission_request(request: dict) -> str:
    """Called by the Copilot SDK for every tool permission check."""
    action = acl.evaluate(request)
    if action == "deny":
        logging.warning("Denied: %s", request)
    return action
```

## API Reference

### `ToolAcl.from_file(path)`

Load ACL from a YAML file. Raises `FileNotFoundError` or `ValueError` on invalid input.

### `ToolAcl.from_env(env_var="TOOL_ACL_PATH")`

Load ACL from the file path in the given environment variable. Returns `None` if unset.

### `acl.evaluate(request) → "allow" | "deny"`

Evaluate a permission request dict. Returns the action string.

### `acl.is_allowed(request) → bool`

Convenience wrapper — returns `True` if `evaluate()` returns `"allow"`.

## Logging

Enable debug logging to see which rules match:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Output:

```
INFO:tool_acl:Loaded tool ACL from tools_acl.yaml: 12 rules, default='deny'
DEBUG:tool_acl:ACL rule #3 (allow) matched 'shell': 'echo hello'
DEBUG:tool_acl:ACL rule #1 (deny) matched 'shell': 'rm -rf /'
DEBUG:tool_acl:ACL default (deny) applied to 'read': '/etc/passwd'
```

## Testing

```bash
pip install pytest pyyaml
pytest test_tool_acl.py -v
```

## License

MIT

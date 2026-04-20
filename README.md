# Armis AppSec MCP Plugin

AI-powered security scanning for [Claude Code](https://claude.ai/code). Scans code, files, and git diffs for vulnerabilities in real-time using the Armis scanning API.

## Features

- **`scan_code`** — Scan a code snippet for vulnerabilities
- **`scan_file`** — Scan a file on disk
- **`scan_diff`** — Scan git changes (staged, unstaged, or diff against a branch)
- **Commit gate** — Automatically blocks `git commit`, `git push`, and `gh pr create` until code is scanned
- **`/security-scan`** — On-demand scanning via slash command

## Installation

### 1. Add the marketplace

In Claude Code:

```
/plugin marketplace add ArmisSecurity/armis-appsec-mcp
```

### 2. Install the plugin

```
/plugin install armis-appsec@armis-appsec-mcp
```

This unpacks the plugin into a versioned directory under
`~/.claude/plugins/cache/armis-appsec-mcp/armis-appsec/<version>/`.

### 3. Set credentials

Run this in a shell **after** installing — it locates the unpacked plugin
directory and writes `.env` into it:

```bash
PLUGIN_DIR="$(ls -dt ~/.claude/plugins/cache/armis-appsec-mcp/armis-appsec/*/ | head -1)"
cat > "$PLUGIN_DIR/.env" << 'EOF'
ARMIS_CLIENT_ID=<your-client-id>
ARMIS_CLIENT_SECRET=<your-client-secret>
EOF
chmod 600 "$PLUGIN_DIR/.env"
```

Contact the Armis AppSec team if you don't have credentials.

### 4. Restart Claude Code

The plugin loads automatically. Verify with:

```
/security-scan
```

## Usage

### Scan staged changes (default)

```
/security-scan
```

### Scan a specific file

```
/security-scan path/to/file.py
```

### Scan diff against a branch

```
/security-scan ref=main
```

### Scan pasted code

Paste code into the conversation and ask:

```
Is this code secure?
```

### Commit gate

When Claude runs `git commit`, `git push`, or `gh pr create`, the plugin automatically:

1. Blocks the command
2. Instructs Claude to scan the changes
3. Allows the command after a clean scan (no HIGH/CRITICAL findings)

If HIGH/CRITICAL findings are found, Claude will attempt to fix them. If findings remain after remediation, Claude asks for your approval before proceeding.

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `ARMIS_CLIENT_ID` | (required) | Client ID for authentication |
| `ARMIS_CLIENT_SECRET` | (required) | Client secret for authentication |
| `APPSEC_ENV` | `prod` | `dev` or `prod` — selects API endpoint |
| `APPSEC_API_URL` | (auto) | Override the API base URL |
| `APPSEC_DEBUG` | (unset) | Set to any value to enable debug logging |

## Running Tests

```bash
pip install pytest httpx mcp[cli] python-dotenv
python -m pytest hooks/tests/ -v
```

## Architecture

```
              +---------------------+
              |  Armis Cloud        |
              |  POST /scan/fast    |
              +--------+------------+
                       ^
                       | HTTPS (JWT Bearer)
              +--------+------------+
              |   Scanner Core       |
              |  scanner_core.py     |
              +--------+------------+
                 +-----+------+
                 |            |
           +-----v-----+ +---v---------+
           | MCP Server | | PreToolUse  |
           | server.py  | | Hook        |
           +------------+ +-------------+
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

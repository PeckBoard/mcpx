# mcpx

An MCP **client** for the shell, plus a local gateway. Point it at the same
`mcp.json` you already use with Claude, Cursor, or VS Code. You can then list
and call any server's tools from scripts, or expose all of them to a bot
through one authenticated HTTP endpoint.

- Supports stdio, streamable HTTP, and legacy HTTP+SSE servers (via
  [`rmcp`](https://crates.io/crates/rmcp)).
- Handles OAuth 2.1 the way the MCP Authorization spec describes: discovery,
  dynamic client registration, PKCE, refresh, and `client_credentials`.
- Prints JSON on stdout, prints errors as JSON on stderr, and exits non-zero
  on failure. Add `--pretty` for tables.

## Install

Static Linux binaries (x86_64, aarch64) are attached to each
[release](https://github.com/PeckBoard/mcpx/releases):

```bash
arch=$(uname -m); [ "$arch" = arm64 ] && arch=aarch64
curl -fsSLo mcpx "https://github.com/PeckBoard/mcpx/releases/latest/download/mcpx-linux-${arch}"
chmod +x mcpx && sudo mv mcpx /usr/local/bin/
```

Or build from source with `cargo install --git https://github.com/PeckBoard/mcpx`.

## Configuration

mcpx looks for the config file in this order:

1. `--config <file>` (or `$MCPX_CONFIG`)
2. `./.mcp.json`
3. `~/.config/mcpx/mcp.json`

The first file found is used. `--import` also merges servers from
`~/.claude.json` (global and current-project entries), `~/.cursor/mcp.json`,
`.cursor/mcp.json`, and `.vscode/mcp.json` (VS Code's `servers` key). When two
files define the same name, the entry from the main config wins.

```json
{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "${HOME}/notes"],
      "env": { "LOG_LEVEL": "warn" },
      "cwd": "/tmp"
    },
    "github": {
      "url": "https://api.githubcopilot.com/mcp/",
      "headers": { "Authorization": "Bearer ${GITHUB_TOKEN}" }
    },
    "linear": { "url": "https://mcp.linear.app/mcp" },
    "legacy": { "type": "sse", "url": "https://old.example.com/sse" },
    "internal": {
      "url": "https://mcp.internal.example/mcp",
      "oauth": {
        "grant": "client_credentials",
        "client_id": "svc-bot",
        "client_secret": "${INTERNAL_SECRET}",
        "scopes": ["mcp.read"]
      }
    }
  }
}
```

- An entry with `command` is a stdio server. An entry with `url` is a
  streamable HTTP server, or a legacy SSE server when it has
  `"transport": "sse"` or `"type": "sse"`. The `"type": "stdio" | "http" | "sse"`
  form is accepted too.
- `${VAR}` and `${VAR:-default}` are expanded in `command`, `args`, `env`,
  `cwd`, `url`, and `headers`. If a variable has no default and is not set,
  that server fails with an error instead of sending an empty value.
- `oauth` is optional. Without it, mcpx registers itself dynamically when the
  server asks for authorization. If you set an `Authorization` header, mcpx
  uses that header and skips OAuth.

## CLI

```bash
mcpx servers                                  # status, serverInfo, capabilities
mcpx tools                                    # every server's tools, with inputSchema
mcpx tools fs --pretty
mcpx call fs.read_file '{"path":"/tmp/notes/todo.md"}'
mcpx call fs.read_file --arg path=/tmp/notes/todo.md
echo '{"query":"is:open"}' | mcpx call github.search_issues -
mcpx call linear.create_issue --arg title=Bug --arg priority=2 --timeout 30
mcpx resources [server]      ;  mcpx read fs file:///tmp/notes/todo.md
mcpx prompts [server]        ;  mcpx prompt fs.summarize --arg style=short
```

- `call` arguments come from a JSON object (positional, or `-` for stdin).
  Each `--arg k=v` sets one key. The value is parsed as JSON when it is valid
  JSON (`2`, `true`, `{"a":1}`) and is a string otherwise.
- `call` exits with code 1 when the tool result has `isError: true`. The
  result is still printed on stdout.
- In `tools`, `resources`, and `prompts`, if some servers fail, the results
  from the others are still printed. Each failure is written to stderr as
  `{"warning": …}`.
- `-v` logs to stderr and shows stdio servers' own stderr (hidden by default).

## OAuth

```bash
mcpx login linear            # opens a browser; --no-browser prints the URL instead
mcpx auth status             # state per server (never prints tokens)
mcpx logout linear
```

mcpx follows the MCP Authorization spec:

1. A request gets 401 with `WWW-Authenticate: Bearer resource_metadata=…`.
2. mcpx reads the RFC 9728 protected-resource metadata, with a `.well-known`
   fallback.
3. It reads the RFC 8414 or OIDC metadata of the authorization server.
4. It registers a client with RFC 7591 dynamic client registration when the
   server offers a `registration_endpoint`. Otherwise it uses
   `oauth.client_id` from the config.
5. It runs the authorization code flow with PKCE (S256) and a loopback
   redirect `http://127.0.0.1:<random>/callback`, and sends the RFC 8707
   `resource` parameter on every request.

Tokens and the client registration are stored in `~/.config/mcpx/tokens.json`
(mode 0600), keyed by server URL. mcpx refreshes a token when it is about to
expire or when the server rejects it with a 401. With
`"grant": "client_credentials"` there is no browser step: mcpx fetches tokens,
and fetches new ones when needed. On a headless machine, run
`mcpx login <server> --no-browser` and open the printed URL in a browser on the same
host, or forward the callback port over SSH.

## Gateway

```bash
mcpx serve                                   # 127.0.0.1:7790
mcpx serve --port 7790 --deny '*__delete*' --allow 'github__*' --allow 'fs__read*'
```

The gateway:

- Listens on `127.0.0.1` only.
- Writes `{port, token, pid}` to `~/.config/mcpx/gateway.json` (mode 0600).
- Connects to each server the first time it is used and keeps the connection
  open. It restarts crashed stdio servers on the next call, and stops stdio
  servers that have been idle for 10 minutes.
- Applies `--allow` and `--deny` globs to `server__tool`, both when listing
  tools and when calling them. `--deny` takes priority. If you give no
  `--allow`, every tool not denied is exposed.

While a gateway is running, CLI commands go through it, so servers are
already connected when you call them. `--direct`, `--config`, or `--import`
bypass the gateway.

### MCP Endpoint

`http://127.0.0.1:7790/mcp` is a streamable-HTTP MCP server. It exposes every
upstream tool and prompt as `<server>__<name>`, plus the upstream resources.
Point any MCP-capable bot or agent at it and use the bearer token as the
credential:

```json
{
  "mcpServers": {
    "mcpx": {
      "url": "http://127.0.0.1:7790/mcp",
      "headers": { "Authorization": "Bearer <token from ~/.config/mcpx/gateway.json>" }
    }
  }
}
```

### REST

```bash
TOKEN=$(jq -r .token ~/.config/mcpx/gateway.json)
curl -s localhost:7790/health
curl -s -H "Authorization: Bearer $TOKEN" localhost:7790/servers
curl -s -H "Authorization: Bearer $TOKEN" 'localhost:7790/tools?server=fs'
curl -s -H "Authorization: Bearer $TOKEN" localhost:7790/call \
  -H 'content-type: application/json' \
  -d '{"server":"fs","tool":"read_file","arguments":{"path":"/tmp/notes/todo.md"},"timeout":30}'
curl -s -H "Authorization: Bearer $TOKEN" 'localhost:7790/resources'
curl -s -H "Authorization: Bearer $TOKEN" localhost:7790/read \
  -H 'content-type: application/json' -d '{"server":"fs","uri":"file:///tmp/notes/todo.md"}'
curl -s -H "Authorization: Bearer $TOKEN" 'localhost:7790/prompts'
curl -s -H "Authorization: Bearer $TOKEN" localhost:7790/prompt \
  -H 'content-type: application/json' -d '{"server":"fs","name":"summarize","arguments":{}}'
```

Error responses look like `{"error": {"message": "…"}}`. The status code
tells you what went wrong:

| Status | Meaning |
| --- | --- |
| 401 | Missing or wrong bearer token. |
| 403 | The tool is blocked by the allow/deny filter, or the `Host` header is not loopback. |
| 404 | Unknown server. |
| 502 | The upstream server failed. |

## Security Notes

- The gateway binds `127.0.0.1` only, and it rejects any `Host` header other
  than loopback, which defends against DNS rebinding. The bearer token is 256
  bits from the OS RNG and is required on every route except `/health`.
- `--no-auth` removes the token check. Requests that carry an `Origin` header
  are then rejected, so browser pages cannot call the gateway. Even so, any
  local process can use every tool exposed through it. Use `--no-auth` only
  on single-user machines.
- The gateway runs every tool with your credentials: stdio servers run as
  your user, and remote servers use your tokens. Use `--allow` and `--deny`
  to expose only what a bot actually needs.
- `tokens.json` and `gateway.json` are written with mode 0600, and tokens
  are never printed. Treat both files like passwords.
- mcpx never adds secrets to `mcp.json`. Keep secrets in the environment and
  reference them with `${VAR}`.

## Development

```bash
cargo test     # unit tests + stdio, SSE, OAuth (fake authorization server) and gateway integration tests
cargo clippy --all-targets
```

`mcpx echo-server` (hidden) is a small stdio MCP server, used by the tests. It
offers the tools `echo` and `fail`, the resource `mem://hello`, and the prompt
`greet`.

## License

MIT

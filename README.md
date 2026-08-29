# AgentKeeper MCP Gateway

Open-source MCP gateway with threat detection, observe mode, and explicit enforcement.

When an MCP client is explicitly routed through it, AgentKeeper proxies and inspects that MCP traffic for threats, sensitive data, and policy violations. Installing the binary alone does not route or protect a client.

## Quick Start

```bash
# Install from the latest GitHub Release
curl -fsSL https://www.agentkeeper.dev/install-gateway.sh | bash

# Preview supported local MCP client migration
agentkeeper-mcp-gateway configure-ide --dry-run

# Explicitly move the previewed supported MCP client configs behind Gateway
agentkeeper-mcp-gateway configure-ide

# Check discovery, routing, auth, and next steps
agentkeeper-mcp-gateway list --health
```

Restart the MCP client after `configure-ide`, then make one real tool call. The gateway proxies routed MCP traffic, detects threats in real time, and logs everything locally. Manual `agentkeeper-mcp-gateway add` is still available for unsupported config sources, gateway-native admin setup, and lab cases, but it is not the default rollout workflow.

## MCP protocol compatibility

The gateway negotiates MCP protocol versions `2024-11-05`, `2025-03-26`,
`2025-06-18`, and `2025-11-25`. It aggregates and routes tools, resources,
resource templates, and prompts only when an upstream server declares the
corresponding capability. Resource-template routing supports the common
single-value `{name}` form; it is not a claim of complete RFC 6570 support.

Backend process configuration is structured: keep the executable in `command`
and its arguments in `args`. Existing legacy command strings remain compatible,
but an executable path containing spaces is treated as one atomic path.

## Local Development

This repository is the standalone Go MCP gateway used by AgentKeeper. The main
AgentKeeper app, Helm chart, and dashboard live in
[`rad-security/agentkeeper-web`](https://github.com/rad-security/agentkeeper-web).

Requirements:

- Go 1.23.3 or compatible
- Node.js/npm if you want to test common `npx` MCP servers locally

Build and test:

```bash
git clone https://github.com/rad-security/agentkeeper-mcp-gateway.git
cd agentkeeper-mcp-gateway
go test ./...
go run . version
go build -o bin/agentkeeper-mcp-gateway .
```

Run a local gateway with a disposable filesystem MCP server:

```bash
go run . add filesystem "npx -y @modelcontextprotocol/server-filesystem /tmp"
go run . list
go run . server
```

Important directories:

```text
cmd/                       Cobra CLI commands
internal/config/           Config path resolution and env overrides
internal/detection/        Threat and sensitive-data detection
internal/ideconfig/        Claude/Cursor IDE config rewrites
internal/policy/           Audit/enforce policy behavior
internal/proxy/            MCP proxy path
internal/skillinventory/   Local skill inventory scan and check-in
internal/telemetry/        Dashboard event upload
```

Config resolution is documented below in "Headless / Config-Managed Install".
Do not hardcode production AgentKeeper API keys while testing; use local config
files or disposable dashboard keys.

## What It Detects

**36 threat detection patterns** running locally at sub-50ms:

| Category | Examples |
|---|---|
| Credential exfiltration | API keys piped to curl, SSH keys sent to external endpoints |
| Reverse shells | bash, netcat, python, perl, ruby, base64-encoded |
| Prompt injection | Override instructions, persona hijacking, jailbreak attempts |
| Security control bypass | Firewall disable, SELinux/AppArmor teardown, AV kill |
| Supply chain attacks | Suspicious package installs from raw URLs |
| Tool poisoning | Hidden instructions in MCP tool descriptions |
| Sensitive data | Stripe/AWS/GitHub keys, credit cards, SSNs, private keys, JWTs |

## Two Modes

**Observe (default; legacy config value `audit`):** Routed calls are inspected and reported, but a deny decision is recorded as `would block` and the downstream call is still forwarded.

```bash
agentkeeper-mcp-gateway server
```

**Enforce:** On traffic actually routed through the process, denied calls are blocked before dispatch and denied results are withheld before returning to the client.

```bash
agentkeeper-mcp-gateway server --enforce
```

Local event files and their containing directory are owner-only (`0600` and
`0700`). If the configured event path is a symlink or another non-regular file,
local persistence is disabled while the in-memory upload buffer remains
available.

## Warn Mode

When a threat is detected in warn mode, the warning is returned to the AI client as context. The AI sees the threat and can self-correct — no developer interruption, no retry loops.

Warnings are returned as MCP context where the client supports displaying tool output. Client presentation varies and must be certified per supported client/version.

## Failure behavior

Observe mode prioritizes continuity, but no software can guarantee that a gateway process will never affect a client. Current behavior is:

- Detection error: tool call proceeds, event logged
- API timeout: falls back to local detection
- Network down: uses the last in-memory policy and durable signed-receipt queue when available
- Gateway process exit: the client loses that MCP session until its own process lifecycle restarts the configured stdio command; the standalone binary does not currently provide a proven transparent crash pass-through

## Connect to Dashboard

Optional. Get fleet-wide visibility, team policies, and identity-aware access controls.

```bash
agentkeeper-mcp-gateway auth login
```

Opens your browser for device authorization. Once connected, events stream to the dashboard and team policies sync every 60 seconds.

## CLI Reference

```bash
# Server management
agentkeeper-mcp-gateway add <name> <command>    # fallback/admin only
agentkeeper-mcp-gateway remove <name>
agentkeeper-mcp-gateway list [--health] [--json]

# Gateway
agentkeeper-mcp-gateway server [--enforce]
agentkeeper-mcp-gateway logs [-f] [-l 50]
agentkeeper-mcp-gateway scan
agentkeeper-mcp-gateway export --format json|csv --since 2026-04-01

# Configuration
agentkeeper-mcp-gateway config show
agentkeeper-mcp-gateway auth login|status|logout
agentkeeper-mcp-gateway completion zsh|bash|fish

# IDE integration (zero-touch)
agentkeeper-mcp-gateway configure-ide [--dry-run] [--ide=claude-code|claude-desktop|cursor|cowork]
```

## Explicit IDE routing

`configure-ide` discovers supported local MCP client configurations and can route them to the gateway while preserving native OAuth MCP servers that the client must authenticate itself. Preview first, then invoke the write separately. The command covers the declared config sources for Claude Desktop, Claude Code, Cursor, and locally represented Cowork MCP sources; it does not make cloud-only connectors routable.

```bash
agentkeeper-mcp-gateway configure-ide --dry-run   # preview; writes nothing
agentkeeper-mcp-gateway configure-ide              # apply
```

For Cowork sources created after setup, run `agentkeeper-mcp-gateway cowork guard` from a login item/service, or rerun `configure-ide`. Native Cowork cloud connectors that are not represented as local MCP sources require the AgentKeeper Cowork ZIP/guardrail path; the standalone gateway can only govern MCP traffic it can route.

Supports **Claude Code** (`~/.claude.json`), **Claude Desktop** (macOS + Linux), and **Cursor** (`~/.cursor/mcp.json`). Claude Code's `~/.claude/settings.json` remains a preferences/hooks file and is never treated as the user MCP route. For each detected IDE it:

1. Backs up the existing config under the gateway backup directory, normally `~/.config/agentkeeper-mcp-gateway/backups/`
2. Migrates routable local MCP servers and explicit-header HTTP servers into the gateway's own config (environment variables and all)
3. Keeps headerless remote HTTP/OAuth servers native so Claude/Cursor/Cowork can complete auth and token refresh
4. Rewrites the IDE's `mcpServers` map to include the gateway plus any native-auth servers that must remain direct
5. Preserves every non-MCP top-level key verbatim (`permissions`, `preferences`, etc.)

A second invocation is a no-op when the exact current Gateway shape is already present. Every write creates a backup and uses a source-hash compare-and-swap check, so a file edited after planning is left unchanged. Package installation must remain stage-only: do not run the applying form from a postinstall script or broad MDM assignment. Managed routing is a separate, explicitly approved activation step after preview and client-state checks.

## AgentKeeper Linux runtime integration

The signed AgentKeeper Linux RPM uses a separate, machine-verifiable managed
mode. Operators should enroll with the `agentkeeper` CLI; they should not invoke
the flags below directly.

```bash
agentkeeper-mcp-gateway enterprise-capabilities --json
agentkeeper-mcp-gateway configure-ide \
  --managed-runtime-config /etc/agentkeeper/mcp-gateway.json \
  --non-interactive
```

In managed mode:

- `/etc/agentkeeper/mcp-gateway.json` is a root-owned, credential-free pointer
  to the local AgentKeeper runtime socket.
- The gateway never receives the workstation device credential. The machine
  broker authenticates the calling Linux UID with `SO_PEERCRED`, authorizes the
  enrolled target user, and adds trusted workstation/user identity.
- Only MCP client configuration files that already exist are structurally
  merged. Missing Claude Code, Claude Desktop, or Cursor files are not created.
- Migrated MCP server definitions remain in the target user's private gateway
  config. The ownership manifest and gateway config are mode `0600`; backups
  stay under the private gateway backup directory.
- Reconciliation is idempotent. Later customer MCP additions are migrated on
  the next pass, and their later edits are preserved during removal.
- `--remove-managed-routing` removes only AgentKeeper-owned routing. It is a
  no-op when nothing was routed and refuses cleanup if an active gateway entry
  has lost its ownership manifest.

Filesystem presence or a sync heartbeat is not enforcement evidence. A real
routed MCP tool call must reach the runtime broker before the integration can
be reported active.

## Manual fallback/admin registration

Use `add` only when no supported local MCP client config can be migrated, or when an admin intentionally wants a gateway-native server entry.

```bash
agentkeeper-mcp-gateway add github "npx -y @modelcontextprotocol/server-github"
agentkeeper-mcp-gateway add remote https://api.example.com/mcp --header "Authorization:Bearer tok"
```

For an enterprise canary, stage the optional signed artifact without editing client configuration, export/review the dry-run, explicitly activate Observe for named clients, let the user restart naturally, then require a real routed call and signed application receipt. `list --health`, package presence, or a heartbeat alone is not proof of routing or enforcement.

## Cowork MCP Gateway Routing

Cowork can expose MCP servers from Claude Desktop config, plugin `.mcp.json`
files, and remote MCP session state. The gateway must be the only MCP path; a
backend that is both imported into AgentKeeper and still present as a native
Cowork remote MCP source can bypass AgentKeeper telemetry.

Important boundary: the standalone local gateway governs Cowork traffic when
Cowork invokes the local `agentkeeper-mcp-gateway server` MCP process. This
release covers MCP backends that are discoverable on disk as Claude Desktop
config, Cowork plugin `.mcp.json`, or Cowork remote MCP session config. It
imports those backends, ensures Cowork has a gateway MCP entrypoint to attach
to, and removes direct remote MCP session entries that would bypass the
gateway.

Connector calls that Cowork never represents in local MCP config can still
execute through Claude's cloud-managed connector API without invoking the local
gateway process. Those cloud-only connector calls require the AgentKeeper
Cowork plugin ZIP path:

```text
https://www.agentkeeper.dev/downloads/cowork/latest/agentkeeper-cowork-guardrail.zip
```

Run the Cowork-specific configure command after install and after plugin or
remote MCP changes:

```bash
agentkeeper-mcp-gateway cowork configure --dry-run
agentkeeper-mcp-gateway cowork configure
agentkeeper-mcp-gateway cowork doctor --strict
```

`cowork configure` imports discovered local/plugin/remote MCP backends into the
gateway config, ensures Claude Desktop/Cowork has an
`agentkeeper-mcp-gateway server` MCP entrypoint, rewrites local `.mcp.json`
files to point at that entrypoint, and disables direct Cowork
`remoteMcpServersConfig` entries after backing up each touched file under the
gateway backup directory, not beside project or plugin `.mcp.json` files.

The local MCP success condition is:

```text
verdict: cowork_local_mcp_routed_native_connectors_require_zip
direct_count: 0
gateway_backend_count: >0
```

`cowork doctor` includes a redacted `gateway_backends` inventory so an
entrypoint-only deployment cannot look healthy. Any direct Cowork MCP source is
a bypass risk. `cowork doctor --strict` exits non-zero until direct sources are
removed, and also exits non-zero when Cowork is wired to the gateway entrypoint
but the gateway config has no backend MCP servers.

If your deployment requires governance of Cowork native/cloud connectors, run:

```bash
agentkeeper-mcp-gateway cowork doctor --strict --require-native-connectors
```

That command intentionally exits non-zero because standalone local MCP routing
cannot cover connector calls that are not exposed to the local gateway process;
install the AgentKeeper Cowork plugin ZIP and verify with `cowork-status.sh`
after a real Cowork tool action.

## Headless / Config-Managed Install

The gateway is designed to work under a fleet config-management tool (Kandji, Ansible, Jamf, MDM) that does not know any individual developer's home directory. Drop a config at `/etc/agentkeeper-mcp-gateway/config.json`, or set env vars, and the gateway picks it up.

**Config path resolution (in priority order):**

| # | Source | Example |
|---|---|---|
| 1 | `--config` flag | `agentkeeper-mcp-gateway --config /opt/ck/cfg.json server` |
| 2 | `$AGENTKEEPER_CONFIG` env var | `export AGENTKEEPER_CONFIG=/opt/ck/cfg.json` |
| 3 | `$XDG_CONFIG_HOME/agentkeeper-mcp-gateway/config.json` (if file exists) | per-user override |
| 4 | `~/.config/agentkeeper-mcp-gateway/config.json` (if file exists) | dev default |
| 5 | `/etc/agentkeeper-mcp-gateway/config.json` (if file exists) | system-wide, fleet-deploy target |
| fallback | `~/.config/agentkeeper-mcp-gateway/config.json` | created on first write |

**Environment overrides:**

| Field | Env var | Rule |
|---|---|---|
| `api_key` | `AGENTKEEPER_API_KEY` | File wins when set; env fills blanks only. |
| `api_url` | `AGENTKEEPER_API_URL` | File wins when set to a non-default value; env fills blanks and the factory default. |

The file-wins-over-env rule is deliberate — rotate the API key by re-rendering the config file, not by setting a shell env var that silently shadows the real config.

**Checking the resolved state:**

```bash
$ agentkeeper-mcp-gateway config show
# config path: /etc/agentkeeper-mcp-gateway/config.json
# api_key:     file
# api_url:     default
{ "mode": "audit", ... }
```

`config show` prints the resolved path and labels every overridable field as `file`, `env`, or `default`.

**Sample systemd unit (Linux):**

```ini
# /etc/systemd/system/agentkeeper-mcp-gateway.service
[Unit]
Description=AgentKeeper MCP Gateway
After=network-online.target

[Service]
User=agentkeeper
ExecStart=/usr/local/bin/agentkeeper-mcp-gateway server
Environment=AGENTKEEPER_CONFIG=/etc/agentkeeper-mcp-gateway/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Architecture

```
MCP Client (Cursor, Claude Code, Windsurf)
    |
    v
agentkeeper-mcp-gateway (local binary, 8MB)
    |
    +---> Detection Engine (36 patterns, <50ms)
    +---> Policy Engine (dashboard + local config)
    +---> Event Logger (JSONL + batch upload)
    +---> Watchdog (fail-open recovery)
    |
    v
MCP Servers (GitHub, filesystem, Slack, etc.)
```

## Works With the Claude Code Plugin

For complete coverage, deploy both:

- **MCP Gateway** — covers MCP tool calls across all IDEs
- **Claude Code Plugin** — covers native tools (Bash, Read, Write, Edit) that MCP can't see

Both report to the same dashboard. Single pane of glass.

## Compliance

| Framework | Controls |
|---|---|
| OWASP Agentic Top 10 | ASI01-ASI05 |
| OWASP LLM Top 10 | LLM01, LLM02, LLM03, LLM06 |
| SOC 2 | CC6.1, CC6.6, CC7.2, CC9.2 |
| EU AI Act | Art. 9, 12, 14, 15 |

## License

MIT

## Links

- [Dashboard](https://www.agentkeeper.dev)
- [Docs](https://www.agentkeeper.dev/docs)
- [Claude Code Plugin](https://github.com/rad-security/agentkeeper-web/tree/main/plugin)

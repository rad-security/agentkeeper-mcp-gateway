# What the Gateway reports

A connected Gateway talks to the AgentKeeper API in four ways: a sync every
30 seconds (`/api/v2/mcp/gateways/register`, when the Gateway has a receipt
signer, followed by `/api/v1/mcp/sync`), an evaluation per routed tool call
(`/api/v2/mcp/evaluate`, falling back to `/api/v1/mcp/evaluate`), event
uploads every 5 seconds (`/api/v1/mcp/events`) and signed receipt uploads
(`/api/v2/mcp/receipts`). This page describes the fields that correlate calls,
record tool definition history and report servers that bypass the Gateway.
Every field is additive; an API that does not know a field ignores it.

## Session id

Each Gateway process has one session id, `gw-<boot id>`. The boot id is the
one on every receipt the process signs: `boot-` followed by 32 hex digits, so
the session id reads `gw-boot-` followed by the same 32 digits. Without a
receipt signer the process generates a boot id of the same form.

- Every evaluation request, v2 and the v1 fallback, carries `session_id`.
- Every event carries `context.session_id`. The id is stamped when the event is
  written, so an event that a later process uploads from the durable queue
  still names the process that observed it.

## Tool definitions

Each `connected_servers` entry of a sync may carry two fields:

| Field | When | Content |
| --- | --- | --- |
| `tools_hash` | Whenever the Gateway holds the server's tool list | `"sha256:<hex>"` of the canonical definitions |
| `tools` | `/api/v1/mcp/sync` only, when due (below) | `[{name, description, inputSchema, annotations}]`, each field present when the tool has it |

```json
{
  "name": "notes",
  "transport": "stdio",
  "tools_hash": "sha256:5b1f0c…",
  "tools": [
    {"name": "archive", "description": "Archive a note.", "inputSchema": {"type": "object"}},
    {"name": "search", "description": "Search notes.", "inputSchema": {"properties": {"query": {"type": "string"}}, "type": "object"}, "annotations": {"readOnlyHint": true}}
  ]
}
```

The tool list is the one in the Gateway's manifest cache: what the server last
returned to `tools/list`, which is also what the client is offered. The Gateway
never starts a server to list it. A server whose list is not known (it has not
started yet, or it exited) has neither field. A server whose consecutive
listings were empty is a known empty list and is reported as `"tools": []`.

**Hash.** The hash covers the complete definitions, before any upload cap: the
tools reduced to `name`, `description`, `inputSchema` and `annotations`,
sorted by name (UTF-16 code unit order, then by canonical form), encoded as
one JSON array in the RFC 8785 canonical form (members sorted by name, numbers
in ECMAScript form, minimal string escaping, no whitespace), then SHA-256.
Key order and formatting in what a server sends never change it; any change to
those four fields does. Other fields (`title`, `outputSchema`, `_meta`) are not
part of the definition history.

**When `tools` is sent.** For each server, the Gateway keeps the last hash the
API accepted (HTTP 2xx with a JSON body) together with its tools. `tools` is
attached when the current hash differs from it, on the first sync of the
process, and at least once every 24 hours. A sync that fails, or is answered
with anything but a 2xx JSON response, leaves the server pending; the next
sync sends it again. The registration request carries `tools_hash` only.

**Caps.** An uploaded description longer than 16 KiB is cut at a character
boundary and ends in `…`. An `inputSchema` larger than 64 KiB in canonical
form is replaced by `{"type": "object", "description": "Schema omitted: <n>
bytes"}`. One sync carries at most 512 KiB of tool lists (and never makes the
whole request larger than 960 KiB); servers that do not fit stay pending, and
the longest-waiting go first next time. A server whose list alone exceeds
512 KiB is sent with every input schema replaced by its placeholder; if it
still does not fit, only its `tools_hash` is reported and a local warning is
printed. Because the hash covers the uncapped definitions, a change hidden past
a cap still changes `tools_hash`.

## Servers that bypass the Gateway

`discovered_servers` lists the MCP servers in local client configs, routed or
not, with `route_state` `direct` or `routed`. For the client a Gateway
process serves, the routing watch adds:

| Field | Values |
| --- | --- |
| `direct_reason` | `added_after_setup`, `oauth`, `plugin`; absent when none applies |
| `first_seen_at` | When this Gateway process first saw the server (RFC 3339, UTC) |
| `route_state` | also `routed_pending_restart`: moved behind the Gateway while the client runs; the client keeps its direct connection until it restarts |

- `oauth`: a remote server without a credential header, which configure-ide
  leaves in the client so the client can run the OAuth flow.
- `plugin`: a server bundled with an installed Claude Code plugin
  (`source_kind` `claude_code_plugin_mcp`, `scope` `plugin`,
  `routable: false`). Reported only.
- `added_after_setup`: a server first seen after this Gateway process started,
  or one in a configure-ide-routed file whose ownership record shows it was not
  there, or was moved into the Gateway, when the file was routed. The second
  rule recognises a server added while the client was closed.

The watch also reports servers discovery does not read: other Claude Code
projects in `~/.claude.json`, plugin servers, and servers routed while the
client still runs them. A change is reported within seconds through an
out-of-band sync.

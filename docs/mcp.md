# MCP Stdio Preview

Blindfold currently supports transformation of newline-delimited MCP JSON-RPC messages
for stdio integrations.

Agent-bound messages are recursively sanitized, including tool descriptions, result
content, and errors:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"safe"}]}}' |
  blindfold mcp --direction to-agent --server demo
```

The library supports injected resolver policies scoped by server, tool, and JSON pointer.
The CLI intentionally uses a deny-all resolver until vault and project policy wiring is
implemented. Therefore a SafeRef in `to-server` mode fails closed.

Not supported:

- HTTP, SSE, or WebSocket MCP transports
- MCP server process supervision
- automatic capability negotiation
- arbitrary SafeRef restoration
- OS sandboxing

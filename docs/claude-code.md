# Claude Code

Blindfold supports Claude Code only in explicit print mode:

```sh
bf run claude -- --print "summarize this repo"
bf run claude -- -p --model sonnet "summarize this repo"
```

The embedded adapter accepts only Claude Code `2.1.152`. Missing, ambiguous, or
different `claude --version` output rejects the run before the proxy or agent starts.

Bare interactive Claude, resume/continue, remote control, worktrees, plugin URLs, tmux,
and permission-bypass modes fail before Claude starts. Blindfold sets an ephemeral
`ANTHROPIC_BASE_URL`, sanitizes accepted JSON requests/responses, accepts bounded
Anthropic response SSE required by print mode, and captures sanitized process output.

The child receives an allowlisted environment and does not inherit parent API-key
variables. Authentication currently relies on Claude's persistent login or credential
store. Blindfold does not yet broker that credential or mediate Claude's filesystem
reads and direct sockets, so this is a managed model-traffic boundary rather than an OS
sandbox. See [Noninteractive Coding Agents](coding-agents.md) for the complete contract.

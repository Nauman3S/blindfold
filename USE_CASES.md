# Blindfold: Simple Use Cases

This is the short guide. You do not need to learn every Blindfold command.

## What Should I Use?

| I want to... | Command |
| --- | --- |
| Start Codex with Blindfold | `blindfold run codex` |
| Start Claude with Blindfold | `blindfold run claude` |
| Start OpenCode with Blindfold | `blindfold run opencode` |
| Temporarily run an agent without Blindfold | `blindfold run codex --no-proxy` |
| Check a project for secrets | `blindfold scan .` |
| Print a file with secrets hidden | `blindfold redact .env` |
| Check changed code before committing | `blindfold diff-check` |
| Give one secret to a command | `blindfold exec --secret NAME -- command` |

## First-Time Setup

Build Blindfold and put it on your current shell's `PATH`:

```sh
git clone https://github.com/Nauman3S/blindfold.git
cd blindfold
cargo build --release
export PATH="$PWD/target/release:$PATH"
```

Create the project configuration and check your setup:

```sh
blindfold init
blindfold doctor
```

`init` creates a preview configuration in the current working directory. `doctor`
validates it, but most runtime commands currently use CLI defaults and flags. Do not run
`init` again if `.blindfold.yaml` already exists.

## Use Case 1: Run Codex Now

Start an interactive Codex session:

```sh
blindfold run codex
```

Pass normal Codex arguments after `--`:

```sh
blindfold run codex -- review
blindfold run codex -- "explain this repository"
blindfold run codex -- --sandbox workspace-write
```

Blindfold starts a temporary local proxy, launches Codex, and stops the proxy when
Codex exits. It does not permanently edit Codex configuration.

## Use Case 2: Run Claude or OpenCode

```sh
blindfold run claude
blindfold run opencode
```

Examples with native arguments:

```sh
blindfold run claude -- --model sonnet
blindfold run opencode -- run "find the failing test"
```

## Use Case 3: Keep Using the Normal Agent Names

Instead of typing `blindfold run` every time, activate shell wrappers:

```sh
eval "$(blindfold shell-init zsh)"
```

For Bash:

```sh
eval "$(blindfold shell-init bash)"
```

Now use the usual commands:

```sh
codex
claude
opencode
```

This activation lasts only for the current terminal. To enable it in every new Zsh
terminal:

```sh
printf '%s\n' 'eval "$(blindfold shell-init zsh)"' >> ~/.zshrc
```

Open a new terminal or run `source ~/.zshrc`.

## Use Case 4: Temporarily Opt Out

If you activated the shell wrappers, bypass Blindfold for one command:

```sh
bf-off codex
bf-off claude
bf-off opencode
```

Without shell wrappers, use:

```sh
blindfold run codex --no-proxy
```

To bypass wrappers for several commands in the current terminal:

```sh
export BLINDFOLD_BYPASS=1
codex
```

Turn Blindfold back on:

```sh
unset BLINDFOLD_BYPASS
```

Blindfold prints a bypass notice when it launches an agent without the proxy.

## Use Case 5: Check a Project Before Sharing It

Scan the current working directory:

```sh
blindfold scan .
```

Scan one file:

```sh
blindfold scan config.json
```

Use JSON output in scripts:

```sh
blindfold scan . --json
```

Exit code `0` means a complete scan with no findings. Exit code `2` means a complete
scan found sensitive content. Exit code `3` means the scan was incomplete because of an
I/O error, oversized file, or traversal budget. Policy skips such as ignored or binary
files are reported but do not by themselves make a scan incomplete.

## Use Case 6: Hide Secrets in a File

Print a redacted version of `.env`:

```sh
blindfold redact .env
```

This prints the safe result to the terminal. It does not modify `.env`.

Write the redacted output to a different file:

```sh
blindfold redact .env --output env.redacted
```

Existing output files are refused by default. Use `--force` only when replacement is
intentional; Blindfold performs forced replacement atomically.

For dotenv files, preserve variable names:

```sh
blindfold redact .env --mode env-ref
```

Example output:

```text
OPENAI_API_KEY=${OPENAI_API_KEY}
DATABASE_URL=${DATABASE_URL}
```

Redact piped text:

```sh
some-command | blindfold redact
```

## Use Case 7: Give a Secret to One Command

Suppose a command needs `DEMO_API_KEY`:

```sh
export DEMO_API_KEY='your-value'
blindfold exec --secret DEMO_API_KEY -- your-command
```

Example:

```sh
blindfold exec --secret DEMO_API_KEY -- \
  sh -c 'test -n "$DEMO_API_KEY" && echo "key is available"'
```

Select multiple secrets by repeating `--secret`:

```sh
blindfold exec \
  --secret OPENAI_API_KEY \
  --secret DATABASE_URL \
  -- your-command
```

Only selected secrets are injected. Blindfold redacts those exact values from captured
stdout and stderr.

Do not place the secret itself in command arguments:

```sh
# Wrong: the raw value becomes a process argument.
your-command --token "$DEMO_API_KEY"
```

Pass secrets through environment variables. Managed child stdin is currently disabled.

## Use Case 8: Check Changes Before Committing

Check current tracked changes:

```sh
blindfold diff-check
```

Check staged changes:

```sh
blindfold diff-check --staged
```

Use this before `git commit` or in CI. Exit code `2` means a possible secret was found
in an added line.

## Use Case 9: Store a Temporary Secret Reference

The vault is an advanced preview. For local evaluation:

```sh
export BLINDFOLD_MASTER_KEY="$(openssl rand -hex 32)"
export DEMO_API_KEY='your-value'
blindfold vault put-env DEMO_API_KEY --ttl-seconds 3600
```

List safe references:

```sh
blindfold vault list
```

Clear the current vault scope:

```sh
blindfold vault clear --yes
```

The OS keychain integration is not implemented. Do not store
`BLINDFOLD_MASTER_KEY` in a project file.

## Everyday Workflow

For most development sessions, this is enough:

```sh
# Start your agent
blindfold run codex

# Before committing
blindfold diff-check
blindfold scan .
```

Or activate the shell wrapper once and continue using `codex` normally:

```sh
eval "$(blindfold shell-init zsh)"
codex
```

## What Blindfold Does Not Do Yet

The coding-agent wrappers sanitize supported provider request and response traffic.
They do not currently:

- sanitize the interactive terminal display;
- prevent an agent from directly reading project files;
- prevent direct network access outside the managed proxy;
- isolate provider credentials from the agent process; or
- provide an operating-system sandbox.

`--strict` refuses to start while those controls are unavailable. Blindfold should be
treated as a managed traffic boundary, not complete agent isolation.

## Getting Help

```sh
blindfold --help
blindfold run --help
blindfold redact --help
blindfold exec --help
```

For full details, see [README.md](README.md). For wrapper internals and custom gateways,
see [docs/coding-agents.md](docs/coding-agents.md).

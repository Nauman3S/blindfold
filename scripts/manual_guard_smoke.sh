#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BLINDFOLD_BIN:-$ROOT/target/debug/blindfold}"
RAW="sk-proj-abcdefghijklmnopqrstuvwxyz012345"

if [[ ! -x "$BIN" ]]; then
  cargo build -p blindfold-cli
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/blindfold-guard-smoke.XXXXXX")"
cleanup() {
  if [[ "${BLINDFOLD_KEEP_SMOKE:-0}" == "1" ]]; then
    echo "Keeping smoke directory: $tmp" >&2
  else
    rm -rf "$tmp"
  fi
}
trap cleanup EXIT

cat >"$tmp/provider.rb" <<'RUBY'
require "socket"

mode, url_file, request_file = ARGV
raw = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"
server = TCPServer.new("127.0.0.1", 0)
File.write(url_file, "http://127.0.0.1:#{server.addr[1]}")
client = server.accept
buffer = +""
until buffer.include?("\r\n\r\n")
  chunk = client.readpartial(512)
  buffer << chunk
end
header, rest = buffer.split("\r\n\r\n", 2)
length = header.lines.find { |line| line.downcase.start_with?("content-length:") }
length = length ? length.split(":", 2)[1].to_i : 0
body = rest || +""
while body.bytesize < length
  body << client.readpartial(512)
end
File.write(request_file, "#{header}\r\n\r\n#{body.byteslice(0, length)}")
response = case mode
when "anthropic"
  %Q({"content":[{"type":"text","text":"echo #{raw}"}]})
when "responses"
  %Q({"output_text":"echo #{raw}"})
when "chat"
  %Q({"choices":[{"message":{"content":"echo #{raw}"}}]})
else
  raise "unknown provider mode: #{mode}"
end
client.write("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: #{response.bytesize}\r\nconnection: close\r\n\r\n#{response}")
client.close
server.close
RUBY

make_agent() {
  local case_dir="$1"
  local mode="$2"
  cat >"$case_dir/agent" <<RUBY
#!/usr/bin/env ruby
require "json"
require "net/http"
require "uri"

mode = "$mode"
raw = "$RAW"
case mode
when "claude"
  uri = URI(ENV.fetch("ANTHROPIC_BASE_URL") + "/v1/messages")
  body = {"messages" => [{"role" => "user", "content" => [{"type" => "text", "text" => "send #{raw}"}]}]}
when "codex"
  config = ARGV.join(" ")
  raise "missing codex openai_base_url: #{ARGV.inspect}" unless config =~ /openai_base_url="?([^"\\s]+)"?/
  uri = URI(\$1 + "/responses")
  body = {"input" => "send #{raw}"}
when "opencode"
  config = JSON.parse(ENV.fetch("OPENCODE_CONFIG_CONTENT"))
  provider = ARGV.include?("anthropic") ? "anthropic" : ARGV.include?("openrouter") ? "openrouter" : "openai"
  base = config.fetch("provider").fetch(provider).fetch("options").fetch("baseURL")
  uri = URI(base + (provider == "anthropic" ? "/messages" : "/chat/completions"))
  body = provider == "anthropic" ? {"messages" => [{"role" => "user", "content" => [{"type" => "text", "text" => "send #{raw}"}]}]} : {"messages" => [{"role" => "user", "content" => "send #{raw}"}]}
else
  raise "unknown fake mode: #{mode}"
end
request = Net::HTTP::Post.new(uri)
request["content-type"] = "application/json"
request.body = JSON.generate(body)
response = Net::HTTP.start(uri.host, uri.port, nil, nil) { |http| http.request(request) }
File.write("agent-response", response.body)
puts response.body
RUBY
  chmod +x "$case_dir/agent"
}

wait_for_url() {
  local file="$1"
  for _ in {1..100}; do
    [[ -s "$file" ]] && return 0
    sleep 0.05
  done
  echo "provider did not start" >&2
  return 1
}

assert_not_contains() {
  local file="$1"
  local needle="$2"
  local label="$3"
  if grep -Fq "$needle" "$file"; then
    echo "FAIL: $label leaked $needle" >&2
    sed -n '1,120p' "$file" >&2
    exit 1
  fi
}

assert_contains() {
  local file="$1"
  local needle="$2"
  local label="$3"
  if ! grep -Fq "$needle" "$file"; then
    echo "FAIL: $label missing $needle" >&2
    sed -n '1,120p' "$file" >&2
    exit 1
  fi
}

run_case() {
  local name="$1"
  local agent="$2"
  local agent_mode="$3"
  local provider_mode="$4"
  local upstream_flag="$5"
  local route="$6"
  shift 6
  local case_dir="$tmp/$name"
  mkdir -p "$case_dir"
  make_agent "$case_dir" "$agent_mode"
  ruby "$tmp/provider.rb" "$provider_mode" "$case_dir/upstream-url" "$case_dir/provider-request" &
  local provider_pid=$!
  wait_for_url "$case_dir/upstream-url"
  local upstream
  upstream="$(cat "$case_dir/upstream-url")"
  set +e
  (
    cd "$case_dir"
    "$BIN" run --guard --trace "$agent" "$upstream_flag" "$upstream" --agent-command "$case_dir/agent" -- "$@"
  ) >"$case_dir/stdout" 2>"$case_dir/stderr"
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    kill "$provider_pid" >/dev/null 2>&1 || true
  fi
  wait "$provider_pid"
  local provider_status=$?
  set -e
  if [[ "$status" -ne 0 || "$provider_status" -ne 0 ]]; then
    echo "FAIL: $name command/provider failed status=$status provider_status=$provider_status" >&2
    echo "--- stdout ---" >&2
    sed -n '1,160p' "$case_dir/stdout" >&2 || true
    echo "--- stderr ---" >&2
    sed -n '1,160p' "$case_dir/stderr" >&2 || true
    echo "--- provider request ---" >&2
    sed -n '1,160p' "$case_dir/provider-request" >&2 || true
    exit 1
  fi

  assert_contains "$case_dir/provider-request" "$route" "$name provider route"
  assert_not_contains "$case_dir/provider-request" "$RAW" "$name provider request"
  assert_contains "$case_dir/provider-request" "[REDACTED:openai_api_key]" "$name provider request"
  assert_not_contains "$case_dir/agent-response" "$RAW" "$name agent response"
  assert_not_contains "$case_dir/stdout" "$RAW" "$name stdout"
  assert_not_contains "$case_dir/stderr" "$RAW" "$name stderr"
  assert_not_contains "$case_dir/.blindfold/trace.jsonl" "$RAW" "$name trace"
  echo "PASS $name"
}

fail_closed_case() {
  local name="$1"
  local agent="$2"
  shift 2
  local case_dir="$tmp/$name"
  mkdir -p "$case_dir"
  cat >"$case_dir/agent" <<'SH'
#!/bin/sh
printf launched > agent-launched
SH
  chmod +x "$case_dir/agent"
  set +e
  (
    cd "$case_dir"
    "$BIN" run --guard "$agent" --agent-command "$case_dir/agent" -- "$@"
  ) >"$case_dir/stdout" 2>"$case_dir/stderr"
  local status=$?
  set -e
  if [[ "$status" -eq 0 || -e "$case_dir/agent-launched" ]]; then
    echo "FAIL: $name did not fail closed" >&2
    exit 1
  fi
  echo "PASS $name"
}

echo "Manual guard smoke using $BIN"
for cmd in claude codex opencode; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "FOUND $cmd: $(command -v "$cmd")"
  else
    echo "MISSING $cmd"
  fi
done

run_case claude-anthropic claude claude anthropic --anthropic-upstream "/v1/messages"
run_case codex-exec-openai codex codex responses --openai-upstream "/v1/responses" exec hello
run_case codex-review-openai codex codex responses --openai-upstream "/v1/responses" review
run_case opencode-openai opencode opencode chat --openai-upstream "/v1/chat/completions" run openai
run_case opencode-anthropic opencode opencode anthropic --anthropic-upstream "/v1/messages" run anthropic
run_case opencode-openrouter opencode opencode chat --openrouter-upstream "/v1/chat/completions" run openrouter
fail_closed_case codex-interactive codex
fail_closed_case opencode-tui opencode

echo "Manual guard smoke passed"

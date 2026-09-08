# ChatGPT / Automation Ops Gateway

This fork adds a small, authenticated operations API on top of CloudSSH's existing SSH stack. It is intended for trusted automation clients (for example a ChatGPT integration) that need to inspect, deploy, and validate servers already saved in CloudSSH.

## Security model

The gateway does **not** accept raw SSH credentials from the caller.

Instead it:

1. authenticates the API caller with `Authorization: Bearer <OPS_API_TOKEN>`;
2. locks access to the single GitHub account configured by `OPS_GITHUB_ID`;
3. looks up servers already owned by that CloudSSH account;
4. reuses CloudSSH's encrypted credential store and one-time connection-token path;
5. requires a previously trusted host fingerprint for the target and every configured jump host;
6. opens an internal CloudSSH SSH session and executes through the existing bounded exec channel;
7. returns only `stdout`, `stderr`, and `exit_code` to the API caller.

Anonymous SSH input cannot enable ops mode: `opsMode` is stripped from untrusted client-supplied connection configs and is only injected by the Worker gateway after authorization.

CloudSSH's existing command safety rules remain active. Catastrophic commands that are permanently blocked remain blocked. Commands classified as requiring confirmation return HTTP `409` with `confirmation_required: true`; the caller must only retry with `approve_risk: true` after explicit human approval.

## Required configuration

### 1. Log in to CloudSSH once

GitHub OAuth login must have created your CloudSSH user record before the ops gateway can resolve the configured GitHub ID.

### 2. Save and verify servers

Add the target servers in the normal CloudSSH UI. Open each target at least once and verify its host key fingerprint. If a server uses SSH jump hosts, verify every hop as well.

Headless ops execution intentionally refuses first-seen host keys. This prevents an automation client from silently accepting a changed or unknown SSH identity.

### 3. Configure Worker variables/secrets

Configure:

- `OPS_GITHUB_ID`: your **numeric GitHub user ID**. This limits the gateway to one CloudSSH account.
- `OPS_API_TOKEN`: a long random bearer token. Treat this as a secret and never commit it to Git.

Recommended token generation:

```bash
openssl rand -hex 32
```

For Wrangler deployments, store the token as a Worker secret:

```bash
wrangler secret put OPS_API_TOKEN
```

Set `OPS_GITHUB_ID` as a Worker environment variable (or secret if you prefer). Do not put the bearer token in `wrangler.toml` or source control.

## API

All routes require:

```http
Authorization: Bearer <OPS_API_TOKEN>
```

### Health

```http
GET /api/ops/health
```

Example response:

```json
{
  "status": "ok",
  "operator": "your-github-login"
}
```

### List saved servers

```http
GET /api/ops/servers
```

Returns the same non-secret server metadata available to the authenticated CloudSSH server list. Credentials are not returned.

### Execute a command

```http
POST /api/ops/exec
Content-Type: application/json

{
  "server_id": 1,
  "command": "uname -a && systemctl --no-pager status nginx",
  "timeout_ms": 30000
}
```

Normal response:

```json
{
  "stdout": "...",
  "stderr": "",
  "exit_code": 0
}
```

`timeout_ms` defaults to 30 seconds and is clamped to 1–180 seconds.

For a command that requires explicit approval, the first request returns:

```json
{
  "error": "...",
  "confirmation_required": true
}
```

with HTTP `409`. After the human explicitly approves that exact operation, retry the same command with:

```json
{
  "server_id": 1,
  "command": "...",
  "timeout_ms": 30000,
  "approve_risk": true
}
```

Permanently blocked commands still return HTTP `403` even when `approve_risk` is true.

## Operational characteristics

The first version intentionally creates a short-lived SSH session for each `/api/ops/exec` request. This keeps authorization and cleanup simple and avoids exposing long-lived session handles over the public API. A future version can add controlled session pooling if repeated-command latency becomes important.

The existing exec channel keeps CloudSSH's output and resource limits, including bounded command output capture and SSH channel cleanup.

## Intended ChatGPT integration

The REST gateway is the server-side foundation. Deploying it does **not by itself** give an arbitrary ChatGPT conversation access to the server. A ChatGPT plugin/integration must be connected to these endpoints and configured with the bearer credential. Keep the bearer token in the integration's secret/credential store rather than pasting it into normal chat messages.

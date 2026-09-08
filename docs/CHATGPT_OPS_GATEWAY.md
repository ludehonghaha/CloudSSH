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
6. runs the shared CloudSSH command-safety policy before opening SSH;
7. opens an internal CloudSSH SSH session only for commands that are allowed to proceed;
8. executes through the existing bounded exec channel and returns only command results.

Anonymous SSH input cannot enable ops mode: `opsMode` is stripped from untrusted client-supplied connection configs and is only injected by the Worker gateway after authorization.

CloudSSH's existing command safety rules remain active. Catastrophic commands that are permanently blocked remain blocked. Commands classified as requiring confirmation return HTTP `409` with `confirmation_required: true`; the caller must only retry with `approve_risk: true` after explicit human approval. The SSH session repeats the same safety check as defense in depth.

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

### List saved servers

```http
GET /api/ops/servers
```

Returns non-secret server metadata only. Credentials are never returned.

### Preflight a command

```http
POST /api/ops/check
Content-Type: application/json

{
  "command": "systemctl restart nginx"
}
```

This endpoint applies the exact CloudSSH command-safety policy **without opening an SSH session**.

Safe command:

```json
{
  "blocked": false,
  "confirmation_required": false
}
```

Command requiring explicit approval:

```json
{
  "blocked": false,
  "confirmation_required": true,
  "reason": "..."
}
```

Permanently blocked command:

```json
{
  "blocked": true,
  "confirmation_required": false,
  "reason": "..."
}
```

### Execute one command

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

`timeout_ms` defaults to 30 seconds and is clamped to 1–180 seconds. Safety classification happens before creating SSH. Permanently blocked commands return HTTP `403`; confirmation-required commands return HTTP `409` unless that exact request carries `approve_risk: true` after explicit human approval.

### Execute a deployment / validation plan

```http
POST /api/ops/run
Content-Type: application/json

{
  "server_id": 1,
  "stop_on_error": true,
  "steps": [
    {
      "name": "environment",
      "command": "uname -a && id && df -h"
    },
    {
      "name": "service-health",
      "command": "systemctl is-active nginx",
      "timeout_ms": 10000
    },
    {
      "name": "listen-ports",
      "command": "ss -lntup"
    }
  ]
}
```

This is the preferred API for deployment and acceptance workflows. The plan is bounded to 20 steps, 128 KiB of combined command text, and 300 seconds of combined requested timeout budget.

Before the first SSH connection is opened, **every step is preflighted**. If any step is permanently blocked, the entire plan returns `403` and nothing runs. If any step requires confirmation and that step does not carry `approve_risk: true`, the entire plan returns `409` and nothing runs. Approval is scoped to the individual step; there is no plan-wide bypass.

By default `stop_on_error` is true. A non-zero exit code stops later steps and the response identifies `failed_step`. Set `stop_on_error: false` only when later diagnostic steps are still useful after a failure.

Example result:

```json
{
  "completed": true,
  "stop_on_error": true,
  "stopped_on_error": false,
  "failed_step": null,
  "results": [
    {
      "index": 0,
      "name": "environment",
      "command": "uname -a && id && df -h",
      "stdout": "...",
      "stderr": "",
      "exit_code": 0
    }
  ]
}
```

If an SSH transport error or timeout occurs partway through a plan, the gateway returns the corresponding error status together with all completed step results so the caller can see exactly where execution stopped.

## Operational characteristics

`/api/ops/exec` creates one short-lived SSH session for one command. `/api/ops/run` currently also keeps steps isolated: each step gets a fresh short-lived SSH session while reusing the already resolved saved-server configuration. This costs a little more connection latency, but it prevents shell state leakage and ensures one broken SSH session cannot poison later steps.

Because shell state is intentionally not shared between plan steps, deployment steps should be self-contained. For example, use `cd /opt/app && git pull && npm ci` in one step rather than relying on a previous `cd`.

The existing exec channel keeps CloudSSH's output and resource limits, including bounded command output capture and SSH channel cleanup.

## Intended ChatGPT integration

The REST gateway is the server-side foundation. Deploying it does **not by itself** give an arbitrary ChatGPT conversation access to the server. A ChatGPT plugin/integration must be connected to these endpoints and configured with the bearer credential. Keep the bearer token in the integration's secret/credential store rather than pasting it into normal chat messages.
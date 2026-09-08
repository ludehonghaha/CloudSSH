import { ALLOWED_LOCATION_HINTS, type Env, type SSHConnectionConfig, type UserInfo } from '../types';

const MAX_COMMAND_CHARS = 32_768;
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 180_000;
const HANDSHAKE_GRACE_MS = 25_000;

type OpsExecRequest = {
  serverId: number;
  command: string;
  timeoutMs: number;
  approveRisk: boolean;
};

type OpsExecFrame = {
  type: 'ops_exec_result';
  request_id: string;
  stdout?: string;
  stderr?: string;
  exit_code?: number;
  blocked?: boolean;
  confirmation_required?: boolean;
  reason?: string;
};

function getUserDBStub(env: Env, githubId: string): DurableObjectStub {
  return env.USER_DB.get(env.USER_DB.idFromName(githubId));
}

function validateLocationHint(value: string | undefined): string | undefined {
  if (!value) return undefined;
  return (ALLOWED_LOCATION_HINTS as readonly string[]).includes(value) ? value : undefined;
}

function jsonError(error: string, status: number, extra?: Record<string, unknown>): Response {
  return Response.json({ error, ...(extra || {}) }, { status });
}

async function digestToken(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
}

async function secureTokenEqual(left: string, right: string): Promise<boolean> {
  if (!left || !right || left.length > 4096 || right.length > 4096) return false;
  const [a, b] = await Promise.all([digestToken(left), digestToken(right)]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function authorizeOpsRequest(request: Request, env: Env): Promise<{ githubId: string } | Response> {
  const expected = env.OPS_API_TOKEN?.trim();
  const githubId = env.OPS_GITHUB_ID?.trim();
  if (!expected || !githubId) {
    return jsonError('Ops gateway is not configured', 503);
  }
  if (!/^\d+$/.test(githubId)) {
    return jsonError('OPS_GITHUB_ID is invalid', 500);
  }

  const auth = request.headers.get('Authorization') || '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match || !(await secureTokenEqual(match[1].trim(), expected))) {
    return jsonError('Unauthorized', 401);
  }
  return { githubId };
}

async function getOperatorUser(env: Env, githubId: string): Promise<UserInfo | Response> {
  const stub = getUserDBStub(env, githubId);
  const response = await stub.fetch(
    new Request(`http://internal/internal/operator-context?github_id=${encodeURIComponent(githubId)}`)
  );
  if (!response.ok) {
    if (response.status === 404) {
      return jsonError('Operator account has not logged in to CloudSSH yet', 409);
    }
    return jsonError('Failed to resolve operator account', 502);
  }
  return response.json<UserInfo>();
}

export function parseOpsExecBody(input: unknown):
  | { ok: true; value: OpsExecRequest }
  | { ok: false; error: string } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: 'Invalid JSON body' };
  }
  const body = input as Record<string, unknown>;
  const rawServerId = body.server_id;
  const rawCommand = body.command;
  const rawTimeout = body.timeout_ms;

  if (!Number.isInteger(rawServerId) || Number(rawServerId) <= 0) {
    return { ok: false, error: 'server_id must be a positive integer' };
  }
  if (typeof rawCommand !== 'string' || rawCommand.trim().length === 0) {
    return { ok: false, error: 'command is required' };
  }
  if (rawCommand.length > MAX_COMMAND_CHARS) {
    return { ok: false, error: `command exceeds ${MAX_COMMAND_CHARS} characters` };
  }

  let timeoutMs = 30_000;
  if (rawTimeout !== undefined) {
    if (typeof rawTimeout !== 'number' || !Number.isFinite(rawTimeout)) {
      return { ok: false, error: 'timeout_ms must be a number' };
    }
    timeoutMs = Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, Math.floor(rawTimeout)));
  }

  return {
    ok: true,
    value: {
      serverId: Number(rawServerId),
      command: rawCommand,
      timeoutMs,
      approveRisk: body.approve_risk === true,
    },
  };
}

async function getSavedConnectionConfig(
  env: Env,
  githubId: string,
  userId: number,
  serverId: number
): Promise<SSHConnectionConfig | Response> {
  const stub = getUserDBStub(env, githubId);
  const tokenResponse = await stub.fetch(
    new Request(`http://internal/internal/servers/${serverId}/connect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: userId }),
    })
  );
  if (!tokenResponse.ok) return tokenResponse;

  const { token } = await tokenResponse.json<{ token: string }>();
  const configResponse = await stub.fetch(
    new Request('http://internal/internal/connect-token/consume', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    })
  );
  if (!configResponse.ok) return configResponse;

  const config = await configResponse.json<SSHConnectionConfig>();
  if (!config.expectedFingerprint || (config.jumpHosts || []).some((hop) => !hop.expectedFingerprint)) {
    return jsonError(
      'Host key is not trusted yet. Open this server once in CloudSSH and verify every host fingerprint before using the ops gateway.',
      409
    );
  }
  config.opsMode = true;
  return config;
}

async function executeOverInternalWebSocket(
  env: Env,
  config: SSHConnectionConfig,
  command: string,
  timeoutMs: number,
  approveRisk: boolean,
  colo: string
): Promise<Response> {
  const sessionName = `ops:${Date.now()}:${crypto.randomUUID()}`;
  const doId = env.SSH_SESSION.idFromName(sessionName);
  const hint = validateLocationHint(config.locationHint);
  const stub = hint
    ? env.SSH_SESSION.get(doId, { locationHint: hint } as any)
    : env.SSH_SESSION.get(doId);

  const internalUrl = new URL('https://ops.internal/api/ssh');
  internalUrl.searchParams.set('session', sessionName);
  const headers = new Headers({ Upgrade: 'websocket' });
  headers.set('x-cloudflare-colo', colo || 'UNKNOWN');
  headers.set('x-ssh-config', encodeURIComponent(JSON.stringify(config)));

  const upgrade = await stub.fetch(new Request(internalUrl.toString(), { headers }));
  const ws = (upgrade as any).webSocket as WebSocket | undefined;
  if (upgrade.status !== 101 || !ws) {
    return jsonError('Failed to create internal SSH session', 502);
  }

  ws.accept();
  const requestId = crypto.randomUUID();

  return new Promise<Response>((resolve) => {
    let settled = false;
    let commandSent = false;
    let lastError = 'SSH session closed before command completed';

    const finish = (response: Response) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        ws.close(1000, 'ops request complete');
      } catch {
        /* already closed */
      }
      resolve(response);
    };

    const timer = setTimeout(() => {
      finish(jsonError('Ops command timed out', 504));
    }, timeoutMs + HANDSHAKE_GRACE_MS);

    ws.addEventListener('message', (event: MessageEvent) => {
      if (typeof event.data !== 'string') return;
      let message: Record<string, unknown>;
      try {
        message = JSON.parse(event.data) as Record<string, unknown>;
      } catch {
        return;
      }

      if (message.type === 'error' && typeof message.message === 'string') {
        lastError = message.message;
        return;
      }

      if (message.type === 'ops_ready' && !commandSent) {
        commandSent = true;
        ws.send(
          JSON.stringify({
            type: 'ops_exec',
            request_id: requestId,
            command,
            timeout_ms: timeoutMs,
            approve_risk: approveRisk,
          })
        );
        return;
      }

      if (message.type !== 'ops_exec_result' || message.request_id !== requestId) return;
      const frame = message as OpsExecFrame;
      if (frame.blocked) {
        finish(jsonError(frame.reason || 'Command blocked by safety policy', 403, { blocked: true }));
        return;
      }
      if (frame.confirmation_required) {
        finish(
          jsonError(frame.reason || 'Command requires explicit approval', 409, {
            confirmation_required: true,
          })
        );
        return;
      }
      finish(
        Response.json({
          stdout: frame.stdout || '',
          stderr: frame.stderr || '',
          exit_code: typeof frame.exit_code === 'number' ? frame.exit_code : -1,
        })
      );
    });

    ws.addEventListener('close', () => {
      if (!settled) finish(jsonError(lastError, 502));
    });

    ws.addEventListener('error', () => {
      if (!settled) finish(jsonError(lastError || 'SSH WebSocket error', 502));
    });
  });
}

export async function handleOpsGateway(request: Request, url: URL, env: Env): Promise<Response> {
  const auth = await authorizeOpsRequest(request, env);
  if (auth instanceof Response) return auth;

  const user = await getOperatorUser(env, auth.githubId);
  if (user instanceof Response) return user;
  const stub = getUserDBStub(env, auth.githubId);

  if (url.pathname === '/api/ops/health' && request.method === 'GET') {
    return Response.json({ status: 'ok', operator: user.username });
  }

  if (url.pathname === '/api/ops/servers' && request.method === 'GET') {
    return stub.fetch(
      new Request(`http://internal/internal/servers?user_id=${user.id}`, { method: 'GET' })
    );
  }

  if (url.pathname === '/api/ops/exec' && request.method === 'POST') {
    let rawBody: unknown;
    try {
      rawBody = await request.json();
    } catch {
      return jsonError('Invalid JSON body', 400);
    }
    const parsed = parseOpsExecBody(rawBody);
    if (!parsed.ok) return jsonError(parsed.error, 400);

    const config = await getSavedConnectionConfig(
      env,
      auth.githubId,
      user.id,
      parsed.value.serverId
    );
    if (config instanceof Response) return config;

    return executeOverInternalWebSocket(
      env,
      config,
      parsed.value.command,
      parsed.value.timeoutMs,
      parsed.value.approveRisk,
      (request as any).cf?.colo || 'UNKNOWN'
    );
  }

  return jsonError('Not Found', 404);
}

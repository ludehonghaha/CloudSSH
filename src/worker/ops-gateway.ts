import { ALLOWED_LOCATION_HINTS, type Env, type SSHConnectionConfig, type UserInfo } from '../types';
import { isBlockedCommand, needsConfirmation } from './agent/safety';

const MAX_COMMAND_CHARS = 32_768;
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 180_000;
const HANDSHAKE_GRACE_MS = 25_000;
const MAX_RUN_STEPS = 20;
const MAX_RUN_TOTAL_COMMAND_CHARS = 131_072;
const MAX_RUN_TOTAL_TIMEOUT_MS = 300_000;
const MAX_STEP_NAME_CHARS = 80;

type OpsExecRequest = {
  serverId: number;
  command: string;
  timeoutMs: number;
  approveRisk: boolean;
};

type OpsRunStep = {
  name?: string;
  command: string;
  timeoutMs: number;
  approveRisk: boolean;
};

type OpsRunRequest = {
  serverId: number;
  steps: OpsRunStep[];
  stopOnError: boolean;
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

type OpsCommandClassification = {
  blocked: boolean;
  confirmation_required: boolean;
  reason?: string;
};

type OpsExecResult = {
  stdout: string;
  stderr: string;
  exit_code: number;
};

type OpsRunResult = OpsExecResult & {
  index: number;
  name?: string;
  command: string;
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

function validateCommand(command: unknown): { ok: true; command: string } | { ok: false; error: string } {
  if (typeof command !== 'string' || command.trim().length === 0) {
    return { ok: false, error: 'command is required' };
  }
  if (command.length > MAX_COMMAND_CHARS) {
    return { ok: false, error: `command exceeds ${MAX_COMMAND_CHARS} characters` };
  }
  return { ok: true, command };
}

function parseTimeout(rawTimeout: unknown): { ok: true; timeoutMs: number } | { ok: false; error: string } {
  if (rawTimeout === undefined) return { ok: true, timeoutMs: 30_000 };
  if (typeof rawTimeout !== 'number' || !Number.isFinite(rawTimeout)) {
    return { ok: false, error: 'timeout_ms must be a number' };
  }
  return {
    ok: true,
    timeoutMs: Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, Math.floor(rawTimeout))),
  };
}

export function classifyOpsCommand(command: unknown):
  | { ok: true; value: OpsCommandClassification }
  | { ok: false; error: string } {
  const validated = validateCommand(command);
  if (!validated.ok) return validated;

  const blocked = isBlockedCommand(validated.command);
  if (blocked.blocked) {
    return {
      ok: true,
      value: {
        blocked: true,
        confirmation_required: false,
        reason: blocked.reason || 'Command blocked by safety policy',
      },
    };
  }

  const confirmation = needsConfirmation(validated.command);
  if (confirmation.required) {
    return {
      ok: true,
      value: {
        blocked: false,
        confirmation_required: true,
        reason: confirmation.reason || 'Command requires explicit approval',
      },
    };
  }

  return {
    ok: true,
    value: {
      blocked: false,
      confirmation_required: false,
    },
  };
}

export function parseOpsExecBody(input: unknown):
  | { ok: true; value: OpsExecRequest }
  | { ok: false; error: string } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: 'Invalid JSON body' };
  }
  const body = input as Record<string, unknown>;
  const rawServerId = body.server_id;

  if (!Number.isInteger(rawServerId) || Number(rawServerId) <= 0) {
    return { ok: false, error: 'server_id must be a positive integer' };
  }
  const validatedCommand = validateCommand(body.command);
  if (!validatedCommand.ok) return validatedCommand;
  const timeout = parseTimeout(body.timeout_ms);
  if (!timeout.ok) return timeout;

  return {
    ok: true,
    value: {
      serverId: Number(rawServerId),
      command: validatedCommand.command,
      timeoutMs: timeout.timeoutMs,
      approveRisk: body.approve_risk === true,
    },
  };
}

export function parseOpsRunBody(input: unknown):
  | { ok: true; value: OpsRunRequest }
  | { ok: false; error: string } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: 'Invalid JSON body' };
  }
  const body = input as Record<string, unknown>;
  const rawServerId = body.server_id;
  const rawSteps = body.steps;

  if (!Number.isInteger(rawServerId) || Number(rawServerId) <= 0) {
    return { ok: false, error: 'server_id must be a positive integer' };
  }
  if (!Array.isArray(rawSteps) || rawSteps.length === 0) {
    return { ok: false, error: 'steps must be a non-empty array' };
  }
  if (rawSteps.length > MAX_RUN_STEPS) {
    return { ok: false, error: `steps exceeds ${MAX_RUN_STEPS} items` };
  }

  const steps: OpsRunStep[] = [];
  let totalCommandChars = 0;
  let totalTimeoutMs = 0;

  for (let index = 0; index < rawSteps.length; index++) {
    const rawStep = rawSteps[index];
    if (!rawStep || typeof rawStep !== 'object' || Array.isArray(rawStep)) {
      return { ok: false, error: `steps[${index}] must be an object` };
    }
    const step = rawStep as Record<string, unknown>;
    const validatedCommand = validateCommand(step.command);
    if (!validatedCommand.ok) {
      return { ok: false, error: `steps[${index}]: ${validatedCommand.error}` };
    }
    const timeout = parseTimeout(step.timeout_ms);
    if (!timeout.ok) {
      return { ok: false, error: `steps[${index}]: ${timeout.error}` };
    }
    let name: string | undefined;
    if (step.name !== undefined) {
      if (typeof step.name !== 'string' || step.name.trim().length === 0) {
        return { ok: false, error: `steps[${index}].name must be a non-empty string` };
      }
      if (step.name.length > MAX_STEP_NAME_CHARS) {
        return { ok: false, error: `steps[${index}].name exceeds ${MAX_STEP_NAME_CHARS} characters` };
      }
      name = step.name;
    }

    totalCommandChars += validatedCommand.command.length;
    totalTimeoutMs += timeout.timeoutMs;
    if (totalCommandChars > MAX_RUN_TOTAL_COMMAND_CHARS) {
      return {
        ok: false,
        error: `combined step commands exceed ${MAX_RUN_TOTAL_COMMAND_CHARS} characters`,
      };
    }
    if (totalTimeoutMs > MAX_RUN_TOTAL_TIMEOUT_MS) {
      return {
        ok: false,
        error: `combined step timeouts exceed ${MAX_RUN_TOTAL_TIMEOUT_MS} ms`,
      };
    }

    steps.push({
      name,
      command: validatedCommand.command,
      timeoutMs: timeout.timeoutMs,
      approveRisk: step.approve_risk === true,
    });
  }

  return {
    ok: true,
    value: {
      serverId: Number(rawServerId),
      steps,
      stopOnError: body.stop_on_error !== false,
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

async function parseExecResponse(response: Response): Promise<OpsExecResult | null> {
  if (!response.ok) return null;
  try {
    const body = await response.clone().json<Record<string, unknown>>();
    return {
      stdout: typeof body.stdout === 'string' ? body.stdout : '',
      stderr: typeof body.stderr === 'string' ? body.stderr : '',
      exit_code: typeof body.exit_code === 'number' ? body.exit_code : -1,
    };
  } catch {
    return null;
  }
}

function preflightRunSteps(steps: OpsRunStep[]): Response | null {
  for (let index = 0; index < steps.length; index++) {
    const step = steps[index];
    const classification = classifyOpsCommand(step.command);
    if (!classification.ok) {
      return jsonError(classification.error, 400, { step_index: index, step_name: step.name });
    }
    if (classification.value.blocked) {
      return jsonError(classification.value.reason || 'Command blocked by safety policy', 403, {
        blocked: true,
        step_index: index,
        step_name: step.name,
      });
    }
    if (classification.value.confirmation_required && !step.approveRisk) {
      return jsonError(classification.value.reason || 'Command requires explicit approval', 409, {
        confirmation_required: true,
        step_index: index,
        step_name: step.name,
      });
    }
  }
  return null;
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

  if (url.pathname === '/api/ops/check' && request.method === 'POST') {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return jsonError('Invalid JSON body', 400);
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return jsonError('Invalid JSON body', 400);
    }
    const classification = classifyOpsCommand((body as Record<string, unknown>).command);
    if (!classification.ok) return jsonError(classification.error, 400);
    return Response.json(classification.value);
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

    const classification = classifyOpsCommand(parsed.value.command);
    if (!classification.ok) return jsonError(classification.error, 400);
    if (classification.value.blocked) {
      return jsonError(classification.value.reason || 'Command blocked by safety policy', 403, {
        blocked: true,
      });
    }
    if (classification.value.confirmation_required && !parsed.value.approveRisk) {
      return jsonError(classification.value.reason || 'Command requires explicit approval', 409, {
        confirmation_required: true,
      });
    }

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

  if (url.pathname === '/api/ops/run' && request.method === 'POST') {
    let rawBody: unknown;
    try {
      rawBody = await request.json();
    } catch {
      return jsonError('Invalid JSON body', 400);
    }
    const parsed = parseOpsRunBody(rawBody);
    if (!parsed.ok) return jsonError(parsed.error, 400);

    const preflight = preflightRunSteps(parsed.value.steps);
    if (preflight) return preflight;

    const config = await getSavedConnectionConfig(
      env,
      auth.githubId,
      user.id,
      parsed.value.serverId
    );
    if (config instanceof Response) return config;

    const results: OpsRunResult[] = [];
    const colo = (request as any).cf?.colo || 'UNKNOWN';
    let stoppedOnError = false;
    let failedStep: number | null = null;

    for (let index = 0; index < parsed.value.steps.length; index++) {
      const step = parsed.value.steps[index];
      const response = await executeOverInternalWebSocket(
        env,
        config,
        step.command,
        step.timeoutMs,
        step.approveRisk,
        colo
      );
      const result = await parseExecResponse(response);
      if (!result) {
        let detail: Record<string, unknown> = {};
        try {
          detail = await response.clone().json<Record<string, unknown>>();
        } catch {
          detail = {};
        }
        return Response.json(
          {
            error: typeof detail.error === 'string' ? detail.error : 'Ops step transport failed',
            step_index: index,
            step_name: step.name,
            results,
          },
          { status: response.status }
        );
      }

      results.push({
        index,
        name: step.name,
        command: step.command,
        ...result,
      });

      if (result.exit_code !== 0) {
        failedStep = index;
        if (parsed.value.stopOnError) {
          stoppedOnError = true;
          break;
        }
      }
    }

    return Response.json({
      completed: results.length === parsed.value.steps.length,
      stop_on_error: parsed.value.stopOnError,
      stopped_on_error: stoppedOnError,
      failed_step: failedStep,
      results,
    });
  }

  return jsonError('Not Found', 404);
}
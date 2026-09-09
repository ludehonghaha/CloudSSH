import type { Env } from '../types';
import { handleOpsGateway } from './ops-gateway';
import {
  authenticateMcpRequest,
  mcpBearerChallenge,
  type McpAuthContext,
} from './mcp-oauth';

const SERVER_INFO = { name: 'cloudssh-ops', version: '1.1.0' } as const;
const MODERN_PROTOCOL_VERSION = '2026-07-28';
const LEGACY_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26'] as const;
const SUPPORTED_PROTOCOL_VERSIONS = [
  MODERN_PROTOCOL_VERSION,
  ...LEGACY_PROTOCOL_VERSIONS,
] as const;

const SERVER_INSTRUCTIONS =
  'Manage only servers already saved and trusted in CloudSSH. Read-only tools may be called directly. ' +
  'cloudssh_exec runs through CloudSSH command safety checks. If a command returns confirmation_required, ' +
  'ask the user for explicit approval before retrying with approve_risk=true.';

type JsonRpcId = string | number | null;

type JsonRpcRequest = {
  jsonrpc?: unknown;
  id?: JsonRpcId;
  method?: unknown;
  params?: unknown;
};

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function serverMeta(): JsonRecord {
  return {
    'io.modelcontextprotocol/serverInfo': SERVER_INFO,
  };
}

function isModernRequest(request: Request, body: JsonRpcRequest): boolean {
  if (request.headers.get('MCP-Protocol-Version') === MODERN_PROTOCOL_VERSION) return true;
  const params = isRecord(body.params) ? body.params : undefined;
  const meta = params && isRecord(params._meta) ? params._meta : undefined;
  return meta?.['io.modelcontextprotocol/protocolVersion'] === MODERN_PROTOCOL_VERSION;
}

function withModernResultFields<T extends JsonRecord>(result: T, modern: boolean): T {
  if (!modern) return result;
  return {
    ...result,
    resultType: 'complete',
    _meta: {
      ...(isRecord(result._meta) ? result._meta : {}),
      ...serverMeta(),
    },
  } as T;
}

function rpcResult(id: JsonRpcId, result: JsonRecord, modern = false): Response {
  return Response.json({
    jsonrpc: '2.0',
    id,
    result: withModernResultFields(result, modern),
  });
}

function rpcError(
  id: JsonRpcId,
  code: number,
  message: string,
  status = 200,
  data?: unknown
): Response {
  return Response.json(
    {
      jsonrpc: '2.0',
      id,
      error: {
        code,
        message,
        ...(data === undefined ? {} : { data }),
      },
    },
    { status }
  );
}

async function parseJsonResponse(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { message: text };
  }
}

function opsRequest(request: Request, env: Env, path: string, init: RequestInit): Request {
  const url = new URL(request.url);
  url.pathname = path;
  url.search = '';

  const headers = new Headers();
  const opsToken = env.OPS_API_TOKEN?.trim();
  if (opsToken) headers.set('Authorization', `Bearer ${opsToken}`);
  if (init.body !== undefined && init.body !== null) {
    headers.set('Content-Type', 'application/json');
  }

  return new Request(url.toString(), {
    ...init,
    headers,
  });
}

async function callOps(
  request: Request,
  env: Env,
  path: string,
  method: 'GET' | 'POST',
  body?: unknown
): Promise<{ response: Response; data: unknown }> {
  const internal = opsRequest(request, env, path, {
    method,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const response = await handleOpsGateway(internal, new URL(internal.url), env);
  return { response, data: await parseJsonResponse(response) };
}

async function authorizeMcp(
  request: Request,
  env: Env,
  id: JsonRpcId,
  scope = 'cloudssh:read'
): Promise<McpAuthContext | Response> {
  const auth = await authenticateMcpRequest(request, env);
  if (!auth) {
    const response = rpcError(id, -32001, 'OAuth authorization required', 401);
    response.headers.set('WWW-Authenticate', mcpBearerChallenge(request, env, scope));
    return response;
  }

  const { response, data } = await callOps(request, env, '/api/ops/health', 'GET');
  if (response.ok) return auth;

  const message =
    isRecord(data) && typeof data.error === 'string'
      ? data.error
      : 'CloudSSH Ops Gateway authentication failed';
  return rpcError(id, -32001, message, response.status, data);
}

export function getMcpTools(): JsonRecord[] {
  return [
    {
      name: 'cloudssh_health',
      title: 'CloudSSH Health',
      description: 'Check whether the authenticated CloudSSH operations gateway is ready.',
      inputSchema: {
        type: 'object',
        properties: {},
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    {
      name: 'cloudssh_list_servers',
      title: 'List CloudSSH Servers',
      description:
        'List non-secret metadata for servers saved under the configured CloudSSH operator account.',
      inputSchema: {
        type: 'object',
        properties: {},
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    {
      name: 'cloudssh_exec',
      title: 'Execute CloudSSH Command',
      description:
        'Execute one shell command on a saved and host-key-trusted CloudSSH server. Commands remain subject to CloudSSH safety policy. Set approve_risk=true only after explicit user approval when a prior call returned confirmation_required.',
      inputSchema: {
        type: 'object',
        properties: {
          server_id: {
            type: 'integer',
            minimum: 1,
            description: 'Saved CloudSSH server ID returned by cloudssh_list_servers.',
          },
          command: {
            type: 'string',
            minLength: 1,
            maxLength: 32768,
            description: 'Shell command to run.',
          },
          timeout_ms: {
            type: 'integer',
            minimum: 1000,
            maximum: 180000,
            default: 30000,
          },
          approve_risk: {
            type: 'boolean',
            default: false,
            description:
              'Retry a confirmation-required command only after explicit human approval. This does not bypass permanently blocked commands.',
          },
        },
        required: ['server_id', 'command'],
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
  ];
}

function toolResult(data: unknown, modern: boolean, isError = false): JsonRecord {
  const text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  const structuredContent = isRecord(data) ? data : { result: data };
  return withModernResultFields(
    {
      content: [{ type: 'text', text }],
      structuredContent,
      ...(isError ? { isError: true } : {}),
    },
    modern
  );
}

async function callMcpTool(
  request: Request,
  env: Env,
  id: JsonRpcId,
  params: JsonRecord,
  modern: boolean,
  auth: McpAuthContext
): Promise<Response> {
  const name = typeof params.name === 'string' ? params.name : '';
  const args = isRecord(params.arguments) ? params.arguments : {};

  let requiredScope: 'cloudssh:read' | 'cloudssh:exec';
  let target: { path: string; method: 'GET' | 'POST'; body?: unknown };
  switch (name) {
    case 'cloudssh_health':
      requiredScope = 'cloudssh:read';
      target = { path: '/api/ops/health', method: 'GET' };
      break;
    case 'cloudssh_list_servers':
      requiredScope = 'cloudssh:read';
      target = { path: '/api/ops/servers', method: 'GET' };
      break;
    case 'cloudssh_exec':
      requiredScope = 'cloudssh:exec';
      target = {
        path: '/api/ops/exec',
        method: 'POST',
        body: {
          server_id: args.server_id,
          command: args.command,
          ...(args.timeout_ms === undefined ? {} : { timeout_ms: args.timeout_ms }),
          ...(args.approve_risk === undefined ? {} : { approve_risk: args.approve_risk }),
        },
      };
      break;
    default:
      return rpcError(id, -32602, `Unknown tool: ${name || '(missing)'}`);
  }

  if (!auth.scopes.has(requiredScope)) {
    return rpcError(id, -32003, `Missing required OAuth scope: ${requiredScope}`, 403);
  }

  const { response, data } = await callOps(request, env, target.path, target.method, target.body);

  if (response.status === 401 || response.status === 503) {
    const message =
      isRecord(data) && typeof data.error === 'string'
        ? data.error
        : 'CloudSSH Ops Gateway authentication failed';
    return rpcError(id, -32001, message, response.status, data);
  }

  return Response.json({
    jsonrpc: '2.0',
    id,
    result: toolResult(data, modern, !response.ok),
  });
}

export async function handleMcpGateway(request: Request, env: Env): Promise<Response> {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        Allow: 'POST, OPTIONS',
        'Access-Control-Allow-Headers':
          'Authorization, Content-Type, Accept, MCP-Protocol-Version, Mcp-Method, Mcp-Name',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
      },
    });
  }

  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'POST, OPTIONS' } });
  }

  const contentType = request.headers.get('Content-Type') || '';
  if (!contentType.toLowerCase().includes('application/json')) {
    return rpcError(null, -32600, 'Content-Type must be application/json', 415);
  }

  let body: JsonRpcRequest;
  try {
    const parsed = await request.json<unknown>();
    if (!isRecord(parsed)) return rpcError(null, -32600, 'Invalid JSON-RPC request', 400);
    body = parsed as JsonRpcRequest;
  } catch {
    return rpcError(null, -32700, 'Parse error', 400);
  }

  const id = body.id ?? null;
  if (body.jsonrpc !== '2.0' || typeof body.method !== 'string') {
    return rpcError(id, -32600, 'Invalid JSON-RPC request', 400);
  }

  const method = body.method;
  const modern = isModernRequest(request, body);

  if (method === 'notifications/initialized' || method === 'notifications/cancelled') {
    const auth = await authorizeMcp(request, env, id);
    if (auth instanceof Response) return auth;
    return new Response(null, { status: 202 });
  }

  const requestedScope =
    method === 'tools/call' &&
    isRecord(body.params) &&
    body.params.name === 'cloudssh_exec'
      ? 'cloudssh:exec'
      : 'cloudssh:read';
  const auth = await authorizeMcp(request, env, id, requestedScope);
  if (auth instanceof Response) return auth;

  if (method === 'server/discover') {
    return rpcResult(
      id,
      {
        supportedVersions: [...SUPPORTED_PROTOCOL_VERSIONS],
        capabilities: { tools: {} },
        instructions: SERVER_INSTRUCTIONS,
        ttlMs: 300000,
        cacheScope: 'private',
      },
      true
    );
  }

  if (method === 'initialize') {
    const params = isRecord(body.params) ? body.params : {};
    const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const protocolVersion = (LEGACY_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
      ? requested
      : LEGACY_PROTOCOL_VERSIONS[0];

    return rpcResult(id, {
      protocolVersion,
      capabilities: { tools: {} },
      serverInfo: SERVER_INFO,
      instructions: SERVER_INSTRUCTIONS,
    });
  }

  if (method === 'ping') {
    return rpcResult(id, {}, modern);
  }

  if (method === 'tools/list') {
    return rpcResult(
      id,
      {
        tools: getMcpTools(),
        ...(modern ? { ttlMs: 300000, cacheScope: 'private' } : {}),
      },
      modern
    );
  }

  if (method === 'tools/call') {
    const params = isRecord(body.params) ? body.params : {};
    return callMcpTool(request, env, id, params, modern, auth);
  }

  return rpcError(id, -32601, `Method not found: ${method}`);
}

import type { Env, UserInfo } from '../types';
import { getAuthenticatedUser } from './auth';

const ACCESS_TTL_SECONDS = 60 * 60;
const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
const CODE_TTL_SECONDS = 5 * 60;
const CLIENT_TTL_SECONDS = 365 * 24 * 60 * 60;
const ALLOWED_SCOPES = ['cloudssh:read', 'cloudssh:exec', 'offline_access'] as const;
const DEFAULT_SCOPE = ALLOWED_SCOPES.join(' ');

type TokenKind = 'client' | 'code' | 'access' | 'refresh';
type JsonRecord = Record<string, unknown>;

type SignedPayload = JsonRecord & {
  typ: TokenKind;
  iat: number;
  exp: number;
};

type ClientPayload = SignedPayload & {
  typ: 'client';
  redirectUris: string[];
  clientName?: string;
};

type CodePayload = SignedPayload & {
  typ: 'code';
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  resource: string;
  githubId: string;
};

type AccessPayload = SignedPayload & {
  typ: 'access';
  clientId: string;
  scope: string;
  resource: string;
  githubId: string;
};

type RefreshPayload = SignedPayload & {
  typ: 'refresh';
  clientId: string;
  scope: string;
  resource: string;
  githubId: string;
};

export type McpAuthContext = {
  githubId: string;
  scopes: Set<string>;
  source: 'oauth' | 'ops-token';
};

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function baseUrl(request: Request, env: Env): string {
  if (env.BASE_URL?.trim()) return env.BASE_URL.trim().replace(/\/$/, '');
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
}

function resourceUrl(request: Request, env: Env): string {
  return `${baseUrl(request, env)}/mcp`;
}

function utf8ToBase64Url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value: string): Uint8Array | null {
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

function base64UrlToUtf8(value: string): string | null {
  const bytes = base64UrlToBytes(value);
  if (!bytes) return null;
  try {
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

async function importSigningKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

async function signPayload(env: Env, payload: JsonRecord): Promise<string> {
  const secret = env.OPS_API_TOKEN?.trim();
  if (!secret) throw new Error('OPS_API_TOKEN is not configured');
  const encoded = utf8ToBase64Url(JSON.stringify(payload));
  const key = await importSigningKey(secret);
  const signature = new Uint8Array(
    await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(encoded))
  );
  return `${encoded}.${bytesToBase64Url(signature)}`;
}

async function verifySignedPayload<T extends SignedPayload>(
  env: Env,
  token: string,
  expectedType: TokenKind
): Promise<T | null> {
  const secret = env.OPS_API_TOKEN?.trim();
  if (!secret || token.length > 24_000) return null;
  const [encoded, signatureText, extra] = token.split('.');
  if (!encoded || !signatureText || extra !== undefined) return null;
  const signature = base64UrlToBytes(signatureText);
  if (!signature) return null;

  const key = await importSigningKey(secret);
  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    signature,
    new TextEncoder().encode(encoded)
  );
  if (!valid) return null;

  const decoded = base64UrlToUtf8(encoded);
  if (!decoded) return null;
  let payload: unknown;
  try {
    payload = JSON.parse(decoded);
  } catch {
    return null;
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const record = payload as JsonRecord;
  if (record.typ !== expectedType) return null;
  if (typeof record.exp !== 'number' || !Number.isFinite(record.exp) || record.exp < nowSeconds()) {
    return null;
  }
  if (typeof record.iat !== 'number' || !Number.isFinite(record.iat)) return null;
  return payload as T;
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  );
  return bytesToBase64Url(digest);
}

function tokenJson(body: JsonRecord, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      'Cache-Control': 'no-store',
      Pragma: 'no-cache',
    },
  });
}

function oauthError(error: string, description: string, status = 400): Response {
  return tokenJson({ error, error_description: description }, status);
}

function normalizeScope(raw: string | null | undefined): string | null {
  const requested = (raw || DEFAULT_SCOPE)
    .split(/\s+/)
    .map((value) => value.trim())
    .filter(Boolean);
  const unique = [...new Set(requested)];
  if (unique.some((scope) => !(ALLOWED_SCOPES as readonly string[]).includes(scope))) return null;
  return unique.join(' ');
}

function scopeSet(scope: string): Set<string> {
  return new Set(scope.split(/\s+/).filter(Boolean));
}

function isScopeSubset(requested: string, granted: string): boolean {
  const grantedSet = scopeSet(granted);
  return [...scopeSet(requested)].every((scope) => grantedSet.has(scope));
}

function validRedirectUri(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.protocol === 'https:') return true;
    if (url.protocol !== 'http:') return false;
    return url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '::1';
  } catch {
    return false;
  }
}

function htmlEscape(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeReturnPath(url: URL): string {
  return `${url.pathname}${url.search}`;
}

function operatorGithubId(env: Env): string | null {
  const value = env.OPS_GITHUB_ID?.trim();
  return value && /^\d+$/.test(value) ? value : null;
}

function verifyOperator(user: UserInfo, env: Env): boolean {
  const expected = operatorGithubId(env);
  return !!expected && String(user.github_id) === expected;
}

function consentPage(params: {
  clientName: string;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  scope: string;
  resource: string;
}): Response {
  const hidden = Object.entries({
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
    state: params.state,
    code_challenge: params.codeChallenge,
    code_challenge_method: 'S256',
    scope: params.scope,
    resource: params.resource,
    response_type: 'code',
  })
    .map(
      ([name, value]) =>
        `<input type="hidden" name="${htmlEscape(name)}" value="${htmlEscape(value)}">`
    )
    .join('');

  return new Response(
    `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>授权 CloudSSH</title><style>body{font-family:system-ui,-apple-system,sans-serif;background:#0b0f0d;color:#e8fff0;margin:0;display:grid;place-items:center;min-height:100vh}.card{width:min(560px,calc(100vw - 32px));background:#111814;border:1px solid #2a4d36;border-radius:18px;padding:28px;box-sizing:border-box;box-shadow:0 18px 60px #0008}h1{margin:0 0 12px;color:#60ff8a;font-size:24px}p{line-height:1.6;color:#cfe6d5}.scope{background:#0b120e;border:1px solid #233c2b;border-radius:12px;padding:14px;margin:18px 0}.actions{display:flex;gap:12px;margin-top:22px}button{border:0;border-radius:10px;padding:11px 18px;font-weight:700;cursor:pointer}.allow{background:#55ff83;color:#07110a}.deny{background:#26322a;color:#e8fff0}</style></head><body><main class="card"><h1>授权 ${htmlEscape(params.clientName)} 访问 CloudSSH</h1><p>该应用将通过你已配置的 CloudSSH 运维网关访问保存并已信任主机密钥的服务器。</p><div class="scope"><strong>权限</strong><p>读取服务器列表，并在 CloudSSH 安全策略约束下执行 SSH 命令。高风险命令仍需要明确确认。</p></div><form method="post" action="/oauth/authorize">${hidden}<div class="actions"><button class="allow" type="submit" name="decision" value="allow">允许</button><button class="deny" type="submit" name="decision" value="deny">拒绝</button></div></form></main></body></html>`,
    { headers: { 'Content-Type': 'text/html;charset=UTF-8', 'Cache-Control': 'no-store' } }
  );
}

async function parseClient(env: Env, clientId: string): Promise<ClientPayload | null> {
  const client = await verifySignedPayload<ClientPayload>(env, clientId, 'client');
  if (!client || !Array.isArray(client.redirectUris)) return null;
  if (client.redirectUris.some((uri) => typeof uri !== 'string' || !validRedirectUri(uri))) return null;
  return client;
}

async function validateAuthorizationParams(
  request: Request,
  env: Env,
  values: URLSearchParams
): Promise<
  | {
      ok: true;
      client: ClientPayload;
      clientId: string;
      redirectUri: string;
      state: string;
      codeChallenge: string;
      scope: string;
      resource: string;
    }
  | { ok: false; response: Response }
> {
  const clientId = values.get('client_id') || '';
  const redirectUri = values.get('redirect_uri') || '';
  const responseType = values.get('response_type') || '';
  const state = values.get('state') || '';
  const codeChallenge = values.get('code_challenge') || '';
  const codeChallengeMethod = values.get('code_challenge_method') || '';
  const scope = normalizeScope(values.get('scope'));
  const resource = values.get('resource') || resourceUrl(request, env);

  if (!clientId || !redirectUri || responseType !== 'code') {
    return { ok: false, response: oauthError('invalid_request', 'Missing or invalid authorization parameters') };
  }
  const client = await parseClient(env, clientId);
  if (!client || !client.redirectUris.includes(redirectUri)) {
    return { ok: false, response: oauthError('invalid_client', 'Unknown client or redirect URI') };
  }
  if (!state) {
    return { ok: false, response: oauthError('invalid_request', 'state is required') };
  }
  if (!codeChallenge || codeChallengeMethod !== 'S256') {
    return { ok: false, response: oauthError('invalid_request', 'PKCE S256 is required') };
  }
  if (!scope) {
    return { ok: false, response: oauthError('invalid_scope', 'Unsupported scope requested') };
  }
  if (resource !== resourceUrl(request, env)) {
    return { ok: false, response: oauthError('invalid_target', 'Invalid MCP resource') };
  }

  return {
    ok: true,
    client,
    clientId,
    redirectUri,
    state,
    codeChallenge,
    scope,
    resource,
  };
}

async function handleRegister(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
  let body: JsonRecord;
  try {
    const parsed = await request.json<unknown>();
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
    body = parsed as JsonRecord;
  } catch {
    return oauthError('invalid_client_metadata', 'Request body must be JSON');
  }

  const redirectUris = Array.isArray(body.redirect_uris)
    ? body.redirect_uris.filter((value): value is string => typeof value === 'string')
    : [];
  if (
    redirectUris.length === 0 ||
    redirectUris.length > 10 ||
    redirectUris.length !== (body.redirect_uris as unknown[])?.length ||
    redirectUris.some((uri) => !validRedirectUri(uri))
  ) {
    return oauthError('invalid_redirect_uri', 'redirect_uris must contain valid HTTPS or loopback URLs');
  }

  const authMethod = typeof body.token_endpoint_auth_method === 'string'
    ? body.token_endpoint_auth_method
    : 'none';
  if (authMethod !== 'none') {
    return oauthError('invalid_client_metadata', 'Only token_endpoint_auth_method=none is supported');
  }

  const now = nowSeconds();
  const clientName = typeof body.client_name === 'string' ? body.client_name.slice(0, 160) : 'ChatGPT MCP';
  const clientId = await signPayload(env, {
    typ: 'client',
    iat: now,
    exp: now + CLIENT_TTL_SECONDS,
    redirectUris,
    clientName,
  });

  return tokenJson(
    {
      client_id: clientId,
      client_id_issued_at: now,
      client_name: clientName,
      redirect_uris: redirectUris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    },
    201
  );
}

async function handleAuthorize(request: Request, env: Env): Promise<Response> {
  const values =
    request.method === 'GET'
      ? new URL(request.url).searchParams
      : request.method === 'POST'
        ? new URLSearchParams(await request.text())
        : null;
  if (!values) return new Response('Method Not Allowed', { status: 405 });

  const parsed = await validateAuthorizationParams(request, env, values);
  if (!parsed.ok) return parsed.response;

  const user = await getAuthenticatedUser(request, env);
  if (!user) {
    const url = new URL(request.url);
    const returnTo = request.method === 'GET' ? safeReturnPath(url) : `/oauth/authorize?${values.toString()}`;
    return Response.redirect(
      `${baseUrl(request, env)}/api/auth/github?return_to=${encodeURIComponent(returnTo)}`,
      302
    );
  }
  if (!verifyOperator(user, env)) {
    return new Response('This GitHub account is not the configured CloudSSH operator.', {
      status: 403,
      headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
    });
  }

  if (request.method === 'GET') {
    return consentPage({
      clientName: parsed.client.clientName || 'ChatGPT MCP',
      clientId: parsed.clientId,
      redirectUri: parsed.redirectUri,
      state: parsed.state,
      codeChallenge: parsed.codeChallenge,
      scope: parsed.scope,
      resource: parsed.resource,
    });
  }

  const redirect = new URL(parsed.redirectUri);
  if (values.get('decision') !== 'allow') {
    redirect.searchParams.set('error', 'access_denied');
    redirect.searchParams.set('state', parsed.state);
    redirect.searchParams.set('iss', baseUrl(request, env));
    return Response.redirect(redirect.toString(), 302);
  }

  const now = nowSeconds();
  const code = await signPayload(env, {
    typ: 'code',
    iat: now,
    exp: now + CODE_TTL_SECONDS,
    clientId: parsed.clientId,
    redirectUri: parsed.redirectUri,
    codeChallenge: parsed.codeChallenge,
    scope: parsed.scope,
    resource: parsed.resource,
    githubId: String(user.github_id),
  });
  redirect.searchParams.set('code', code);
  redirect.searchParams.set('state', parsed.state);
  redirect.searchParams.set('iss', baseUrl(request, env));
  return Response.redirect(redirect.toString(), 302);
}

async function issueTokens(
  env: Env,
  input: {
    clientId: string;
    scope: string;
    resource: string;
    githubId: string;
  }
): Promise<JsonRecord> {
  const now = nowSeconds();
  const accessToken = await signPayload(env, {
    typ: 'access',
    iat: now,
    exp: now + ACCESS_TTL_SECONDS,
    clientId: input.clientId,
    scope: input.scope,
    resource: input.resource,
    githubId: input.githubId,
  });
  const refreshToken = await signPayload(env, {
    typ: 'refresh',
    iat: now,
    exp: now + REFRESH_TTL_SECONDS,
    clientId: input.clientId,
    scope: input.scope,
    resource: input.resource,
    githubId: input.githubId,
  });
  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TTL_SECONDS,
    refresh_token: refreshToken,
    scope: input.scope,
  };
}

async function handleToken(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
  const contentType = request.headers.get('Content-Type') || '';
  if (!contentType.toLowerCase().includes('application/x-www-form-urlencoded')) {
    return oauthError('invalid_request', 'Token requests must use application/x-www-form-urlencoded', 415);
  }
  const form = new URLSearchParams(await request.text());
  const grantType = form.get('grant_type') || '';
  const clientId = form.get('client_id') || '';
  const client = await parseClient(env, clientId);
  if (!client) return oauthError('invalid_client', 'Unknown or expired client', 401);

  if (grantType === 'authorization_code') {
    const codeText = form.get('code') || '';
    const redirectUri = form.get('redirect_uri') || '';
    const verifier = form.get('code_verifier') || '';
    const code = await verifySignedPayload<CodePayload>(env, codeText, 'code');
    if (!code || code.clientId !== clientId || code.redirectUri !== redirectUri) {
      return oauthError('invalid_grant', 'Invalid or expired authorization code');
    }
    if (!client.redirectUris.includes(redirectUri)) {
      return oauthError('invalid_grant', 'redirect_uri does not match the registered client');
    }
    if (!verifier || (await sha256Base64Url(verifier)) !== code.codeChallenge) {
      return oauthError('invalid_grant', 'PKCE verification failed');
    }
    const requestedResource = form.get('resource');
    if (requestedResource && requestedResource !== code.resource) {
      return oauthError('invalid_target', 'resource does not match the authorization request');
    }
    if (operatorGithubId(env) !== code.githubId) {
      return oauthError('invalid_grant', 'CloudSSH operator changed after authorization');
    }
    return tokenJson(
      await issueTokens(env, {
        clientId,
        scope: code.scope,
        resource: code.resource,
        githubId: code.githubId,
      })
    );
  }

  if (grantType === 'refresh_token') {
    const refreshText = form.get('refresh_token') || '';
    const refresh = await verifySignedPayload<RefreshPayload>(env, refreshText, 'refresh');
    if (!refresh || refresh.clientId !== clientId) {
      return oauthError('invalid_grant', 'Invalid or expired refresh token');
    }
    if (operatorGithubId(env) !== refresh.githubId) {
      return oauthError('invalid_grant', 'CloudSSH operator changed after authorization');
    }
    const requestedResource = form.get('resource');
    if (requestedResource && requestedResource !== refresh.resource) {
      return oauthError('invalid_target', 'resource does not match the refresh token');
    }
    const normalizedRequestedScope = form.get('scope') ? normalizeScope(form.get('scope')) : refresh.scope;
    if (!normalizedRequestedScope || !isScopeSubset(normalizedRequestedScope, refresh.scope)) {
      return oauthError('invalid_scope', 'Requested scope exceeds the originally granted scope');
    }
    return tokenJson(
      await issueTokens(env, {
        clientId,
        scope: normalizedRequestedScope,
        resource: refresh.resource,
        githubId: refresh.githubId,
      })
    );
  }

  return oauthError('unsupported_grant_type', 'Only authorization_code and refresh_token are supported');
}

function authorizationServerMetadata(request: Request, env: Env): Response {
  const base = baseUrl(request, env);
  return Response.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: [...ALLOWED_SCOPES],
    authorization_response_iss_parameter_supported: true,
    client_id_metadata_document_supported: false,
  });
}

function protectedResourceMetadata(request: Request, env: Env): Response {
  const base = baseUrl(request, env);
  return Response.json({
    resource: `${base}/mcp`,
    authorization_servers: [base],
    scopes_supported: [...ALLOWED_SCOPES],
    bearer_methods_supported: ['header'],
  });
}

export function mcpBearerChallenge(request: Request, env: Env, scope = 'cloudssh:read'): string {
  const base = baseUrl(request, env);
  return `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource", scope="${scope}"`;
}

export async function authenticateMcpRequest(
  request: Request,
  env: Env
): Promise<McpAuthContext | null> {
  const header = request.headers.get('Authorization') || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const token = match[1].trim();
  const expectedOperator = operatorGithubId(env);
  if (!expectedOperator) return null;

  const opsToken = env.OPS_API_TOKEN?.trim();
  if (opsToken && token === opsToken) {
    return {
      githubId: expectedOperator,
      scopes: new Set(ALLOWED_SCOPES),
      source: 'ops-token',
    };
  }

  const payload = await verifySignedPayload<AccessPayload>(env, token, 'access');
  if (!payload) return null;
  if (payload.githubId !== expectedOperator) return null;
  if (payload.resource !== resourceUrl(request, env)) return null;
  const normalized = normalizeScope(payload.scope);
  if (!normalized) return null;
  return {
    githubId: payload.githubId,
    scopes: scopeSet(normalized),
    source: 'oauth',
  };
}

export async function handleMcpOAuthRoute(
  request: Request,
  env: Env
): Promise<Response | null> {
  const url = new URL(request.url);

  if (
    url.pathname === '/.well-known/oauth-protected-resource' ||
    url.pathname === '/.well-known/oauth-protected-resource/mcp'
  ) {
    return protectedResourceMetadata(request, env);
  }
  if (
    url.pathname === '/.well-known/oauth-authorization-server' ||
    url.pathname === '/.well-known/openid-configuration'
  ) {
    return authorizationServerMetadata(request, env);
  }
  if (url.pathname === '/oauth/register') return handleRegister(request, env);
  if (url.pathname === '/oauth/authorize') return handleAuthorize(request, env);
  if (url.pathname === '/oauth/token') return handleToken(request, env);

  return null;
}

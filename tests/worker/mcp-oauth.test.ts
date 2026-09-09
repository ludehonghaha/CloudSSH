import { describe, expect, it } from 'vitest';

import type { Env } from '../../src/types';
import { handleMcpGateway } from '../../src/worker/mcp-gateway';
import { handleMcpOAuthRoute } from '../../src/worker/mcp-oauth';

function env(): Env {
  return {
    OPS_API_TOKEN: 'unit-test-ops-secret',
    OPS_GITHUB_ID: '254142048',
    BASE_URL: 'https://cloudssh.example.test',
  } as unknown as Env;
}

describe('MCP OAuth facade', () => {
  it('publishes protected resource metadata for the MCP endpoint', async () => {
    const response = await handleMcpOAuthRoute(
      new Request('https://cloudssh.example.test/.well-known/oauth-protected-resource'),
      env()
    );
    expect(response).not.toBeNull();
    expect(response!.status).toBe(200);
    expect(await response!.json()).toEqual({
      resource: 'https://cloudssh.example.test/mcp',
      authorization_servers: ['https://cloudssh.example.test'],
      scopes_supported: ['cloudssh:read', 'cloudssh:exec', 'offline_access'],
      bearer_methods_supported: ['header'],
    });
  });

  it('publishes OAuth authorization server metadata', async () => {
    const response = await handleMcpOAuthRoute(
      new Request('https://cloudssh.example.test/.well-known/oauth-authorization-server'),
      env()
    );
    expect(response).not.toBeNull();
    expect(response!.status).toBe(200);
    const body = (await response!.json()) as Record<string, unknown>;
    expect(body.issuer).toBe('https://cloudssh.example.test');
    expect(body.authorization_endpoint).toBe('https://cloudssh.example.test/oauth/authorize');
    expect(body.token_endpoint).toBe('https://cloudssh.example.test/oauth/token');
    expect(body.registration_endpoint).toBe('https://cloudssh.example.test/oauth/register');
    expect(body.code_challenge_methods_supported).toEqual(['S256']);
    expect(body.scopes_supported).toEqual([
      'cloudssh:read',
      'cloudssh:exec',
      'offline_access',
    ]);
  });

  it('supports dynamic public client registration without exposing a client secret', async () => {
    const response = await handleMcpOAuthRoute(
      new Request('https://cloudssh.example.test/oauth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'ChatGPT',
          redirect_uris: ['https://chatgpt.com/connector/oauth/callback'],
          token_endpoint_auth_method: 'none',
        }),
      }),
      env()
    );
    expect(response).not.toBeNull();
    expect(response!.status).toBe(201);
    const body = (await response!.json()) as Record<string, unknown>;
    expect(typeof body.client_id).toBe('string');
    expect(body.client_secret).toBeUndefined();
    expect(body.token_endpoint_auth_method).toBe('none');
    expect(body.grant_types).toEqual(['authorization_code', 'refresh_token']);
    expect(body.redirect_uris).toEqual(['https://chatgpt.com/connector/oauth/callback']);
  });

  it('rejects an unauthenticated MCP request with OAuth discovery metadata', async () => {
    const response = await handleMcpGateway(
      new Request('https://cloudssh.example.test/mcp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: { protocolVersion: '2025-11-25' },
        }),
      }),
      env()
    );
    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toContain(
      'resource_metadata="https://cloudssh.example.test/.well-known/oauth-protected-resource"'
    );
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.jsonrpc).toBe('2.0');
    expect(body.error).toBeTruthy();
  });
});

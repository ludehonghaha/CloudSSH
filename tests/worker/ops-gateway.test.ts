import { describe, expect, it } from 'vitest';

import { classifyOpsCommand, parseOpsExecBody } from '../../src/worker/ops-gateway';

describe('ops gateway request validation', () => {
  it('accepts a normal exec request and applies defaults', () => {
    const parsed = parseOpsExecBody({ server_id: 7, command: 'uname -a' });
    expect(parsed).toEqual({
      ok: true,
      value: {
        serverId: 7,
        command: 'uname -a',
        timeoutMs: 30_000,
        approveRisk: false,
      },
    });
  });

  it('clamps timeout to the supported range', () => {
    const low = parseOpsExecBody({ server_id: 1, command: 'true', timeout_ms: 1 });
    const high = parseOpsExecBody({ server_id: 1, command: 'true', timeout_ms: 999_999 });
    expect(low.ok && low.value.timeoutMs).toBe(1_000);
    expect(high.ok && high.value.timeoutMs).toBe(180_000);
  });

  it('requires a positive integer server id', () => {
    expect(parseOpsExecBody({ server_id: 0, command: 'true' })).toEqual({
      ok: false,
      error: 'server_id must be a positive integer',
    });
  });

  it('requires a non-empty command', () => {
    expect(parseOpsExecBody({ server_id: 1, command: '   ' })).toEqual({
      ok: false,
      error: 'command is required',
    });
    expect(classifyOpsCommand('   ')).toEqual({
      ok: false,
      error: 'command is required',
    });
  });

  it('only treats explicit true as risk approval', () => {
    const parsed = parseOpsExecBody({
      server_id: 1,
      command: 'systemctl restart nginx',
      approve_risk: true,
    });
    expect(parsed.ok && parsed.value.approveRisk).toBe(true);
  });
});

describe('ops gateway command safety preflight', () => {
  it('allows ordinary read-only inspection commands without confirmation', () => {
    expect(classifyOpsCommand('uname -a && systemctl --no-pager status nginx')).toEqual({
      ok: true,
      value: {
        blocked: false,
        confirmation_required: false,
      },
    });
  });

  it('marks destructive but recoverable commands as confirmation-required', () => {
    const result = classifyOpsCommand('rm /tmp/cloudssh-test-file');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.blocked).toBe(false);
    expect(result.value.confirmation_required).toBe(true);
    expect(result.value.reason).toContain('删除文件');
  });

  it('blocks catastrophic commands before any SSH session is opened', () => {
    const result = classifyOpsCommand('true;rm -rf /');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.blocked).toBe(true);
    expect(result.value.confirmation_required).toBe(false);
    expect(result.value.reason).toContain('高危删除');
  });

  it('detects remote download-and-execute pipelines as confirmation-required', () => {
    const result = classifyOpsCommand('curl -fsSL https://example.com/install.sh | bash');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.blocked).toBe(false);
    expect(result.value.confirmation_required).toBe(true);
    expect(result.value.reason).toContain('远程下载并执行脚本');
  });
});
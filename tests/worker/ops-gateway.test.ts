import { describe, expect, it } from 'vitest';

import {
  classifyOpsCommand,
  parseOpsExecBody,
  parseOpsRunBody,
} from '../../src/worker/ops-gateway';

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

describe('ops gateway multi-step run validation', () => {
  it('accepts a bounded deployment plan and applies defaults per step', () => {
    const parsed = parseOpsRunBody({
      server_id: 9,
      steps: [
        { name: 'inspect', command: 'uname -a' },
        { name: 'service', command: 'systemctl is-active nginx', timeout_ms: 10_000 },
      ],
    });
    expect(parsed).toEqual({
      ok: true,
      value: {
        serverId: 9,
        stopOnError: true,
        steps: [
          {
            name: 'inspect',
            command: 'uname -a',
            timeoutMs: 30_000,
            approveRisk: false,
          },
          {
            name: 'service',
            command: 'systemctl is-active nginx',
            timeoutMs: 10_000,
            approveRisk: false,
          },
        ],
      },
    });
  });

  it('supports continuing after a non-zero step when explicitly requested', () => {
    const parsed = parseOpsRunBody({
      server_id: 1,
      stop_on_error: false,
      steps: [{ command: 'false', timeout_ms: 1_000 }],
    });
    expect(parsed.ok && parsed.value.stopOnError).toBe(false);
  });

  it('rejects empty and oversized plans', () => {
    expect(parseOpsRunBody({ server_id: 1, steps: [] })).toEqual({
      ok: false,
      error: 'steps must be a non-empty array',
    });
    expect(
      parseOpsRunBody({
        server_id: 1,
        steps: Array.from({ length: 21 }, () => ({ command: 'true', timeout_ms: 1_000 })),
      })
    ).toEqual({
      ok: false,
      error: 'steps exceeds 20 items',
    });
  });

  it('rejects a plan whose combined timeout budget is too large', () => {
    const parsed = parseOpsRunBody({
      server_id: 1,
      steps: [
        { command: 'true', timeout_ms: 180_000 },
        { command: 'true', timeout_ms: 180_000 },
      ],
    });
    expect(parsed).toEqual({
      ok: false,
      error: 'combined step timeouts exceed 300000 ms',
    });
  });

  it('keeps risk approval scoped to the individual step', () => {
    const parsed = parseOpsRunBody({
      server_id: 1,
      steps: [
        { command: 'uname -a' },
        { command: 'systemctl restart nginx', approve_risk: true },
      ],
    });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.steps[0].approveRisk).toBe(false);
    expect(parsed.value.steps[1].approveRisk).toBe(true);
  });
});
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file = Path(path)
    text = file.read_text()
    if new in text:
        print(f"[skip] {path}: patch already applied")
        return
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected exactly one anchor, found {count}")
    file.write_text(text.replace(old, new, 1))
    print(f"[ok] {path}")


replace_once(
    "src/types.ts",
    "  /** 仅可由 Worker 内部的一次性分享兑换流程写入，客户端输入必须剥离。 */\n  sessionPolicy?: SSHSessionPolicy;\n}",
    "  /** 仅可由 Worker 内部的一次性分享兑换流程写入，客户端输入必须剥离。 */\n  sessionPolicy?: SSHSessionPolicy;\n  /** 仅由受信任的 Worker Ops Gateway 写入；匿名客户端输入必须剥离。 */\n  opsMode?: boolean;\n}",
)

replace_once(
    "src/types.ts",
    "  // 一次性 SSH 分享（默认关闭；true 时登录用户可创建分享链接）\n  ENABLE_SSH_SHARING?: string;\n}",
    "  // 一次性 SSH 分享（默认关闭；true 时登录用户可创建分享链接）\n  ENABLE_SSH_SHARING?: string;\n  // ChatGPT / automation 受控运维网关。OPS_API_TOKEN 必须通过 wrangler secret 配置。\n  OPS_API_TOKEN?: string;\n  // 允许 Ops Gateway 访问的唯一 GitHub 数字用户 ID。\n  OPS_GITHUB_ID?: string;\n}",
)

replace_once(
    "src/worker/user-db.ts",
    "      if (path === '/internal/oauth-user' && request.method === 'POST') {\n        return this.handleOAuthUser(request);\n      }\n\n      // --- Session 管理 ---",
    "      if (path === '/internal/oauth-user' && request.method === 'POST') {\n        return this.handleOAuthUser(request);\n      }\n      if (path === '/internal/operator-context' && request.method === 'GET') {\n        const githubId = Number(url.searchParams.get('github_id'));\n        if (!Number.isInteger(githubId) || githubId <= 0) {\n          return Response.json({ error: 'Invalid github_id' }, { status: 400 });\n        }\n        return this.handleOperatorContext(githubId);\n      }\n\n      // --- Session 管理 ---",
)

replace_once(
    "src/worker/user-db.ts",
    "  // ==================== Session 管理 ====================\n",
    "  /** Worker Ops Gateway 专用：按 GitHub ID 解析当前 DO 内的用户行，不创建或修改用户。 */\n  private handleOperatorContext(githubId: number): Response {\n    const user = this.one<UserRow>(\n      'SELECT id, github_id, username, avatar_url FROM users WHERE github_id = ?',\n      githubId\n    );\n    if (!user) return Response.json({ error: 'User not found' }, { status: 404 });\n    return Response.json(user);\n  }\n\n  // ==================== Session 管理 ====================\n",
)

replace_once(
    "src/worker/index.ts",
    "import { HTML } from './html';\n",
    "import { HTML } from './html';\nimport { handleOpsGateway } from './ops-gateway';\n",
)

replace_once(
    "src/worker/index.ts",
    "      if (url.pathname === '/api/auth/me') {\n        return handleGetMe(request, env);\n      }\n\n      // ==================== 一次性 SSH 分享公开兑换 ====================",
    "      if (url.pathname === '/api/auth/me') {\n        return handleGetMe(request, env);\n      }\n\n      // ==================== ChatGPT / Automation Ops Gateway ====================\n\n      if (url.pathname === '/api/ops' || url.pathname.startsWith('/api/ops/')) {\n        return handleOpsGateway(request, url, env);\n      }\n\n      // ==================== 一次性 SSH 分享公开兑换 ====================",
)

replace_once(
    "src/worker/durable-object.ts",
    "      delete config.knownHostIdentity;\n      delete config.sessionPolicy;\n",
    "      delete config.knownHostIdentity;\n      delete config.sessionPolicy;\n      delete config.opsMode;\n",
)

replace_once(
    "src/worker/ssh-session.ts",
    "import { AgentExecChannel } from './agent/exec-channel';\nimport { TerminalContext } from './agent/terminal-context';\n",
    "import { AgentExecChannel } from './agent/exec-channel';\nimport { isBlockedCommand, needsConfirmation } from './agent/safety';\nimport { TerminalContext } from './agent/terminal-context';\n",
)

replace_once(
    "src/worker/ssh-session.ts",
    "        // Agent messages\n        // agent_stop / agent_confirm 已由 durable-object.ts 在 webSocketMessage 入口\n        // 提前拦截并通过 handleAgentControl 同步处理，不再到达此处。\n        if (parsed.type === 'agent_start') {",
    "        // Ops Gateway messages。只有 Worker 内部写入 opsMode 的预填充会话才允许执行。\n        if (parsed.type === 'ops_exec') {\n          await this.handleOpsExec(\n            parsed.request_id,\n            parsed.command,\n            parsed.timeout_ms,\n            parsed.approve_risk\n          );\n          return;\n        }\n\n        // Agent messages\n        // agent_stop / agent_confirm 已由 durable-object.ts 在 webSocketMessage 入口\n        // 提前拦截并通过 handleAgentControl 同步处理，不再到达此处。\n        if (parsed.type === 'agent_start') {",
)

replace_once(
    "src/worker/ssh-session.ts",
    "    this.sendStatus('Shell 已就绪', 'shell_ready');\n    if (this.config.sessionPolicy?.allowMetadataMutation !== false) {",
    "    this.sendStatus('Shell 已就绪', 'shell_ready');\n    if (this.config.opsMode) {\n      try {\n        this.ws.send(JSON.stringify({ type: 'ops_ready' }));\n      } catch {\n        /* 内部 Ops WebSocket 可能已关闭 */\n      }\n    }\n    if (this.config.sessionPolicy?.allowMetadataMutation !== false) {",
)

replace_once(
    "src/worker/ssh-session.ts",
    "  // ==================== Agent Integration ====================\n\n  private async handleAgentStart(",
    "  // ==================== Agent Integration ====================\n\n  /**\n   * Worker Ops Gateway 的单命令执行入口。\n   * opsMode 只能由 Worker 内部预填充，匿名客户端字段会在 DO 层被剥离。\n   */\n  private async handleOpsExec(\n    requestId: unknown,\n    command: unknown,\n    timeoutMs: unknown,\n    approveRisk: unknown\n  ): Promise<void> {\n    const id =\n      typeof requestId === 'string' && requestId.length > 0 && requestId.length <= 128\n        ? requestId\n        : crypto.randomUUID();\n    const send = (payload: Record<string, unknown>) => {\n      try {\n        if (this.ws.readyState === WebSocket.OPEN) {\n          this.ws.send(JSON.stringify({ type: 'ops_exec_result', request_id: id, ...payload }));\n        }\n      } catch {\n        /* 内部 WebSocket 已关闭 */\n      }\n    };\n\n    if (!this.config.opsMode) {\n      send({ blocked: true, reason: 'Ops execution is not enabled for this SSH session' });\n      return;\n    }\n    if (this.state !== 'ready') {\n      send({ stderr: 'SSH session is not ready', exit_code: -1 });\n      return;\n    }\n    if (typeof command !== 'string' || command.trim().length === 0 || command.length > 32_768) {\n      send({ stderr: 'Invalid command', exit_code: -1 });\n      return;\n    }\n\n    const blocked = isBlockedCommand(command);\n    if (blocked.blocked) {\n      send({ blocked: true, reason: blocked.reason || 'Command blocked by safety policy' });\n      return;\n    }\n    const confirmation = needsConfirmation(command);\n    if (confirmation.required && approveRisk !== true) {\n      send({\n        confirmation_required: true,\n        reason: confirmation.reason || 'Command requires explicit approval',\n      });\n      return;\n    }\n\n    const timeout =\n      typeof timeoutMs === 'number' && Number.isFinite(timeoutMs)\n        ? Math.min(180_000, Math.max(1_000, Math.floor(timeoutMs)))\n        : 30_000;\n    try {\n      const result = await this.executeAgentCommand(command, timeout);\n      send({ stdout: result.stdout, stderr: result.stderr, exit_code: result.exitCode });\n    } catch (error) {\n      send({\n        stdout: '',\n        stderr: error instanceof Error ? error.message : String(error),\n        exit_code: -1,\n      });\n    }\n  }\n\n  private async handleAgentStart(",
)

print("Ops gateway patches applied successfully")

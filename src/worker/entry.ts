import type { Env } from '../types';
import app from './index';
import { handleMcpGateway } from './mcp-gateway';

export { SSHSessionDO, SSHShareDO, UserDBDO } from './index';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/mcp') {
      return handleMcpGateway(request, env);
    }
    return app.fetch(request, env);
  },
};

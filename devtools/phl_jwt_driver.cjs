/**
 * PHL（Node）侧的 P3 驱动 —— 给 `devtools/test_phl_jwt.py` 用。
 *
 * 它**不是** PHL 的一部分：把 PHL 的 `phix-session.cjs` / `cloudsync.cjs` 当库来调，
 * 好让 Python 那头能对着**真服务端**验证"客户端这一层接上了 P3"。
 *
 *   node phl_jwt_driver.cjs jwt-flow   <server> <user> <pass> <dataDir>
 *   node phl_jwt_login      同 jwt-flow 的前半（注册 + 落盘 + 一次业务请求）
 *   node phl_jwt_me         只做一次业务请求（验自动续期 / 只用一次）
 *   node phl_jwt_logout     登出并核对两串都失效
 *
 * 输出：`__PHL_RESULT__<json>` 一行（前面可能有日志）。
 * **绝不输出任何令牌、口令、密钥**：令牌要留给后面的命令用时，写进数据目录里
 * 那个临时文件夹（脚本跑完由 Python 整目录删掉）。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ELECTRON = process.env.PHL_ELECTRON_DIR || 'D:\\phl-dev\\PH-Launcher\\electron';
const cloudsync = require(path.join(ELECTRON, 'cloudsync.cjs'));
const session = require(path.join(ELECTRON, 'phix-session.cjs'));
const phixCrypto = require(path.join(ELECTRON, 'phix-crypto.cjs'));

const API = '/api/v1';

function emit(payload) {
  process.stdout.write('\n__PHL_RESULT__' + JSON.stringify(payload) + '\n');
}

const tokensFile = (dir) => path.join(dir, '.jwt-tokens.json');
const readTokens = (dir) => {
  try { return JSON.parse(fs.readFileSync(tokensFile(dir), 'utf8')); } catch { return {}; }
};
const writeTokens = (dir, value) => {
  try { fs.writeFileSync(tokensFile(dir), JSON.stringify(value), { mode: 0o600 }); } catch { /* 无所谓 */ }
};
const dropTokens = (dir) => { try { fs.rmSync(tokensFile(dir), { force: true }); } catch { /* 同上 */ } };

/** 只报"有没有、够不够长"，绝不回传令牌本身。 */
const shape = (value) => ({ present: Boolean(value), length: String(value || '').length });

/**
 * 令牌的**短指纹**：`sha256` 的前 8 位十六进制。
 *
 * 用来跨命令、跨进程比较"是不是同一串"而**不泄露令牌本身**（哈希不可逆，
 * 而且这里连完整哈希都不打出来）。
 */
const fingerprint = (value) => (value
  ? require('crypto').createHash('sha256').update(String(value)).digest('hex').slice(0, 8)
  : '');
const storedFingerprints = (dir) => {
  const tokens = readTokens(dir);
  return { access: fingerprint(tokens.access), refresh: fingerprint(tokens.refresh) };
};

async function rawJson(method, url, body = null, token = '') {
  const response = await fetch(url, {
    method,
    headers: {
      Accept: 'application/json',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: 'Bearer ' + token } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await response.text();
  let data = {};
  try { data = JSON.parse(text); } catch { data = {}; }
  return { status: response.status, data };
}

/**
 * 一次业务请求 + "这条链路上到底发了几次 HTTP、续期是一次还是两次"。
 *
 * 不是靠数客户端代码，而是**拦在真正发请求的那一层**（`_plainRequest`）上数：
 *   attempts        这一轮业务请求实际发了几次（1 = 没续期，2 = 续期后重试了一次）
 *   refreshCalls    有没有调/../auth/refresh
 *   refreshStatus   续期那一次服务端给的 HTTP 状态码（**这是真服务端的真话**）
 *   refreshAuthSent 续期请求有没有带上 Bearer（协议要求免认证，不该带）
 */
async function requestWithCount(client, run) {
  const seen = { attempts: 0, refreshCalls: 0, refreshStatus: 0, refreshAuthSent: false };
  const inner = client._plainRequest.bind(client);
  client._plainRequest = async (method, route, payload, token, timeoutMs) => {
    if (route === '/auth/refresh') {
      seen.refreshCalls += 1;
      // 续期是免认证接口（协议明确要求不带 Bearer）。`token` 为空串 = 没带。
      seen.refreshAuthSent = Boolean(token);
      try {
        return await inner(method, route, payload, token, timeoutMs);
      } catch (error) {
        seen.refreshStatus = error?.status || 0;
        throw error;
      }
    }
    seen.attempts += 1;
    return inner(method, route, payload, token, timeoutMs);
  };
  try {
    const data = await run();
    return { ok: true, data, ...seen };
  } catch (error) {
    return { ok: false, error: String(error?.message || error), code: error?.code || '', ...seen };
  } finally {
    delete client._plainRequest;     // 还原成原型上的那个
  }
}

/**
 * 把这条链路上每一次请求的"路径 + 状态码 + 有没有带 Bearer"打出来。
 *
 * 调试用（`PHL_JWT_DEBUG=1` 时才打印），**只打状态、绝不打令牌**。
 */
function traceHttp(client) {
  if (!process.env.PHL_JWT_DEBUG) return;
  const inner = client._plainRequest.bind(client);
  client._plainRequest = async (method, route, payload, token, timeoutMs) => {
    try {
      const out = await inner(method, route, payload, token, timeoutMs);
      console.error(`  [http] ${method} ${route} -> 200 bearer=${Boolean(token)}`);
      return out;
    } catch (error) {
      console.error(`  [http] ${method} ${route} -> ${error?.status || '?'} ${error?.code || ''} bearer=${Boolean(token)}`);
      throw error;
    }
  };
}

function makeSession(dataDir) {
  session.configure({ dataDir });
  return new session.PhixSession({ log: () => {} });
}

/** 登录（账号不存在就注册）—— `jwt-flow` 与 `jwt-login` 共用这一段。 */
async function ensureAccount(api, server, username, password) {
  try {
    const status = await api.login(server, username, password);
    return { status, created: false };
  } catch (error) {
    if (error?.code !== 'bad_credentials') throw error;
    const status = await api.register(server, username, password);
    return { status, created: true };
  }
}

async function loginFlow([server, username, password, dataDir]) {
  const api = makeSession(dataDir);
  // 先试登录；账号还不存在（本地库刚清过）就注册一个 —— 两条路都会走
  // `PhixSession` 自己的落盘逻辑，正是要验的那一段。
  const { status, created } = await ensureAccount(api, server, username, password);
  const me = await api.client.me();
  const tokens = {
    access: api.client.accessToken,
    refresh: api.client.refreshToken,
    legacy: api.client.token,
  };
  writeTokens(dataDir, tokens);
  // `/auth/me` 把"当前这条会话"放在 `device` 里（jwt / session_id 都在那儿）
  const device = me?.device || {};
  const meInfo = {
    ok: Boolean(me?.user_id), user_id: me?.user_id,
    session_id: device.session_id || me?.session_id || 0,
    jwt: device.jwt === true, name: device.name || '',
  };
  return {
    ok: true,
    created,
    status: {
      logged_in: status.logged_in, unlocked: status.unlocked,
      has_token: status.has_token, has_access_token: status.has_access_token,
      has_refresh_token: status.has_refresh_token,
    },
    me: meInfo,
    shapes: { access: shape(tokens.access), refresh: shape(tokens.refresh), legacy: shape(tokens.legacy) },
    stored: { access: fingerprint(tokens.access), refresh: fingerprint(tokens.refresh) },
  };
}

async function jwtLogin(args) {
  const out = await loginFlow(args);
  dropTokens(args[3]);
  return out;
}

async function jwtMe([server, username, password, dataDir]) {
  const api = makeSession(dataDir);
  // **不重新登录**：像程序重启那样把盘上的令牌装回来（access 已经过期了），
  // 然后发一次业务请求 —— 看它会不会自己续期 + 重试一次。
  const restored = await api.restore(server, username);
  if (!restored || !restored.logged_in) {
    return { ok: false, error: '盘上没有可恢复的令牌（restore 失败）' };
  }
  const used = { access: fingerprint(api.client.accessToken), refresh: fingerprint(api.client.refreshToken) };
  const out = await requestWithCount(api.client, () => api.client.me());
  return { ...out, used, now: { access: fingerprint(api.client.accessToken), refresh: fingerprint(api.client.refreshToken) } };
}

async function jwtFlow([server, username, password, dataDir]) {
  const api = makeSession(dataDir);
  const { status, created } = await ensureAccount(api, server, username, password);
  traceHttp(api.client);
  const tokens = { access: api.client.accessToken, refresh: api.client.refreshToken, legacy: api.client.token };
  writeTokens(dataDir, tokens);
  const me = await api.client.me();
  const meDevice = me?.device || {};

  // 第二台设备：同一个账号在**另一个客户端**上再登一次
  // （必须换客户端，否则会把本机手里那两串令牌换成新会话的，后面全测歪了）
  const second = session.makeClient(server);
  const other = await second.login(username, password, 'PHL 测试机 B');
  const otherSessionId = other.session_id;

  const listing = await api.sessions();
  const mine = listing.sessions.filter((item) => item.current);

  // 注销"另一台"
  const revoke = await api.revokeSession({ sessionId: otherSessionId });
  const otherMe = await rawJson('GET', server.replace(/\/+$/, '') + API + '/auth/me', null, other.access_token);
  const mineMe = await rawJson('GET', server.replace(/\/+$/, '') + API + '/auth/me', null, tokens.access);

  const logout = await api.logout();
  const afterMe = await rawJson('GET', server.replace(/\/+$/, '') + API + '/auth/me', null, tokens.access);
  const afterRefresh = await rawJson('POST', server.replace(/\/+$/, '') + API + '/auth/refresh',
    { refresh_token: tokens.refresh });
  writeTokens(dataDir, {});
  dropTokens(dataDir);

  return {
    ok: true,
    created,
    status: {
      logged_in: status.logged_in, unlocked: status.unlocked,
      has_token: status.has_token, has_access_token: status.has_access_token,
      has_refresh_token: status.has_refresh_token,
    },
    login: {
      logged_in: status.logged_in, unlocked: status.unlocked,
      has_token: status.has_token, has_access_token: status.has_access_token,
      has_refresh_token: status.has_refresh_token,
    },
    me: { ok: Boolean(me?.user_id), user_id: me?.user_id, session_id: meDevice.session_id || 0, jwt: meDevice.jwt === true },
    sessions: listing.sessions,
    sessions_count: listing.sessions.length,
    current_count: mine.length,
    revoke,
    other_revoked: otherMe.status,
    mine_still_ok: mineMe.status,
    logout: { logged_in: logout.logged_in, has_access_token: logout.has_access_token, has_refresh_token: logout.has_refresh_token },
    after_logout: { status: afterMe.status, refresh_status: afterRefresh.status },
  };
}

async function jwtLogout([server, username, password, dataDir]) {
  const api = makeSession(dataDir);
  await api.restore(server, username);
  const tokens = readTokens(dataDir);
  const logout = await api.logout();
  // 两串都拿真令牌去打服务端：access 当 Bearer 发业务、refresh 喂给 /auth/refresh
  const afterMe = await rawJson('GET', server.replace(/\/+$/, '') + API + '/auth/me', null, tokens.access);
  const afterRefresh = await rawJson('POST', server.replace(/\/+$/, '') + API + '/auth/refresh',
    { refresh_token: tokens.refresh });
  writeTokens(dataDir, {});
  dropTokens(dataDir);
  return {
    ok: true,
    logout: { logged_in: logout.logged_in, has_access_token: logout.has_access_token, has_refresh_token: logout.has_refresh_token },
    after_logout: { status: afterMe.status, refresh_status: afterRefresh.status },
  };
}

(async () => {
  const [command, ...rest] = process.argv.slice(2);
  try {
    if (command === 'jwt-flow') emit(await jwtFlow(rest));
    else if (command === 'jwt-login') emit(await jwtLogin(rest));
    else if (command === 'jwt-me') emit(await jwtMe(rest));
    else if (command === 'jwt-logout') emit(await jwtLogout(rest));
    else emit({ ok: false, error: 'unknown command: ' + command });
  } catch (error) {
    emit({ ok: false, error: String((error && error.message) || error), code: (error && error.code) || null });
  }
})();

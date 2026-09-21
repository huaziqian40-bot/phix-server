/**
 * 应用层加密传输（P1）的 Node 侧专项测试。
 *
 * 对应 `加密链路思路.md` §3：**用应用层加密替代 HTTPS**。要证明的不只是"能跑通"，
 * 而是**网线上抓到的只有密文**、以及重放/篡改/换公钥这些攻击都挡得住。
 *
 *     cd D:\phix\server
 *     node devtools\test_transport_e2e.cjs
 *
 * 对照：Python 侧同一套在 `devtools/test_e2e_transport.py`（34 项）。
 * 全程只写 D:\phix\_lab\nodetest\transport，绝不碰真实 data/。
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const ELECTRON = 'D:/phl-dev/PH-Launcher/electron';
const cs = require(`${ELECTRON}/cloudsync.cjs`);
const pc = require(`${ELECTRON}/phix-crypto.cjs`);

const SERVER = process.env.PHIX_SERVER || 'http://127.0.0.1:8931';
const API = `${SERVER.replace(/\/+$/, '')}/api/v1`;
const LAB = 'D:\\phix\\_lab\\nodetest\\transport';
const PIN = path.join(LAB, 'pin');

const PASSED = [];
const FAILED = [];

function check(name, condition, extra = '') {
  (condition ? PASSED : FAILED).push(name);
  console.log(`  [${' '}${condition ? 'OK  ' : 'FAIL'}] ${name}${!condition && extra ? `   ${extra}` : ''}`);
  return condition;
}

/** 裸请求：直接看网线上的字节（测试要证明"抓到的只有密文"，必须绕开客户端封装）。 */
function rawRequest(method, route, bodyText, headers = {}) {
  const url = new URL(`${API}${route}`);
  const body = bodyText === undefined || bodyText === null ? null : Buffer.from(bodyText, 'utf8');
  const finalHeaders = { Accept: 'application/json', ...headers };
  if (body) finalHeaders['Content-Length'] = String(body.length);
  return new Promise((resolve) => {
    const request = http.request({
      hostname: url.hostname, port: url.port || 80, path: `${url.pathname}${url.search}`,
      method, headers: finalHeaders, agent: false,
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({
        status: response.statusCode,
        text: Buffer.concat(chunks).toString('utf8'),
        headers: response.headers,
      }));
    });
    request.on('error', (error) => resolve({ status: 0, text: String(error.message), headers: {} }));
    if (body) request.write(body);
    request.end();
  });
}

const jsonOf = (response) => { try { return JSON.parse(response.text); } catch { return {}; } };

async function main() {
  console.log('='.repeat(78));
  console.log('应用层加密传输（P1）· Node 侧专项测试');
  console.log('='.repeat(78));
  console.log(`服务器: ${SERVER}`);

  fs.rmSync(PIN, { recursive: true, force: true });
  fs.mkdirSync(PIN, { recursive: true });

  // ---------- 1. 服务器声明支持 ----------
  console.log('\n[1] 服务器声明支持加密传输');
  const ping = await new cs.PhixClient(SERVER).ping();
  check('ping 返回 enc=1', Number(ping.enc || 0) === 1, String(ping.enc));
  check('拿到 32 字节 X25519 公钥', pc.b64d(ping.pk).length === 32, String(pc.b64d(ping.pk).length));
  const serverPk = pc.b64d(ping.pk);

  // ---------- 2. 加密往返 ----------
  console.log('\n[2] 加密往返：注册 / 读 / 写 / 删');
  const client = new cs.PhixClient(SERVER, null, 30000, { pinDir: PIN });
  check('客户端启用了加密', (await client.ensureE2e()) === true && client.encrypted === true);
  const user = `nodetr${crypto.randomBytes(4).toString('hex')}`;
  const password = 'Transport-Test-1';
  const [info, material] = await client.register(user, password, '加密传输测试');
  check('注册成功（走加密）', Boolean(info.token), JSON.stringify(info).slice(0, 160));
  const userId = info.user_id;
  const token = info.token;

  const c2 = new cs.PhixClient(SERVER, token, 30000, { pinDir: PIN });
  check('manifest 可用（走加密）', (await c2.manifest()).ok === true);

  const payload = JSON.stringify({ events: [{ id: 1, title: '加密传输测试' }], lastId: 1 });
  const envelope = pc.sealObject(material.dek, userId, 'schedule', Buffer.from(payload, 'utf8'));
  check('PUT 成功（走加密）', (await c2.putObject('schedule', 0, envelope, '测试')).revision === 1);
  const got = await c2.getObject('schedule');
  check('GET 解出内容正确',
    JSON.parse(pc.unsealObject(material.dek, userId, 'schedule', got.payload).toString('utf8')).events[0].title === '加密传输测试');
  check('DELETE 成功（query 在信封里）', (await c2.deleteObject('schedule', 1)).deleted === true);

  // ---------- 3. 核心：网线上真的是密文 ----------
  console.log('\n[3] 网线上抓到的只有密文（这是这一层存在的意义）');
  // v2 账号登录要发 **auth_hash**（服务器永远见不到口令）。
  // 手工构造信封时也得按协议来，否则测出来的是"账号密码不对"而不是传输层。
  const meta = await c2.keymaterial(user);
  const credential = cs.PhixClient.credential(password, {
    authSalt: meta.auth_salt || meta.kdf_salt, algo: meta.kdf_algo,
  });
  check('v2 账号的登录凭证里没有口令明文（只有 auth_hash）',
    'password' in credential === false && typeof credential.auth_hash === 'string'
    && credential.auth_hash.length === 64, JSON.stringify(credential));
  const marker = `WireMarker-${crypto.randomBytes(4).toString('hex')}`;
  const { envelope: envl, sk } = pc.makeEnvelope(serverPk, 'POST', '/api/v1/auth/login',
    { username: user, ...credential, device: marker }, '');
  const wireBody = JSON.stringify(envl);
  check('请求体里没有口令明文', !wireBody.includes(password));
  check('请求体里没有设备名明文（标记串）', !wireBody.includes(marker));
  check('请求体里没有用户名明文', !wireBody.includes(user));
  check('请求体里没有 password 字段名', !wireBody.includes('password'));
  check('请求体里没有 auth_hash 明文（它也在信封里）', !wireBody.includes(credential.auth_hash));
  check('请求体只有 sealed_sk / iv / ct 三个字段',
    JSON.stringify(Object.keys(envl).sort()) === JSON.stringify(['ct', 'iv', 'sealed_sk']),
    Object.keys(envl).join(','));

  const loginResp = await rawRequest('POST', '/auth/login', wireBody,
    { 'Content-Type': 'application/json; charset=utf-8', 'X-Phix-Enc': '1' });
  check('服务器 200', loginResp.status === 200, `${loginResp.status} ${loginResp.text.slice(0, 120)}`);
  check('响应头标了 X-Phix-Enc', loginResp.headers['x-phix-enc'] === '1', String(loginResp.headers['x-phix-enc']));
  const respJson = jsonOf(loginResp);
  check('响应体也是信封（只有 iv/ct）',
    JSON.stringify(Object.keys(respJson).sort()) === JSON.stringify(['ct', 'iv']), Object.keys(respJson).join(','));
  let opened = null;
  try {
    opened = JSON.parse(pc.openEnvelopeResponse(sk, 'POST', '/api/v1/auth/login', respJson).toString('utf8'));
    check('解开响应信封拿到令牌', Boolean(opened.token));
  } catch (error) {
    check('解开响应信封拿到令牌', false, String(error.message));
  }
  check('响应密文里没有令牌明文（抓到了也没用）', opened ? !loginResp.text.includes(opened.token) : false);
  check('响应密文里没有用户名明文', !loginResp.text.includes(user));

  // ---------- 4. 抗重放 ----------
  console.log('\n[4] 抗重放：同一个信封不许用第二次');
  const replay = pc.makeEnvelope(serverPk, 'POST', '/api/v1/auth/login',
    { username: user, ...credential, device: '重放' }, '');
  const replayBody = JSON.stringify(replay.envelope);
  const encHeaders = { 'Content-Type': 'application/json; charset=utf-8', 'X-Phix-Enc': '1' };
  const r1 = await rawRequest('POST', '/auth/login', replayBody, encHeaders);
  const r2 = await rawRequest('POST', '/auth/login', replayBody, encHeaders);
  check('第一次成功', r1.status === 200, String(r1.status));
  check('重放同一条被拒（400）', r2.status === 400, String(r2.status));
  check('拒绝原因是重复请求', r2.text.includes('重复'), r2.text.slice(0, 160));

  console.log('\n[4b] 过期的时间戳被拒');
  const oldInner = {
    m: 'POST', p: '/api/v1/auth/login', q: '', b: { username: user },
    ts: Math.floor(Date.now() / 1000) - 3600, nonce: pc.b64e(crypto.randomBytes(16)),
  };
  const sk3 = pc.newSessionKey();
  const iv3 = crypto.randomBytes(12);
  const ct3 = pc.sealRaw(sk3, iv3, Buffer.from(JSON.stringify(oldInner), 'utf8'),
    pc.envAad('POST', '/api/v1/auth/login'));
  const sealed3 = pc.sealBox(sk3, serverPk);
  const r3 = await rawRequest('POST', '/auth/login', JSON.stringify({
    sealed_sk: pc.b64e(sealed3), iv: pc.b64e(iv3), ct: pc.b64e(ct3),
  }), encHeaders);
  check('过期请求被拒', r3.status === 400 && r3.text.includes('过期'), r3.text.slice(0, 160));

  // ---------- 5. 篡改 ----------
  console.log('\n[5] 篡改挡得住');
  const tamper = pc.makeEnvelope(serverPk, 'POST', '/api/v1/auth/login',
    { username: user, ...credential }, '');
  const bad = { ...tamper.envelope };
  const rawCt = pc.b64d(bad.ct);
  rawCt[rawCt.length - 1] ^= 0x01;
  bad.ct = pc.b64e(rawCt);
  const r4 = await rawRequest('POST', '/auth/login', JSON.stringify(bad), encHeaders);
  check('改了密文 → 400', r4.status === 400, String(r4.status));

  // 把给 /auth/login 的信封发到别的路径 → AAD 不匹配
  const r5 = await rawRequest('POST', '/auth/register', JSON.stringify(tamper.envelope), encHeaders);
  check('换路径重放 → 400（AAD 绑了路径）', r5.status === 400, String(r5.status));

  const bad2 = { ...tamper.envelope, sealed_sk: pc.b64e(crypto.randomBytes(80)) };
  const r6 = await rawRequest('POST', '/auth/login', JSON.stringify(bad2), encHeaders);
  check('伪造 sealed_sk → 400', r6.status === 400, String(r6.status));

  // ---------- 6. 公钥固定 ----------
  console.log('\n[6] 公钥固定：服务器公钥变了要拒绝（防冒充）');
  const host = SERVER.split('://').slice(-1)[0];
  const pinFile = path.join(PIN, `${host.replace(/[^A-Za-z0-9._-]/g, '_')}.txt`);
  check('首次连接把公钥存下来了', fs.existsSync(pinFile), pinFile);
  check('存的就是服务器公钥', fs.readFileSync(pinFile, 'utf8').trim() === serverPk.toString('hex'));
  fs.writeFileSync(pinFile, `${'ab'.repeat(32)}\n`, 'utf8');
  const c3 = new cs.PhixClient(SERVER, null, 30000, { pinDir: PIN });
  let pinError = null;
  try {
    await c3.ensureE2e();
  } catch (error) { pinError = error; }
  check('公钥对不上要报错', pinError && pinError.code === 'server_key_changed',
    pinError ? `${pinError.code}: ${pinError.message}` : '居然通过了');
  check('报错信息是中文人话', pinError ? /公钥和本机记住的不一样/.test(pinError.message) : false,
    pinError ? pinError.message : '');
  c3.trustNewServerKey();
  check('重新信任后能连上', (await c3.ensureE2e()) === true && c3.encrypted === true);
  check('重新信任后固定文件写的是新公钥',
    fs.readFileSync(pinFile, 'utf8').trim() === serverPk.toString('hex'));

  // ---------- 7. 明文回退 ----------
  console.log('\n[7] 明文路径完全不受影响（老客户端 / curl / 心履服务间调用）');
  const r7 = await rawRequest('POST', '/auth/login', JSON.stringify({ username: user, ...credential }));
  check('不带 X-Phix-Enc 头 → 仍走明文且成功',
    r7.status === 200 && jsonOf(r7).ok === true, String(r7.status));
  const plainClient = new cs.PhixClient(SERVER, null, 30000, { e2e: false });
  check('客户端可以显式关掉加密', Boolean((await plainClient.login(user, password)).token));
  check('关掉加密时不发信封（走明文）', plainClient.encrypted === false);

  const noEncServer = new cs.PhixClient('http://127.0.0.1:9', null, 1000, { pinDir: PIN });
  const declined = await noEncServer.ensureE2e();
  check('服务器不可达时不抛错、只退回明文', declined === false && noEncServer.encrypted === false);

  // ---------- 8. 大对象 ----------
  console.log('\n[8] 大对象也要能过（信封会让体积膨胀 ~1.33 倍）');
  // 先量一下"信封在网线上有多大"：900 KB 明文的密封对象信封约 1.2 MB，
  // 加密后再包一层请求信封（base64）会到 ~1.6 MB —— 要看服务端的请求体上限。
  const big = crypto.randomBytes(900 * 1024);
  const bigEnv = pc.sealObject(material.dek, userId, 'agent:big', big);
  const wireEstimate = pc.makeEnvelope(serverPk, 'PUT', '/api/v1/sync/objects/agent:big',
    { base_revision: 0, payload: bigEnv, device: '大对象测试' }, '').envelope;
  const wireBytes = Buffer.byteLength(JSON.stringify(wireEstimate), 'utf8');
  console.log(`  （900KB 明文 → 对象信封 ${(bigEnv.length / 1048576).toFixed(2)} MB `
    + `→ 网线请求体 ${(wireBytes / 1048576).toFixed(2)} MB）`);
  const c5 = new cs.PhixClient(SERVER, token, 30000, { pinDir: PIN });
  let bigError = null;
  let r8 = null;
  try {
    r8 = await c5.putObject('agent:big', 0, bigEnv, '大对象测试');
  } catch (error) { bigError = error; }
  check('900KB 明文的信封装得下（网线请求体 ~1.6MB）',
    r8 && r8.revision === 1,
    bigError ? `${bigError.code}/${bigError.status}: ${bigError.message}` : JSON.stringify(r8).slice(0, 160));
  if (r8) {
    const back = await c5.getObject('agent:big');
    check('取回来逐字节一致',
      pc.unsealObject(material.dek, userId, 'agent:big', back.payload).equals(big));
  }
  // 再测一个"请求体刚过 2.5 MB（Django 默认上限）"的量级，确认服务端确实放开了
  const mid = crypto.randomBytes(1500 * 1024);
  const midEnv = pc.sealObject(material.dek, userId, 'agent:mid', mid);
  const midWire = Buffer.byteLength(JSON.stringify(pc.makeEnvelope(serverPk, 'PUT',
    '/api/v1/sync/objects/agent:mid', { base_revision: 0, payload: midEnv, device: '中等' }, '').envelope), 'utf8');
  let midError = null;
  try {
    await c5.putObject('agent:mid', 0, midEnv, '中等');
  } catch (error) { midError = error; }
  check('1.5MB 明文（网线请求体 ~2.7MB，超过 Django 默认的 2.5MB）也过得去',
    !midError, midError ? `${midError.code}/${midError.status}: ${midError.message}` : '');
  void midWire;

  // ---------- 9. 服务端解不开信封时的明文错误 ----------
  console.log('\n[9] 信封打不开时服务端回的是明文错误，客户端要按内容判断');
  const brokenResp = await rawRequest('POST', '/auth/login', JSON.stringify({ sealed_sk: 'x', iv: 'y', ct: 'z' }), encHeaders);
  const brokenJson = jsonOf(brokenResp);
  check('服务端回的是明文错误（不带 iv/ct）',
    brokenResp.status === 400 && !('ct' in brokenJson), brokenResp.text.slice(0, 120));
  const brokenClient = new cs.PhixClient(SERVER, null, 30000, { pinDir: PIN });
  let clientError = null;
  try {
    await brokenClient.login('definitely-not-a-user', 'x');
  } catch (error) { clientError = error; }
  check('客户端把明文错误当普通错误抛（不是"信封解不开"）',
    clientError && clientError.code !== 'bad_envelope',
    clientError ? `${clientError.code}: ${clientError.message}` : '居然成功了');

  console.log('\n' + '='.repeat(78));
  console.log(`通过 ${PASSED.length} 项，失败 ${FAILED.length} 项`);
  if (FAILED.length) {
    console.log('失败清单：');
    for (const name of FAILED) console.log(`  - ${name}`);
  }
  console.log(`实验目录（可整删，与真实数据无关）：${LAB}`);
  console.log('='.repeat(78));
  return FAILED.length ? 1 : 0;
}

main()
  .then((code) => { process.exitCode = code; })
  .catch((error) => {
    console.error('\n测试脚本本身出错：', error && error.stack ? error.stack : error);
    process.exitCode = 2;
  });

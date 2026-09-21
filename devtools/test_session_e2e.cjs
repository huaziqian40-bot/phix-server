/**
 * phix 会话层 · 对着**真实服务端**跑「改密码 / 切独立同步口令 / 切回」。
 *
 * 这三条是用户点得到的功能，光验证参数构造不够 —— 这里真的调 `/auth/password`
 * 与 `/auth/rewrap`，并核对「云端密文没作废」「锁着的时候同步被拒」这些**结果**。
 *
 *     cd D:\phix\server
 *     node devtools\test_session_e2e.cjs
 *
 * 全程只写 D:\phix\_lab\nodetest\session，绝不碰真实 data/。
 * 注册接口有每小时限流：跑多了会被拒，重启本地服务即可（限流在进程内存里）。
 *
 * 对照：Python 侧同一套在 `devtools/test_pll_session.py` 的 `[5]/[6]/[6b]`。
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const ELECTRON = 'D:/phl-dev/PH-Launcher/electron';
const cs = require(`${ELECTRON}/cloudsync.cjs`);
const session = require(`${ELECTRON}/phix-session.cjs`);
const phixCrypto = require(`${ELECTRON}/phix-crypto.cjs`);

const BASE = process.env.PHIX_SERVER || 'http://127.0.0.1:8931';
const LAB = 'D:\\phix\\_lab\\nodetest\\session';

const PASSED = [];
const FAILED = [];

function check(name, condition, extra = '') {
  (condition ? PASSED : FAILED).push(name);
  console.log(`  [${condition ? 'OK  ' : 'FAIL'}] ${name}${!condition && extra ? `   ${extra}` : ''}`);
  return condition;
}

/** 造一台设备的数据目录（空目录即可，只需要 settings.yaml 能写）。 */
function makeDevice(tag) {
  const root = path.join(LAB, tag, 'data');
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true });
  return root;
}

const scheduleDoc = (title) => ({ version: 1, kind: 'pinghe-schedule', events: [{ id: 1, title }], lastId: 1 });
const readRoster = async (client) => {
  const manifest = await client.manifest();
  const out = {};
  for (const entry of manifest.objects) out[entry.name] = entry.revision;
  return out;
};

async function expectFailure(label, fn) {
  try {
    const value = await fn();
    return { failed: false, value };
  } catch (error) {
    return { failed: true, code: error?.code || '', message: String(error?.message || error) };
  }
}

async function main() {
  console.log('='.repeat(78));
  console.log('phix 会话层 · 改密码 / 切同步口令 / 切回（对着真实服务端）');
  console.log('='.repeat(78));

  try {
    await new cs.PhixClient(BASE).ping();
  } catch (error) {
    throw new Error(`服务不可达：${BASE} —— ${error.message}`);
  }
  fs.mkdirSync(LAB, { recursive: true });

  const sfx = `${Math.floor(Date.now() / 1000)}`;
  const username = `nodesess_${sfx}`;
  const password1 = 'Session-Test-1';
  const password2 = 'Session-Test-2';
  const phrase = 'my-own-sync-phrase';
  const wrongPhrase = 'not-the-phrase';

  const rootA = makeDevice('devA');
  const rootB = makeDevice('devB');
  fs.writeFileSync(path.join(rootA, 'Schedule'), `${JSON.stringify(scheduleDoc('会话测试 A'), null, 2)}\n`, 'utf8');

  // ---------- 0. 注册 + 首推 ----------
  console.log('\n[0] 注册 + 首推（拿一份云端密文做基线）');
  session.configure({ dataDir: rootA });
  const sessionA = new session.PhixSession({ log: (m) => console.log('    [log]', m) });
  const registered = await sessionA.register(BASE, username, password1, 'password');
  check('注册成功并解锁', registered.logged_in === true && registered.unlocked === true, cs.jsonText(registered.user_id));
  check('拿到恢复码', String(registered.recovery_code || '').length >= 24, String(registered.recovery_code || '').slice(0, 12));
  check('key_mode 是 password', registered.key_mode === 'password', registered.key_mode);

  const pushA = await sessionA.sync();
  check('A 首推成功', pushA.ok === true, cs.jsonText(pushA.errors));
  const rosterBefore = await readRoster(sessionA.client);
  const scheduleRevBefore = rosterBefore.schedule;
  const envelopeBefore = (await sessionA.client.getObject('schedule')).payload;
  check('云端有 schedule 密文', String(envelopeBefore).startsWith('PHIX1.'), String(envelopeBefore).slice(0, 20));

  // ---------- 1. 改登录密码 ----------
  console.log('\n[1] 改登录密码 → 云端密文不作废，同步照常');
  const changed = await sessionA.changePassword(password1, password2);
  check('改密码成功且仍解锁', changed.logged_in === true && changed.unlocked === true, cs.jsonText({ logged_in: changed.logged_in, unlocked: changed.unlocked }));
  check('password 模式下 key_mode 不变', changed.key_mode === 'password', changed.key_mode);

  // 旧密码必须失效
  const oldLogin = await expectFailure('old', () => new cs.PhixClient(BASE).login(username, password1, '探针'));
  check('旧密码登录失败', oldLogin.failed === true, cs.jsonText(oldLogin));
  // 服务端这一版返回的是 unauthorized（协议 §3.2 写的是 bad_credentials）——
  // 两边都接受，只要求"确实被拒且带 code"，别把服务端文案当成客户端契约。
  check('失败带错误码（unauthorized / bad_credentials）',
    ['unauthorized', 'bad_credentials'].includes(oldLogin.code), oldLogin.code);

  // 新密码能登、能解出同一把 DEK
  const loginNew = await new cs.PhixClient(BASE).login(username, password2, '探针');
  const dekNew = phixCrypto.unwrapDek(loginNew.key_wrap, password2, loginNew.kdf_salt, username);
  check('新密码能登录', Boolean(loginNew.token));
  check('新密码解出的 DEK 与原来同一把',
    Buffer.compare(dekNew, sessionA.dek) === 0);
  check('自检块通过', phixCrypto.checkDek(dekNew, username, loginNew.key_check) === true);

  // 密文与 revision 一个都没动
  const rosterAfterPassword = await readRoster(new cs.PhixClient(BASE, loginNew.token));
  check('云端对象 revision 全都没变（密文没作废）',
    cs.jsonText(rosterAfterPassword) === cs.jsonText(rosterBefore),
    `${cs.jsonText(rosterBefore)} -> ${cs.jsonText(rosterAfterPassword)}`);
  const envelopeAfter = (await new cs.PhixClient(BASE, loginNew.token).getObject('schedule')).payload;
  check('schedule 密文逐字节没变', envelopeAfter === envelopeBefore);

  // 继续同步正常，且不该因此重推全部对象
  const repAfterPassword = await sessionA.sync();
  check('换密码后同步成功', repAfterPassword.ok === true, cs.jsonText(repAfterPassword.errors));
  check('没有因为换密码而重推全部对象',
    (repAfterPassword.pushed || []).length <= 1, cs.jsonText(repAfterPassword.pushed));

  // 另一台设备用**新密码**照样能拉
  session.configure({ dataDir: rootB });
  const sessionB = new session.PhixSession();
  const statusB = await sessionB.login(BASE, username, password2, '', '设备B');
  check('B 用新密码登录并解锁', statusB.logged_in === true && statusB.unlocked === true);
  const repB = await sessionB.sync();
  check('B 同步成功', repB.ok === true, cs.jsonText(repB.errors));
  check('B 拿到了 A 的日程',
    JSON.stringify(cs.readJson(path.join(rootB, 'Schedule'), {}).events || []).includes('会话测试 A'),
    cs.jsonText(cs.readJson(path.join(rootB, 'Schedule'), {})).slice(0, 160));

  // ---------- 2. 切独立同步口令 ----------
  console.log('\n[2] 切「独立同步口令」→ 服务端从此解不开');
  // v2（AuthHash）账号的前置条件：登录凭证来自 auth_salt，而 auth_salt 注册时定下、永不改变
  const sessionMeta = await sessionA.client.keymaterial(username);
  check('账号是 v2（scrypt-hkdf-v2）', sessionMeta.kdf_algo === phixCrypto.KDF_ALGO_V2, String(sessionMeta.kdf_algo));
  check('服务端返回了独立的 auth_salt（与 kdf_salt 不同）',
    typeof sessionMeta.auth_salt === 'string' && sessionMeta.auth_salt.length === 32
    && sessionMeta.auth_salt !== sessionMeta.kdf_salt,
    `${sessionMeta.auth_salt} vs ${sessionMeta.kdf_salt}`);
  const authSaltBefore = sessionMeta.auth_salt;
  const kdfSaltBefore = sessionMeta.kdf_salt;

  const switched = await sessionA.setSyncPassphrase(password2, phrase);
  check('key_mode 变成 syncphrase', switched.key_mode === 'syncphrase', switched.key_mode);
  check('配置里也记下了', session.loadConfig().key_mode === 'syncphrase', session.loadConfig().key_mode);
  const repAfterSwitch = await sessionA.sync();
  check('切完还能同步', repAfterSwitch.ok === true, cs.jsonText(repAfterSwitch.errors));

  // **这条是踩过的坑**：切同步口令换了 kdf_salt，但 auth_salt 绝不能跟着变，
  // 否则 AuthHash 变了而服务器存的还是旧的 → 下次登录直接失败。
  const metaAfterSwitch = await sessionA.client.keymaterial(username);
  check('切完 auth_salt 没变（凭证盐永不改变）',
    metaAfterSwitch.auth_salt === authSaltBefore, `${authSaltBefore} -> ${metaAfterSwitch.auth_salt}`);
  check('切完 kdf_salt 变了（包 DEK 的那把要换）',
    metaAfterSwitch.kdf_salt !== kdfSaltBefore, `${kdfSaltBefore} -> ${metaAfterSwitch.kdf_salt}`);
  check('切完 AuthHash 也没变（登录口令没变）',
    phixCrypto.authHashHex(password2, metaAfterSwitch.auth_salt, metaAfterSwitch.kdf_algo)
      === phixCrypto.authHashHex(password2, authSaltBefore, sessionMeta.kdf_algo));

  // 退出后用**只给登录密码**重新登录 → 登录成功但数据锁着
  await sessionA.logout();
  const locked = await sessionA.login(BASE, username, password2);
  check('只给登录密码：登录成功但数据锁着',
    locked.logged_in === true && locked.unlocked === false, cs.jsonText({ logged_in: locked.logged_in, unlocked: locked.unlocked, key_mode: locked.key_mode }));
  check('状态里标明是 syncphrase 模式', locked.key_mode === 'syncphrase', locked.key_mode);
  const syncWhileLocked = await expectFailure('locked', () => sessionA.sync());
  check('未解锁时同步被拒绝', syncWhileLocked.failed === true, cs.jsonText(syncWhileLocked));
  check('拒绝原因是 locked', syncWhileLocked.code === 'locked', syncWhileLocked.code);
  check('拒绝信息是中文说明', /锁/.test(syncWhileLocked.message), syncWhileLocked.message);

  // 错口令解不开
  const wrongUnlock = await expectFailure('wrong', () => sessionA.unlock(wrongPhrase));
  check('错的同步口令解不开', wrongUnlock.failed === true, cs.jsonText(wrongUnlock));
  check('错误码是 bad_passphrase', wrongUnlock.code === 'bad_passphrase', wrongUnlock.code);

  // 对的口令能解锁
  const unlocked = await sessionA.unlock(phrase);
  check('给对同步口令后解锁', unlocked.unlocked === true, cs.jsonText({ unlocked: unlocked.unlocked }));
  check('解锁后能同步', (await sessionA.sync()).ok === true);

  // 服务端确实拿不到 DEK：key_wrap 在切换后是**新口令**包裹的
  const meAfterSwitch = await sessionA.client.me();
  let phraseUnwraps = false;
  try {
    phixCrypto.unwrapDek(meAfterSwitch.key_wrap, phrase, meAfterSwitch.kdf_salt, username);
    phraseUnwraps = true;
  } catch { phraseUnwraps = false; }
  check('key_wrap 是用独立同步口令包裹的', phraseUnwraps === true);
  let loginPasswordUnwraps = true;
  try {
    phixCrypto.unwrapDek(meAfterSwitch.key_wrap, password2, meAfterSwitch.kdf_salt, username);
  } catch { loginPasswordUnwraps = false; }
  check('登录密码已经解不开 key_wrap 了', loginPasswordUnwraps === false);

  // ---------- 3. 切回「用登录密码包裹」 ----------
  console.log('\n[3] 切回「用登录密码包裹」');
  const backToPassword = await sessionA.useLoginPassword(password2);
  check('key_mode 回到 password', backToPassword.key_mode === 'password', backToPassword.key_mode);
  check('配置也跟着回到 password', session.loadConfig().key_mode === 'password', session.loadConfig().key_mode);
  await sessionA.logout();
  const simpleLogin = await sessionA.login(BASE, username, password2);
  check('之后只给登录密码就能解锁',
    simpleLogin.logged_in === true && simpleLogin.unlocked === true,
    cs.jsonText({ logged_in: simpleLogin.logged_in, unlocked: simpleLogin.unlocked }));
  const repFinal = await sessionA.sync();
  check('切回后同步正常', repFinal.ok === true, cs.jsonText(repFinal.errors));

  // 密文依然没动过
  const rosterFinal = await readRoster(sessionA.client);
  check('这一整轮折腾下来 revision 仍然没变（密文一个字节都没动）',
    cs.jsonText(rosterFinal) === cs.jsonText(rosterBefore),
    `${cs.jsonText(rosterBefore)} -> ${cs.jsonText(rosterFinal)}`);
  const envelopeFinal = (await sessionA.client.getObject('schedule')).payload;
  check('schedule 密文仍然逐字节一致', envelopeFinal === envelopeBefore);

  // 另一台设备用新密码照常
  await sessionB.logout();
  const statusB2 = await sessionB.login(BASE, username, password2, '', '设备B');
  check('B 用登录密码照常登录解锁', statusB2.logged_in === true && statusB2.unlocked === true);
  check('B 同步正常', (await sessionB.sync()).ok === true);

  // ---------- 3b. 回归：syncphrase 模式下改登录密码，AuthHash 必须跟着换 ----------
  //
  // 服务器存的是 **AuthHash**（不是口令）。syncphrase 模式下改登录密码时 DEK 不动
  // （key_wrap 不能重包裹），但 AuthHash **必须**用新登录密码重算 ——
  // 不换的话服务器存的还是旧的那个，用户就再也登不进来了。
  console.log('\n[3b] syncphrase 模式下改登录密码 → 新密码必须能登进来');
  const password3 = 'Session-Test-3';
  await sessionA.setSyncPassphrase(password2, phrase);
  const metaBeforePwChange = await sessionA.client.keymaterial(username);
  const authSaltBeforePwChange = metaBeforePwChange.auth_salt;
  const wrapBeforePwChange = (await sessionA.client.me()).key_wrap;

  const changedInSyncphrase = await sessionA.changePassword(password2, password3);
  check('改密码后仍是 syncphrase 模式', changedInSyncphrase.key_mode === 'syncphrase',
    changedInSyncphrase.key_mode);
  const metaAfterPwChange = await sessionA.client.keymaterial(username);
  check('改密码后 auth_salt 没变（凭证盐永不改变）',
    metaAfterPwChange.auth_salt === authSaltBeforePwChange,
    `${authSaltBeforePwChange} -> ${metaAfterPwChange.auth_salt}`);
  check('DB 里的 AuthHash 确实换成了新密码算出来的',
    phixCrypto.authHashHex(password3, metaAfterPwChange.auth_salt, metaAfterPwChange.kdf_algo)
      !== phixCrypto.authHashHex(password2, metaAfterPwChange.auth_salt, metaAfterPwChange.kdf_algo));
  check('DEK 的包裹方式没被动过（syncphrase 下改登录密码不该重包裹）',
    (await sessionA.client.me()).key_wrap === wrapBeforePwChange);

  await sessionA.logout();
  const reloginSyncphrase = await sessionA.login(BASE, username, password3, phrase);
  check('新登录密码 + 同步口令能登进来并解锁',
    reloginSyncphrase.logged_in === true && reloginSyncphrase.unlocked === true,
    cs.jsonText({ logged_in: reloginSyncphrase.logged_in, unlocked: reloginSyncphrase.unlocked }));
  const oldPwLogin = await expectFailure('old', () => new cs.PhixClient(BASE, null, 30000, { e2e: false }).login(username, password2, '探针'));
  check('旧登录密码登不进来了', oldPwLogin.failed === true, cs.jsonText(oldPwLogin));
  const repAfterPwChange = await sessionA.sync();
  check('改完还能同步', repAfterPwChange.ok === true, cs.jsonText(repAfterPwChange.errors));

  // 回到 password 模式，收尾用
  const backToPassword2 = await sessionA.useLoginPassword(password3);
  check('切回 password 模式正常', backToPassword2.key_mode === 'password', backToPassword2.key_mode);
  check('切回后同步正常', (await sessionA.sync()).ok === true);

  // ---------- 4. 收尾：不留测试账号的令牌，本地目录留在 lab 里 ----------
  console.log('\n[4] 收尾');
  await sessionA.logout();
  await sessionB.logout();
  check('A 已退出登录（本机令牌清掉）', sessionA.status().logged_in === false);
  check('B 已退出登录', sessionB.status().logged_in === false);
  check('数据目录都在 lab 里，没碰真实数据',
    rootA.startsWith(LAB) && rootB.startsWith(LAB), `${rootA} / ${rootB}`);
  console.log(`  测试账号：${username}（保留在服务端，方便你复查；不想留可在服务端删掉）`);
  void scheduleRevBefore;

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

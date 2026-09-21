/**
 * PHL(Node)侧的驱动脚本 —— 给跨程序互通测试用。
 *
 * 它**不是** PHL 的一部分，只是把 PHL 的 cloudsync 当库来调，方便 Python 那头编排
 * 「PLL 与 PHL 对着同一个 data/ 轮流同步」这种场景。
 *
 *   node phl_driver.cjs sync   <server> <user> <pass> <dataDir> [device]
 *   node phl_driver.cjs add    <dataDir> <title> [day]
 *   node phl_driver.cjs account <user>
 *
 * 一律输出一行 JSON 到 stdout（前面可能有日志，取最后一行）。
 */
'use strict';

const path = require('path');
const fs = require('fs');

const PHL_ELECTRON = process.env.PHL_ELECTRON_DIR || 'D:\\phl-dev\\PH-Launcher\\electron';
const cloudsync = require(path.join(PHL_ELECTRON, 'cloudsync.cjs'));
const crypto = require(path.join(PHL_ELECTRON, 'phix-crypto.cjs'));

function emit(obj) {
  process.stdout.write('\n__PHL_RESULT__' + JSON.stringify(obj) + '\n');
}

function readSchedule(dataDir) {
  const p = path.join(dataDir, 'Schedule');
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    return { version: 1, kind: 'pinghe-schedule', events: [], lastId: 0 };
  }
}

function writeSchedule(dataDir, doc) {
  fs.writeFileSync(path.join(dataDir, 'Schedule'),
    JSON.stringify(doc, null, 2) + '\n', 'utf8');
}

async function cmdSync([server, username, password, dataDir, device]) {
  const client = new cloudsync.PhixClient(server);
  const info = await client.login(username, password, device || 'PHL驱动');
  // login() 只返回令牌，不会自动装到客户端上（与 Python 版一致，由调用方负责）
  client.token = info.token;
  const dek = crypto.unwrapDek(info.key_wrap, password, info.kdf_salt, info.username);
  const engine = new cloudsync.SyncEngine(client, dek, info.user_id, info.username,
    { dataDir, device: device || 'PHL驱动' });
  const report = await engine.sync();
  emit({
    ok: !!report.ok,
    skipped: report.skipped || null,
    username: info.username,
    user_id: info.user_id,
    accountName: engine.accountName,
    statePath: engine.statePath,
    actions: Object.fromEntries(Object.entries(report.objects || {})
      .map(([k, v]) => [k, v.action])),
    pushed: report.pushed || [],
    pulled: report.pulled || [],
    conflicts: (report.conflicts || []).length,
    errors: report.errors || [],
  });
}

function cmdAdd([dataDir, title, day]) {
  const doc = readSchedule(dataDir);
  const events = doc.events || [];
  const maxId = Math.max(doc.lastId || 0, ...events.map((e) => e.id || 0), 0);
  const id = maxId + 1;
  events.push({
    id, day: day || '2026-11-11', time: '09:00', title,
    note: 'PHL 加的', created: new Date().toISOString(),
  });
  doc.events = events;
  doc.lastId = id;
  writeSchedule(dataDir, doc);
  emit({ ok: true, id, count: events.length });
}

function cmdAccount([username]) {
  emit({ ok: true, accountName: cloudsync.safeAccountName
    ? cloudsync.safeAccountName(username)
    : new cloudsync.SyncEngine(null, Buffer.alloc(32), 0, username, {}).accountName });
}

/**
 * 走 PHL 的**会话层**（用户真正点的那条路）跑一遍
 * 注册 → 换登录密码 → 切独立同步口令 → 切回，并核对云端密文没作废。
 */
async function cmdSessionTest([server, username, password, dataDir]) {
  const session = require(path.join(PHL_ELECTRON, 'phix-session.cjs'));
  session.configure({ dataDir });

  const out = {};
  const mk = () => new session.PhixSession({ log: () => {} });

  const s1 = mk();
  const reg = await s1.register(server, username, password);
  out.register = { logged_in: !!reg.logged_in, unlocked: !!reg.unlocked,
                   has_recovery: (reg.recovery_code || '').length >= 24 };
  const rep0 = await s1.sync();
  out.first_sync_ok = !!rep0.ok;
  const revBefore = (await s1.client.getObject('schedule')).revision;

  // ---- 换登录密码 ----
  const newPass = password + '-new';
  const stCp = await s1.changePassword(password, newPass);
  out.after_change = { logged_in: !!stCp.logged_in, key_mode: stCp.key_mode };

  const s2 = mk();
  try {
    await s2.login(server, username, password);
    out.old_password_rejected = false;
  } catch (e) { out.old_password_rejected = true; }

  const s3 = mk();
  const st3 = await s3.login(server, username, newPass);
  out.new_password_ok = !!(st3.logged_in && st3.unlocked);
  const revAfter = (await s3.client.getObject('schedule')).revision;
  out.revision_unchanged = revBefore === revAfter;
  out.rev = { before: revBefore, after: revAfter };
  out.sync_after_change = !!(await s3.sync()).ok;

  // ---- 切独立同步口令 ----
  const phrase = 'phl-own-phrase-9';
  const stSp = await s3.setSyncPassphrase(newPass, phrase);
  out.after_set_phrase = { key_mode: stSp.key_mode };

  const s4 = mk();
  const st4 = await s4.login(server, username, newPass);
  out.locked_without_phrase = !!(st4.logged_in && !st4.unlocked);
  try {
    await s4.sync();
    out.sync_blocked_when_locked = false;
  } catch (e) { out.sync_blocked_when_locked = true; }

  const s5 = mk();
  const st5 = await s5.login(server, username, newPass, phrase);
  out.unlock_with_phrase = !!(st5.logged_in && st5.unlocked);
  out.sync_with_phrase = !!(await s5.sync()).ok;

  // ---- 切回用登录密码包裹 ----
  const stBack = await s5.useLoginPassword(newPass);
  out.after_back = { key_mode: stBack.key_mode };
  const s6 = mk();
  const st6 = await s6.login(server, username, newPass);
  out.plain_login_after_back = !!(st6.logged_in && st6.unlocked);

  out.ok = true;
  emit(out);
}

(async () => {
  const [cmd, ...rest] = process.argv.slice(2);
  try {
    if (cmd === 'sync') await cmdSync(rest);
    else if (cmd === 'add') cmdAdd(rest);
    else if (cmd === 'account') cmdAccount(rest);
    else if (cmd === 'session-test') await cmdSessionTest(rest);
    else emit({ ok: false, error: 'unknown command: ' + cmd });
  } catch (err) {
    emit({ ok: false, error: String((err && err.message) || err),
           code: (err && err.code) || null });
  }
})();

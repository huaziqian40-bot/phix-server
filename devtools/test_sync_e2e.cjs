/**
 * phix 云同步 · Node 侧双设备端到端验证（PHL 的 `electron/cloudsync.cjs`）。
 *
 * **全程在副本上跑，绝不碰真实 data/。**
 * 源数据只读复制自 `D:\HPHL\testenv\data`，测试用两个隔离的数据目录。
 *
 *     cd D:\phix\server
 *     node devtools\test_sync_e2e.cjs
 *
 * 场景与 `devtools/test_sync_e2e.py`（Python 侧 46 项）逐条对应，另加 PHL 侧特有项
 * （settings.yaml 注释/未知段保留、revision_conflict 重试、单对象名同步、并发护栏、
 * **按账号隔离的状态/快照与老布局迁移**）。
 *
 *     PHIX_SERVER=http://127.0.0.1:8931   服务地址（默认本机 8931）
 *     PHIX_SOURCE=D:\HPHL\testenv\data    只读源数据
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ELECTRON = 'D:/phl-dev/PH-Launcher/electron';
const cs = require(`${ELECTRON}/cloudsync.cjs`);
const phixCrypto = require(`${ELECTRON}/phix-crypto.cjs`);
const sharedSettings = require(`${ELECTRON}/settings-yaml.cjs`);

const BASE = process.env.PHIX_SERVER || 'http://127.0.0.1:8931';
const SOURCE = process.env.PHIX_SOURCE || 'D:\\HPHL\\testenv\\data';
const LAB = 'D:\\phix\\_lab\\nodetest';

const PASSED = [];
const FAILED = [];

function check(name, condition, extra = '') {
  (condition ? PASSED : FAILED).push(name);
  console.log(`  [${condition ? 'OK  ' : 'FAIL'}] ${name}${!condition && extra ? `   ${extra}` : ''}`);
  return condition;
}

// ---------------------------------------------------------------- 工具
function copyTree(from, to, filter = () => true) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    if (!filter(entry.name)) continue;
    const src = path.join(from, entry.name);
    const dst = path.join(to, entry.name);
    if (entry.isDirectory()) copyTree(src, dst);
    else if (entry.isFile()) fs.copyFileSync(src, dst);
  }
}

/**
 * 从真实数据的**副本**造一台"设备"的 data 目录。
 *
 * 只跳过运行标记：真实 testenv 里那份 `.pll-running` 是 PLL 自己留下的，
 * 复制过来会让"对方程序正在运行"的护栏判定命中，同步直接跳过。
 */
function makeDevice(tag) {
  const dst = path.join(LAB, `dev${tag}`, 'data');
  fs.rmSync(dst, { recursive: true, force: true });
  copyTree(SOURCE, dst, (name) => name !== '.pll-running' && name !== '.phl-running');
  return dst;
}

const readSchedule = (root) => cs.readJson(path.join(root, 'Schedule'), {}) || {};
const eventsOf = (root) => {
  const out = {};
  for (const event of readSchedule(root).events || []) out[event.id] = event;
  return out;
};
const titlesOf = (root) => new Set(Object.values(eventsOf(root)).map((event) => event.title));
const readTimetable = (root) => cs.readJson(path.join(root, 'Timetable'), {}) || {};
const readSchool = (root) => cs.readJson(path.join(root, 'School'), {}) || {};
const writeSchedule = (root, doc) => cs.writeJson(path.join(root, 'Schedule'), doc);

const engine = (client, dek, userId, username, root, tag) => new cs.SyncEngine(
  client, dek, userId, username, { dataDir: root, device: tag, siblingApp: 'pll' },
);

const changed = (report) => Object.entries(report.objects)
  .filter(([, entry]) => !['noop', 'skip', 'remote-deleted'].includes(entry.action))
  .map(([name]) => name);

// ---------------------------------------------------------------- 主流程
async function main() {
  if (!fs.existsSync(SOURCE)) throw new Error(`找不到真实数据目录 ${SOURCE}`);
  fs.mkdirSync(LAB, { recursive: true });

  console.log('='.repeat(78));
  console.log('phix 云同步 · Node 侧双设备端到端（数据全程用副本，源目录只读）');
  console.log('='.repeat(78));

  const rootA = makeDevice('A');
  const rootB = makeDevice('B');
  const rootC = makeDevice('C');           // 第三台：只用于 revision_conflict 重试
  console.log(`\n设备 A: ${rootA}`);
  console.log(`设备 B: ${rootB}`);
  console.log(`设备 C: ${rootC}（仅用于冲突重试）`);
  console.log(`起始日程条数: A=${Object.keys(eventsOf(rootA)).length} B=${Object.keys(eventsOf(rootB)).length}`);

  const suffix = `${Math.floor(Date.now() / 1000)}`;
  const username = `nodee2e_${suffix}`;
  const password = 'Sync-Test-123';

  // ---------- 0. 服务连通 ----------
  console.log('\n[0] 服务连通与本地原语');
  const anon = new cs.PhixClient(BASE);
  const pingStart = Date.now();
  const ping = await anon.ping();
  console.log(`  （首次请求耗时 ${Date.now() - pingStart} ms，timeout=${anon.timeout}）`);
  check('phix 服务可达', ping.ok === true, JSON.stringify(ping).slice(0, 200));
  check('服务端声明支持两种密钥模式',
    Array.isArray(ping.key_modes) && ping.key_modes.includes('syncphrase'), JSON.stringify(ping.key_modes));

  const sample = { b: 1, a: '中文' };
  check('哈希与 Python 侧一致（排序键 + 无空格 + 不转义中文）',
    cs.hashDocument(sample) === crypto.createHash('sha256')
      .update(Buffer.from('{"a":"中文","b":1}', 'utf8')).digest('hex'),
    cs.documentBytes(sample).toString('utf8'));
  check('时间戳带本地时区偏移', /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/.test(cs.nowIso()),
    cs.nowIso());
  check('空文档哈希为空串', cs.hashDocument(null) === '');

  const [info, material] = await anon.register(username, password, '设备A');
  check('注册成功', Boolean(info.token) && info.user_id > 0, JSON.stringify(info).slice(0, 200));
  const userId = info.user_id;
  const tokenA = info.token;
  const dek = material.dek;
  const recoveryCode = material.recovery_code;
  console.log(`  注册成功 user_id=${userId} username=${username} 恢复码=${recoveryCode}`);

  // ---------- 1. A 首推 ----------
  console.log('\n[1] A 首次同步（把本地全部推上云）');
  const ca = new cs.PhixClient(BASE, tokenA);
  const ea = engine(ca, dek, userId, username, rootA, '设备A');
  const reportA = await ea.sync();
  const pushedA = Object.entries(reportA.objects).filter(([, e]) => e.action === 'push').map(([n]) => n);
  check('A 首推成功', reportA.ok === true, JSON.stringify(reportA.errors));
  for (const name of ['schedule', 'settings.lessons', 'settings.accounts', 'timetable', 'school']) {
    check(`推了 ${name}`, pushedA.includes(name), JSON.stringify(pushedA));
  }
  check('推了 AI 会话对象', pushedA.some((n) => n.startsWith('agent:')), JSON.stringify(pushedA));

  const manifest = await ca.manifest();
  const cloudNames = manifest.objects.map((o) => o.name);
  check('云端没有 phll/ 私有对象',
    !cloudNames.some((n) => /^(phll|phl|logs|_backups|\.sync)/.test(n)), JSON.stringify([...cloudNames].sort()));
  check('云端没有 .gh_token', !cloudNames.includes('.gh_token'));

  // ---------- 2. B 登录并拉取 ----------
  console.log('\n[2] B 登录 + 拉取，应与 A 完全一致');
  const login = await new cs.PhixClient(BASE).login(username, password, '设备B');
  const tokenB = login.token;
  const dekB = phixCrypto.unwrapDek(login.key_wrap, password, login.kdf_salt, username);
  check('B 解出同一把 DEK', Buffer.compare(dekB, dek) === 0);
  check('B 自检块解得开（口令正确）', phixCrypto.checkDek(dekB, username, login.key_check) === true);

  const rootBOld = path.join(LAB, 'devB-empty', 'data');
  fs.rmSync(rootBOld, { recursive: true, force: true });
  copyTree(SOURCE, rootBOld, (name) => name !== '.pll-running' && name !== '.phl-running');
  // B 用"清空了本地内容"的副本，才能真正验证"远端数据被拉了下来"
  fs.writeFileSync(path.join(rootBOld, 'Schedule'), JSON.stringify({ version: 1, kind: 'pinghe-schedule', events: [], lastId: 0 }), 'utf8');
  fs.writeFileSync(path.join(rootBOld, 'Timetable'), JSON.stringify({ version: 1, kind: 'pinghe-timetable', days: {} }), 'utf8');
  const cb = new cs.PhixClient(BASE, tokenB);
  const eb = engine(cb, dekB, userId, username, rootBOld, '设备B');
  const reportB0 = await eb.sync();
  check('B 同步成功', reportB0.ok === true, JSON.stringify(reportB0.errors));
  check('B 的选课与 A 一致',
    cs.jsonText(ea.collect('settings.lessons')) === cs.jsonText(eb.collect('settings.lessons')));
  check('B 的账号段与 A 一致',
    cs.jsonText(ea.collect('settings.accounts')) === cs.jsonText(eb.collect('settings.accounts')));
  check('B 把 A 的日程拉了回来（本地原本是空的）',
    Object.keys(eventsOf(rootBOld)).length > 0, `${Object.keys(eventsOf(rootBOld)).length} 条`);
  check('B 把 A 的课表拉了回来（本地原本是空的）',
    Object.keys(readTimetable(rootBOld).days || {}).length > 0);
  check('B 的日程与 A 一致',
    cs.sameValue(ea.collect('schedule'), eb.collect('schedule')),
    `${cs.jsonText(ea.collect('schedule')).slice(0, 300)} VS ${cs.jsonText(eb.collect('schedule')).slice(0, 300)}`);

  // 回到"两台设备本地相同"的常规起点
  const ebSame = engine(cb, dekB, userId, username, rootB, '设备B');
  await ebSame.sync();

  // ---------- 3. 两边各加一条日程（含 id 撞车） ----------
  console.log('\n[3] 两边各加一条日程 → 双向合并（含 id 撞车）');
  await ea.sync();
  const schedA = readSchedule(rootA);
  const nextA = Math.max(0, ...(schedA.events || []).map((e) => e.id)) + 1;
  schedA.events = [...(schedA.events || []), { id: nextA, day: '2026-09-25', time: '16:00', title: 'A加的（Node e2e）', note: '', created: cs.nowIso() }];
  schedA.lastId = nextA;
  writeSchedule(rootA, schedA);

  const schedB = readSchedule(rootB);
  const nextB = Math.max(0, ...(schedB.events || []).map((e) => e.id)) + 1;
  schedB.events = [...(schedB.events || []), { id: nextB, day: '2026-09-26', time: '17:00', title: 'B加的（Node e2e）', note: '', created: cs.nowIso() }];
  schedB.lastId = nextB;
  writeSchedule(rootB, schedB);

  const reportA2 = await ea.sync();
  check('A 推送自己那条', reportA2.objects.schedule.action === 'push', cs.jsonText(reportA2.objects.schedule));
  const reportB2 = await ebSame.sync();
  check('B 合并了 A 的那条（action=merge）', reportB2.objects.schedule.action === 'merge',
    cs.jsonText(reportB2.objects.schedule));
  await ea.sync();

  const titlesA = titlesOf(rootA);
  const titlesB = titlesOf(rootB);
  check('A 侧含两条新日程',
    titlesA.has('A加的（Node e2e）') && titlesA.has('B加的（Node e2e）'), JSON.stringify([...titlesA]));
  check('B 侧含两条新日程',
    titlesB.has('A加的（Node e2e）') && titlesB.has('B加的（Node e2e）'), JSON.stringify([...titlesB]));
  check('两端日程条数一致', Object.keys(eventsOf(rootA)).length === Object.keys(eventsOf(rootB)).length,
    `A=${Object.keys(eventsOf(rootA)).length} B=${Object.keys(eventsOf(rootB)).length}`);
  check('跨设备 id 撞车时两份都留下了（远端那条被改号）',
    reportB2.conflicts.some((c) => String(c.note || '').startsWith('两台设备各自新增')),
    cs.jsonText(reportB2.conflicts).slice(0, 300));
  check('两条新日程的 id 不相同',
    new Set(Object.values(eventsOf(rootA))
      .filter((e) => ['A加的（Node e2e）', 'B加的（Node e2e）'].includes(e.title))
      .map((e) => e.id)).size === 2,
    cs.jsonText(Object.values(eventsOf(rootA)).map((e) => [e.title, e.id])));
  const lastIdA = readSchedule(rootA).lastId;
  // lastId 只保证"不小于两边见过的最大 id"（撞车改号可能让它更大），所以判 >=
  check('lastId 取了两边的最大值（不小于）', lastIdA >= Math.max(nextA, nextB),
    `lastId=${lastIdA} nextA=${nextA} nextB=${nextB}`);
  check('lastId 是数字而不是字符串', typeof lastIdA === 'number');

  // ---------- 4. 删除传播 ----------
  console.log('\n[4] A 删一条 → B 同步后也应删掉（三方合并，不是"看不见就当没删"）');
  const before = Object.keys(eventsOf(rootA)).length;
  const schedDel = readSchedule(rootA);
  schedDel.events = schedDel.events.filter((e) => e.title !== 'A加的（Node e2e）');
  writeSchedule(rootA, schedDel);
  await ea.sync();
  await ebSame.sync();
  const titlesAfterDelete = titlesOf(rootB);
  check('B 侧那条已消失', !titlesAfterDelete.has('A加的（Node e2e）'), JSON.stringify([...titlesAfterDelete]));
  check('B 侧还留着 B 自己加的那条', titlesAfterDelete.has('B加的（Node e2e）'));
  check('条数减少 1', Object.keys(eventsOf(rootB)).length === before - 1,
    `${Object.keys(eventsOf(rootB)).length} vs ${before - 1}`);

  // ---------- 5. 冲突：两边改同一条 ----------
  console.log('\n[5] 两边改同一条日程 → 报冲突但不静默丢数据');
  const tid = Object.values(readSchedule(rootA).events).find((e) => e.title === 'B加的（Node e2e）').id;
  // 显式给两边**不同**的 updated_at：合并规则靠它判新旧，同一秒里写两次会让两条
  // 记录在规则眼里"完全相同"，冲突就测不出来了（不是引擎的问题，是测试要造清楚）。
  const stampA = new Date(Date.now() - 2000);
  const stampB = new Date();
  for (const [root, tag, stamp] of [[rootA, 'A改的', stampA], [rootB, 'B改的', stampB]]) {
    const doc = readSchedule(root);
    for (const event of doc.events) {
      if (event.id === tid) { event.note = tag; event.updated_at = cs.nowIso(stamp); }
    }
    writeSchedule(root, doc);
  }
  await ea.sync();
  const reportB3 = await ebSame.sync();
  const conflictsB3 = reportB3.conflicts.filter((c) => String(c.path || '').startsWith('events'));
  check('报告了同一条的冲突', conflictsB3.length > 0, cs.jsonText(reportB3.conflicts).slice(0, 300));
  const mergedNotes = Object.values(eventsOf(rootB)).filter((e) => e.id === tid).map((e) => e.note);
  check('合并后本地内容仍在（没被清空）', mergedNotes.length > 0 && Boolean(mergedNotes[0]), JSON.stringify(mergedNotes));
  await ea.sync();
  check('两端最终一致',
    cs.sameValue(eventsOf(rootA), eventsOf(rootB)),
    `A=${JSON.stringify(eventsOf(rootA))} B=${JSON.stringify(eventsOf(rootB))}`);

  // ---------- 6. 空的一周不清课表 ----------
  console.log('\n[6] 远端「空的一周」绝不许清掉本地课表');
  const timetableB = readTimetable(rootB);
  const daysB = timetableB.days || {};
  const nonEmpty = Object.keys(daysB).filter((day) => (daysB[day] || []).length);
  if (!nonEmpty.length) {
    check('B 有课表可测', false, 'Timetable 里没有非空的一天');
  } else {
    const day = nonEmpty[0];
    const beforeCards = daysB[day].length;
    const timetableA = readTimetable(rootA);
    timetableA.days = { ...(timetableA.days || {}), [day]: [] };
    cs.writeJson(path.join(rootA, 'Timetable'), timetableA);
    await ea.sync();
    await ebSame.sync();
    const afterCards = ((readTimetable(rootB).days || {})[day] || []).length;
    check(`B 的 ${day} 课卡没被清空`, afterCards === beforeCards, `before=${beforeCards} after=${afterCards}`);
  }
  // 整份课表为空也不能清空对方（unionOnly 护栏的另一面）
  const beforeAll = Object.values(readTimetable(rootB).days || {}).reduce((sum, list) => sum + list.length, 0);
  const timetableAEmpty = readTimetable(rootA);
  timetableAEmpty.days = {};
  cs.writeJson(path.join(rootA, 'Timetable'), timetableAEmpty);
  await ea.sync();
  await ebSame.sync();
  const afterAll = Object.values(readTimetable(rootB).days || {}).reduce((sum, list) => sum + list.length, 0);
  check('远端整份课表为空也不清空本地', afterAll === beforeAll, `before=${beforeAll} after=${afterAll}`);

  // ---------- 7. 学校数据并集 ----------
  console.log('\n[7] School 的 managebac / edupage 取并集');
  const schoolB = readSchool(rootB);
  const mbTasks = (schoolB.managebac || {}).tasks || [];
  check('B 有 managebac 数据可测', mbTasks.length > 0, `${mbTasks.length} 条`);
  const schoolA = readSchool(rootA);
  schoolA.managebac = { ...(schoolA.managebac || {}) };
  schoolA.managebac.tasks = [...(schoolA.managebac.tasks || []), {
    id: 'node-e2e-task-1', course_id: '0', course: 'E2E', title: 'Node e2e 造出来的作业',
    due_at: '2026-10-01 23:59', due_text: '', status: 'Pending', score: '',
  }];
  cs.writeJson(path.join(rootA, 'School'), schoolA);
  await ea.sync();
  await ebSame.sync();
  const tasksB = ((readSchool(rootB).managebac || {}).tasks) || [];
  const idsB = tasksB.map((task) => String(task.id));
  check('B 收到了 A 新增的作业（并集）', idsB.includes('node-e2e-task-1'), JSON.stringify(idsB).slice(0, 200));
  check('B 原有的作业没被抹掉', tasksB.length >= mbTasks.length, `${tasksB.length} vs ${mbTasks.length}`);

  // ---------- 8. 二次同步应无事可做 ----------
  console.log('\n[8] 稳定态：再同步一次应当没有变化（收敛性）');
  const r1 = await ea.sync();
  const r2 = await ebSame.sync();
  const changedA = changed(r1);
  const changedB = changed(r2);
  check('A 已收敛', changedA.length === 0, JSON.stringify(changedA));
  check('B 已收敛', changedB.length === 0, JSON.stringify(changedB));
  const r3 = await ea.sync();
  const r4 = await ebSame.sync();
  check('第三轮仍然收敛', changed(r3).length === 0 && changed(r4).length === 0,
    `${JSON.stringify(changed(r3))} / ${JSON.stringify(changed(r4))}`);
  check('timetable 没有"每轮都变"（快照哈希对得上）',
    r3.objects.timetable.action === 'noop' && r4.objects.timetable.action === 'noop',
    `${r3.objects.timetable.action}/${r4.objects.timetable.action}`);

  // ---------- 9. 禁止上云名单 ----------
  console.log('\n[9] 禁止上云名单');
  const forbidden = ['phll/managebac/session_x.json', 'phl/profile/x', 'logs/app.log',
    '_backups/data-1.zip', '.gh_token', '.sync/state.json', '.phl-running', '.pll-running',
    'phll', 'phl', 'logs', '_backups', '_migrated_backup', 'phll/data/x', ''];
  for (const bad of forbidden) {
    check(`${JSON.stringify(bad)} 被判为禁止`, cs.SyncEngine.isForbidden(bad) === true);
  }
  for (const good of ['schedule', 'settings.lessons', 'agent:20260910-213045', 'school',
    'settings.accounts', 'settings.ai', 'timetable']) {
    check(`${good} 允许同步`, cs.SyncEngine.isForbidden(good) === false);
  }
  // 名单在真同步里也生效（不是只有静态函数认得）
  const reportForbidden = await ea.sync({ names: ['phll/managebac/session_x.json', 'schedule'] });
  check('真同步里禁止名单生效（skip 而不是 error）',
    reportForbidden.objects['phll/managebac/session_x.json'].action === 'skip',
    cs.jsonText(reportForbidden.objects['phll/managebac/session_x.json']));
  check('同一轮里允许的对象照常处理', reportForbidden.objects.schedule.action === 'noop',
    cs.jsonText(reportForbidden.objects.schedule));

  // ---------- 10. 服务端真的看不懂 ----------
  console.log('\n[10] 服务端拿到的只有密文');
  const object = await ca.getObject('settings.lessons');
  check('payload 是 PHIX1 信封', String(object.payload).startsWith('PHIX1.'));
  const plainLessons = cs.jsonText(ea.collect('settings.lessons'));
  const marker = plainLessons.slice(10, 30);
  check('密文里不含选课明文', !String(object.payload).includes(marker), marker);
  let decryptWithWrongName = false;
  try { phixCrypto.unsealObject(dek, userId, 'timetable', object.payload); } catch { decryptWithWrongName = true; }
  check('换个对象名（AAD 不匹配）解不开', decryptWithWrongName);

  // ---------- 11. 预览（不写入） ----------
  console.log('\n[11] 预览：只算不写');
  const schedPreview = readSchedule(rootB);
  const nextPreview = Math.max(0, ...schedPreview.events.map((e) => e.id)) + 1;
  schedPreview.events.push({ id: nextPreview, day: '2026-09-27', time: '09:00', title: 'B加的（预览用）', note: '', created: cs.nowIso() });
  schedPreview.lastId = nextPreview;
  writeSchedule(rootB, schedPreview);
  const previewState = cs.jsonText(cs.readJson(path.join(rootB, '.sync', 'state.json'), {}));
  const previewReport = await ebSame.sync({ dryRun: true });
  check('预览报告 schedule 会推送', previewReport.objects.schedule.action === 'push',
    cs.jsonText(previewReport.objects.schedule));
  check('预览没有推进同步状态',
    cs.jsonText(cs.readJson(path.join(rootB, '.sync', 'state.json'), {})) === previewState);
  // 真同步一次，把这条清掉并让两端重新一致
  const pushReport = await ebSame.sync();
  check('真同步确实推送了', pushReport.objects.schedule.action === 'push',
    cs.jsonText(pushReport.objects.schedule));
  await ea.sync();

  // ---------- 12. 单对象同步 + 其余对象不动 ----------
  console.log('\n[12] 只同步指定对象');
  const onlyReport = await ea.sync({ names: ['settings.ui'] });
  check('只处理了 settings.ui', Object.keys(onlyReport.objects).length === 1
    && Object.hasOwn(onlyReport.objects, 'settings.ui'), cs.jsonText(Object.keys(onlyReport.objects)));

  // ---------- 13. revision_conflict 重试（"有人在我们同步期间又写了"） ----------
  console.log('\n[13] 同步途中的 409 冲突 → 拉最新再合并一次');
  const cc = new cs.PhixClient(BASE, tokenB);
  const ec = engine(cc, dekB, userId, username, rootC, '设备C');
  await ec.sync();
  // 两台引擎各自读到同一版本，然后 A 先推，C 再推 → C 必吃 409
  const ca2 = new cs.PhixClient(BASE, tokenA);
  const ea2 = engine(ca2, dek, userId, username, rootA, '设备A');
  await ea2.sync();
  const scheduleA3 = readSchedule(rootA);
  const nextA3 = Math.max(0, ...scheduleA3.events.map((e) => e.id)) + 1;
  scheduleA3.events.push({ id: nextA3, day: '2026-09-28', time: '10:00', title: 'A加的（409 用）', note: '', created: cs.nowIso() });
  scheduleA3.lastId = nextA3;
  writeSchedule(rootA, scheduleA3);
  const scheduleC = readSchedule(rootC);
  const nextC = Math.max(0, ...scheduleC.events.map((e) => e.id)) + 1;
  scheduleC.events.push({ id: nextC, day: '2026-09-29', time: '11:00', title: 'C加的（409 用）', note: '', created: cs.nowIso() });
  scheduleC.lastId = nextC;
  writeSchedule(rootC, scheduleC);
  await ea2.sync();
  const reportC = await ec.sync();
  check('C 同步成功（409 被重试吸收）', reportC.ok === true, cs.jsonText(reportC.errors));
  check('C 的冲突记录里没有 revision_conflict 错误',
    !reportC.errors.some((line) => String(line).includes('revision_conflict')), cs.jsonText(reportC.errors));
  check('C 侧两份日程都在（不是二选一）',
    titlesOf(rootC).has('A加的（409 用）') && titlesOf(rootC).has('C加的（409 用）'),
    JSON.stringify([...titlesOf(rootC)]));
  await ea2.sync();
  check('A 侧也拿到了 C 那条', titlesOf(rootA).has('C加的（409 用）'), JSON.stringify([...titlesOf(rootA)]));

  // ---------- 14. settings.yaml 的注释与未知段不被抹掉 ----------
  console.log('\n[14] settings.yaml：注释、别的段与未知字段一律保留');
  const fileA = path.join(rootA, 'settings.yaml');
  const original = fs.readFileSync(fileA, 'utf8');
  const decorated = `# 用户手写的注释，绝不能被同步抹掉\n${original}\nfuture_section:\n  nested:\n    key: keep-me\n`;
  fs.writeFileSync(fileA, decorated, 'utf8');
  const ui = ea.collect('settings.ui');
  ui.ui = { ...ui.ui, course_order: ['Physics HL1', 'TOK'] };
  ea.apply('settings.ui', ui);
  const afterUi = fs.readFileSync(fileA, 'utf8');
  check('注释保留', afterUi.startsWith('# 用户手写的注释，绝不能被同步抹掉\n'));
  check('未知段保留', /future_section:\n {2}nested:\n {4}key: keep-me/.test(afterUi));
  check('accounts 段保留', afterUi.includes('liqian1982') === original.includes('liqian1982'));
  check('agent 段保留', afterUi.includes('send_grades_to_llm'));
  check('lessons 段条数不变',
    (afterUi.match(/^- subject:/gm) || []).length === (original.match(/^- subject:/gm) || []).length);
  check('ui 段写进去了', cs.jsonText(ea.collect('settings.ui')) === cs.jsonText(ui));
  // 往返之后仍然能被读取
  const reread = cs.readSettingsSection(fileA, 'accounts');
  check('写完之后 accounts 仍可解析', Boolean(reread && reread.edupage));
  // 恢复成"两台一致"再继续
  fs.writeFileSync(fileA, decorated, 'utf8');

  // 新对象 settings.ai 也能同步（PHL 特有）
  console.log('\n[15] settings.ai / settings.ui 单独同步到 B');
  const aiA = ea.collect('settings.ai');
  check('A 的 ai 段读得到 providers', Array.isArray((aiA.ai || {}).providers) && aiA.ai.providers.length > 0,
    cs.jsonText(aiA).slice(0, 160));
  aiA.ai.active_model = 'glm-5.3-flash';
  ea.apply('settings.ai', aiA);
  await ea.sync({ names: ['settings.ai'] });
  await ebSame.sync({ names: ['settings.ai'] });
  const aiB = ebSame.collect('settings.ai');
  // B 的 active_model 原本是空串、A 改成了有值。**没有基版时"空的让位"**（PLL 侧的
  // 既定规则，§21 有完整场景），所以 B 直接收下 A 的值，不报冲突。
  check('B 的空值让位给 A 的有值（不报冲突）',
    aiB.ai.active_model === 'glm-5.3-flash', cs.jsonText(aiB.ai.active_model));
  check('B 的 ai providers 还在（没被空值清掉）',
    Array.isArray((aiB.ai || {}).providers) && aiB.ai.providers.length > 0);

  // A 那边没动过、B 这边新加的东西要能传过去（真正的并集）
  aiB.ai.providers = [...aiB.ai.providers, { id: 'p-node-e2e', name: 'Node e2e 供应商', protocol: 'openai', base_url: 'http://127.0.0.1:1/v1', api_key: 'not-a-real-key', models: ['x'], notes: '' }];
  ebSame.apply('settings.ai', aiB);
  await ebSame.sync({ names: ['settings.ai'] });
  await ea.sync({ names: ['settings.ai'] });
  const aiAFinal = ea.collect('settings.ai');
  check('B 新加的供应商传到了 A（对象并集）',
    cs.sameValue(aiAFinal.ai.providers, aiB.ai.providers),
    cs.jsonText(aiAFinal.ai.providers).slice(0, 300));

  // 反过来：A 只动自己的叶子、B 只动另一个叶子 → A 的改动必须在合并后还在。
  // （这条是移植期实测抓到的：合并结果里若用**新对象**替代"内容没变的本地对象"，
  //   上一层会把本地判成"改过了"，于是改信远端，用远端那个空值把本地悄悄覆盖掉。）
  const aiAKeep = ea.collect('settings.ai');
  aiAKeep.ai.active_model = 'glm-5.3-pro';
  ea.apply('settings.ai', aiAKeep);
  await ea.sync({ names: ['settings.ai'] });
  const aiBKeep = ebSame.collect('settings.ai');
  aiBKeep.ai.providers = [...aiBKeep.ai.providers, { id: 'p-node-e2e-2', name: 'Node e2e 供应商二号', protocol: 'openai', base_url: 'http://127.0.0.1:1/v1', api_key: 'not-a-real-key', models: ['x'], notes: '' }];
  ebSame.apply('settings.ai', aiBKeep);
  await ebSame.sync({ names: ['settings.ai'] });
  const aiAReport = await ea.sync({ names: ['settings.ai'] });
  const aiAAfter = ea.collect('settings.ai');
  check('A 自己改的 active_model 没被远端旧值抹掉',
    aiAAfter.ai.active_model === 'glm-5.3-pro',
    `A=${cs.jsonText(aiAAfter.ai)} report=${cs.jsonText(aiAReport.objects['settings.ai'])}`);
  check('A 同时收下了 B 新增的供应商',
    (aiAAfter.ai.providers || []).some((p) => p.id === 'p-node-e2e-2'),
    cs.jsonText(aiAAfter.ai.providers).slice(0, 300));

  // 记录一条已知取舍：两边都改了同一个叶子且远端那侧"值与原版相同"时，
  // 合并按"后写者赢"取远端值（Python 侧同样的规则，见汇报里的对照实验）。
  console.log('  [note] 同叶子两边都改时按"后写者赢"取远端值（与 Python 一致，已记入汇报）');

  // 并发护栏
  console.log('\n[16] 并发护栏：对方程序在跑就跳过这轮');
  const markerFile = path.join(rootA, '.pll-running');
  fs.writeFileSync(markerFile, JSON.stringify({ kind: 'pll', pid: process.pid, startedAt: new Date().toISOString(), updatedAt: new Date().toISOString() }), 'utf8');
  const skipped = await ea.sync();
  check('检测到 PLL 在跑 → 本轮跳过', skipped.ok === false && Boolean(skipped.skipped), cs.jsonText(skipped.skipped));
  const forced = await ea.sync({ force: true });
  check('force=true 时不跳过', forced.skipped === null, cs.jsonText(forced.skipped));
  fs.rmSync(markerFile, { force: true });
  fs.writeFileSync(markerFile, JSON.stringify({ kind: 'pll', pid: 999999, startedAt: '2020-01-01T00:00:00+08:00', updatedAt: '2020-01-01T00:00:00+08:00' }), 'utf8');
  const staleReport = await ea.sync();
  check('死进程 / 心跳过期的标记不算"在运行"', staleReport.skipped === null, cs.jsonText(staleReport.skipped));
  fs.rmSync(markerFile, { force: true });

  // ---------- 17. 三台设备最终一致 ----------
  console.log('\n[17] 三台设备最终一致（B 落后两轮，同步后追上）');
  await ec.sync();
  await ebSame.sync();
  await ea.sync();
  check('A/B/C 三方日程一致',
    cs.sameValue(eventsOf(rootA), eventsOf(rootB)) && cs.sameValue(eventsOf(rootB), eventsOf(rootC)),
    `A=${Object.keys(eventsOf(rootA)).length} B=${Object.keys(eventsOf(rootB)).length} C=${Object.keys(eventsOf(rootC)).length}`);

  // 状态与快照**按账号隔离**（协议补充：换账号不沿用别人的快照，否则会误判成"远端删除"）
  console.log('\n[18] 状态与快照按账号隔离，命名与 PLL 一致');
  const accountDirA = path.join(rootA, '.sync', 'accounts', cs.safeAccountName(username));
  check('状态落在 .sync/accounts/<账号>/state.json',
    fs.existsSync(path.join(accountDirA, 'state.json')), accountDirA);
  check('账号目录名与 PLL 的 _account_dir() 规则一致（非 [A-Za-z0-9._@+-] 换 _、截断 60）',
    cs.safeAccountName(username) === username.replace(/[^A-Za-z0-9._@+-]/g, '_').slice(0, 60),
    cs.safeAccountName(username));
  // 纯点串（`.` / `..`）不含非法字符，会原样变成目录名再被 path.join 解析到上一级 → 必须挡住
  check('纯点串账号名不会逃出账号目录',
    cs.safeAccountName('.') === 'default' && cs.safeAccountName('..') === 'default'
    && cs.safeAccountName('...') === 'default',
    `[${cs.safeAccountName('.')}, ${cs.safeAccountName('..')}, ${cs.safeAccountName('...')}]`);
  check('纯点串时 accountDir 仍在本账号目录之下',
    path.dirname(new cs.SyncEngine(anon, dek, userId, '..', { dataDir: rootA }).accountDir)
      === path.join(rootA, '.sync', 'accounts'));
  check('老布局的 .sync/state.json 没有被创建（新装的就是新布局）',
    !fs.existsSync(path.join(rootA, '.sync', 'state.json')));
  const snapshotNames = fs.readdirSync(path.join(accountDirA, 'last')).sort();
  check('schedule.json 存在', snapshotNames.includes('schedule.json'), JSON.stringify(snapshotNames));
  check('settings.accounts.json 存在', snapshotNames.includes('settings.accounts.json'));
  check('agent 会话快照名把冒号换成 __',
    snapshotNames.some((name) => /^agent__.+\.json$/.test(name)), JSON.stringify(snapshotNames));
  const stateA = cs.readJson(path.join(accountDirA, 'state.json'), {});
  check('state.json 的 kind / version 与 PLL 一致',
    stateA.kind === 'phix-sync-state' && stateA.version === 1, cs.jsonText({ kind: stateA.kind, version: stateA.version }));
  check('state.json 里有 server / user_id / username / device / objects / conflicts',
    ['server', 'user_id', 'username', 'device', 'objects', 'conflicts'].every((key) => Object.hasOwn(stateA, key)),
    cs.jsonText(Object.keys(stateA)));

  // 同一个 data/ 换成另一个账号：绝不能沿用别人的基版
  console.log('\n[19] 同一个 data/ 换账号：不沿用别人的状态与快照');
  const rootD = makeDevice('D');
  const beforeD = eventsOf(rootD);
  const ed = new cs.SyncEngine(new cs.PhixClient(BASE, tokenB), dekB, userId, username, { dataDir: rootD, device: '设备D' });
  await ed.sync();
  check('D 用账号 A 同步后有自己的账号目录',
    fs.existsSync(path.join(rootD, '.sync', 'accounts', cs.safeAccountName(username), 'state.json')));
  const otherAccount = new cs.PhixClient(BASE, tokenB);
  const otherUser = new cs.SyncEngine(otherAccount, dekB, userId, '完全另一个账号', { dataDir: rootD, device: '设备D' });
  check('另一个账号的目录名不同', otherUser.accountDir !== ed.accountDir, otherUser.accountDir);
  check('另一个账号看不到旧账号的状态', Object.keys(otherUser.loadState()).length === 0,
    cs.jsonText(otherUser.loadState()).slice(0, 160));
  check('另一个账号看不到旧账号的快照', otherUser.loadSnapshot('schedule') === null);
  // 日程文件是两个程序共用的，同步本身会把它按统一格式重写一遍（那不算丢数据）；
  // 与账号 A 的云端一致才是这里要核对的（D 用的是同一个账号）。
  check('本地日程与账号 A 一致（一条都没丢）', cs.sameValue(eventsOf(rootD), eventsOf(rootA)),
    `${Object.keys(eventsOf(rootD)).length} vs ${Object.keys(eventsOf(rootA)).length}`);

  // 老布局迁移：把 A 的状态与快照手工摆成老布局，确认"复制过去、老文件保留"
  console.log('\n[20] 老布局（.sync/state.json）迁移：复制 + 原样保留');
  const rootE = makeDevice('E');
  const legacyDir = path.join(rootE, '.sync');
  fs.mkdirSync(path.join(legacyDir, 'last'), { recursive: true });
  // 老布局就是设备 E 自己上一次留下的：device 必须是 E，否则同步会正确地重记一遍。
  const legacyDoc = JSON.parse(fs.readFileSync(path.join(accountDirA, 'state.json'), 'utf8'));
  legacyDoc.device = '设备E';
  legacyDoc.username = username;
  const realState = `${JSON.stringify(legacyDoc, null, 2)}\n`;
  fs.writeFileSync(path.join(legacyDir, 'state.json'), realState, 'utf8');
  fs.copyFileSync(path.join(accountDirA, 'last', 'schedule.json'), path.join(legacyDir, 'last', 'schedule.json'));
  const ee = new cs.SyncEngine(new cs.PhixClient(BASE, tokenA), dek, userId, username, { dataDir: rootE, device: '设备E' });
  const migrated = ee.loadState();
  check('老状态被复制到按账号的目录', Object.keys(migrated.objects || {}).length > 0,
    cs.jsonText(Object.keys(migrated.objects || {})).slice(0, 200));
  check('老快照不被当成可信基版（免得把别人的明文当基版乱删）',
    ee.loadSnapshot('schedule') === null && migrated.objects.schedule.sha256 === '',
    cs.jsonText(migrated.objects.schedule));
  check('老 state.json 原样保留', fs.readFileSync(path.join(legacyDir, 'state.json'), 'utf8') === realState);
  check('老快照文件原样保留', fs.existsSync(path.join(legacyDir, 'last', 'schedule.json')));
  const migratedReport = await ee.sync();
  // 搬家之后**一条都不能丢**，也不会平白冒出一份冲突记录
  check('迁移之后日程一条都没丢', cs.sameValue(eventsOf(rootE), eventsOf(rootA)),
    `${Object.keys(eventsOf(rootE)).length} vs ${Object.keys(eventsOf(rootA)).length}`);
  check('迁移之后没有平白多出冲突记录', (migratedReport.conflicts || []).length === 0,
    cs.jsonText(migratedReport.conflicts).slice(0, 240));
  check('迁移不会把"本地缺的那些"当成删除推回云端',
    migratedReport.objects.schedule.action !== 'push',
    cs.jsonText(migratedReport.objects.schedule));
  const afterMigration = await ee.sync();
  check('迁移之后第二轮就收敛',
    ['noop', 'pull'].includes(afterMigration.objects.schedule.action),
    cs.jsonText(afterMigration.objects.schedule));

  // 别人的老状态：一个字都不动
  const rootF = makeDevice('F');
  fs.mkdirSync(path.join(rootF, '.sync'), { recursive: true });
  const foreignState = cs.jsonText({ ...JSON.parse(realState), username: 'someone-else' });
  fs.writeFileSync(path.join(rootF, '.sync', 'state.json'), foreignState, 'utf8');
  const ef = new cs.SyncEngine(new cs.PhixClient(BASE, tokenA), dek, userId, username, { dataDir: rootF, device: '设备F' });
  check('不属于当前账号的老状态不许搬', Object.keys(ef.loadState()).length === 0);
  check('不属于当前账号的老状态原样保留',
    fs.readFileSync(path.join(rootF, '.sync', 'state.json'), 'utf8') === foreignState);

  // ---------- 21. 首次同步没有基版：空的那边必须让步，且绝不能崩 ----------
  //
  // 用两台**全新副本**做干净场景：G 配好 active_model 推上去，H 是"还没配过 AI 的新设备"
  // （空串 + 从没见过这个对象）。这正是这条规则要保护的情形。
  console.log('\n[21] 首次同步（没有基版）：空的那边让步，云端配置不被新设备抹掉');
  const aiObjects = [...cs.DEFAULT_OBJECTS, 'settings.ai'];
  const rootG = makeDevice('G');
  const eg = new cs.SyncEngine(new cs.PhixClient(BASE, tokenA), dek, userId, username, { dataDir: rootG, device: '设备G' });
  const aiG = eg.collect('settings.ai');
  aiG.ai.active_model = 'model-from-A';
  eg.apply('settings.ai', aiG);
  const repAiG = await eg.sync({ names: aiObjects });
  check('G 把 settings.ai 推上去了',
    ['push', 'merge'].includes(repAiG.objects['settings.ai']?.action),
    cs.jsonText(repAiG.objects['settings.ai']));
  check('G 这轮没有报错（哨兵没泄漏）', repAiG.ok === true, cs.jsonText(repAiG.errors));

  const rootH = makeDevice('H');
  const eh = new cs.SyncEngine(new cs.PhixClient(BASE, tokenB), dekB, userId, username, { dataDir: rootH, device: '设备H' });
  const aiHDoc = eh.collect('settings.ai');
  aiHDoc.ai.active_model = '';
  eh.apply('settings.ai', aiHDoc);
  const repAiH = await eh.sync({ names: aiObjects });
  check('H 首拉没有崩', repAiH.ok === true, cs.jsonText(repAiH.errors));
  check('H 拿到了云端的 model-from-A（空值没有把云端配置抹掉）',
    eh.collect('settings.ai').ai.active_model === 'model-from-A',
    cs.jsonText(eh.collect('settings.ai').ai.active_model));
  await eg.sync({ names: aiObjects });
  check('G 的配置没被 H 的空值覆盖',
    eg.collect('settings.ai').ai.active_model === 'model-from-A',
    cs.jsonText(eg.collect('settings.ai').ai.active_model));
  const repAiG2 = await eg.sync({ names: aiObjects });
  check('两边都收敛',
    Object.values(repAiG2.objects).every((entry) => ['noop', 'skip'].includes(entry.action)),
    cs.jsonText(Object.fromEntries(Object.entries(repAiG2.objects).map(([k, v]) => [k, v.action]))));
  check('状态文件写成功了（哨兵漏了这里就会崩）',
    Boolean(cs.readJson(path.join(rootG, '.sync', 'accounts', cs.safeAccountName(username), 'state.json'), {}).objects));

  // ---------- 22. 云端删除 → 本地也要落地 ----------
  console.log('\n[22] 云端删掉一个对象 → 本地真的会跟着处理');
  const agentNames = ea.allObjectNames().filter((name) => name.startsWith('agent:'));
  if (!agentNames.length) {
    check('有 AI 会话对象可测', false, '本地没有 agent/*.json');
  } else {
    const agentName = agentNames[0];
    await ea.sync({ names: [agentName] });
    await ebSame.sync({ names: [agentName] });
    const agentFile = path.join(rootB, 'agent', `${agentName.slice('agent:'.length)}.json`);
    check('B 本地有那个会话文件', fs.existsSync(agentFile));
    const revision = (await ca.getObject(agentName)).revision;
    await ca.deleteObject(agentName, revision);
    const repDel = await ebSame.sync({ names: [agentName] });
    check('B 这轮没报错', repDel.ok === true, cs.jsonText(repDel.errors));
    check('B 本地的会话文件被删了（删除真的传播了）', !fs.existsSync(agentFile),
      cs.jsonText(repDel.objects[agentName]));
    const repDel2 = await ebSame.sync({ names: [agentName] });
    const entry2 = repDel2.objects[agentName];
    check('再同步一次不再反复报同一条',
      !entry2 || ['noop', 'remote-deleted', 'skip'].includes(entry2.action), cs.jsonText(entry2));
  }

  // (a2) 「首拉全 noop 也必须记基线」→ 否则云端删除永远传播不过来
  //      两台**从同一份副本起步**的设备：J 先推（把云端定成这份），
  //      I 再首拉 —— 数据本来就一样，所以这一轮应当以 noop 为主，
  //      但 state 里必须有条目，紧接着删掉它的 AI 会话要真的落地。
  console.log('\n[22b] 首拉全 noop 也必须记基线（否则删除传播不过来）');
  const rootJ = makeDevice('J');
  const ej = new cs.SyncEngine(new cs.PhixClient(BASE, tokenB), dekB, userId, username, { dataDir: rootJ, device: '设备J' });
  await ej.sync();
  const rootI = makeDevice('I');
  const ei = new cs.SyncEngine(new cs.PhixClient(BASE, tokenB), dekB, userId, username, { dataDir: rootI, device: '设备I' });
  const repI1 = await ei.sync();
  check('I 首拉成功', repI1.ok === true, cs.jsonText(repI1.errors));
  const iStatePath = path.join(rootI, '.sync', 'accounts', cs.safeAccountName(username), 'state.json');
  const iState = cs.readJson(iStatePath, {});
  const iActions = Object.fromEntries(Object.entries(repI1.objects).map(([name, entry]) => [name, entry.action]));
  check('I 首拉以 noop 为主（数据本来就一样）',
    Object.values(iActions).filter((action) => action === 'noop').length >= 4, cs.jsonText(iActions));
  check('收下 noop 的对象也**记下了基线**',
    Object.entries(iActions).filter(([, action]) => action === 'noop')
      .every(([name]) => Boolean((iState.objects || {})[name]?.sha256)),
    cs.jsonText(Object.fromEntries(Object.entries(iActions).filter(([, a]) => a === 'noop').map(([n]) => [n, (iState.objects || {})[n]]))));
  check('I 首拉之后能认得出自家快照',
    ei.loadSnapshot('schedule') !== null);
  const iAgent = ei.allObjectNames().find((name) => name.startsWith('agent:'));
  if (iAgent) {
    const iAgentFile = path.join(rootI, 'agent', `${iAgent.slice('agent:'.length)}.json`);
    check('I 本地有会话文件', fs.existsSync(iAgentFile));
    const iRev = (await ca.getObject(iAgent)).revision;
    await ca.deleteObject(iAgent, iRev);
    const repIDel = await ei.sync({ names: [iAgent] });
    check('I 也跟着删了会话文件（删除传播得动）', !fs.existsSync(iAgentFile),
      cs.jsonText(repIDel.objects[iAgent]));
  }

  // (b) 共用大文件（Schedule）：**不自动删**，但保留本地并报一次，然后收敛
  const schedBefore = eventsOf(rootB);
  const schedRevision = (await ca.getObject('schedule')).revision;
  await ca.deleteObject('schedule', schedRevision);
  const repDel3 = await ebSame.sync({ names: ['schedule'] });
  check('B 报出「云端删了共用大文件、本地保留」',
    repDel3.conflicts.some((c) => String(c.note || '').includes('共用的大文件')),
    cs.jsonText(repDel3.conflicts).slice(0, 300));
  check('B 的 Schedule 还在（没被误删）', fs.existsSync(path.join(rootB, 'Schedule')));
  check('B 的日程条数没变', cs.sameValue(eventsOf(rootB), schedBefore),
    `${Object.keys(eventsOf(rootB)).length} vs ${Object.keys(schedBefore).length}`);
  const repDel4 = await ebSame.sync({ names: ['schedule'] });
  check('第二轮不再重复报这条（已收敛）',
    !repDel4.conflicts.some((c) => String(c.note || '').includes('共用的大文件')),
    cs.jsonText(repDel4.conflicts).slice(0, 240));

  // (c) 云端删了、但本地改过 → 保留本地并推回云端（否决这次删除）
  const schedEdited = readSchedule(rootB);
  const nextEdited = Math.max(0, ...schedEdited.events.map((e) => e.id)) + 1;
  schedEdited.events.push({ id: nextEdited, day: '2026-12-01', time: '10:00', title: '删除后又改的（Node e2e）', note: '', created: cs.nowIso() });
  schedEdited.lastId = nextEdited;
  writeSchedule(rootB, schedEdited);
  const veto = await ebSame.sync({ names: ['schedule'] });
  check('B 把本地的改动推回云端（否决这次删除）', veto.objects.schedule.action === 'push',
    cs.jsonText(veto.objects.schedule));
  check('B 报出了「保留本地并推回云端」',
    veto.conflicts.some((c) => String(c.note || '').includes('推回云端')),
    cs.jsonText(veto.conflicts).slice(0, 300));
  await ea.sync({ names: ['schedule'] });
  check('A 又从云端拿到了这份日程', titlesOf(rootA).has('删除后又改的（Node e2e）'),
    JSON.stringify([...titlesOf(rootA)]));
  check('两端一致', cs.sameValue(eventsOf(rootA), eventsOf(rootB)),
    `${Object.keys(eventsOf(rootA)).length} vs ${Object.keys(eventsOf(rootB)).length}`);

  // ---------- 23. 本地不是完整副本时，绝不许静默删掉云端数据 ----------
  //
  // 触发条件：本地文件不是"那一轮的完整副本"（老布局迁移、文件被别的程序重写过…）。
  // 老实现把"本地没有某条"当成"本地删了" → 合并结果只留本地那几条，还会推回云端。
  console.log('\n[23] 本地不是完整副本时，绝不许静默删掉云端数据');
  const rootK = makeDevice('K');
  const ek = new cs.SyncEngine(new cs.PhixClient(BASE, tokenA), dek, userId, username, { dataDir: rootK, device: '设备K' });
  await ek.sync({ names: ['schedule'] });
  const cloudEvents = eventsOf(rootK);
  check('K 拿到云端的日程（有 2 条以上可测）', Object.keys(cloudEvents).length >= 2,
    `${Object.keys(cloudEvents).length} 条`);
  const cloudTitles = [...titlesOf(rootK)].sort();

  // 把 K 的日程砍到只剩 1 条，并把状态与快照摆成"老布局"（= 一份不属于本轮的基版）
  const trimmed = readSchedule(rootK);
  const keptEvent = trimmed.events[0];
  trimmed.events = [keptEvent];
  trimmed.lastId = keptEvent.id;
  writeSchedule(rootK, trimmed);
  const kStateDir = path.join(rootK, '.sync', 'accounts', cs.safeAccountName(username));
  fs.mkdirSync(path.join(rootK, '.sync', 'last'), { recursive: true });
  fs.copyFileSync(path.join(kStateDir, 'state.json'), path.join(rootK, '.sync', 'state.json'));
  fs.copyFileSync(path.join(kStateDir, 'last', 'schedule.json'), path.join(rootK, '.sync', 'last', 'schedule.json'));
  fs.rmSync(kStateDir, { recursive: true, force: true });

  const ekStale = new cs.SyncEngine(new cs.PhixClient(BASE, tokenA), dek, userId, username, { dataDir: rootK, device: '设备K' });
  const kReport = await ekStale.sync({ names: ['schedule'] });
  check('K 的日程没被"本地只有一条"带着删掉', Object.keys(eventsOf(rootK)).length >= cloudTitles.length,
    `${Object.keys(eventsOf(rootK)).length} vs ${cloudTitles.length}`);
  check('K 没有把"少掉的那些"当删除推回云端', kReport.objects.schedule.action !== 'push',
    cs.jsonText(kReport.objects.schedule));
  await ea.sync({ names: ['schedule'] });
  check('云端也一条没少', cs.sameValue([...titlesOf(rootA)].sort(), cloudTitles),
    `${JSON.stringify([...titlesOf(rootA)].sort())} vs ${JSON.stringify(cloudTitles)}`);

  // 密码学自检
  console.log('\n[24] 本地密码学自检');
  const selfCheck = phixCrypto.selfCheck();
  for (const [name, value] of Object.entries(selfCheck)) {
    check(`crypto.${name}`, value === true);
  }

  // 服务端与本地数据未被污染
  console.log('\n[25] 源数据只读：真实目录一个字节都没动');
  const sourceStat = fs.statSync(path.join(SOURCE, 'settings.yaml'));
  check('源 settings.yaml 仍在', sourceStat.isFile());
  check('源目录没有被写入 .sync', !fs.existsSync(path.join(SOURCE, '.sync')));
  check('源目录没有被写入 .phix-*', fs.readdirSync(SOURCE).every((name) => !name.startsWith('.phix')));

  console.log('\n' + '='.repeat(78));
  console.log(`通过 ${PASSED.length} 项，失败 ${FAILED.length} 项`);
  if (FAILED.length) {
    console.log('失败清单：');
    for (const name of FAILED) console.log(`  - ${name}`);
  }
  console.log(`\n实验目录（可整删，与真实数据无关）：${LAB}`);
  console.log('='.repeat(78));
  return FAILED.length ? 1 : 0;
}

main()
  .then((code) => { process.exitCode = code; })
  .catch((error) => {
    console.error('\n测试脚本本身出错：', Date.now(), error && error.stack ? error.stack : error);
    process.exitCode = 2;
  });

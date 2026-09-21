# -*- coding: utf-8 -*-
"""phix 面板 **真实界面** 探针：真正的 Api + 真正的 ui/app.js + 真窗口。

与 `_ui_test.py` 的区别：那个用 MockApi 只测渲染；这个接**真实 bridge**，
验证「设置页 → phix 面板」在真环境里确实能出来、能切换状态。

    $env:PHLL_DATA_DIR = "D:\\phix\\_lab\\panel\\data"
    python -X utf8 D:\\phix\\server\\devtools\\probe_phix_panel.py out.json

数据根指向副本，绝不碰真实 data/。
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import threading
import time
from pathlib import Path

ROOT = Path(r"D:\phl-lite-dev")
SOURCE = Path(r"D:\HPHL\testenv\data")
LAB = Path(r"D:\phix\_lab\panel\data")
SERVER = os.environ.get("PHIX_SERVER", "http://127.0.0.1:8931")

# 先把副本准备好，再让 PLL 解析数据根
if LAB.exists():
    shutil.rmtree(LAB)
LAB.parent.mkdir(parents=True, exist_ok=True)
shutil.copytree(SOURCE, LAB)
os.environ["PHLL_DATA_DIR"] = str(LAB)

sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8")

import webview  # noqa: E402

from hellopinghe.app.bridge import Api  # noqa: E402

UI = ROOT / "ui" / "index.html"
result: dict = {}

PROBE_JS = r"""
window.__probe_result = null;
window.__probeErrs = [];
window.addEventListener('error', (e) => window.__probeErrs.push(String(e.message)));
window.addEventListener('unhandledrejection',
  (e) => window.__probeErrs.push('reject: ' + String(e.reason)));
(async () => {
  const out = {};
  try {
    // 进设置页
    document.querySelector('#nav [data-go="settings"]').click();
    await new Promise((r) => setTimeout(r, 1200));

    out.cardExists = !!document.getElementById('phix-card');
    out.loginBoxShown = !document.getElementById('phix-login-box').hidden;
    out.mainBoxHidden = document.getElementById('phix-main-box').hidden;
    out.serverValue = document.getElementById('phix-server').value || '';
    out.hasTestBtn = !!document.getElementById('phix-test');
    out.hasRegisterBtn = !!document.getElementById('phix-register');
    out.apiMethods = Object.keys(window.pywebview.api || {})
      .filter((k) => k.startsWith('phix_')).length;

    // 真连接测试
    const user = 'panel' + Date.now().toString().slice(-8);
    document.getElementById('phix-server').value = __SERVER__;
    document.getElementById('phix-username').value = user;
    document.getElementById('phix-password').value = 'Panel-Test-1';
    document.getElementById('phix-test').click();
    await new Promise((r) => setTimeout(r, 1500));
    out.pingMsg = document.getElementById('phix-login-msg').textContent;

    // 真注册 → 真同步
    window.confirm = () => true;
    document.getElementById('phix-register').click();
    await new Promise((r) => setTimeout(r, 6000));
    out.afterRegisterMainShown = !document.getElementById('phix-main-box').hidden;
    out.recoveryShown = !document.getElementById('phix-recovery').hidden;
    out.recoveryCode = document.getElementById('phix-recovery-code').textContent || '';
    out.statusLine = document.getElementById('phix-status-line').textContent || '';
    out.objCheckboxes =
      document.querySelectorAll('#phix-objs input[data-obj]').length;

    // 真同步一次
    document.getElementById('phix-sync').click();
    await new Promise((r) => setTimeout(r, 6000));
    out.syncMsg = document.getElementById('phix-sync-msg').textContent || '';

    // 真登出
    document.getElementById('phix-logout').click();
    await new Promise((r) => setTimeout(r, 3000));
    out.backToLogin = !document.getElementById('phix-login-box').hidden &&
      document.getElementById('phix-main-box').hidden;
    out.finalLoginMsg = document.getElementById('phix-login-msg').textContent || '';
  } catch (e) {
    out.fatal = String(e && e.stack ? e.stack : e);
  }
  out.jsErrors = window.__probeErrs;
  window.__probe_result = JSON.stringify(out);
})();
""".replace("__SERVER__", json.dumps(SERVER))


def run(window) -> None:
    deadline = time.time() + 25
    while time.time() < deadline:
        try:
            if window.evaluate_js("!!window.pywebview && !!window.pywebview.api"):
                break
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.3)
    time.sleep(3)
    try:
        window.evaluate_js(PROBE_JS)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"inject: {type(exc).__name__}: {exc}"
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            value = window.evaluate_js("window.__probe_result || null")
        except Exception:  # noqa: BLE001
            value = None
        if value:
            result["raw"] = value
            break
        time.sleep(0.5)
    try:
        window.destroy()
    except Exception:  # noqa: BLE001
        pass


def main() -> int:
    print("数据根:", LAB)
    print("服务器:", SERVER)
    api = Api()
    window = webview.create_window("phix panel probe", str(UI), js_api=api,
                                   width=1400, height=900)
    webview.start(run, window, gui="edgechromium")
    payload = result.get("raw") or result.get("error") or "no result"
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(str(payload), encoding="utf-8")
    try:
        data = json.loads(payload)
        print(json.dumps(data, ensure_ascii=False, indent=1))
        bad = [k for k, v in data.items()
               if v is False or k == "fatal" or (k == "jsErrors" and v)]
        print("\n看这几项:", bad if bad else "无异常项")
    except Exception:  # noqa: BLE001
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

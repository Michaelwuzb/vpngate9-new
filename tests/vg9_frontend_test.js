/* 前端逻辑单测：从 vpngate9_multi.py 抽出面板内联 JS，用最小 DOM stub 跑，
   只验证"全部通道用同一个国家"新增的那几个函数（不依赖真实浏览器）。 */
const fs = require("fs");
const path = require("path");

function findSrc(start) {
  const cands = [start, path.join(start, ".."),
                 path.join(start, "vpngate9_fixed"),
                 path.join(start, "..", "vpngate9_fixed")];
  for (const c of cands) {
    const f = path.join(c, "vpngate9_multi.py");
    if (fs.existsSync(f)) return f;
  }
  throw new Error("找不到 vpngate9_multi.py，请在仓库目录内运行本测试");
}
const SRC = findSrc(__dirname);
const py = fs.readFileSync(SRC, "utf8");
const blocks = [...py.matchAll(/^<script>\n([\s\S]*?)^<\/script>/gm)].map(m => m[1]);
if (blocks.length !== 2) {
  console.error(`!! 期望 2 个 script 块，实际 ${blocks.length}`);
  process.exit(2);
}

let PASS = 0, FAIL = 0;
function check(name, ok, extra) {
  if (ok) { PASS++; console.log(`  [OK]   ${name}`); }
  else { FAIL++; console.log(`  [FAIL] ${name}  ${extra === undefined ? "" : extra}`); }
}

// ---- 最小 DOM stub ----
const els = {};
function mkEl(id) {
  return {
    id, value: "", checked: false, innerHTML: "", textContent: "", disabled: false,
    style: {}, options: [],
    classList: { _s: new Set(["modal"]), add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
                 contains(c) { return this._s.has(c); } },
    addEventListener() {},          // 面板会给筛选下拉挂 change 监听
    getAttribute() { return this._attr || null; },
    setAttribute(k, v) { this._attr = v; },
  };
}
for (const id of ["grid", "nc", "oc", "as_body", "as_msg", "as_apply", "as_ctry_row", "as_ctry",
                  "as_ctry_hint", "as_fill", "as_ipt", "as_count", "assignModal", "adminModal",
                  "rc", "a_msg", "a_pass", "a_newpass", "a_newpass2", "a_newuser",
                  "f_status", "f_country", "f_type", "f_sort",
                  "job", "job_txt", "job_bar", "btnPing", "btnSpeed", "btnStop", "ckall"]) {
  els[id] = mkEl(id);
}
let radioMode = "same";
let domRows = [];                 // 表格里的 checkbox 行
global.document = {
  getElementById: id => els[id] || (els[id] = mkEl(id)),
  querySelector: sel => (sel.indexOf("as_mode") >= 0 ? { value: radioMode } : null),
  querySelectorAll: sel => (sel.indexOf("#tb .cb") >= 0 ? domRows : []),
};
global.alert = () => {};
global.confirm = () => true;
global.CH = [];
global._CS = {};
global._CTRY = [];
// 顶层会执行 rf()，让 fetch 永远 pending，避免 render() 真的去碰 DOM
global.fetch = () => new Promise(() => {});
global.location = { href: "/" };

// 执行两个脚本块（顶层 var 落到 globalThis）
for (const b of blocks) {
  (0, eval)(b);
}

console.log("[1] 国家下拉：按可用节点数降序，默认选中最多可用的那个");
_CS = {
  "Japan": { total: 42, residential: 27, mobile: 1, hosting: 14, used: 0 },
  "Korea Republic of": { total: 33, residential: 30, mobile: 0, hosting: 3, used: 5 },
  "Thailand": { total: 8, residential: 8, mobile: 0, hosting: 0, used: 0 },
  "China": { total: 1, residential: 1, mobile: 0, hosting: 0, used: 1 },
};
_CTRY = ["Thailand", "China", "Japan", "Korea Republic of"];
fillCtryOptions();
const html = els.as_ctry.innerHTML;
const order = [...html.matchAll(/value="([^"]+)"/g)].map(m => m[1]);
check("按可用数降序排列", JSON.stringify(order) ===
      JSON.stringify(["Japan", "Korea Republic of", "Thailand", "China"]), JSON.stringify(order));
check("label 带可用/总数", html.indexOf("Japan · 可用 42/42") >= 0, html.slice(0, 120));
check("无可用节点显示 0", html.indexOf("China · 可用 0/1") >= 0);
check("默认选中第一个（可用最多）", els.as_ctry.value === "Japan", els.as_ctry.value);

console.log("\n[2] 已选国家在刷新后保留，不会被轮询冲掉");
els.as_ctry.value = "Thailand";
fillCtryOptions();
check("保留用户选择", els.as_ctry.value === "Thailand", els.as_ctry.value);

console.log("\n[3] 本次需要几条通道 / 可用数量提示");
els.as_count.value = "";
CH = new Array(9).fill({});
check("count 为空取通道总数", needCount() === 9, String(needCount()));
els.as_count.value = "4";
check("count 有值按值取", needCount() === 4, String(needCount()));
els.as_count.value = "";
els.as_ctry.value = "Japan";
asCtryHint();
check("提示显示可用数与需求数",
      /可用[\s\S]*42[\s\S]*9 条/.test(els.as_ctry_hint.innerHTML), els.as_ctry_hint.innerHTML);
check("够用时标绿", els.as_ctry_hint.innerHTML.indexOf("#22c55e") >= 0);
els.as_ctry.value = "Thailand";
asCtryHint();
check("不够时标橙", els.as_ctry_hint.innerHTML.indexOf("#f59e0b") >= 0, els.as_ctry_hint.innerHTML);

console.log("\n[4] 模式切换时的显隐");
radioMode = "same"; asModeUI();
check("same 模式显示国家选择区", els.as_ctry_row.style.display === "flex", els.as_ctry_row.style.display);
radioMode = "country"; asModeUI();
check("country 模式隐藏国家选择区", els.as_ctry_row.style.display === "none", els.as_ctry_row.style.display);
radioMode = "ip"; asModeUI();
check("ip 模式隐藏国家选择区", els.as_ctry_row.style.display === "none");

console.log("\n[5] 请求参数拼接");
els.as_ipt.value = "residential";
els.as_count.value = "6";
els.as_ctry.value = "Korea Republic of";
els.as_fill.checked = true;
radioMode = "same";
let q = asQ();
const qs = new URLSearchParams(q);
check("mode=same", qs.get("mode") === "same", q);
check("带上 country", qs.get("country") === "Korea Republic of", q);
check("带上 fill=1", qs.get("fill") === "1", q);
check("保留 ip_type 与 count", qs.get("ip_type") === "residential" && qs.get("count") === "6", q);
radioMode = "country";
q = asQ();
check("country 模式不残留 country 参数", new URLSearchParams(q).get("country") === "", q);
check("country 模式 fill 归零", new URLSearchParams(q).get("fill") === "0", q);

console.log("\n[6] 转义：国家名里的特殊字符不会破坏 HTML");
_CS = { 'A"B<script>': { total: 3, used: 0 } };
_CTRY = ['A"B<script>'];
els.as_ctry.value = "";
fillCtryOptions();
check("引号与尖括号已转义",
      els.as_ctry.innerHTML.indexOf("&quot;") >= 0 && els.as_ctry.innerHTML.indexOf("<script>") < 0,
      els.as_ctry.innerHTML);

console.log("\n[7] 时间 / 速率格式化");
check("fmtAge 秒", fmtAge(30) === "30 秒前", fmtAge(30));
check("fmtAge 分钟", fmtAge(120) === "2 分钟前", fmtAge(120));
check("fmtAge 小时", fmtAge(7200) === "2 小时前", fmtAge(7200));
check("fmtAge 天", fmtAge(172800) === "2 天前", fmtAge(172800));
check("fmtAge 负数返回 -", fmtAge(-1) === "-", fmtAge(-1));
check("fmtBps Mbps", fmtBps(10000000) === "10.0 Mbps", fmtBps(10000000));
check("fmtBps Gbps", fmtBps(2000000000) === "2.00 Gbps", fmtBps(2000000000));
check("fmtBps Kbps", fmtBps(500000) === "500 Kbps", fmtBps(500000));
check("fmtBps 0 显示 -", fmtBps(0) === "-", fmtBps(0));

console.log("\n[8] 节点勾选（批量测速用）");
CK = {};
const fakeRow = id => ({ checked: false, getAttribute: () => id });
const f1 = fakeRow("n1");
ckNode(Object.assign({}, f1, { checked: true }));
check("单个勾选写入 CK", CK["n1"] === 1, JSON.stringify(CK));
ckNode(Object.assign({}, f1, { checked: false }));
check("取消勾选从 CK 移除", !CK["n1"], JSON.stringify(CK));
domRows = [fakeRow("a"), fakeRow("b"), fakeRow("c")];
domRows.forEach(r => { r.checked = true; });
toggleAllNodes(true);
check("全选写入 3 个 id", checkedIds().length === 3, JSON.stringify(checkedIds()));
domRows.forEach(r => { r.checked = false; });
toggleAllNodes(false);
check("全不选清空 CK", checkedIds().length === 0, JSON.stringify(checkedIds()));

console.log("\n[9] 任务进度条");
els.job.style.display = "none";
updateJobs({ ping_task: { running: true, done: 3, total: 6, ok: 2, fail: 1 }, speed_task: {} });
check("延迟任务进行中展开进度区", els.job.style.display === "", els.job.style.display);
check("文案带 done/total", /3\/6/.test(els.job_txt.textContent), els.job_txt.textContent);
check("进度条宽度按比例", els.job_bar.style.width === "50%", els.job_bar.style.width);
check("测速未跑时不显示停止按钮", els.btnStop.style.display === "none", els.btnStop.style.display);
check("两个启动按钮都被禁用防重复提交",
      els.btnSpeed.disabled === true && els.btnPing.disabled === true);
updateJobs({ ping_task: {}, speed_task: { running: true, done: 1, total: 4, current_ip: "1.2.3.4:443" } });
check("显示当前正在测的节点", els.job_txt.textContent.indexOf("1.2.3.4:443") >= 0,
      els.job_txt.textContent);
check("测速中出现停止按钮", els.btnStop.style.display === "", els.btnStop.style.display);

console.log(`\n===== 结果: ${PASS} 通过 / ${FAIL} 失败 =====`);
process.exit(FAIL ? 1 : 0);

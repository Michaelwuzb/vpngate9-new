"""端到端验证「精确到县（都道府县）」：/api/regions + auto_assign?region= + 页面元素。

流程：起一个隔离的面板实例 -> 登录 -> 查行政区列表 -> 预览"日本 东京都 9 通道"
-> 检查方案里每条通道都带了县信息、目标县优先、不够时按距离递补。

依赖 IP 情报（ip-api）才能有县数据。拿不到时会明确标 SKIP，而不是误报失败。
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

SRC = os.path.dirname(os.path.abspath(__file__))


def _find_src(start):
    for c in (start, os.path.join(start, os.pardir)):
        c = os.path.abspath(c)
        if os.path.isfile(os.path.join(c, "vpngate9_multi.py")):
            return c
    raise SystemExit("找不到 vpngate9_multi.py，请在仓库目录内运行本测试")


FIX = _find_src(SRC)
WORK = tempfile.mkdtemp(prefix="vg9regionhttp_")
ROOT = os.path.join(WORK, "opt").replace("\\", "/")
PORT = 18803
PY = sys.executable

PASS = FAIL = SKIP = 0


def check(name, ok, extra=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [OK]   {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}  {extra}")


def skip(name, why=""):
    global SKIP
    SKIP += 1
    print(f"  [SKIP] {name}  {why}")


for f in sorted(n for n in os.listdir(FIX) if n.endswith(".py")):
    txt = open(os.path.join(FIX, f), encoding="utf-8").read()
    txt = txt.replace('Path("/opt/michaelvpn")', f'Path(r"{ROOT}")')
    txt = txt.replace('UI_HOST = "::"', 'UI_HOST = "127.0.0.1"')
    txt = txt.replace("UI_PORT = 8787", f"UI_PORT = {PORT}")
    open(os.path.join(WORK, f), "w", encoding="utf-8").write(txt)

env = dict(os.environ)
env["no_proxy"] = env["NO_PROXY"] = "127.0.0.1,localhost"
env["VPNGATE_UI_TLS"] = "off"

op = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                urllib.request.HTTPCookieProcessor())


def call(method, path, body=None, timeout=120):
    url = f"http://127.0.0.1:{PORT}{path}"
    data = urllib.parse.urlencode(body).encode() if isinstance(body, dict) else body
    req = urllib.request.Request(url, data=data, method=method)
    if isinstance(body, dict):
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        r = op.open(req, timeout=timeout)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:      # noqa: BLE001
        return -1, str(e)


print(f"[setup] 隔离目录 {WORK}，端口 {PORT}")
srv = subprocess.Popen([PY, "vpngate9_multi.py"], cwd=WORK,
                       stdout=open(os.path.join(WORK, "srv.log"), "w"),
                       stderr=subprocess.STDOUT, env=env)
ready = False
for _ in range(90):
    s = socket.socket(); s.settimeout(1)
    try:
        s.connect(("127.0.0.1", PORT)); s.close(); ready = True; break
    except Exception:
        s.close(); time.sleep(1)
check("面板启动并监听端口", ready)

try:
    for _ in range(120):
        code, _t = call("GET", "/")
        if code == 200:
            break
        time.sleep(1)

    print("\n[1] 登录")
    code, txt = call("POST", "/api/login", {"username": "admin", "password": "admin"})
    check("登录成功", code == 200 and "分配出口" in txt, f"code={code}")

    print("\n[2] 等节点池就绪（含 IP 情报）")
    code, txt = call("GET", "/api/status")
    st = json.loads(txt) if code == 200 else {}
    check("拿到 status", code == 200, f"code={code}")
    node_count = st.get("node_count", 0)
    check("节点池非空", node_count > 0, f"node_count={node_count}")
    print(f"         节点 {node_count} 个，国家 {len(st.get('countries', []))} 个")
    # 面板选了「住宅」时，国家下拉要按住宅口径显示"可用 N/M"，这份数据从 /api/status 来
    cst = st.get("country_stats_by_type") or {}
    check("/api/status 带按 IP 类型分开的国家供给",
          {"residential", "hosting", "mobile", "unknown"} <= set(cst), str(list(cst)))
    cs_all = st.get("country_stats") or {}
    if "Japan" in cs_all:
        check("按类型供给与总供给口径一致（Japan 住宅数 = 总数里的 residential）",
              cst["residential"]["Japan"]["total"] == cs_all["Japan"]["residential"],
              f'{cst["residential"]["Japan"]["total"]} vs {cs_all["Japan"]["residential"]}')

    print("\n[3] /api/regions?country=Japan")
    code, txt = call("GET", "/api/regions?country=Japan")
    d = json.loads(txt) if code == 200 else {}
    check("返回 200", code == 200, f"code={code}")
    rows = d.get("regions") or []
    check("日本返回 47 个都道府县", len(rows) == 47, f"len={len(rows)}")
    check("has_presets=true", d.get("has_presets") is True)
    by_key = {r["key"]: r for r in rows}
    check("含 JP-13 东京都", by_key.get("JP-13", {}).get("name") == "东京都", str(by_key.get("JP-13")))
    check("东京都带大区=关东", by_key.get("JP-13", {}).get("zone") == "关东")
    chains = d.get("chains") or {}
    check("返回东京都的固定递补顺序",
          chains.get("JP-13") == ["东京都", "埼玉县", "神奈川县", "千叶县", "山梨县"],
          str(chains.get("JP-13")))
    with_nodes = [r for r in rows if r.get("total", 0) > 0]
    print(f"         有节点的县 {len(with_nodes)} 个；"
          f"东京都 可用 {by_key.get('JP-13', {}).get('free')}/{by_key.get('JP-13', {}).get('total')}")
    if not with_nodes:
        skip("东京都节点供给", "节点池里没有带行政区信息的日本节点（ip-api 不可用？）")

    print("\n[3b] /api/regions?ip_type=residential：计数只算住宅")
    code, txt = call("GET", "/api/regions?country=Japan&ip_type=residential")
    d3 = json.loads(txt) if code == 200 else {}
    check("住宅口径返回 200", code == 200, f"code={code}")
    check("响应回显 ip_type", d3.get("ip_type") == "residential", str(d3.get("ip_type")))
    r_rows = d3.get("regions") or []
    check("同样 47 个都道府县", len(r_rows) == 47, str(len(r_rows)))
    if with_nodes:
        tot_all = sum(r.get("total", 0) for r in rows)
        tot_res = sum(r.get("total", 0) for r in r_rows)
        check("住宅计数不超过总数", tot_res <= tot_all, f"{tot_res} vs {tot_all}")
        by_res = {r["key"]: r for r in r_rows}
        check("每个县的住宅数都不超过该县总数",
              all(by_res.get(k, {}).get("total", 0) <= v.get("total", 0)
                  for k, v in by_key.items()),
              str([(k, v.get("total"), by_res.get(k, {}).get("total"))
                   for k, v in by_key.items() if v.get("total")]))
        print(f"         东京都 全部 {by_key.get('JP-13', {}).get('total')} 个 / "
              f"住宅 {by_res.get('JP-13', {}).get('total')} 个")
    else:
        skip("住宅/总数对比", "没有带县信息的节点")

    print("\n[3c] 住宅模式规划：不能出现机房节点")
    code, txt = call("POST",
                     "/api/channels/auto_assign?dry_run=1&mode=same&country=Japan"
                     "&region=JP-13&ip_type=residential&count=")
    d4 = json.loads(txt) if code == 200 else {}
    if code == 503:
        # 全站没有住宅节点 -> 后端拒绝分配是**正确**行为（旧版会静默用机房顶上）
        check("没有住宅节点时拒绝分配（而不是拿机房顶替）",
              "已排除其它类型" in txt, txt[:160])
    else:
        check("住宅模式预览返回 200", code == 200, f"code={code} {txt[:160]}")
        bad = [p for p in (d4.get("plan") or []) if p.get("ip_type") != "residential"]
        check("方案里没有一条是机房/移动/未知", not bad, str(bad[:3]))

    print("\n[4] 缺参数/未知国家")
    code, _t = call("GET", "/api/regions")
    check("不带 country -> 400", code == 400, f"code={code}")
    code, txt = call("GET", "/api/regions?country=Nowhereland")
    d2 = json.loads(txt) if code == 200 else {}
    check("未知国家返回空列表而不报错", code == 200 and d2.get("regions") == [],
          f"code={code}")

    print("\n[5] 预览：mode=same + Japan + 东京都")
    q = ("/api/channels/auto_assign?dry_run=1&mode=same&country=Japan"
         "&region=JP-13&count=")
    code, txt = call("POST", q)
    d = json.loads(txt) if code == 200 else {}
    if code == 503:
        skip("东京都方案", f"节点池里没有 Japan 节点：{txt[:120]}")
    else:
        check("返回 200", code == 200, f"code={code} {txt[:160]}")
        plan = d.get("plan") or []
        check("规划 9 条", len(plan) == 9, f"len={len(plan)}")
        check("返回 region 名（中文）", d.get("region") == "东京都", str(d.get("region")))
        check("返回 regions 供给表", len(d.get("regions") or []) == 47,
              str(len(d.get("regions") or [])))
        have_region_field = all("region" in p for p in plan)
        check("每条方案都带县字段", have_region_field)
        chain = d.get("region_chain") or []
        check("预览返回固定递补顺序", chain[:2] == ["东京都", "埼玉县"], str(chain))
        keyed = [p for p in plan if p.get("region_key")]
        if keyed:
            # 固定顺序：埼玉(1) -> 神奈川(2) -> 千叶(3) -> 山梨(4) 必须按序出现
            pos = {"JP-11": 1, "JP-14": 2, "JP-12": 3, "JP-19": 4}
            seq = [pos[p["region_key"]] for p in keyed if p["region_key"] in pos]
            check("固定顺序的落点按 埼玉→神奈川→千叶→山梨 依次出现",
                  seq == sorted(seq), str(seq))
            tokyo = [p for p in keyed if p["region_key"] == "JP-13"]
            check("优先落在东京都（至少有命中）", len(tokyo) >= 1,
                  str([p.get("region") for p in plan]))
            # 命中目标县的必须排在降级的前面
            tiers = [p.get("region_tier") for p in keyed]
            check("tier 顺序：命中县在前", tiers == sorted(tiers), str(tiers))
            deg = [p for p in keyed if p.get("region_tier") != 0]
            if deg:
                check("降级项带距离", all(p.get("distance_km") is not None for p in deg),
                      str([p.get("distance_km") for p in deg]))
                msgs = " ".join(d.get("warnings") or [])
                check("警告里说明了就近降级", "就近降级" in msgs, msgs[:200])
                print(f"         降级落点: "
                      f"{[(p['region'], round(p['distance_km'])) for p in deg]}")
            else:
                check("全部命中东京都时给正向 note", "东京都" in (d.get("note") or ""),
                      d.get("note"))
        else:
            skip("县匹配断言", "节点都没有行政区信息")

    print("\n[6] 单通道 connect 带 region 参数")
    code, txt = call("POST", "/api/channel/0/connect?country=Japan&region=JP-13&ip_type=")
    d = json.loads(txt) if code == 200 else {}
    if code == 503:
        skip("单通道 region 连接", "没有可用节点")
    else:
        ch = d.get("channel") or {}
        check("接口接受 region 参数", code == 200 and "channel" in d, f"code={code} {txt[:120]}")
        check("force_region 已写入", ch.get("force_region") == "JP-13",
              str(ch.get("force_region")))

    print("\n[6b] 通道状态带 region_lock（降级锁定落点）")
    code, txt = call("GET", "/api/status")
    st = json.loads(txt) if code == 200 else {}
    chs = st.get("channels") or []
    check("通道列表带 region_lock 字段",
          bool(chs) and all("region_lock" in c for c in chs), f"len={len(chs)}")

    print("\n[7] 页面元素")
    code, html = call("GET", "/")
    for token in ("精确到县", "id=\"as_region\"", "id=\"f_region\"", "function fillAsRegions",
                  "function loadRegions", "function fillRegionSel", "县/州",
                  "function asRegionHint", "region_tier", "已锁定",
                  "function regionChainText", "固定递补顺序"):
        check(f"页面含 {token}", token in html)

    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    js = os.path.join(WORK, "page.js")
    open(js, "w", encoding="utf-8").write("\n;\n".join(scripts))
    node = os.environ.get("NODE") or shutil.which("node") or "node"
    if os.path.isfile(node) or shutil.which(node):
        r = subprocess.run([node, "--check", js], capture_output=True, text=True)
        check("前端 JS 语法检查通过", r.returncode == 0, (r.stderr or "")[:300])
    else:
        skip("前端 JS 语法检查", "找不到 node")
finally:
    srv.terminate()
    try:
        srv.wait(timeout=5)
    except Exception:
        srv.kill()

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 / {SKIP} 跳过 =====")
ok = FAIL == 0
if not ok:
    print(f"（服务端日志：{os.path.join(WORK, 'srv.log')}）")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if not ok else 0)

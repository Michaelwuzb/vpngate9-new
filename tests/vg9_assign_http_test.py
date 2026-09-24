"""端到端验证「分配出口」接口：预览 -> 应用 -> 状态回读，外加前端页面/JS 检查。"""
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
    """定位源码目录：兼容 源码与测试同目录 / tests 子目录 / 旧的 vpngate9_fixed 布局。"""
    for c in (start, os.path.join(start, os.pardir),
              os.path.join(start, "vpngate9_fixed"),
              os.path.join(start, os.pardir, "vpngate9_fixed")):
        c = os.path.abspath(c)
        if os.path.isfile(os.path.join(c, "vpngate9_multi.py")):
            return c
    raise SystemExit("找不到 vpngate9_multi.py，请在仓库目录内运行本测试")


FIX = _find_src(SRC)
WORK = tempfile.mkdtemp(prefix="vg9http_")
ROOT = os.path.join(WORK, "opt").replace("\\", "/")
PORT = 18801
PY = sys.executable

PASS = FAIL = 0
def check(name, ok, extra=""):
    global PASS, FAIL
    if ok:
        PASS += 1; print(f"  [OK]   {name}")
    else:
        FAIL += 1; print(f"  [FAIL] {name}  {extra}")

for f in ("vpngate9_multi.py", "vpn_utils.py", "proxy_server_multi.py",
          "speedtest_utils.py"):
    txt = open(os.path.join(FIX, f), encoding="utf-8").read()
    txt = txt.replace('Path("/opt/michaelvpn")', f'Path(r"{ROOT}")')
    txt = txt.replace('UI_HOST = "::"', 'UI_HOST = "127.0.0.1"')
    txt = txt.replace("UI_PORT = 8787", f"UI_PORT = {PORT}")
    open(os.path.join(WORK, f), "w", encoding="utf-8").write(txt)

env = dict(os.environ)
env["no_proxy"] = env["NO_PROXY"] = "127.0.0.1,localhost"

op = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                urllib.request.HTTPCookieProcessor())

def call(method, path, body=None, cookie=None, timeout=90):
    url = f"http://127.0.0.1:{PORT}{path}"
    data = urllib.parse.urlencode(body).encode() if isinstance(body, dict) else body
    req = urllib.request.Request(url, data=data, method=method)
    if isinstance(body, dict):
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        r = op.open(req, timeout=timeout)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
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
    # 等面板起来（首次会拉 VPNGate + ip-api 富化）
    for _ in range(90):
        code, _txt = call("GET", "/")
        if code == 200:
            break
        time.sleep(1)

    print("\n[1] 未登录访问分配接口")
    code, _ = call("POST", "/api/channels/auto_assign?dry_run=1")
    check("未登录 -> 401", code == 401, f"code={code}")

    print("\n[2] 登录")
    code, txt = call("POST", "/api/login", {"username": "admin", "password": "admin"})
    # 登录是 302 跳转，opener 会自动跟随；这里用状态判断是否进了面板
    check("登录成功（能拿到面板页）", code == 200 and "分配出口" in txt, f"code={code}")
    cookie = None
    for h in op.handlers:
        if isinstance(h, urllib.request.HTTPCookieProcessor):
            for c in h.cookiejar:
                if c.name == "token":
                    cookie = f"token={c.value}"
    check("拿到会话 cookie", bool(cookie))

    print("\n[3] 等节点池就绪")
    ok_nodes = False
    for _ in range(120):
        code, txt = call("GET", "/api/status", cookie=cookie)
        try:
            st = json.loads(txt)
        except Exception:
            time.sleep(2); continue
        if st.get("node_count", 0) > 0:
            ok_nodes = True
            break
        time.sleep(2)
    check("节点池已就绪", ok_nodes, f"node_count={st.get('node_count')}")
    print(f"         节点 {st.get('node_count')} 个，国家 {len(st.get('countries', []))} 个")
    cs = st.get("country_stats", {})
    top = sorted(cs.items(), key=lambda kv: -kv[1]["total"])[:5]
    for k, v in top:
        print(f"         {k:20} 总{v['total']:3} 住宅{v['residential']:3} 已占{v['used']}")

    print("\n[4] 预览分配（mode=country）")
    code, txt = call("POST", "/api/channels/auto_assign?dry_run=1&mode=country", cookie=cookie)
    d = json.loads(txt)
    check("返回 200 且有方案", code == 200 and d.get("ok") and len(d.get("plan", [])) == 9,
          f"code={code} n={len(d.get('plan', []))}")
    plan = d["plan"]
    for p in plan:
        print(f"         CH{p['index']}  {p['country']:20} {p['ip']:16} {p['owner'][:26]}")
    check("出口 IP 互不重复", len({p["ip"] for p in plan}) == 9)
    check("覆盖多个国家", len({p["country"] for p in plan}) >= 6,
          f"{len({p['country'] for p in plan})} 个国家")
    check("未把 CN 节点分进来", all(p["country"].lower() != "china" for p in plan))
    check("带返回统计与警告", "countries" in d and "warnings" in d)
    for w in d.get("warnings", []):
        print(f"         警告: {w}")

    print("\n[5] 应用方案")
    plan_q = ",".join(f"{p['index']}:{p['node_id']}" for p in plan)
    code, txt = call("POST",
                     "/api/channels/auto_assign?mode=country&plan=" + urllib.parse.quote(plan_q, safe=""),
                     cookie=cookie)
    d2 = json.loads(txt)
    check("应用返回 ok", code == 200 and d2.get("ok"), f"code={code} {txt[:160]}")
    check("9 条通道全部下发", len(d2.get("applied", [])) == 9, str(len(d2.get("applied", []))))

    print("\n[6] 回读状态，确认配置生效且不撞 IP")
    time.sleep(3)
    code, txt = call("GET", "/api/status", cookie=cookie)
    st2 = json.loads(txt)
    chans = st2["channels"]
    fc = {c["index"]: c["force_country"] for c in chans}
    print(f"         force_country: {fc}")
    check("每通道写入了指定国家",
          sum(1 for c in chans if c["force_country"]) == 9, str(fc))
    check("每通道 enabled=True", all(c["enabled"] for c in chans))
    ips = [c["node_ip"] for c in chans if c["node_ip"]]
    dup = [c for c in chans if c.get("ip_dup_with")]
    check("出口 IP 无重复（ip_dup_with 全空）", not dup, str([(c["index"], c["ip_dup_with"]) for c in dup]))
    check("接口返回 outlets 出口占用统计", isinstance(st2.get("outlets"), dict))
    print(f"         出口占用: {len(st2.get('outlets', {}))} 个"
          f"（VM 里没 openvpn，能连上的通道数为 0 属正常）")

    print("\n[7] mode=ip 预览")
    code, txt = call("POST", "/api/channels/auto_assign?dry_run=1&mode=ip&ip_type=residential", cookie=cookie)
    d3 = json.loads(txt)
    check("住宅类型方案 9 条且 IP 唯一",
          d3.get("ok") and len({p["ip"] for p in d3["plan"]}) == len(d3["plan"]) == 9,
          txt[:200])
    print(f"         住宅IP 方案: {[p['ip'] for p in d3.get('plan', [])]}")

    print("\n[7b] mode=same：9 条通道全用同一个国家")
    cand = [k for k, v in cs.items()
            if (v["total"] - v["used"]) >= 9 and k.lower() != "china"]
    cand.sort(key=lambda k: -(cs[k]["total"] - cs[k]["used"]))
    target_c = cand[0] if cand else max(cs, key=lambda k: cs[k]["total"])
    free_c = cs[target_c]["total"] - cs[target_c]["used"]
    print(f"         固定国家 = {target_c}（可用 {free_c} 个）")
    q = "/api/channels/auto_assign?dry_run=1&mode=same&country=" + urllib.parse.quote(target_c)
    code, txt = call("POST", q, cookie=cookie)
    d5 = json.loads(txt)
    plan5 = d5.get("plan", [])
    check("same 模式返回 9 条方案", code == 200 and d5.get("ok") and len(plan5) == 9,
          f"code={code} n={len(plan5)} {txt[:160]}")
    check("9 条通道全在同一个国家",
          all(p["country"] == target_c for p in plan5),
          str(sorted({p["country"] for p in plan5})))
    check("9 个出口 IP 互不重复", len({p["ip"] for p in plan5}) == 9)
    check("返回 note 正向说明", bool(d5.get("note")), str(d5.get("note")))
    print(f"         note: {d5.get('note')}")
    for p in plan5[:3]:
        print(f"         CH{p['index']}  {p['country']:18} {p['ip']:16} {p['owner'][:24]}")

    print("\n[7c] same 模式：应用到前 3 条通道并回读")
    plan_q3 = ",".join(f"{p['index']}:{p['node_id']}" for p in plan5[:3])
    code, txt = call("POST", "/api/channels/auto_assign?mode=same&count=3&country="
                     + urllib.parse.quote(target_c)
                     + "&plan=" + urllib.parse.quote(plan_q3, safe=""), cookie=cookie)
    d6 = json.loads(txt)
    check("下发返回 ok 且 3 条", code == 200 and d6.get("ok") and len(d6.get("applied", [])) == 3,
          txt[:180])
    time.sleep(2)
    code, txt = call("GET", "/api/status", cookie=cookie)
    st3 = json.loads(txt)
    fc3 = {c["index"]: c["force_country"] for c in st3["channels"][:3]}
    check("前 3 条通道的固定国家都已写入",
          all(v == target_c for v in fc3.values()), str(fc3))

    print("\n[7d] same 模式：该国节点不够 / 非法国家")
    small = sorted(cs, key=lambda k: cs[k]["total"])[0]
    free_s = cs[small]["total"] - cs[small]["used"]
    code, txt = call("POST", "/api/channels/auto_assign?dry_run=1&mode=same&country="
                     + urllib.parse.quote(small), cookie=cookie)
    d7 = json.loads(txt)
    n7 = len(d7.get("plan", []))
    print(f"         {small} 可用 {free_s} 个 -> 方案 {n7} 条")
    check("节点不够时不硬凑（方案短于 9 条）", d7.get("ok") and n7 <= max(free_s, 1),
          f"n={n7} free={free_s}")
    check("给出\"填不满\"警告并推荐够用的国家",
          any("填不满" in w or "够填满" in w for w in d7.get("warnings", [])),
          str(d7.get("warnings"))[:220])
    code, txt = call("POST", "/api/channels/auto_assign?dry_run=1&mode=same&country="
                     + urllib.parse.quote(small) + "&fill=1", cookie=cookie)
    d8 = json.loads(txt)
    check("fill=1 时用其它国家补满 9 条",
          d8.get("ok") and len(d8.get("plan", [])) == 9
          and len({p["ip"] for p in d8["plan"]}) == 9,
          txt[:200])
    print(f"         补满后国家分布: {sorted({p['country'] for p in d8.get('plan', [])})}")
    code, txt = call("POST", "/api/channels/auto_assign?dry_run=1&mode=same&country=NotACountry",
                     cookie=cookie)
    check("不存在的国家 -> 503 且提示", code == 503, f"code={code} {txt[:140]}")

    print("\n[8] 单通道指定国家 / 冲突拒绝")
    code, txt = call("POST", "/api/channel/0/connect?country=" + urllib.parse.quote("Japan") + "&ip_type=",
                     cookie=cookie)
    d4 = json.loads(txt)
    check("单通道连接接口可用", code == 200 and "channel" in d4, txt[:160])

    print("\n[9] 前端页面与 JS")
    code, html = call("GET", "/", cookie=cookie)      # 登录后再取页面
    open(os.path.join(WORK, "index.html"), "w", encoding="utf-8").write(html)
    check("取到的是面板页（非登录页）", code == 200 and "<form" not in html[:400], f"code={code}")
    for token in ("分配出口", "assignModal", "function dupTag", "function previewAssign",
                  "function applyAssign", "country_stats", "ip_dup_with", "id=\"oc\"",
                  "value=\"same\"", "as_ctry", "as_fill", "function fillCtryOptions",
                  "function needCount", "全部通道用同一个国家"):
        check(f"页面含 {token}", token in html)
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    js = os.path.join(WORK, "page.js")
    open(js, "w", encoding="utf-8").write("\n;\n".join(scripts))
    print(f"         script 块 {len(scripts)} 个，已抽出 {os.path.getsize(js)} 字节")
    node = "C:/Users/Administrator/.workbuddy/binaries/node/versions/22.22.2-3/node.exe"
    r = subprocess.run([node, "--check", js], capture_output=True, text=True)
    check("前端 JS 语法检查通过", r.returncode == 0, (r.stderr or "")[:300])
finally:
    srv.terminate()
    try:
        srv.wait(timeout=5)
    except Exception:
        srv.kill()

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
ok = FAIL == 0
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if not ok else 0)

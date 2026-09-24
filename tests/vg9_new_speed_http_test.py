"""端到端验证【新节点标记】与【测速】接口（起真实面板进程 + mock 的 VPNGate 接口）。

为什么要 mock 节点源：真实 VPNGate 节点在境外，从本机测延迟全部超时、且数据每轮都在变，
断言没法稳定。这里把 API_URL 指向本地，喂一份自己造的节点表，就能精确控制
"哪些节点通、哪些不通、哪一轮多了节点"。

覆盖：
  [1] 未登录访问节点接口返回 401
  [2] 首次建基准不刷屏；/api/nodes 的首现时间字段
  [3] 下一轮新出现的节点被精确标记为"新"（filter=new / status.new_node_count）
  [4] 清除新标记：当前不新了，但之后新增的还能标上
  [5] 延迟测试：能连通的 >0、连不通的 =0，任务进度能收敛，结果回写到节点表
  [6] 按实测延迟排序
  [7] 带宽测速任务在无 openvpn 的环境里能正常跑完并如实报告失败（不卡死）
  [8] 通道测速接口的边界：未连接时给出明确错误
  [9] 页面上确实有这些新入口
"""
import base64
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
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
WORK = tempfile.mkdtemp(prefix="vg9nshttp_")
ROOT = os.path.join(WORK, "opt").replace("\\", "/")
PORT = 18823
PY = sys.executable

PASS = FAIL = 0
def check(name, ok, extra=""):
    global PASS, FAIL
    if ok:
        PASS += 1; print(f"  [OK]   {name}")
    else:
        FAIL += 1; print(f"  [FAIL] {name}  {extra}")

def head(t):
    print(f"\n=== {t} ===")

# ------------------------------------------------------- mock VPNGate 节点源
NODES = []
API_HITS = [0]

def build_csv():
    out = ["*VPN Gate Public VPN Relay Servers",
           "#HostName,IP,Port,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
           "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64"]
    cfg = base64.b64encode(b"client\ndev tun\nproto tcp\n").decode()
    for n in NODES:
        out.append(f"{n['hn']},{n['ip']},{n['port']},1000,{n['ping']},{n['speed']},"
                   f"Japan,JP,10,1000,10,1GB,2lines,{n['owner']},,{cfg}")
    return "\n".join(out) + "\n"


class MockApiHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        API_HITS[0] += 1
        body = build_csv().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


api_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockApiHandler)
API_PORT = api_srv.server_address[1]
threading.Thread(target=api_srv.serve_forever, daemon=True).start()
print(f"[setup] mock VPNGate API :{API_PORT}")

# 一个开着的端口当"通的节点"，关掉的端口当"不通的节点"
opened = socket.socket(); opened.bind(("127.0.0.1", 0)); opened.listen(5)
OPEN_PORT = opened.getsockname()[1]
tmp = socket.socket(); tmp.bind(("127.0.0.1", 0)); CLOSED_PORT = tmp.getsockname()[1]; tmp.close()
print(f"[setup] 通的端口 {OPEN_PORT} / 不通的端口 {CLOSED_PORT}")

NODES[:] = [
    {"hn": "n-ok",     "ip": "127.0.0.1", "port": OPEN_PORT,   "ping": 10, "speed": 50000000, "owner": "ISP-A"},
    {"hn": "n-dead",   "ip": "127.0.0.1", "port": CLOSED_PORT, "ping": 20, "speed": 10000000, "owner": "ISP-B"},
    {"hn": "n-third",  "ip": "127.0.0.1", "port": CLOSED_PORT, "ping": 30, "speed":  5000000, "owner": "ISP-C"},
]

# ------------------------------------------------------------- 隔离副本
for f in ("vpngate9_multi.py", "vpn_utils.py", "proxy_server_multi.py",
          "speedtest_utils.py"):
    txt = open(os.path.join(FIX, f), encoding="utf-8").read()
    txt = txt.replace('Path("/opt/michaelvpn")', f'Path(r"{ROOT}")')
    txt = txt.replace('UI_HOST = "::"', 'UI_HOST = "127.0.0.1"')
    txt = txt.replace("UI_PORT = 8787", f"UI_PORT = {PORT}")
    txt = txt.replace('API_URL = "https://www.vpngate.net/api/iphone/"',
                      f'API_URL = "http://127.0.0.1:{API_PORT}/api/iphone/"')
    txt = txt.replace("FETCH_INTERVAL = int(os.environ.get(\"FETCH_INTERVAL\", \"600\"))",
                      "FETCH_INTERVAL = 3600")          # 别让自动采集干扰断言
    txt = txt.replace('CONNECT_TIMEOUT = int(os.environ.get("CONNECT_TIMEOUT", "45"))',
                      'CONNECT_TIMEOUT = 3')            # 无 openvpn 时快速失败
    # 不联网做 IP 富化，避免测试依赖外网（只在主模块上打补丁，
    # 换行锚点要够精确，否则会误伤 proxy_server_multi 里缩进过的同名 import）
    if f == "vpngate9_multi.py":
        txt = txt.replace("import vpn_utils\nimport speedtest_utils\n",
                          "import vpn_utils\nimport speedtest_utils\n"
                          "vpn_utils.enrich_ip_info = lambda nodes: None\n", 1)
    open(os.path.join(WORK, f), "w", encoding="utf-8").write(txt)

env = dict(os.environ)
env["no_proxy"] = env["NO_PROXY"] = "127.0.0.1,localhost"
env["PYTHONUNBUFFERED"] = "1"

op = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                 urllib.request.HTTPCookieProcessor())
COOKIE = [None]

def call(method, path, body=None, timeout=60, use_cookie=True):
    url = f"http://127.0.0.1:{PORT}{path}"
    data = urllib.parse.urlencode(body).encode() if isinstance(body, dict) else body
    req = urllib.request.Request(url, data=data, method=method)
    if isinstance(body, dict):
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if use_cookie and COOKIE[0]:
        req.add_header("Cookie", COOKIE[0])
    try:
        r = op.open(req, timeout=timeout)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)

def jget(path, **kw):
    st, body = call("GET", path, **kw)
    try: return st, json.loads(body)
    except Exception: return st, {}

def jpost(path, **kw):
    st, body = call("POST", path, **kw)
    try: return st, json.loads(body)
    except Exception: return st, {}

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
check("[1] 面板启动并监听端口", ready)
if not ready:
    print(open(os.path.join(WORK, "srv.log"), encoding="utf-8", errors="replace").read()[-3000:])
    sys.exit(1)

# ------------------------------------------------------------ 登录
head("[1] 鉴权")
st, body = call("GET", "/api/nodes", use_cookie=False)
check("未登录访问 /api/nodes 返回 401", st == 401, f"status={st} body={body[:120]}")

st, body = call("POST", "/api/login", {"username": "admin", "password": "admin"})
check("登录接口可调用", st in (200, 302, 303, 0), f"status={st}")
# 登录是 302 跳转，Set-Cookie 在跳转响应上；这里直接看 opener 的 cookie jar
jar = None
for h in op.handlers:
    if isinstance(h, urllib.request.HTTPCookieProcessor):
        jar = h.cookiejar
names = [c.name for c in (jar or [])]
check("登录后拿到会话 token", "token" in names, str(names))
COOKIE[0] = None   # 交给 opener 的 cookie jar 统一管理

st, d = jget("/api/nodes")
check("登录后能读节点表", st == 200 and "nodes" in d, f"status={st}")

# ------------------------------------------------------ 新节点标记
head("[2] 首次建基准")
st, d = jpost("/api/fetch_nodes")
check("手动拉取成功", st == 200 and d.get("ok") is True, str(d)[:200])
check("启动时已建过基准，这里不再整池报新增", d.get("new") == 0, str(d))
check("总节点数正确", d.get("total") == 3, str(d))

st, d = jget("/api/nodes")
check("节点表返回 3 条", d.get("total") == 3, str(d.get("total")))
check("建基准后没有任何节点被标成新", not any(n["is_new"] for n in d["nodes"]),
      str([(n["id"], n["is_new"]) for n in d["nodes"]]))
check("每条节点都有首现时间", all(n["first_seen"] > 0 for n in d["nodes"]))
check("带回了官方速度字段", any(n["speed"] > 0 for n in d["nodes"]))

st, s = jget("/api/status")
check("status.new_node_count 为 0", s.get("new_node_count") == 0, str(s.get("new_node_count")))

head("[3] 下一轮出现新节点")
NODES.append({"hn": "n-new", "ip": "127.0.0.1", "port": CLOSED_PORT,
              "ping": 5, "speed": 80000000, "owner": "ISP-NEW"})
st, d = jpost("/api/fetch_nodes")
check("识别出 1 个新增节点", d.get("new") == 1, str(d))
check("新增节点的 id 被报回来", d.get("new_ids") == ["n-new"], str(d.get("new_ids")))
check("baseline 已不是 True", d.get("baseline") is False, str(d))

st, d = jget("/api/nodes")
new_rows = [n for n in d["nodes"] if n["is_new"]]
check("只有新节点带 is_new", len(new_rows) == 1 and new_rows[0]["id"] == "n-new",
      str([(n["id"], n["is_new"]) for n in d["nodes"]]))
check("新节点的首现时间就是这一轮", 0 <= new_rows[0]["new_age_s"] <= 30,
      str(new_rows[0]["new_age_s"]))
check("老节点的首现时间早于新节点",
      all(n["first_seen"] <= new_rows[0]["first_seen"] for n in d["nodes"]))

st, d = jget("/api/nodes?filter=new")
check("filter=new 只返回新节点", d.get("total") == 1 and d["nodes"][0]["id"] == "n-new", str(d.get("total")))

st, s = jget("/api/status")
check("status.new_node_count 变成 1", s.get("new_node_count") == 1, str(s.get("new_node_count")))
check("status.new_node_ttl 有值", s.get("new_node_ttl", 0) > 0)

head("[4] 清除新标记")
st, d = jpost("/api/nodes/clear_new")
check("清除接口成功", d.get("ok") is True, str(d))
check("报告清掉了 1 个标记", d.get("cleared") == 1, str(d))
st, d = jget("/api/nodes")
check("清除后没有节点算新", not any(n["is_new"] for n in d["nodes"]))
st, s = jget("/api/status")
check("status.new_node_count 归零", s.get("new_node_count") == 0)

NODES.append({"hn": "n-new2", "ip": "127.0.0.1", "port": CLOSED_PORT,
              "ping": 8, "speed": 20000000, "owner": "ISP-NEW2"})
st, d = jpost("/api/fetch_nodes")
check("清除标记后新出现的节点依然会被标记", d.get("new") == 1 and d.get("new_ids") == ["n-new2"], str(d))

# ------------------------------------------------------------ 延迟测试
head("[5] 延迟测试")
st, d = jget("/api/nodes/ping")
check("任务未启动时 running=false", d.get("running") is False, str(d))

st, d = jpost("/api/nodes/ping")
check("启动延迟测试成功", st == 200 and d.get("ok") is True, f"status={st} {d}")
check("任务总数等于节点数", d.get("total") == 5, str(d))

st, d = jpost("/api/nodes/ping")
check("重复启动被拒绝（不会叠任务）", st == 409 and d.get("ok") is False, f"status={st} {d}")

done = False
for _ in range(60):
    st, task = jget("/api/nodes/ping")
    if not task.get("running"):
        done = True; break
    time.sleep(0.5)
check("延迟测试任务收敛结束", done, str(task))
check("统计到 1 个通、4 个不通", task.get("ok") == 1 and task.get("fail") == 4, str(task))

st, d = jget("/api/nodes")
by_id = {n["id"]: n for n in d["nodes"]}
check("能连通的节点实测延迟 > 0", by_id["n-ok"]["tcp_latency"] > 0, str(by_id["n-ok"]["tcp_latency"]))
check("连不通的节点实测延迟 = 0", by_id["n-dead"]["tcp_latency"] == 0, str(by_id["n-dead"]["tcp_latency"]))
check("结果写回了测速时间戳", by_id["n-ok"]["tcp_latency_at"] > 0)
check("实测延迟远小于官方 Ping 字段（确实是本机实测）",
      by_id["n-ok"]["tcp_latency"] < 1000, str(by_id["n-ok"]["tcp_latency"]))

st, d = jget("/api/nodes?sort=latency")
check("按实测延迟排序：通的排最前", d["nodes"][0]["id"] == "n-ok",
      str([n["id"] for n in d["nodes"]]))
check("排序时延迟为 0 的排最后", d["nodes"][-1]["tcp_latency"] == 0)

# 刷新后结果不能被冲掉
st, _ = jpost("/api/fetch_nodes")
st, d = jget("/api/nodes")
by_id = {n["id"]: n for n in d["nodes"]}
check("整池刷新后实测延迟仍保留", by_id["n-ok"]["tcp_latency"] > 0,
      str(by_id["n-ok"].get("tcp_latency")))

# ------------------------------------------------------------ 带宽测速
head("[7] 带宽测速任务（本机无 openvpn，应当如实报告失败且不卡死）")
st, d = jpost("/api/channels/speedtest")
check("没有已连接通道时明确报错", st == 409 and d.get("ok") is False, f"status={st} {d}")
st, d = jpost("/api/channel/0/speedtest")
check("对未连接的通道测速会报错", st == 409 and d.get("ok") is False, f"status={st} {d}")

st, d = jpost("/api/nodes/speedtest?ids=n-ok,n-dead")
check("节点带宽测速任务能启动", st == 200 and d.get("ok") is True, f"status={st} {d}")
check("任务总数正确", d.get("total") == 2, str(d))

st, d = jpost("/api/nodes/speedtest?ids=n-ok")
check("同类型任务不能并行（防抢通道）", st == 409, f"status={st} {d}")

done = False
for _ in range(90):
    st, task = jget("/api/nodes/speedtest")
    if not task.get("running"):
        done = True; break
    time.sleep(0.5)
if not done:
    jpost("/api/nodes/speedtest_stop")
    time.sleep(1)
    st, task = jget("/api/nodes/speedtest")
check("测速任务能收敛结束（不会卡死）", done, f"running={task.get('running')} done={task.get('done')}")
check("失败数如实记录", task.get("fail") >= 1, str({k: task.get(k) for k in ("ok", "fail", "done")}))
res = task.get("results", {})
check("每个节点都有结果条目", len(res) == 2, str(res))
check("失败原因可读（不是空字符串）",
      all(str(v.get("error") or "") for v in res.values()), str(res))

st, s = jget("/api/status")
check("status 里能拿到测速任务摘要", "speed_task" in s and "results" not in s["speed_task"],
      str(s.get("speed_task"))[:200])

# 借用过的通道要把 enabled 还回去
st, s = jget("/api/status")
enabled_states = [c["enabled"] for c in s["channels"]]
check("测速借用的通道没有把 enabled 弄乱",
      all(isinstance(e, bool) for e in enabled_states), str(enabled_states))

head("[8] 停止接口的边界")
st, d = jpost("/api/nodes/speedtest_stop")
check("没有任务时停止会给出明确提示", st == 409 and d.get("ok") is False, f"status={st} {d}")

# ------------------------------------------------------------ 页面元素
head("[9] 页面与脚本")
st, html = call("GET", "/", use_cookie=False)
check("页面能打开", st == 200 and "MichaelVPN" in html, f"status={st}")
for kw, desc in [("测延迟", "延迟测试按钮"), ("测带宽", "带宽测速按钮"),
                 ("清除新标记", "清除新标记按钮"), ("通道测速", "通道测速按钮"),
                 ("只看新节点", "只看新节点筛选"), ("实测带宽", "实测带宽列")]:
    check(f"页面含{desc}", kw in html, kw)
check("页面含新节点徽标样式", "bnw" in html)
check("页面含勾选框（用于批量测速）", 'class="cb"' in html)

print(f"\n[info] mock API 被请求 {API_HITS[0]} 次")
srv.terminate()
try:
    srv.wait(timeout=10)
except Exception:
    srv.kill()

print("\n=== 结果 ===")
print(f"PASS={PASS}  FAIL={FAIL}")
sys.exit(1 if FAIL else 0)

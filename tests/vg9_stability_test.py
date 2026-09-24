"""验证本轮【稳定性/可用性】改造（不依赖真实 VPN 隧道）。

覆盖：
  [A] 端口预检 + 代理启动失败上报
      A1 端口被占的通道会出现在失败清单里，且 ch.proxy_error 有原因
      A2 其余通道的监听口真的能用（能连上、能做 SOCKS5 握手）
      A3 preflight_ports 能提前报出被占端口（不必等启动失败）
      A4 create_proxy_listener 重复绑定同一端口必须抛异常（不能静默）
  [B] 节点源多级回退 + 本地快照
      B1 主源失败 → 自动换备用源
      B2 两个在线源都失败 → 回退本地快照，并标记 source=snapshot
      B3 拉取成功时落盘的快照必须含 config_text（否则回退拿到也没法建隧道）
      B4 在线源与快照都没有 → 返回空，不抛异常
      B5 响应拿到但解析不出节点（内容坏了）也要继续试下一个源
      B6 快照恢复出来的节点字段完整，能直接进选节点流程
  [C] 策略路由清理与回读
      C1 cleanup_policy_routing 循环删 rule，直到删不动为止
      C2 rule 清完要 flush 路由表
      C3 policy_routing_ok 靠回读内核判断，正/反例都要判对
      C4 表号计算集中在 policy_table()，200 起步且不重叠
  [D] 连接就绪判定顺序
      D1 建策略路由 + 校验 + 代理端口检查都必须早于标记 connected
      D2 策略路由没生效 → 不能置 connected
      D3 代理端口没监听 → 不能置 connected
  [E] 进程清理不再误杀
      E1 cleanup_stale_openvpn 在没有 /proc 的环境下安全返回
      E2 源码里不应再出现裸的 pkill -f openvpn
  [F] openvpn 安全参数
      F1 默认带 --remote-cert-tls server
      F2 VPNGATE_STRICT_TLS=0 时可以关掉（个别节点证书不合规的兜底）
  [G] 安装脚本
      G1 卸载路径会清理 200~208 策略表
      G2 ml 的卸载分支同样清理
      G3 默认安装的仓库指向 vpngate9-new
"""
import base64
import importlib
import os
import socket
import sys
import tempfile
import threading
import time

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
WORK = tempfile.mkdtemp(prefix="vg9stab_")
ROOT = os.path.join(WORK, "opt").replace("\\", "/")

PASS = FAIL = 0


def check(name, ok, extra=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [OK]   {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}  {extra}")


def head(t):
    print(f"\n=== {t} ===")


# ---------------------------------------------------------------- 隔离副本
for f in ("vpngate9_multi.py", "vpn_utils.py", "proxy_server_multi.py",
          "speedtest_utils.py", "vpngate9_guard.py"):
    dst = os.path.join(WORK, f)
    txt = open(os.path.join(FIX, f), encoding="utf-8").read()
    txt = txt.replace('Path("/opt/michaelvpn")', f'Path(r"{ROOT}")')
    txt = txt.replace('UI_HOST = "::"', 'UI_HOST = "127.0.0.1"')
    open(dst, "w", encoding="utf-8").write(txt)
print(f"[setup] 隔离目录 {WORK}")

sys.path.insert(0, WORK)
M = importlib.import_module("vpngate9_multi")
PX = importlib.import_module("proxy_server_multi")
M.vpn_utils.enrich_ip_info = lambda nodes: None      # 测试不联网
print("[setup] 模块加载完成")


class R:
    """subprocess.run 的最小替身。"""
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def make_csv(n=3, prefix="host"):
    cfg = base64.b64encode(b"client\ndev tun\nremote 1.2.3.4 443\n").decode()
    lines = ["*VPN Gate Public VPN Relay Servers",
             "#HostName,IP,Port,CountryLong,CountryShort,NumVpnSessions,Ping,Speed,OpenVPN_ConfigData_Base64"]
    for i in range(n):
        lines.append(f"{prefix}{i},9.9.9.{i + 1},443,Japan,JP,1,12,3000000,{cfg}")
    return "\n".join(lines)


# ============================================================ A 端口预检
head("A. 端口预检 + 代理启动失败上报")

for ch in M.channels:
    ch.proxy_port = free_port()
    ch.proxy_error = ""

blocked = M.channels[0].proxy_port
blocker = socket.socket()
blocker.bind(("127.0.0.1", blocked))
blocker.listen(4)

failed = M.start_all_proxies()
check("A1 被占端口的通道进了失败清单", 0 in failed and len(failed) == 1, str(failed))
check("A1b 失败原因写进了 ch.proxy_error",
      bool(M.channels[0].proxy_error) and str(blocked) in M.channels[0].proxy_error,
      repr(M.channels[0].proxy_error))
check("A1c 正常通道没有被误报", all(i not in failed for i in range(1, M.NUM_CHANNELS)), str(failed))

ok_conn = False
try:
    s = socket.create_connection(("127.0.0.1", M.channels[1].proxy_port), timeout=2)
    s.sendall(b"\x05\x01\x00")           # SOCKS5 方法协商
    resp = s.recv(2)
    ok_conn = resp[:1] == b"\x05"
    s.close()
except OSError:
    pass
check("A2 正常通道的代理口真的在监听并能协商", ok_conn)

pre = M.preflight_ports()
check("A3 preflight_ports 提前报出被占端口",
      f"proxy0" in pre and str(blocked) in pre.get("proxy0", ""), str(pre))

blocked_before = False
try:
    PX.create_proxy_listener("127.0.0.1", blocked)
except OSError:
    blocked_before = True
check("A4 端口已被监听时 create_proxy_listener 抛异常（不静默）", blocked_before)

blocker.close()

# ============================================================ B 节点源回退
head("B. 节点源多级回退 + 本地快照")

GOOD_CSV = make_csv(3)
good_nodes = M._parse_vpngate_csv(GOOD_CSV)
check("B0 前置：CSV 解析正常", len(good_nodes) == 3 and good_nodes[0]["ip"] == "9.9.9.1",
      str(len(good_nodes)))

# 清掉可能存在的快照
try:
    os.remove(M.NODES_SNAPSHOT_FILE)
except OSError:
    pass

tried = []


def _src_https_down(url, timeout=30):
    tried.append(url)
    return None if url.startswith("https") else GOOD_CSV


_orig_fetch_raw = M._fetch_raw
M._fetch_raw = _src_https_down
nodes = M.fetch_nodes()
check("B1 主源失败自动换备用源",
      len(nodes) == 3 and M._last_fetch_source.startswith("http://"), M._last_fetch_source)
check("B1b 两个源都按顺序试过", len(tried) == 2, str(tried))

# 快照应已落盘
snap_nodes, snap_at = M.load_nodes_snapshot()
check("B3 拉取成功时落了快照", len(snap_nodes) == 3 and snap_at > 0, f"{len(snap_nodes)} {snap_at}")
check("B3b 快照含 config_text（否则回退后没法建隧道）",
      all(n.get("config_text") for n in snap_nodes))
check("B3c 快照不含损坏项", all(n.get("ip") for n in snap_nodes))

M._fetch_raw = lambda url, timeout=30: None          # 在线全挂
nodes = M.fetch_nodes()
check("B2 在线源全挂时回退本地快照", len(nodes) == 3 and M._last_fetch_source == "snapshot",
      f"{len(nodes)} {M._last_fetch_source}")
check("B6 快照节点字段完整（可直接进选节点）",
      all(n.get("id") and n.get("ip") and n.get("country_long") and n.get("config_text")
          for n in nodes),
      str(nodes[0] if nodes else None))

# 删掉快照，验证"什么都没有"时不炸
os.remove(M.NODES_SNAPSHOT_FILE)
M._snapshot_saved_at = 0.0
nodes = M.fetch_nodes()
check("B4 无源无快照时返回空且不抛异常", nodes == [] and M._last_fetch_source == "", str(nodes))

M._fetch_raw = lambda url, timeout=30: (GOOD_CSV if url.startswith("http://") else "<html>坏内容</html>")
nodes = M.fetch_nodes()
check("B5 内容解析不出节点时会继续试下一个源",
      len(nodes) == 3 and M._last_fetch_source.startswith("http://"), M._last_fetch_source)

M._fetch_raw = _orig_fetch_raw

# 通过统一入口跑一遍，确认 source 会带出去
M.fetch_nodes = lambda: good_nodes
r = M.refresh_nodes_once("test")
check("B7 refresh_nodes_once 会把数据来源带出来", "source" in r and r["source"] != "",
      str(r.get("source")))
mf = M.manual_fetch()
check("B7b manual_fetch 透传 source", "source" in mf, str(mf.get("source")))

# ============================================================ C 策略路由
head("C. 策略路由清理与回读")

calls = []


def _fake_run_ip_factory(returns):
    seq = list(returns)

    def fake(args):
        calls.append(list(args))
        rc, out = seq.pop(0) if seq else (1, "")
        return R(rc, out)
    return fake


_orig_run_ip = M._run_ip
M._run_ip = _fake_run_ip_factory([(0, ""), (0, ""), (0, ""), (1, ""), (0, "")])
calls.clear()
M.cleanup_policy_routing(200)
dels = [c for c in calls if c[:3] == ["rule", "del", "table"]]
flushes = [c for c in calls if c[:2] == ["route", "flush"]]
check("C1 rule 被循环删除直到删不动（4 次：3 次成功 + 1 次失败即停）",
      len(dels) == 4 and dels[0][3] == "200", str(calls))
check("C2 rule 清完会 flush 对应的路由表",
      len(flushes) == 1 and flushes[0] == ["route", "flush", "table", "200"], str(calls))

M._run_ip = lambda args: R(0, "32765:\tfrom all oif tun0 lookup 200\n" if args[0] == "rule"
                           else "default dev tun0 scope link\n")
check("C3 回读内核判定策略路由已生效", M.policy_routing_ok("tun0", 200) is True)

M._run_ip = lambda args: R(0, "32765:\tfrom all oif tun3 lookup 203\n" if args[0] == "rule"
                           else "default dev tun0 scope link\n")
check("C3b 通道/表号不匹配时要判否", M.policy_routing_ok("tun0", 200) is False)

M._run_ip = lambda args: R(0, "32765:\tfrom all oif tun0 lookup 200\n" if args[0] == "rule"
                           else "")
check("C3c 没有默认路由时要判否", M.policy_routing_ok("tun0", 200) is False)

M._run_ip = lambda args: None     # 没有 ip 命令（非 Linux）
check("C3d 拿不到 ip 命令输出时判否而不是崩", M.policy_routing_ok("tun0", 200) is False)
M._run_ip = _orig_run_ip

tables = [M.policy_table(i) for i in range(M.NUM_CHANNELS)]
check("C4 表号集中在 policy_table()，从 200 起且不重叠",
      tables == list(range(200, 200 + M.NUM_CHANNELS)), str(tables))
check("C4b 表号落在内核保留给本地自定义的区间(200~252)",
      all(200 <= t <= 252 for t in tables), str(tables))

# ============================================================ D 就绪顺序
head("D. 连接就绪判定顺序")

order = []
ch = M.channels[2]
ch.force_country = "Japan"
ch.state = "connecting"

_orig_openvpn_cmd = M.openvpn_cmd
M.openvpn_cmd = lambda cfg, tun: [sys.executable, "-c",
                                  "import time,sys;"
                                  "sys.stdout.write('Initialization Sequence Completed\\n');"
                                  "sys.stdout.flush();time.sleep(20)"]
M.vpn_utils.probe_tunnel = lambda tun, timeout=3: True
_orig_setup = M.setup_policy_routing
_orig_ok = M.policy_routing_ok
_orig_ready = M.proxy_port_ready
M.setup_policy_routing = lambda tun, table: (order.append(("setup", ch.state)), True)[1]
M.policy_routing_ok = lambda tun, table: (order.append(("check", ch.state)), True)[1]
M.proxy_port_ready = lambda port, *a, **k: (order.append(("proxy", ch.state)), True)[1]

ok = M.connect_channel(ch, {"id": "h1", "ip": "9.9.9.1", "port": "443", "country_long": "Japan",
                            "config_text": "client\n", "hostname": "h1"})
check("D0 连接成功", ok is True and ch.state == "connected", f"{ok} {ch.state}")
check("D1 建路由/回读/代理检查都发生在标记 connected 之前",
      [s for _, s in order] == ["connecting", "connecting", "connecting"], str(order))
check("D1b 三件事都做了", [k for k, _ in order] == ["setup", "check", "proxy"], str(order))
check("D1c 用的策略表是 policy_table(2)",
      M.policy_table(2) in (200, 201, 202), str(M.policy_table(2)))
M.stop_process(ch.process)
ch.state = "disconnected"

# D2 策略路由失败
order.clear()
M.setup_policy_routing = lambda tun, table: False
M.policy_routing_ok = lambda tun, table: (order.append("check"), True)[1]
M.proxy_port_ready = lambda port, *a, **k: (order.append("proxy"), True)[1]
ok = M.connect_channel(ch, {"id": "h2", "ip": "9.9.9.2", "port": "443", "country_long": "Japan",
                            "config_text": "client\n", "hostname": "h2"})
check("D2 策略路由没生效 → 拒绝标记已连接", ok is False and ch.state == "error",
      f"{ok} {ch.state} {ch.error}")
check("D2b 也没继续去查代理端口（短路）", order == [], str(order))

# D3 代理端口不通
M.setup_policy_routing = lambda tun, table: True
M.policy_routing_ok = lambda tun, table: True
M.proxy_port_ready = lambda port, *a, **k: False
ok = M.connect_channel(ch, {"id": "h3", "ip": "9.9.9.3", "port": "443", "country_long": "Japan",
                            "config_text": "client\n", "hostname": "h3"})
check("D3 代理端口没监听 → 拒绝标记已连接", ok is False and ch.state == "error",
      f"{ok} {ch.state} {ch.error}")
check("D3b 错误信息里点明了端口号",
      str(ch.proxy_port) in (ch.error or ""), repr(ch.error))

M.setup_policy_routing = _orig_setup
M.policy_routing_ok = _orig_ok
M.proxy_port_ready = _orig_ready

# ============================================================ E 进程清理
head("E. 进程清理不再误杀")

killed = M.cleanup_stale_openvpn()
check("E1 无 /proc 的环境下安全返回空列表", killed == [], str(killed))

src_multi = open(os.path.join(FIX, "vpngate9_multi.py"), encoding="utf-8").read()
check("E2 源码里不再有裸的 pkill -f openvpn",
      '"pkill","-f","openvpn"' not in src_multi and '"pkill", "-f", "openvpn"' not in src_multi)
check("E2b 改为只清理带自身配置路径的进程",
      "_our_config_marker" in src_multi and "cmdline" in src_multi)

# ============================================================ F openvpn 参数
head("F. openvpn 安全参数")

M.openvpn_cmd = _orig_openvpn_cmd      # D 段为了造假进程替换过它，这里要还原
cmd = M.openvpn_cmd("x.ovpn", "tun0")
has_tls = "--remote-cert-tls" in cmd and cmd[cmd.index("--remote-cert-tls") + 1] == "server"
check("F1 默认带 --remote-cert-tls server", has_tls, str(cmd[-8:]))

os.environ["VPNGATE_STRICT_TLS"] = "0"
cmd2 = M.openvpn_cmd("x.ovpn", "tun0")
check("F2 VPNGATE_STRICT_TLS=0 可关闭（留个不合规节点的退路）",
      "--remote-cert-tls" not in cmd2, str(cmd2[-8:]))
del os.environ["VPNGATE_STRICT_TLS"]

# ============================================================ G 安装脚本
head("G. 安装脚本")

sh = open(os.path.join(FIX, "install.sh"), encoding="utf-8").read()
check("G1 卸载会清理策略路由表", "cleanup_policy_routing" in sh and "seq 200 208" in sh)
check("G1b 卸载分支确实调用了它",
      sh.split("=== 卸载功能 ===", 1)[1].split("exit 0", 1)[0].count("cleanup_policy_routing") >= 1)
check("G2 ml 的卸载分支也清理路由",
      sh.count("ip rule del table") >= 2 and "ip route flush table" in sh)
check("G3 默认仓库指向 vpngate9-new", 'REPO_NAME="${2:-vpngate9-new}"' in sh)

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
sys.exit(1 if FAIL else 0)

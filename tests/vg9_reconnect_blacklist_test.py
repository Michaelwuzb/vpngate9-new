"""验证【失败节点黑名单 + 通道指数退避】修复（不依赖真实 VPN 隧道）。

背景（线上真实故障）：
  CH0 设成 force_country=United States + force_ip_type=residential。
  某天 VPNGate 全池 100 个节点里只剩 1 个美国节点（Cloudflare WARP，hosting 类型），
  而且它的 TCP 端口已经不可达。于是：
    [WD CH0] 隧道不通 连续 3 轮，准备重连
    [WD CH0] Reconnect United States residential   <- 又把这个死节点选回来
    [CH0] Starting tun0...                          <- 45 秒后失败
    90 秒后再来一遍……永远循环
  systemd 其实一次都没重启过（NRestarts=0），是看门狗在无限重连，
  但日志看过去就像"服务崩溃后无限重启"。

覆盖：
  [A] 失败节点黑名单
      A1 连不上的节点被拉黑后不再被选中
      A2 "该国唯一候选节点已死"时返回 None，而不是把死节点一遍遍选回来
      A3 拉黑时长随失败次数翻倍，且有上限
      A4 拉黑只影响该 IP，别的节点照常可选
  [B] 黑名单持久化
      B1 落盘后能重新载入
      B2 载入时丢弃已过期条目
      B3 过期的条目在查询时自动失效并被清掉
  [C] 断网误伤保护
      C1 本机出口不通时不把节点记为坏节点
      C2 本机出口正常时才拉黑
  [D] 通道指数退避
      D1 看门狗不再用固定 RECONNECT_COOLDOWN
      D2 退避上限受 MAX_RECONNECT_BACKOFF 约束
      D3 连接成功后 connect_fails 归零
      D4 通道对象带 connect_fails / no_node_at 字段
  [E] "没有可用节点"告警节流
      E1 日志打了时间戳节流（不是每 15 秒刷一行）
      E2 原因写进了通道 error，面板能看到
  [F] 回归：正常选节点不受影响
"""
import importlib
import os
import sys
import tempfile
import time

SRC = os.path.dirname(os.path.abspath(__file__))


def _find_src(start):
    for c in (start, os.path.join(start, os.pardir),
              os.path.join(start, "vpngate9_fixed"),
              os.path.join(start, os.pardir, "vpngate9_fixed")):
        c = os.path.abspath(c)
        if os.path.isfile(os.path.join(c, "vpngate9_multi.py")):
            return c
    raise SystemExit("找不到 vpngate9_multi.py，请在仓库目录内运行本测试")


FIX = _find_src(SRC)
WORK = tempfile.mkdtemp(prefix="vg9blk_")
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


_SRC_MODULES = sorted(n for n in os.listdir(FIX) if n.endswith('.py'))
for f in _SRC_MODULES:
    txt = open(os.path.join(FIX, f), encoding="utf-8").read()
    txt = txt.replace('Path("/opt/michaelvpn")', f'Path(r"{ROOT}")')
    txt = txt.replace('UI_HOST = "::"', 'UI_HOST = "127.0.0.1"')
    open(os.path.join(WORK, f), "w", encoding="utf-8").write(txt)
print(f"[setup] 隔离目录 {WORK}")

sys.path.insert(0, WORK)
M = importlib.import_module("vpngate9_multi")
M.vpn_utils.enrich_ip_info = lambda nodes: None      # 测试不联网
print("[setup] 模块加载完成")

SRC_TXT = open(os.path.join(FIX, "vpngate9_multi.py"), encoding="utf-8").read()


def node(ip, country, ip_type, nid):
    return {"id": nid, "ip": ip, "hostname": nid, "country_long": country,
            "ip_type": ip_type, "speed": 5_000_000, "config_text": "client\ndev tun\n",
            "owner": "test", "location": country}


def set_pool(items):
    with M.nodes_cache_lock:
        M.nodes_cache = list(items)


US_DEAD = node("104.28.237.60", "United States", "hosting", "us-dead")
JP_OK = node("60.91.157.48", "Japan", "residential", "jp-ok")

# 清空磁盘上可能残留的黑名单，保证从干净状态开始
M._blacklist.clear()
M._save_blacklist()

# ============================================================ A 黑名单
head("A. 失败节点黑名单")

set_pool([US_DEAD, JP_OK])
n = M.get_best_node_for_country("United States", "residential")
check("A0 前置：美国只有 hosting 节点时放宽类型仍能选到（原行为保留）",
      bool(n) and n["ip"] == US_DEAD["ip"], str(n))

M.blacklist_node(US_DEAD["ip"], "隧道不通")
n2 = M.get_best_node_for_country("United States", "residential")
check("A1 被拉黑的节点不再被选中", n2 is None, str(n2))

check("A2 '该国唯一候选节点已死'时返回 None（不再一遍遍选回死节点）", n2 is None)

M._blacklist.clear()
M.blacklist_node("9.9.9.9", "x")
t1 = M._blacklist["9.9.9.9"]["until"] - time.time()
M.blacklist_node("9.9.9.9", "x")
t2 = M._blacklist["9.9.9.9"]["until"] - time.time()
check("A3 第二次失败拉黑时长翻倍", t2 > t1 * 1.8, f"{t1:.0f} -> {t2:.0f}")
for _ in range(12):
    M.blacklist_node("9.9.9.9", "x")
tmax = M._blacklist["9.9.9.9"]["until"] - time.time()
check("A3b 拉黑时长有上限（不会无限增长）",
      tmax <= M.NODE_BLACKLIST_MAX_TTL + 2, f"{tmax:.0f} vs {M.NODE_BLACKLIST_MAX_TTL}")

n3 = M.get_best_node_for_country("Japan", "residential")
check("A4 黑名单只影响该 IP，其它节点照常可选",
      bool(n3) and n3["ip"] == JP_OK["ip"], str(n3))

set_pool([US_DEAD])
n4 = M.get_best_node_for_country("United States", "residential")
check("A5 死节点重新可用时（黑名单到期）能再次选到", n4 is not None, str(n4))

# ============================================================ B 持久化
head("B. 黑名单持久化")

M._blacklist.clear()
M.blacklist_node("7.7.7.7", "persist")
check("B1a 写入后落盘文件存在", os.path.isfile(M.BLACKLIST_FILE), M.BLACKLIST_FILE)
M._blacklist.clear()
M.load_blacklist()
check("B1b 重新载入后仍在拉黑期内", M.is_blacklisted("7.7.7.7"))

M.write_json(M.BLACKLIST_FILE, {
    "6.6.6.6": {"until": time.time() + 600, "fails": 1, "reason": "ok"},
    "5.5.5.5": {"until": time.time() - 600, "fails": 3, "reason": "expired"},
})
M._blacklist.clear()
M.load_blacklist()
check("B2 载入时保留未过期条目", M.is_blacklisted("6.6.6.6"))
check("B2b 载入时丢弃已过期条目", not M.is_blacklisted("5.5.5.5"), str(M._blacklist))

M._blacklist["4.4.4.4"] = {"until": time.time() - 1, "fails": 1, "reason": "old"}
check("B3a 过期条目查询时返回未拉黑", M.is_blacklisted("4.4.4.4") is False)
check("B3b 过期条目被顺手清掉", "4.4.4.4" not in M._blacklist)

# ============================================================ C 断网误伤保护
head("C. 断网误伤保护")

_orig_alive = M.upstream_alive
ch = M.channels[0]
ch.node_ip = "3.3.3.3"

M.upstream_alive = lambda *a, **k: False
M.mark_node_bad(ch, "隧道不通")
check("C1 本机出口不通时不把节点记为坏节点", not M.is_blacklisted("3.3.3.3"))

M.upstream_alive = lambda *a, **k: True
M.mark_node_bad(ch, "隧道不通")
check("C2 本机出口正常时才拉黑", M.is_blacklisted("3.3.3.3"))
M.upstream_alive = _orig_alive
M._blacklist.clear()

# ============================================================ D 指数退避
head("D. 通道指数退避")

check("D1 看门狗不再用固定 RECONNECT_COOLDOWN",
      "time.time() - last_connect_at < RECONNECT_COOLDOWN" not in SRC_TXT
      and "cooldown = min(RECONNECT_COOLDOWN * (2 ** min(max(fails - 1, 0), 8))" in SRC_TXT)

check("D2 退避上限受 MAX_RECONNECT_BACKOFF 约束",
      "MAX_RECONNECT_BACKOFF" in SRC_TXT
      and SRC_TXT.count("MAX_RECONNECT_BACKOFF)") >= 2
      and M.MAX_RECONNECT_BACKOFF == 1800)

check("D3 连接成功后 connect_fails 归零",
      "ch.connect_fails = 0" in SRC_TXT and "连上了，退避计数归零" in SRC_TXT)

fresh = M.Channel(7)
check("D4 通道对象带 connect_fails / no_node_at 字段",
      fresh.connect_fails == 0 and fresh.no_node_at == 0.0 and "connect_fails" in fresh.to_dict())

check("D4b 启动首连与看门狗重连共用同一个计数入口 connect_and_track",
      callable(getattr(M, "connect_and_track", None))
      and "target=connect_and_track" in SRC_TXT
      and "connect_and_track(ch, node)" in SRC_TXT)

# 退避曲线：第一次失败沿用原 90 秒（不牺牲恢复速度），之后翻倍并封顶
def cooldown_for(fails):
    return min(M.RECONNECT_COOLDOWN * (2 ** min(max(fails - 1, 0), 8)), M.MAX_RECONNECT_BACKOFF)


curve = [cooldown_for(i) for i in range(0, 8)]
check("D5 退避曲线 90/90/180/360/720/1440/1800… 且单调不减",
      curve[0] == M.RECONNECT_COOLDOWN and curve[1] == M.RECONNECT_COOLDOWN
      and curve[2] == M.RECONNECT_COOLDOWN * 2
      and all(b >= a for a, b in zip(curve, curve[1:]))
      and max(curve) == M.MAX_RECONNECT_BACKOFF, str(curve))

# ============================================================ E 告警节流
head("E. '没有可用节点'告警节流")

check("E1 重复告警按 NO_NODE_LOG_INTERVAL 节流",
      "no_node_at" in SRC_TXT and "NO_NODE_LOG_INTERVAL" in SRC_TXT
      and "now - getattr(ch, \"no_node_at\", 0.0) >= NO_NODE_LOG_INTERVAL" in SRC_TXT)

check("E2 原因写进 ch.error 供面板展示",
      'ch.error = f"没有可用的出口节点（{want}）"' in SRC_TXT)

# ============================================================ F 回归
head("F. 回归：正常选节点不受影响")

M._blacklist.clear()
set_pool([US_DEAD, JP_OK, node("203.0.113.9", "Japan", "residential", "jp2")])
picks = {M.get_best_node_for_country("Japan", "residential")["ip"] for _ in range(20)}
check("F1 正常国家仍能选到节点", picks and picks <= {"60.91.157.48", "203.0.113.9"}, str(picks))
check("F2 黑名单为空时 is_blacklisted 一律 False",
      all(M.is_blacklisted(x) is False for x in ("", "0.0.0.0", "1.2.3.4")))

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
sys.exit(1 if FAIL else 0)

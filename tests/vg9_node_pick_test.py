"""验证【失败节点短期跳过 + 国家无货时放宽到全池 + 通道指数退避】（不依赖真实 VPN 隧道）。

背景（线上真实故障 + 需求变更）：
  CH0 设成 force_country=United States + force_ip_type=residential。
  某天 VPNGate 全池 100 个节点里只剩 1 个美国节点（Cloudflare WARP，hosting 类型），
  而且它的 TCP 端口已经不可达。于是：
    [WD CH0] 隧道不通 连续 3 轮，准备重连
    [WD CH0] Reconnect United States residential   <- 又把这个死节点选回来
    [CH0] Starting tun0...                          <- 45 秒后失败
    90 秒后再来一遍……永远循环
  systemd 其实一次都没重启过（NRestarts=0），是看门狗在无限重连。

  第一版修复用了"持久化黑名单 + TTL 随失败次数翻倍到 12 小时"，跑起来确实不再死循环，
  但引入新问题：名单越积越多，节点其实早就恢复可用了，却仍因为"还在拉黑期内"被一直跳过。
  用户要求改成：
    * 不要黑名单（不落盘、不累积、不延长）；
    * 指定国家没有可用节点时，直接放宽到全池随便跳个能用的，不要死等那一个国家。

覆盖：
  [A] 失败节点短期跳过（内存态，非黑名单）
      A1 刚失败的节点不再被选中
      A2 指定国家唯一候选被跳过后 -> 放宽到别的国家，而不是返回 None（核心需求）
      A3 纯内存：不产生任何落盘文件
      A4 跳过时长固定，不随失败次数翻倍
      A5 只影响该 IP，其它节点照常可选
      A6 到期自动恢复，且查询时顺手清掉过期记录
      A7 源码中已不存在 blacklist 相关标识（防回退）
  [B] 国家无货 -> 放宽到全池
      B1 指定国家完全不在池中，仍能返回一个可用节点
      B2 放宽时排除默认不用的国家（如 CN）
      B3 放宽会在日志里写明
  [C] 断网误伤保护
      C1 本机出口不通时不把节点记为坏节点
      C2 本机出口正常时才跳过
  [D] 通道指数退避
      D1 看门狗不再用固定 RECONNECT_COOLDOWN
      D2 退避上限受 MAX_RECONNECT_BACKOFF 约束
      D3 连接成功后 connect_fails 归零
      D4 通道对象带 connect_fails / no_node_at 字段
      D5 启动首连与看门狗重连共用同一个计数入口 connect_and_track
      D6 退避曲线单调不减且封顶
  [E] "全池都没有节点"告警节流
      E1 日志按 NO_NODE_LOG_INTERVAL 节流（不是每 15 秒刷一行）
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
WORK = tempfile.mkdtemp(prefix="vg9pick_")
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
            "country": country, "ip_type": ip_type, "speed": 5_000_000,
            "config_text": "client\ndev tun\n", "owner": "test", "location": country}


def set_pool(items):
    with M.nodes_cache_lock:
        M.nodes_cache = list(items)


US_DEAD = node("104.28.237.60", "United States", "hosting", "us-dead")
JP_OK = node("60.91.157.48", "Japan", "residential", "jp-ok")
CN_NODE = node("203.0.113.77", "China", "residential", "cn-1")

M._skip_until.clear()

# ============================================================ A 短期跳过
head("A. 失败节点短期跳过（内存态，非黑名单）")

set_pool([US_DEAD, JP_OK])
n = M.get_best_node_for_country("United States", "residential")
check("A0 前置：美国只有 hosting 节点时放宽类型仍能选到（原行为保留）",
      bool(n) and n["ip"] == US_DEAD["ip"], str(n))

M.skip_node(US_DEAD["ip"], "隧道不通")
check("A1 被跳过的节点不再被选中", M.is_node_skipped(US_DEAD["ip"]))

n2 = M.get_best_node_for_country("United States", "residential")
check("A2 指定国家唯一候选被跳过后 -> 放宽到别的国家可用节点，而不是返回 None（核心需求）",
      bool(n2) and n2["ip"] == JP_OK["ip"], str(n2))

check("A3 纯内存：不产生黑名单文件",
      not os.path.exists(os.path.join(ROOT, "vpngate9_data", "blacklist.json")),
      os.path.join(ROOT, "vpngate9_data"))

M._skip_until.clear()
M.skip_node("9.9.9.9", "x")
t1 = M._skip_until["9.9.9.9"] - time.time()
for _ in range(12):
    M.skip_node("9.9.9.9", "x")
t2 = M._skip_until["9.9.9.9"] - time.time()
check("A4 跳过时长为固定值，不随失败次数翻倍",
      abs(t1 - M.NODE_SKIP_TTL) < 3 and abs(t2 - M.NODE_SKIP_TTL) < 3,
      f"{t1:.0f} -> {t2:.0f} (TTL={M.NODE_SKIP_TTL})")

n3 = M.get_best_node_for_country("Japan", "residential")
check("A5 跳过只影响该 IP，其它节点照常可选",
      bool(n3) and n3["ip"] == JP_OK["ip"], str(n3))

M._skip_until["4.4.4.4"] = time.time() - 1
check("A6a 过期条目查询时返回未跳过", M.is_node_skipped("4.4.4.4") is False)
check("A6b 过期条目被顺手清掉", "4.4.4.4" not in M._skip_until)

check("A7 源码中已无 blacklist 相关标识（防回退）", "blacklist" not in SRC_TXT.lower())

M._skip_until.clear()

# ============================================================ B 放宽到全池
head("B. 指定国家无货 -> 放宽到全池")

set_pool([JP_OK, node("203.0.113.9", "Japan", "residential", "jp2")])
b1 = M.get_best_node_for_country("United States", "residential")
check("B1 指定国家完全不在池中，仍能返回一个可用节点",
      bool(b1) and b1["ip"] in {"60.91.157.48", "203.0.113.9"}, str(b1))

set_pool([CN_NODE])
b2 = M.get_best_node_for_country("United States", "residential")
check("B2 放宽时排除默认不用的国家（CN），宁可不选也不跳境内节点", b2 is None, str(b2))

check("B3 放宽时会在日志里写明已自动放宽", "已自动放宽到" in SRC_TXT)

set_pool([US_DEAD, JP_OK])
M._skip_until.clear()

# ============================================================ C 断网误伤保护
head("C. 断网误伤保护")

_orig_alive = M.upstream_alive
ch = M.channels[0]
ch.node_ip = "3.3.3.3"

M.upstream_alive = lambda *a, **k: False
M.mark_node_bad(ch, "隧道不通")
check("C1 本机出口不通时不把节点记为坏节点", not M.is_node_skipped("3.3.3.3"))

M.upstream_alive = lambda *a, **k: True
M.mark_node_bad(ch, "隧道不通")
check("C2 本机出口正常时才跳过", M.is_node_skipped("3.3.3.3"))
M.upstream_alive = _orig_alive
M._skip_until.clear()

# ============================================================ D 指数退避
head("D. 通道指数退避")

check("D1 看门狗不再用固定 RECONNECT_COOLDOWN",
      "time.time() - last_connect_at < RECONNECT_COOLDOWN" not in SRC_TXT
      and "cooldown = min(RECONNECT_COOLDOWN * (2 ** min(max(fails - 1, 0), 8))" in SRC_TXT)

check("D2 退避上限受 MAX_RECONNECT_BACKOFF 约束",
      "MAX_RECONNECT_BACKOFF" in SRC_TXT
      and SRC_TXT.count("MAX_RECONNECT_BACKOFF)") >= 2
      and M.MAX_RECONNECT_BACKOFF == 1800)

check("D3 连接成功后 connect_fails 归零", "ch.connect_fails = 0" in SRC_TXT)

fresh = M.Channel(7)
check("D4 通道对象带 connect_fails / no_node_at 字段",
      fresh.connect_fails == 0 and fresh.no_node_at == 0.0 and "connect_fails" in fresh.to_dict())

check("D5 启动首连与看门狗重连共用同一个计数入口 connect_and_track",
      callable(getattr(M, "connect_and_track", None))
      and "target=connect_and_track" in SRC_TXT
      and "connect_and_track(ch, node)" in SRC_TXT)


# 退避曲线：第一次失败沿用原 90 秒（不牺牲恢复速度），之后翻倍并封顶
def cooldown_for(fails):
    return min(M.RECONNECT_COOLDOWN * (2 ** min(max(fails - 1, 0), 8)), M.MAX_RECONNECT_BACKOFF)


curve = [cooldown_for(i) for i in range(0, 8)]
check("D6 退避曲线 90/90/180/360/720/1440/1800… 且单调不减",
      curve[0] == M.RECONNECT_COOLDOWN and curve[1] == M.RECONNECT_COOLDOWN
      and curve[2] == M.RECONNECT_COOLDOWN * 2
      and all(b >= a for a, b in zip(curve, curve[1:]))
      and max(curve) == M.MAX_RECONNECT_BACKOFF, str(curve))

# ============================================================ E 告警节流
head("E. '全池无可用节点'告警节流")

check("E1 重复告警按 NO_NODE_LOG_INTERVAL 节流",
      "no_node_at" in SRC_TXT and "NO_NODE_LOG_INTERVAL" in SRC_TXT
      and "now - getattr(ch, \"no_node_at\", 0.0) >= NO_NODE_LOG_INTERVAL" in SRC_TXT)

check("E2 原因写进 ch.error 供面板展示",
      'ch.error = f"没有可用的出口节点（{want}）"' in SRC_TXT)

check("E3 无节点日志已改为'全池'口径（不再说'该国家没有节点'）",
      "全池都没有可用出口节点" in SRC_TXT)

# ============================================================ F 回归
head("F. 回归：正常选节点不受影响")

M._skip_until.clear()
set_pool([US_DEAD, JP_OK, node("203.0.113.9", "Japan", "residential", "jp2")])
picks = {M.get_best_node_for_country("Japan", "residential")["ip"] for _ in range(20)}
check("F1 正常国家仍能选到节点", picks and picks <= {"60.91.157.48", "203.0.113.9"}, str(picks))
check("F2 跳过表为空时 is_node_skipped 一律 False",
      all(M.is_node_skipped(x) is False for x in ("", "0.0.0.0", "1.2.3.4")))
check("F3 不落盘 / 已无持久化函数",
      not hasattr(M, "_save_blacklist") and not hasattr(M, "load_blacklist"))

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
sys.exit(1 if FAIL else 0)

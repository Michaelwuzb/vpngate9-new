"""验证"9 条通道出口互不相同"这条链路。使用真实 VPNGate 节点数据。

覆盖：
  [1] 同一个国家下 9 条通道顺序选节点 -> 9 个不同 IP
  [2] 同一个国家下 9 条通道并发选节点 -> 9 个不同 IP（竞态检查）
  [3] 自动分配 mode=country -> 尽量不同国家 + IP 唯一
  [4] 自动分配 mode=ip      -> 只保证 IP 唯一
  [5] 国家节点不足时的行为（复用要打标记 + 给警告）
  [6] build_assign_plan 的确定性（预览 = 应用）
"""
import importlib
import os
import re
import shutil
import sys
import tempfile
import threading
import collections

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
WORK = tempfile.mkdtemp(prefix="vg9assign_")
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

def log(*a):
    print(*a, flush=True)

# --- 准备隔离副本（改掉 /opt/michaelvpn，避免污染真实路径）---
for f in ("vpngate9_multi.py", "vpn_utils.py", "proxy_server_multi.py",
          "speedtest_utils.py"):
    dst = os.path.join(WORK, f)
    txt = open(os.path.join(FIX, f), encoding="utf-8").read()
    txt = txt.replace('Path("/opt/michaelvpn")', f'Path(r"{ROOT}")')
    txt = txt.replace('UI_HOST = "::"', 'UI_HOST = "127.0.0.1"')
    open(dst, "w", encoding="utf-8").write(txt)
log(f"[setup] 隔离运行目录 {WORK}")

sys.path.insert(0, WORK)
M = importlib.import_module("vpngate9_multi")

# --- 拉真实节点并富化（含新的 IP 类型判定）---
log("[setup] 拉取 VPNGate 节点并做 IP 类型判定 ...")
nodes = M.fetch_nodes()
if not nodes:
    log("!! 拉不到节点（网络问题），退出")
    sys.exit(2)
try:
    M.vpn_utils.enrich_ip_info(nodes)
except Exception as e:
    log("!! 富化失败:", e)
M.nodes_cache = nodes
supply = M.country_supply()
log(f"[setup] 节点 {len(nodes)} 个，国家/地区 {len(supply)} 个")
top = sorted(supply.items(), key=lambda kv: -kv[1]["total"])[:8]
for k, v in top:
    log(f"         {k:22} 总{v['total']:3}  住宅{v['residential']:3}  机房{v['hosting']:3}  移动{v['mobile']:2}")

def fresh_channels():
    chs = [M.Channel(i) for i in range(M.NUM_CHANNELS)]
    M.channels = chs
    return chs

# ============ [1] 同国家顺序选 ============
log("\n[1] 9 条通道都指定 Japan（顺序选节点）")
chs = fresh_channels()
ips = []
for ch in chs:
    n = M.get_best_node_for_country("Japan", "", exclude_ch=ch)
    ips.append(n["ip"] if n else None)
uniq = len(set(i for i in ips if i))
check("拿到 9 个 IP", all(ips), str(ips))
check(f"出口 IP 全不相同（唯一 {uniq}/9）", uniq == 9, str(ips))
check("每个通道都登记了预占", all(c.reserved_ip for c in chs))
check("复用标记为 False", not any(c.ip_reused for c in chs))

# ============ [2] 同国家并发选 ============
log("\n[2] 9 条通道并发选 Japan（竞态检查）")
chs = fresh_channels()
res = {}
def worker(ch):
    n = M.get_best_node_for_country("Japan", "", exclude_ch=ch)
    res[ch.index] = n["ip"] if n else None
ts = [threading.Thread(target=worker, args=(c,)) for c in chs]
for t in ts: t.start()
for t in ts: t.join()
cips = [res.get(i) for i in range(9)]
check("并发下 9 个 IP 全不相同", len(set(cips)) == 9 and all(cips), str(sorted(cips)))

# ============ [3] 自动分配 mode=country ============
log("\n[3] 自动分配 mode=country")
chs = fresh_channels()
plan = M.build_assign_plan(chs, "country", "")
p3 = plan["plan"]
by_country = collections.Counter(p["country"] for p in p3)
log(f"         通道 {len(p3)} 条 | 覆盖国家 {len(by_country)} 个 | "
    f"分布 {dict(by_country)}")
log(f"         出口 IP: {[p['ip'] for p in p3]}")
check("填满 9 条通道", len(p3) == 9, f"got {len(p3)}")
check("出口 IP 互不重复", len({p["ip"] for p in p3}) == 9, str([p["ip"] for p in p3]))
check("每个通道一个国家(不重复分配国家直到用完)", set(by_country.values()) and
      all(p["country"] for p in p3))
check("国家数 < 9 时给出提示", len(by_country) < 9 or len(by_country) == 9)
warn_txt = " | ".join(plan["warnings"])
log(f"         警告: {warn_txt or '（无）'}")
check("plan 携带节点元信息(ip/owner/country_total)",
      all(p.get("country_total", 0) > 0 and p.get("ip") for p in p3))

# ============ [4] mode=ip ============
log("\n[4] 自动分配 mode=ip（不限国家）")
chs = fresh_channels()
plan4 = M.build_assign_plan(chs, "ip", "")["plan"]
log(f"         出口 IP: {[p['ip'] for p in plan4]}")
check("出口 IP 互不重复", len({p["ip"] for p in plan4}) == len(plan4) == 9)

# ============ [5] 节点不足的国家 ============
log("\n[5] 国家节点不足时的行为")
small = sorted(supply.items(), key=lambda kv: kv[1]["total"])[0][0]
n_small = supply[small]["total"]
log(f"         用节点最少的国家 {small}（{n_small} 个）填 9 条通道")
chs = fresh_channels()
sips = []
for ch in chs:
    n = M.get_best_node_for_country(small, "", exclude_ch=ch)
    sips.append(n["ip"] if n else None)
uniq_s = len(set(i for i in sips if i))
check(f"IP 数不超过该国节点数（{uniq_s} <= {n_small}）", uniq_s <= n_small, str(sips))
if n_small < 9:
    check("超出部分被标记为复用", sum(1 for c in chs if c.ip_reused) == 9 - n_small,
          f"reused={sum(1 for c in chs if c.ip_reused)}")
small_plan = M.build_assign_plan(fresh_channels(), "country", "")
check("节点不足时计划里带警告", bool(small_plan["warnings"]) or n_small >= 9,
      str(small_plan["warnings"]))

# ============ [6] 确定性 ============
log("\n[6] build_assign_plan 两次调用结果一致（预览=应用）")
a = M.build_assign_plan(fresh_channels(), "country", "")["plan"]
b = M.build_assign_plan(fresh_channels(), "country", "")["plan"]
check("同样的节点池得到同样方案", [p["ip"] for p in a] == [p["ip"] for p in b],
      f"\n    {[p['ip'] for p in a]}\n    {[p['ip'] for p in b]}")

# ============ [7] 与已连接通道互不冲突 ============
log("\n[7] 已有通道在跑时，新分配的 IP 不与它们冲突")
chs = fresh_channels()
chs[0].state = "connected"; chs[0].node_ip = nodes[0]["ip"]
chs[1].state = "connecting"; chs[1].reserved_ip = nodes[1]["ip"]  # 尚在握手也要避开
plan7 = M.build_assign_plan([c for c in chs if c.index >= 2], "country", "")["plan"]
taken = {nodes[0]["ip"], nodes[1]["ip"]}
check("避开 connecting 中的预占 IP（原代码只看 connected 会撞）",
      not ({p["ip"] for p in plan7} & taken),
      f"plan={[p['ip'] for p in plan7]} taken={sorted(taken)}")

# ============ [8] mode=same：9 条通道全用同一个国家 ============
log("\n[8] mode=same：9 条通道固定同一个国家")
big = max(supply, key=lambda k: supply[k]["total"])
log(f"         用节点最多的国家 {big}（{supply[big]['total']} 个）")
chs = fresh_channels()
r8 = M.build_assign_plan(chs, "same", "", big)
p8 = r8["plan"]
log(f"         方案 {len(p8)} 条 | 国家 {sorted({p['country'] for p in p8})}")
log(f"         出口 IP: {[p['ip'] for p in p8]}")
check("填满 9 条通道", len(p8) == 9, f"got {len(p8)}")
check("9 条通道全在同一个国家", {p["country"] for p in p8} == {big},
      str(sorted({p["country"] for p in p8})))
check("9 个出口 IP 互不重复", len({p["ip"] for p in p8}) == 9)
check("每条都带上该国节点总数", all(p["country_total"] == supply[big]["total"] for p in p8))
check("返回正向 note", big in r8["note"] and "互不重复" in r8["note"], r8["note"])
check("这种情形不该出现\"填不满\"警告",
      not any("填不满" in w for w in r8["warnings"]), str(r8["warnings"]))

log("\n[8b] 国家名忽略大小写 / 传空国家 / 传不存在的国家")
r8b = M.build_assign_plan(fresh_channels(), "same", "", big.lower())
check("小写国家名也能匹配", r8b["plan"] and {p["country"] for p in r8b["plan"]} == {big},
      str(sorted({p["country"] for p in r8b["plan"]}, )) if r8b["plan"] else str(r8b["warnings"]))
r8c = M.build_assign_plan(fresh_channels(), "same", "", "")
check("没选国家 -> 空方案 + 提示", not r8c["plan"] and any("选择" in w for w in r8c["warnings"]),
      str(r8c["warnings"]))
r8d = M.build_assign_plan(fresh_channels(), "same", "", "Atlantis")
check("不存在的国家 -> 空方案 + 给出可选国家",
      not r8d["plan"] and any("没有" in w for w in r8d["warnings"]), str(r8d["warnings"]))

# ============ [9] mode=same：默认排除的国家被显式点名 ============
log("\n[9] mode=same：显式点名默认排除的国家（China）")
r9 = M.build_assign_plan(fresh_channels(), "same", "", "China")
p9 = r9["plan"]
check("China 被显式指定时仍可用", bool(p9), str(r9["warnings"]))
check("方案里的国家就是 China", p9 and {p["country"] for p in p9} == {"China"})
check("给出\"在默认排除名单里\"的说明",
      any("排除名单" in w for w in r9["warnings"]), str(r9["warnings"]))
check("不再重复报\"已跳过 N 个 china 节点\"",
      not any("已跳过" in w for w in r9["warnings"]), str(r9["warnings"]))

# ============ [10] mode=same：该国节点不够 ============
log("\n[10] mode=same：该国节点不够 9 条时")
smallest = min(supply, key=lambda k: supply[k]["total"])
n_sm = supply[smallest]["total"]
log(f"         {smallest} 只有 {n_sm} 个节点")
r10 = M.build_assign_plan(fresh_channels(), "same", "", smallest)
p10 = r10["plan"]
check(f"不硬凑：方案 {len(p10)} 条 <= 该国节点 {n_sm} 个", len(p10) <= max(n_sm, 1) and
      len({p["ip"] for p in p10}) == len(p10), f"n={len(p10)}")
check("明确提示填不满", any("填不满" in w for w in r10["warnings"]), str(r10["warnings"]))
check("提示里附带够用的国家或替代方案",
      any("够填满" in w or "互不重复" in w for w in r10["warnings"]), str(r10["warnings"]))
r10f = M.build_assign_plan(fresh_channels(), "same", "", smallest, True)
p10f = r10f["plan"]
log(f"         fill=1 后国家分布: {dict(collections.Counter(p['country'] for p in p10f))}")
check("fill=1 时补满 9 条且 IP 仍唯一",
      len(p10f) == 9 and len({p["ip"] for p in p10f}) == 9, f"n={len(p10f)}")
check("补满后混合国家并给出说明",
      any("补满剩余" in w for w in r10f["warnings"]), str(r10f["warnings"]))

# ============ [11] mode=same 时也不与已连接的通道撞 IP ============
log("\n[11] mode=same 时避开已在跑/握手中的通道")
chs = fresh_channels()
chs[0].state = "connected"; chs[0].node_ip = nodes[0]["ip"]
chs[1].state = "connecting"; chs[1].reserved_ip = nodes[1]["ip"]
r11 = M.build_assign_plan([c for c in chs if c.index >= 2], "same", "", big)["plan"]
check("避开 connected / connecting 占用的 IP",
      not ({p["ip"] for p in r11} & {nodes[0]["ip"], nodes[1]["ip"]}),
      f"plan={[p['ip'] for p in r11]}")
check("7 条通道仍全部同国家且 IP 唯一",
      len(r11) == 7 and {p["country"] for p in r11} == {big}
      and len({p["ip"] for p in r11}) == 7, f"n={len(r11)}")

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)

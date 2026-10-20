"""验证"国家级之下再精确到县（都道府县）"这条链路。

覆盖：
  [1] 行政区名的多写法归一（中文/日文/罗马字/JIS 码/JP-13）
  [2] 目标县有节点 -> 9 条通道全部落在该县
  [3] 目标县节点不够 -> 同大区就近递补（按距离，不是随机）
  [4] 目标县一个节点都没有 -> 直接就近递补（关东最近的县）
  [5] 目标国家没有任何节点 -> 放宽到其它国家，但不会报错/卡死
  [6] build_assign_plan(mode=same, region=...) 的方案与提示文案
  [7] region_supply 会带上 47 个都道府县（0 节点的也列出来）
  [8] 旧节点没有行政区数据时不崩（region 为空）

用合成数据跑，不依赖外网 —— 行政区判定是纯函数，不该受节点源可用性影响。
"""
import importlib
import os
import shutil
import sys
import tempfile

SRC = os.path.dirname(os.path.abspath(__file__))


def _find_src(start):
    for c in (start, os.path.join(start, os.pardir)):
        c = os.path.abspath(c)
        if os.path.isfile(os.path.join(c, "vpngate9_multi.py")):
            return c
    raise SystemExit("找不到 vpngate9_multi.py，请在仓库目录内运行本测试")


FIX = _find_src(SRC)
WORK = tempfile.mkdtemp(prefix="vg9region_")
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


for f in sorted(n for n in os.listdir(FIX) if n.endswith(".py")):
    txt = open(os.path.join(FIX, f), encoding="utf-8").read()
    txt = txt.replace('Path("/opt/michaelvpn")', f'Path(r"{ROOT}")')
    txt = txt.replace('UI_HOST = "::"', 'UI_HOST = "127.0.0.1"')
    open(os.path.join(WORK, f), "w", encoding="utf-8").write(txt)

sys.path.insert(0, WORK)
M = importlib.import_module("vpngate9_multi")
G = importlib.import_module("region_geo")

# ============ [1] 行政区名归一 ============
log("\n[1] 行政区名多写法归一")
for alias in ("东京都", "东京", "東京都", "Tokyo", "Tokyo-to", "tokyo", "13", "JP-13", "jp13"):
    pref = G.lookup_prefecture(alias)
    check(f"「{alias}」-> JP-13", pref is not None and pref["key"] == "JP-13",
          str(pref and pref["key"]))
check("大阪府 -> JP-27", (G.lookup_prefecture("大阪") or {}).get("key") == "JP-27")
check("北海道 -> JP-01", (G.lookup_prefecture("Hokkaido") or {}).get("key") == "JP-01")
check("关东大区含 7 个县", len(G.ZONES.get("关东", [])) == 7, str(G.ZONES.get("关东")))
d = G.haversine_km(35.6895, 139.6917, 35.6074, 140.1231)   # 东京 -> 千叶
check("东京到千叶约 40~60km", d is not None and 40 <= d <= 60, str(d))


# ============ 合成节点池 ============
def mk(ip, pref_key="", ip_type="residential", speed=100, city=""):
    p = G.lookup_prefecture(pref_key) if pref_key else None
    return {
        "id": f"n-{ip}", "ip": ip, "port": "443", "config_text": "client\ndev tun\n",
        "country_long": "Japan", "country": "Japan", "country_code": "JP",
        "region": p["name"] if p else "", "region_key": p["key"] if p else "",
        "region_zone": p["zone"] if p else "",
        "city": city, "lat": p["lat"] if p else None, "lon": p["lon"] if p else None,
        "ip_type": ip_type, "ping": 10, "speed": speed, "owner": "Test ISP",
        "location": ("Japan " + p["name"]) if p else "Japan",
    }


def set_pool(nodes):
    M.nodes_cache = nodes
    M.channels = [M.Channel(i) for i in range(M.NUM_CHANNELS)]
    return M.channels


# ============ [2] 目标县有足够节点 ============
log("\n[2] 东京都有 9 个节点 -> 9 条通道全部落在东京都")
pool = [mk(f"10.0.0.{i}", "JP-13") for i in range(1, 10)]
chs = set_pool(pool)
picked = []
for ch in chs:
    n = M.get_best_node_for_country("Japan", "", exclude_ch=ch, region="JP-13")
    picked.append(n)
check("9 条都拿到节点", all(picked))
check("全部在东京都", all(n and n["region_key"] == "JP-13" for n in picked))
check("出口 IP 互不重复", len({n["ip"] for n in picked}) == 9)

# ============ [3] 目标县不够 -> 同大区按距离递补 ============
log("\n[3] 东京都只有 2 个节点 -> 其余按距离就近递补（神奈川/千叶/埼玉，都是关东）")
pool = [mk("10.1.0.1", "JP-13"), mk("10.1.0.2", "JP-13"),
        mk("10.1.1.1", "JP-14"),   # 神奈川 ~28km
        mk("10.1.2.1", "JP-12"),   # 千叶 ~41km
        mk("10.1.3.1", "JP-11"),   # 埼玉 ~29km
        mk("10.1.4.1", "JP-27"),   # 大阪 ~400km
        mk("10.1.5.1", "JP-47")]   # 冲绳 ~1600km
chs = set_pool(pool)
res = []
for ch in chs:
    res.append(M.get_best_node_for_country("Japan", "", exclude_ch=ch, region="JP-13"))
keys = [n["region_key"] for n in res if n]
tiers = [M.region_rank(n, M.region_target("Japan", "JP-13"))[0] for n in res if n]
check("前 2 条落在东京都", keys[:2] == ["JP-13", "JP-13"], str(keys))
check("第 3 条是同大区（关东）递补，没跳到关西/冲绳",
      keys[2] in ("JP-14", "JP-11", "JP-12"), str(keys))
check("大阪/冲绳排在关东各县之后", keys.index("JP-27") > keys.index("JP-14"), str(keys))
# 前 7 条是"未占用节点"（后面两条属于 IP 复用），这一段的档位必须单调不降
fresh = [t for ch, t in zip(chs, tiers) if not ch.ip_reused]
check("未复用段的档位单调不降（先同县，再同大区，最后全国）",
      all(fresh[i] <= fresh[i + 1] for i in range(len(fresh) - 1)), str(tiers))
check("降级通道 tier>=1", tiers[2] >= 1, str(tiers))

# ============ [4] 目标县一个节点都没有 ============
log("\n[4] 东京都 0 个节点 -> 直接就近递补（关东最近的县）")
pool = [mk("10.2.1.1", "JP-14"), mk("10.2.2.1", "JP-12"), mk("10.2.3.1", "JP-27")]
chs = set_pool(pool)
n = M.get_best_node_for_country("Japan", "", exclude_ch=chs[0], region="JP-13")
check("仍然返回节点，而不是 None", n is not None)
check("选的是最近的县（千叶/神奈川，不是大阪）", n["region_key"] in ("JP-14", "JP-12"),
      str(n and n["region_key"]))

# ============ [5] 该国家没有任何节点 ============
log("\n[5] 日本完全没有节点 -> 放宽到其它国家")
us = mk("10.3.0.1", "", city="Los Angeles")
us.update({"country_long": "United States", "country": "United States",
           "country_code": "US", "region": "California",
           "region_key": "US:california", "region_zone": "", "location": "US California"})
chs = set_pool([us])
n = M.get_best_node_for_country("Japan", "", exclude_ch=chs[0], region="JP-13")
check("放宽后仍能拿到节点", n is not None and n["ip"] == "10.3.0.1", str(n and n["ip"]))

# ============ [6] build_assign_plan ============
log("\n[6] build_assign_plan(mode=same, country=Japan, region=东京都)")
pool = [mk("10.4.0.1", "JP-13"), mk("10.4.0.2", "JP-13"),
        mk("10.4.1.1", "JP-14"), mk("10.4.2.1", "JP-12"), mk("10.4.3.1", "JP-11"),
        mk("10.4.4.1", "JP-27"), mk("10.4.5.1", "JP-26"), mk("10.4.6.1", "JP-23"),
        mk("10.4.7.1", "JP-40"), mk("10.4.8.1", "JP-01"), mk("10.4.9.1", "JP-47")]
chs = set_pool(pool)
plan = M.build_assign_plan(chs, "same", "", "Japan", False, "JP-13")
pl = plan["plan"]
check("规划出 9 条", len(pl) == 9, str(len(pl)))
exact = [p for p in pl if p["region_tier"] == 0]
check("其中 2 条命中东京都", len(exact) == 2, str([p["region"] for p in pl]))
check("其余标为降级 tier>=1", all(p["region_tier"] >= 1 for p in pl if p["region_tier"] != 0))
check("IP 互不重复", len({p["ip"] for p in pl}) == 9)
msgs = " ".join(plan["warnings"])
check("警告里说明「东京都只有 2 个可用节点」", "东京都 只有 2 个可用节点" in msgs, msgs[:200])
check("警告里列出就近落点", "就近降级" in msgs, msgs[:200])
check("返回的 region 名是中文", plan["region"] == "东京都", plan["region"])
check("返回 regions 供给表", len(plan.get("regions") or []) == 47,
      str(len(plan.get("regions") or [])))

# 目标县够用时应给绿色 note
log("\n[6b] 东京都节点充足 -> 绿色 note")
pool = [mk(f"10.5.0.{i}", "JP-13") for i in range(1, 10)]
chs = set_pool(pool)
plan = M.build_assign_plan(chs, "same", "", "Japan", False, "JP-13")
check("9 条全部东京都", all(p["region_key"] == "JP-13" for p in plan["plan"]))
check("有正向 note", "东京都" in (plan.get("note") or ""), plan.get("note"))
check("没有降级警告", not any("就近降级" in w for w in plan["warnings"]))

# 不指定县时行为不变
log("\n[6c] 不指定 region -> 与旧行为一致（全国任意）")
chs = set_pool(pool + [mk("10.5.1.1", "JP-27")])
plan = M.build_assign_plan(chs, "same", "", "Japan", False, "")
check("9 条照常规划", len(plan["plan"]) == 9)
check("region 字段为空", plan.get("region") == "")

# ============ [7] region_supply ============
log("\n[7] region_supply：47 个都道府县全部列出")
chs = set_pool(pool)
rows = M.region_supply("Japan")
check("47 条", len(rows) == 47, str(len(rows)))
tokyo = [r for r in rows if r["key"] == "JP-13"]
check("东京都在列表里", len(tokyo) == 1)
check("东京都计数正确", tokyo and tokyo[0]["total"] == 9 and tokyo[0]["free"] == 9,
      str(tokyo))
zero = [r for r in rows if r["total"] == 0]
check("0 节点的县也在列表里（能选才能触发降级）", len(zero) == 46, str(len(zero)))

# ============ [8] 没有行政区数据的旧节点 ============
log("\n[8] 节点没有区县数据（旧缓存/情报缺失）时不能崩")
old = {"id": "old1", "ip": "10.6.0.1", "port": "443", "config_text": "x",
       "country_long": "Japan", "ip_type": "residential", "ping": 10, "speed": 1}
chs = set_pool([old])
try:
    n = M.get_best_node_for_country("Japan", "", exclude_ch=chs[0], region="JP-13")
    ok = n is not None
except Exception as e:      # noqa: BLE001
    ok, n = False, e
check("无区县数据也能选出节点", ok, str(n))
plan = M.build_assign_plan(chs, "same", "", "Japan", False, "JP-13")
check("build_assign_plan 也不崩", len(plan["plan"]) == 1)
check("降级说明不会出现空县名", "None" not in " ".join(plan["warnings"]))
msgs = " ".join(plan["warnings"])
check("整池没有县数据时说清原因（而不是假装就近算过）",
      "还没有县/州信息" in msgs, msgs[:160])

print(f"\n=== 通过 {PASS} / {PASS + FAIL} ===")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(0 if FAIL == 0 else 1)

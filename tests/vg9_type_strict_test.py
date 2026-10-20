"""验证"指定 IP 类型后就严格按类型走"——住宅模式下机房 IP 不参与降级。

用户的原话：
  "我设置的是住宅的 IP，东京没有 IP 了，在确定没有 IP 了往就近的地区跳。
   但是这前提是排除掉 SoftEther 机房的 IP。"

所以"东京都还有 5 个机房节点"必须等于"东京都没货"，要继续往埼玉/神奈川降级；
而不是（旧行为）把类型静默放宽，留在东京都用机房 IP。

覆盖：
  [1] type_key 归一 + _region_free 按类型过滤
  [2] 东京都只剩机房 -> 住宅模式落埼玉（不限类型时仍可选东京都机房，旧行为不变）
  [3] 混合池：住宅模式 9 条全是住宅，机房一条都不混进来
  [4] 全站只有机房 -> 返回 None（保持原状），并给出一次告警（不刷屏）
  [5] 跨国家放宽只放宽"国家"，不放宽类型：宁可去美国住宅，也不碰日本机房
  [6] 未占用节点用尽时的"复用"同样只复用住宅
  [7] build_assign_plan：区域降级只用住宅；全站无住宅时拒绝分配并说明原因
  [8] region_supply / rescan_region 的计数与判定都按同一口径（住宅）
  [9] 锁定县 + 住宅：东京都有住宅也不切回
"""
import importlib
import os
import sys
import tempfile
import time

SRC = os.path.dirname(os.path.abspath(__file__))


def _find_src(start):
    for c in (start, os.path.join(start, os.pardir)):
        c = os.path.abspath(c)
        if os.path.isfile(os.path.join(c, "vpngate9_multi.py")):
            return c
    raise SystemExit("找不到 vpngate9_multi.py，请在仓库目录内运行本测试")


FIX = _find_src(SRC)
WORK = tempfile.mkdtemp(prefix="vg9type_")
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

# 本文件测的是"选谁"，默认关掉"降级前重扫"（否则会真联网）。[8] 里单独打开并打桩。
M.REGION_RESCAN_ENABLED = False


def mk(ip, pref_key="", ip_type="residential", speed=100):
    p = G.lookup_prefecture(pref_key) if pref_key else None
    return {
        "id": f"n-{ip}", "ip": ip, "port": "443", "config_text": "client\ndev tun\n",
        "country_long": "Japan", "country": "Japan", "country_code": "JP",
        "region": p["name"] if p else "", "region_key": p["key"] if p else "",
        "region_zone": p["zone"] if p else "",
        "city": "", "lat": p["lat"] if p else None, "lon": p["lon"] if p else None,
        "ip_type": ip_type, "ping": 10, "speed": speed, "owner": "Test ISP",
        "location": ("Japan " + p["name"]) if p else "Japan",
    }


def set_pool(nodes):
    M.nodes_cache = nodes
    M.channels = [M.Channel(i) for i in range(M.NUM_CHANNELS)]
    return M.channels


def ip_types(rows):
    return [ (n or {}).get("ip_type", "") for n in rows ]


# ============ [1] 基础口径 ============
log("\n[1] type_key 归一 + _region_free 按类型过滤")
check("residential 归一", M.type_key("residential") == "residential")
check("大小写/空格不计", M.type_key(" Residential ") == "residential")
check("乱填当不限", M.type_key("whatever") == "", repr(M.type_key("whatever")))
check("空串当不限", M.type_key("") == "")
pool = [mk("10.0.0.1", "JP-13", "hosting"), mk("10.0.0.2", "JP-13", "residential"),
        mk("10.0.0.3", "JP-13", "unknown")]
check("_region_free 不限类型 = 3 条", len(M._region_free(pool, "JP-13")) == 3)
check("_region_free(residential) 只 1 条",
      [n["ip"] for n in M._region_free(pool, "JP-13", set(), "residential")] == ["10.0.0.2"])
check("_region_free(hosting) 只 1 条",
      [n["ip"] for n in M._region_free(pool, "JP-13", set(), "hosting")] == ["10.0.0.1"])

# ============ [2] 东京都只剩机房 ============
log("\n[2] 东京都 5 个机房、埼玉 1 个住宅 -> 住宅模式必须落埼玉")
pool = [mk(f"10.1.0.{i}", "JP-13", "hosting") for i in range(1, 6)] + \
       [mk("10.1.1.1", "JP-11", "residential")]
chs = set_pool(pool)
n = M.get_best_node_for_country("Japan", "residential", exclude_ch=chs[0], region="JP-13")
check("拿到了节点", n is not None)
check("落在埼玉（不是留着用东京都机房）", (n or {}).get("region_key") == "JP-11",
      str(n and n.get("region_key")))
check("类型确实是住宅", (n or {}).get("ip_type") == "residential", str(n and n.get("ip_type")))
n2 = M.get_best_node_for_country("Japan", "", exclude_ch=chs[1], region="JP-13")
check("不限类型时行为不变：仍优先东京都（机房也用）",
      (n2 or {}).get("region_key") == "JP-13" and (n2 or {}).get("ip_type") == "hosting",
      str(n2 and (n2.get("region_key"), n2.get("ip_type"))))

# ============ [3] 混合池，9 条都不许混机房 ============
log("\n[3] 东京都 2 住宅 + 4 机房，埼玉 3 住宅，神奈川 4 住宅 -> 9 条全是住宅")
pool = [mk("10.2.0.1", "JP-13", "residential"), mk("10.2.0.2", "JP-13", "residential")] + \
       [mk(f"10.2.1.{i}", "JP-13", "hosting") for i in range(1, 5)] + \
       [mk(f"10.2.2.{i}", "JP-11", "residential") for i in range(1, 4)] + \
       [mk(f"10.2.3.{i}", "JP-14", "residential") for i in range(1, 5)]
chs = set_pool(pool)
res = [M.get_best_node_for_country("Japan", "residential", exclude_ch=ch, region="JP-13")
       for ch in chs]
check("9 条都拿到", all(res), str(ip_types(res)))
check("9 条全是住宅", all((n or {}).get("ip_type") == "residential" for n in res), str(ip_types(res)))
keys = [(n or {}).get("region_key") for n in res]
check("前 2 条东京都", keys[:2] == ["JP-13", "JP-13"], str(keys))
check("其余按 埼玉 -> 神奈川 递补", keys[2:5] == ["JP-11", "JP-11", "JP-11"], str(keys))
check("东京都的 4 个机房一个都没被选中",
      not any(k == "JP-13" and (n or {}).get("ip_type") == "hosting"
              for k, n in zip(keys, res)), str(keys))

# ============ [4] 全站只有机房 ============
log("\n[4] 全站只有机房 -> 住宅模式返回 None，不静默降级成机房")
pool = [mk("10.3.0.1", "JP-13", "hosting"), mk("10.3.0.2", "JP-11", "hosting"),
        mk("10.3.0.3", "JP-14", "mobile")]
chs = set_pool(pool)
logs = []
_orig_log = M.log
M.log = lambda *a: (logs.append(" ".join(str(x) for x in a)), _orig_log(*a))[1]
try:
    n = M.get_best_node_for_country("Japan", "residential", exclude_ch=chs[0], region="JP-13")
    n_again = M.get_best_node_for_country("Japan", "residential", exclude_ch=chs[0], region="JP-13")
finally:
    M.log = _orig_log
check("返回 None（保持原样，不切到机房）", n is None, str(n and n.get("ip")))
check("通道没有被预占 IP", chs[0].reserved_ip == "", repr(chs[0].reserved_ip))
check("日志说清「没有可用的住宅节点」",
      any("没有可用的住宅节点" in x for x in logs), str(logs[-3:]))
check("同样的告警被节流（只打一次）",
      sum(1 for x in logs if "没有可用的住宅节点" in x) == 1,
      str(sum(1 for x in logs if "没有可用的住宅节点" in x)))

# ============ [5] 跨国家放宽：只放宽国家 ============
log("\n[5] 日本全是机房、美国有住宅 -> 去美国住宅，不碰日本机房")
us = mk("10.4.0.1", "", "residential")
us.update({"country_long": "United States", "country": "United States",
           "country_code": "US", "region": "California",
           "region_key": "US:california", "region_zone": "",
           "location": "US California"})
pool = [mk("10.4.1.1", "JP-13", "hosting"), mk("10.4.1.2", "JP-11", "hosting"), us]
chs = set_pool(pool)
n = M.get_best_node_for_country("Japan", "residential", exclude_ch=chs[0], region="JP-13")
check("放宽到了美国", (n or {}).get("ip") == "10.4.0.1", str(n and n.get("ip")))
check("仍然是住宅", (n or {}).get("ip_type") == "residential")

# ============ [6] 复用也只复用同类 ============
log("\n[6] 住宅已被占满、机房空闲 -> 宁可复用住宅，不用机房")
pool = [mk("10.5.0.1", "JP-13", "residential")] + \
       [mk(f"10.5.1.{i}", "JP-13", "hosting") for i in range(1, 4)]
chs = set_pool(pool)
first = M.get_best_node_for_country("Japan", "residential", exclude_ch=chs[0], region="JP-13")
check("第一条拿到唯一的住宅", (first or {}).get("ip") == "10.5.0.1")
second = M.get_best_node_for_country("Japan", "residential", exclude_ch=chs[1], region="JP-13")
check("第二条复用的是住宅（不是空闲的机房）",
      (second or {}).get("ip") == "10.5.0.1" and (second or {}).get("ip_type") == "residential",
      str(second and (second.get("ip"), second.get("ip_type"))))
check("标记为 IP 复用", chs[1].ip_reused is True)

# ============ [7] build_assign_plan ============
log("\n[7a] 规划：东京都 3 机房，埼玉 6 住宅，神奈川 3 住宅 -> 全部住宅")
pool = [mk(f"10.6.0.{i}", "JP-13", "hosting") for i in range(1, 4)] + \
       [mk(f"10.6.1.{i}", "JP-11", "residential") for i in range(1, 7)] + \
       [mk(f"10.6.2.{i}", "JP-14", "residential") for i in range(1, 4)]
chs = set_pool(pool)
plan = M.build_assign_plan(chs, "same", "residential", "Japan", False, "JP-13")
pl = plan["plan"]
check("规划出 9 条", len(pl) == 9, str(len(pl)))
check("全部是住宅", all(p["ip_type"] == "residential" for p in pl), str([p["ip_type"] for p in pl]))
check("没有一条落在东京都（那里只有机房）",
      all(p["region_key"] != "JP-13" for p in pl), str([p["region_key"] for p in pl]))
check("先埼玉后神奈川",
      [p["region_key"] for p in pl][:6] == ["JP-11"] * 6, str([p["region_key"] for p in pl]))
msgs = " ".join(plan["warnings"])
check("警告说明是「没有住宅节点」而不是「没有节点」", "住宅节点" in msgs, msgs[:200])
check("警告说明其它类型不参与降级", "其它类型不参与降级" in msgs, msgs[:260])
check("没有绿色 note（因为发生了降级）", plan.get("note") == "", plan.get("note"))

log("\n[7b] 东京都住宅充足 -> 绿色 note 标明只算住宅")
pool = [mk(f"10.7.0.{i}", "JP-13", "residential") for i in range(1, 10)] + \
       [mk(f"10.7.1.{i}", "JP-13", "hosting") for i in range(1, 4)]
chs = set_pool(pool)
plan = M.build_assign_plan(chs, "same", "residential", "Japan", False, "JP-13")
check("9 条全在东京都", all(p["region_key"] == "JP-13" for p in plan["plan"]))
check("note 里写明「住宅节点」", "住宅节点" in (plan.get("note") or ""), plan.get("note"))

log("\n[7c] 全站没有住宅 -> 拒绝分配（而不是忽略类型用机房）")
pool = [mk("10.8.0.1", "JP-13", "hosting"), mk("10.8.0.2", "JP-11", "hosting")]
chs = set_pool(pool)
plan = M.build_assign_plan(chs, "same", "residential", "Japan", False, "JP-13")
check("plan 为空", plan["plan"] == [], str(plan["plan"]))
msgs = " ".join(plan["warnings"])
check("提示已排除其它类型（含机房 IP）", "已排除其它类型（含机房 IP）" in msgs, msgs[:200])
check("没有出现「已忽略 IP 类型限制」这种旧文案", "忽略 IP 类型限制" not in msgs, msgs[:200])

log("\n[7d] 机型不限时仍可规划机房（旧行为不受影响）")
plan = M.build_assign_plan(chs, "same", "", "Japan", False, "JP-13")
check("2 条都规划出来了", len(plan["plan"]) == 2, str(len(plan["plan"])))
check("用的是机房节点", all(p["ip_type"] == "hosting" for p in plan["plan"]))

# ============ [8] region_supply / rescan 同口径 ============
log("\n[8a] region_supply：东京都只剩机房时，住宅口径算 0")
pool = [mk(f"10.9.0.{i}", "JP-13", "hosting") for i in range(1, 4)] + \
       [mk("10.9.1.1", "JP-11", "residential")]
chs = set_pool(pool)
rows = M.region_supply("Japan", "residential")
tokyo = [r for r in rows if r["key"] == "JP-13"][0]
saitama = [r for r in rows if r["key"] == "JP-11"][0]
check("东京都 total=0（3 个机房不算）", tokyo["total"] == 0 and tokyo["free"] == 0, str(tokyo))
check("埼玉 total=1", saitama["total"] == 1 and saitama["free"] == 1, str(saitama))
rows_all = M.region_supply("Japan", "")
check("不限类型时东京都仍是 3", [r for r in rows_all if r["key"] == "JP-13"][0]["total"] == 3)

log("\n[8b] rescan_region：住宅口径判定「真没货」")
M.REGION_RESCAN_ENABLED = True
M._nodes_refreshed_at = time.time()          # 池子新鲜 -> 不联网
M._rescan_at.clear()
r1 = M.rescan_region("Japan", "JP-13", need=1, ip_type="residential")
check("住宅口径 ok=False", r1["ok"] is False, str(r1))
check("住宅口径 found=0 / total=0", r1["found"] == 0 and r1["total"] == 0, str(r1))
check("返回值带上 ip_type", r1.get("ip_type") == "residential", str(r1.get("ip_type")))
M._rescan_at.clear()
r2 = M.rescan_region("Japan", "JP-13", need=1)
check("不限类型时同一个县仍有 3 个", r2["ok"] is True and r2["found"] == 3, str(r2))
M.REGION_RESCAN_ENABLED = False

# ============ [9] 锁定县 + 住宅 ============
log("\n[9] 锁定在埼玉的住宅通道：东京都住宅恢复也不切回")
pool = [mk(f"10.10.0.{i}", "JP-13", "residential") for i in range(1, 6)] + \
       [mk("10.10.1.1", "JP-11", "residential"),
        mk("10.10.1.2", "JP-11", "hosting")]
chs = set_pool(pool)
ch = chs[0]
ch.force_country, ch.force_region, ch.region_lock = "Japan", "JP-13", "JP-11"
n = M.get_best_node_for_country("Japan", "residential", exclude_ch=ch, region="JP-13")
check("仍留在埼玉", (n or {}).get("region_key") == "JP-11", str(n and n.get("region_key")))
check("而且用的是埼玉的住宅，不是那台机房",
      (n or {}).get("ip") == "10.10.1.1", str(n and n.get("ip")))
chs[1].reserved_ip, chs[1].state = "10.10.1.1", "connected"
n = M.get_best_node_for_country("Japan", "residential", exclude_ch=ch, region="JP-13")
# 整条链（埼玉→神奈川→千叶→山梨）都没有住宅了，才允许回到原目标县 —— 这是最后一名，
# 而且回到的仍然必须是住宅。绝对不能因为"埼玉还有一台机房"就留在埼玉用机房。
check("埼玉住宅被占 -> 不碰埼玉那台机房", (n or {}).get("ip") != "10.10.1.2",
      str(n and n.get("ip")))
check("确实是住宅", (n or {}).get("ip_type") == "residential", str(n and n.get("ip_type")))
check("回到东京都是最后一档（TIER_AVOID），不是优先回切",
      M.region_rank(n, M.region_target("Japan", "JP-13"), "JP-11")[0] == M.TIER_AVOID,
      str(M.region_rank(n, M.region_target("Japan", "JP-13"), "JP-11") if n else None))

log("\n=== 通过 %d / %d ===" % (PASS, PASS + FAIL))
sys.exit(1 if FAIL else 0)

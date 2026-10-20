#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# 依据 GPL-3.0 分发；本文件为 vpngate9-new 的衍生新增部分，同样以 GPL-3.0 发布。
# ---------------------------------------------------------------------------
"""region_geo.py —— 国家级之下的"省/州/都道府县"级定位与就近降级

为什么需要这个模块
------------------
VPNGate 的节点列表里只有国家级（CountryLong=Japan），没有更细的行政区。
要做到"出口 IP 落在日本东京都"，只能借 IP 情报（ip-api 的 region / regionName）
把节点的行政区补出来，再按行政区筛选。

日本这层用 **JIS 都道府县码** 做键：ip-api 对 JP 的 `region` 字段返回 "01"~"47"，
是语言无关的强匹配；同时保留中/日/英三语别名，面板下拉能显示中文，
用户手输 "東京都" / "Tokyo" / "Tokyo-to" 也都能认出来。

降级顺序（对应需求"东京都要是没有 IP 可以就近的选用，再没有就往下推"）：

    同县/都道府县  ->  用户指定的固定顺序（东京都：埼玉 -> 神奈川 -> 千叶 -> 山梨）
                   ->  同一大区（如关东）内按距离  ->  全国按距离  ->  全国任意
                   ->  其它国家（全池）

固定顺序见本文件的 NEAR_FIRST：它是业务偏好，压过"按直线距离"——
山梨比千叶远，但东京圈用户往往更愿意先拿到山梨而不是跳到别的地区。

距离用节点 IP 的经纬度（ip-api 的 lat/lon）到目标都道府县中心点的球面距离。
没有经纬度时按"同大区 / 其它"分层，同层内保持原有质量排序。
"""
from __future__ import annotations

import math
import unicodedata
from typing import Any

# ---------------------------------------------------------------------------
# 日本 47 都道府县
#   code  : JIS 地方公共团体编码（ip-api region 字段值，零填充两位）
#   zh    : 面板显示用的中文名
#   ja    : 日文名（ip-api 用 lang=ja 时返回这种写法）
#   en    : 罗马字（ip-api 默认 / lang=en 时返回这种写法）
#   lat/lon: 县厅所在地，用于"就近"计算
#   zone  : 八大区（降级第二层用到）
# ---------------------------------------------------------------------------
# (code, zh, ja, en, lat, lon, zone)
_JP_ROWS: tuple[tuple[str, str, str, str, float, float, str], ...] = (
    ("01", "北海道",   "北海道",   "Hokkaido",  43.0642, 141.3469, "北海道"),
    ("02", "青森县",   "青森県",   "Aomori",    40.8244, 140.7400, "东北"),
    ("03", "岩手县",   "岩手県",   "Iwate",     39.7036, 141.1527, "东北"),
    ("04", "宫城县",   "宮城県",   "Miyagi",    38.2682, 140.8721, "东北"),
    ("05", "秋田县",   "秋田県",   "Akita",     39.7186, 140.1024, "东北"),
    ("06", "山形县",   "山形県",   "Yamagata",  38.2404, 140.3633, "东北"),
    ("07", "福岛县",   "福島県",   "Fukushima", 37.7503, 140.4676, "东北"),
    ("08", "茨城县",   "茨城県",   "Ibaraki",   36.3418, 140.4468, "关东"),
    ("09", "栃木县",   "栃木県",   "Tochigi",   36.5657, 139.8836, "关东"),
    ("10", "群马县",   "群馬県",   "Gunma",     36.3911, 139.0608, "关东"),
    ("11", "埼玉县",   "埼玉県",   "Saitama",   35.8569, 139.6489, "关东"),
    ("12", "千叶县",   "千葉県",   "Chiba",     35.6074, 140.1231, "关东"),
    ("13", "东京都",   "東京都",   "Tokyo",     35.6895, 139.6917, "关东"),
    ("14", "神奈川县", "神奈川県", "Kanagawa",  35.4478, 139.6425, "关东"),
    ("15", "新潟县",   "新潟県",   "Niigata",   37.9026, 139.0234, "中部"),
    ("16", "富山县",   "富山県",   "Toyama",    36.6953, 137.2113, "中部"),
    ("17", "石川县",   "石川県",   "Ishikawa",  36.5947, 136.6256, "中部"),
    ("18", "福井县",   "福井県",   "Fukui",     36.0652, 136.2216, "中部"),
    ("19", "山梨县",   "山梨県",   "Yamanashi", 35.6642, 138.5684, "中部"),
    ("20", "长野县",   "長野県",   "Nagano",    36.6513, 138.1810, "中部"),
    ("21", "岐阜县",   "岐阜県",   "Gifu",      35.3912, 136.7223, "中部"),
    ("22", "静冈县",   "静岡県",   "Shizuoka",  34.9769, 138.3831, "中部"),
    ("23", "爱知县",   "愛知県",   "Aichi",     35.1802, 136.9066, "中部"),
    ("24", "三重县",   "三重県",   "Mie",       34.7303, 136.5086, "近畿"),
    ("25", "滋贺县",   "滋賀県",   "Shiga",     35.0045, 135.8686, "近畿"),
    ("26", "京都府",   "京都府",   "Kyoto",     35.0212, 135.7556, "近畿"),
    ("27", "大阪府",   "大阪府",   "Osaka",     34.6863, 135.5199, "近畿"),
    ("28", "兵库县",   "兵庫県",   "Hyogo",     34.6913, 135.1830, "近畿"),
    ("29", "奈良县",   "奈良県",   "Nara",      34.6851, 135.8328, "近畿"),
    ("30", "和歌山县", "和歌山県", "Wakayama",  34.2260, 135.1675, "近畿"),
    ("31", "鸟取县",   "鳥取県",   "Tottori",   35.5039, 134.2377, "中国"),
    ("32", "岛根县",   "島根県",   "Shimane",   35.4723, 133.0505, "中国"),
    ("33", "冈山县",   "岡山県",   "Okayama",   34.6618, 133.9344, "中国"),
    ("34", "广岛县",   "広島県",   "Hiroshima", 34.3966, 132.4596, "中国"),
    ("35", "山口县",   "山口県",   "Yamaguchi", 34.1859, 131.4707, "中国"),
    ("36", "德岛县",   "徳島県",   "Tokushima", 34.0658, 134.5593, "四国"),
    ("37", "香川县",   "香川県",   "Kagawa",    34.3401, 134.0434, "四国"),
    ("38", "爱媛县",   "愛媛県",   "Ehime",     33.8416, 132.7661, "四国"),
    ("39", "高知县",   "高知県",   "Kochi",     33.5597, 133.5311, "四国"),
    ("40", "福冈县",   "福岡県",   "Fukuoka",   33.6064, 130.4183, "九州"),
    ("41", "佐贺县",   "佐賀県",   "Saga",      33.2494, 130.2988, "九州"),
    ("42", "长崎县",   "長崎県",   "Nagasaki",  32.7448, 129.8737, "九州"),
    ("43", "熊本县",   "熊本県",   "Kumamoto",  32.7898, 130.7417, "九州"),
    ("44", "大分县",   "大分県",   "Oita",      33.2382, 131.6126, "九州"),
    ("45", "宫崎县",   "宮崎県",   "Miyazaki",  31.9111, 131.4239, "九州"),
    ("46", "鹿儿岛县", "鹿児島県", "Kagoshima", 31.5602, 130.5581, "九州"),
    ("47", "冲绳县",   "沖縄県",   "Okinawa",   26.2124, 127.6809, "九州"),
)

JP_PREFECTURES: list[dict[str, Any]] = [
    {"code": c, "key": f"JP-{c}", "name": zh, "ja": ja, "en": en,
     "lat": lat, "lon": lon, "zone": zone}
    for c, zh, ja, en, lat, lon, zone in _JP_ROWS
]

_BY_CODE: dict[str, dict[str, Any]] = {p["code"]: p for p in JP_PREFECTURES}
_BY_KEY: dict[str, dict[str, Any]] = {p["key"]: p for p in JP_PREFECTURES}
# 大区名 -> 该区所有都道府县键（降级第二层用）
ZONES: dict[str, list[str]] = {}
for _p in JP_PREFECTURES:
    ZONES.setdefault(_p["zone"], []).append(_p["key"])


# ---------------------------------------------------------------------------
# 用户点名的"就近顺序"（写死的业务偏好，优先于"按直线距离"）
# ---------------------------------------------------------------------------
# 默认降级是"同大区按距离 -> 全国按距离"，但有些目标是用户明确指定了先后次序的：
# 东京都没节点时先试 埼玉 -> 神奈川 -> 千叶 -> 山梨，而不是按距离先跳到千叶。
# 因为"直线最近"不等于"线路最合适"：山梨在地理上比千叶远，但常被当成东京圈一部分。
# 名单走完之后，仍然回到"同大区按距离 -> 全国按距离"继续往下推。
NEAR_FIRST: dict[str, tuple[str, ...]] = {
    "JP-13": ("JP-11", "JP-14", "JP-12", "JP-19"),   # 东京都：埼玉 -> 神奈川 -> 千叶 -> 山梨
}


def near_first_chain(key: str) -> list[str]:
    """目标的完整优先链：[目标本身] + 固定顺序。没有配置时只有目标自己。"""
    k = (key or "").strip().upper()
    if not k:
        return []
    out = [k]
    for nk in NEAR_FIRST.get(k, ()):
        if nk not in out:
            out.append(nk)
    return out


def near_first_names(key: str) -> list[str]:
    """优先链对应的中文名，给面板/日志写人话用。"""
    out = []
    for k in near_first_chain(key):
        p = _BY_KEY.get(k)
        out.append(p["name"] if p else k)
    return out


def _norm(text: str) -> str:
    """归一化：全角转半角、去空格/连字符/点/斜杠、统一"県/縣"→"县"、转小写。

    目标是让 "Tokyo-to" / "tokyo to" / "TOKYO" / "東京都" 这类写法都能落到同一个桶里。
    """
    if not text:
        return ""
    s = unicodedata.normalize("NFKC", str(text)).strip().lower()
    s = s.replace("県", "县").replace("縣", "县")
    for ch in " \t-_./·・'\"()（）":
        s = s.replace(ch, "")
    return s


# 常见后缀：英文的 prefecture / ken / fu / to / do，以及中文的 都/府/县
_EN_SUFFIXES = ("prefecture", "ken", "fu", "to", "do", "gun")
_CN_SUFFIXES = ("都", "府", "县")

_ALIAS: dict[str, dict[str, Any]] = {}


def _register(pref: dict[str, Any]) -> None:
    names = [pref["name"], pref["ja"], pref["en"], pref["code"],
             f"jp-{pref['code']}", f"jp{pref['code']}"]
    for n in names:
        _ALIAS.setdefault(_norm(n), pref)
    # "Tokyo-to" / "Osaka-fu" 这类带后缀的写法，统一在 lookup_prefecture 里
    # 去掉后缀再查（见 _EN_SUFFIXES），这里不再逐条展开——否则
    # "Tokyo".endswith("to") 会把 "tok" 也注册成东京，属于误伤。
    # 中文名去掉 都/府/县：东京都 -> 东京，大阪府 -> 大阪，千叶县 -> 千叶
    for n in (pref["name"], pref["ja"]):
        for suf in _CN_SUFFIXES:
            if n.endswith(suf) and len(n) > len(suf):
                _ALIAS.setdefault(_norm(n[: -len(suf)]), pref)


for _p in JP_PREFECTURES:
    _register(_p)

# 几个手输率很高的俗称（不在正式名称体系里，但用户会这么打）
for _alias, _key in {
    "tokio": "JP-13", "edo": "JP-13", "东京市": "JP-13", "東京都心": "JP-13",
    "oosaka": "JP-27", "osaka fu": "JP-27",
    "kyoto fu": "JP-26", "kyouto": "JP-26",
    "sapporo": "JP-01", "札幌": "JP-01",
    "yokohama": "JP-14", "横滨": "JP-14",
    "nagoya": "JP-23", "名古屋": "JP-23",
    "kobe": "JP-28", "神户": "JP-28",
    "fukuoka shi": "JP-40",
    "naha": "JP-47", "那霸": "JP-47",
}.items():
    _ALIAS.setdefault(_norm(_alias), _BY_KEY[_key])


def haversine_km(lat1: float | None, lon1: float | None,
                 lat2: float | None, lon2: float | None) -> float | None:
    """两点球面距离（公里）。任一坐标缺失返回 None（表示"算不出距离"）。"""
    if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
        return None
    try:
        p1, p2 = math.radians(float(lat1)), math.radians(float(lat2))
        dp = p2 - p1
        dl = math.radians(float(lon2) - float(lon1))
        a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
        return round(6371.0088 * 2 * math.asin(min(1.0, math.sqrt(a))), 1)
    except (TypeError, ValueError):
        return None


def is_japan(country_name: str, country_code: str = "") -> bool:
    if (country_code or "").strip().upper() == "JP":
        return True
    n = _norm(country_name or "")
    return n in ("japan", "日本", "jp")


def lookup_prefecture(*names: Any) -> dict[str, Any] | None:
    """按任意写法（码 / 中 / 日 / 英 / 别名）找都道府县。"""
    for raw in names:
        if raw is None:
            continue
        s = str(raw).strip()
        if not s:
            continue
        # 1) 纯数字码（ip-api region 对 JP 返回 "13"，也可能带前导零）
        if s.isdigit():
            code = s.zfill(2)
            if code in _BY_CODE:
                return _BY_CODE[code]
        # 2) JP-13 这种键
        up = s.upper().replace("_", "-")
        if up in _BY_KEY:
            return _BY_KEY[up]
        if up.startswith("JP") and up[2:].lstrip("-").isdigit():
            code = up[2:].lstrip("-").zfill(2)
            if code in _BY_CODE:
                return _BY_CODE[code]
        # 3) 名称/别名
        pref = _ALIAS.get(_norm(s))
        if pref:
            return pref
        # 4) 带行政后缀的写法：Tokyo-to / Osaka-fu / Kyoto Prefecture
        base = _norm(s)
        for suf in _EN_SUFFIXES:
            if base.endswith(suf) and len(base) > len(suf) + 3:
                pref = _ALIAS.get(base[: -len(suf)])
                if pref:
                    return pref
    return None


def canonicalize(country_name: str, country_code: str,
                 region_code: str, region_name: str) -> dict[str, Any]:
    """把 IP 情报里的行政区归一成 {key, name, zone, lat, lon, preset}。

    * 日本：命中都道府县 -> key=JP-13 / name=东京都 / zone=关东 / 有中心点坐标。
      日本但没命中（少见，如离岛或情报缺失）-> key=JP:原始名，无坐标、无大区。
    * 其它国家：key=国家码:归一化区名，name 保留原始写法，无预置坐标。
      （没有预置表也没关系：vpngate9_multi 会拿该国同区节点的平均坐标来估中心点）
    """
    cc = (country_code or "").strip().upper()
    rc = (region_code or "").strip()
    rn = (region_name or "").strip()
    if is_japan(country_name, cc):
        pref = lookup_prefecture(rc, rn)
        if pref:
            return {"key": pref["key"], "name": pref["name"], "zone": pref["zone"],
                    "lat": pref["lat"], "lon": pref["lon"], "preset": True}
        raw = rn or rc
        return {"key": f"JP:{_norm(raw)}", "name": raw or "未知", "zone": "",
                "lat": None, "lon": None, "preset": False}
    if not (rn or rc):
        return {"key": "", "name": "", "zone": "", "lat": None, "lon": None,
                "preset": False}
    raw = rn or rc
    return {"key": f"{cc or '??'}:{_norm(raw)}", "name": raw, "zone": "",
            "lat": None, "lon": None, "preset": False}


def resolve_target(region: str, country_name: str = "",
                   country_code: str = "") -> dict[str, Any] | None:
    """把用户选/输入的行政区解析成目标描述；认不出来返回 None。

    支持：面板下拉传回来的键（JP-13）、中文名（东京都 / 东京）、
    日文名（東京都）、英文名（Tokyo / Tokyo-to）、JIS 码（13）。
    """
    s = (region or "").strip()
    if not s:
        return None
    # 形如 "US:california" 这种键：直接认，按"非日本、无坐标"处理
    if ":" in s and not s.upper().startswith("JP-"):
        cc, _, name = s.partition(":")
        return {"key": s, "name": name or s, "zone": "",
                "lat": None, "lon": None, "preset": False}
    pref = lookup_prefecture(s)
    if pref:
        return {"key": pref["key"], "name": pref["name"], "zone": pref["zone"],
                "lat": pref["lat"], "lon": pref["lon"], "preset": True}
    # 认不出来：当作"该国某个自定义区名"，靠节点数据里的同名区去匹配
    return {"key": f"{(country_code or '').upper() or '??'}:{_norm(s)}", "name": s,
            "zone": "", "lat": None, "lon": None, "preset": False}


def zone_of_key(key: str) -> str:
    pref = _BY_KEY.get((key or "").strip().upper())
    return pref["zone"] if pref else ""


def options_for(country_name: str, country_code: str = "") -> list[dict[str, Any]]:
    """面板下拉用：日本返回全部 47 个（即使当前 0 个节点），其它国家返回空。"""
    if not is_japan(country_name, country_code):
        return []
    return [{"key": p["key"], "name": p["name"], "zone": p["zone"],
             "lat": p["lat"], "lon": p["lon"]} for p in JP_PREFECTURES]

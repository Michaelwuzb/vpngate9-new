#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# 衍生自 aimili-vpngate (https://github.com/baoweise-bot/aimili-vpngate)
# 依据 GPL-3.0 修改与分发；本文件的衍生部分同样以 GPL-3.0 发布。
# 完整许可见同目录 LICENSE，改造说明见 NOTICE。
# ---------------------------------------------------------------------------
"""
vpngate9_multi.py - 9-Channel VPN Gateway + Node Management UI
Combines: multi-tunnel + full node table (IP info, filters, assign to channels)
"""
from __future__ import annotations
import base64, csv, io, json, os, random, re, shlex, signal, socket, subprocess, sys
import threading, time, urllib.request, urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import vpn_utils
import speedtest_utils

# === Auth ===
# 密码以 PBKDF2-SHA256 哈希存储(兼容旧版明文自动升级)；
# 守护脚本走单独的长效令牌文件，改面板账号密码不会让它失联。
import hashlib, hmac, secrets

auth_token_store: dict[str, float] = {}
login_fail_store: dict[str, list[float]] = {}
GUARD_TOKEN = ""                  # 启动时从 guard_token 文件载入
SESSION_TTL = 86400               # 会话有效期(秒)
MAX_LOGIN_FAILS = 5               # 连续失败 N 次后锁定
LOGIN_FAIL_WINDOW = 300           # 锁定观察窗口(秒)

def _auth_file() -> Path:
    return DATA_DIR / "ui_auth.json"

def _guard_token_file() -> Path:
    return DATA_DIR / "guard_token"

def _hash_password(password: str, salt: str | None = None, iterations: int = 200_000) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:
        return False

def load_auth_config() -> dict:
    cfg = read_json(_auth_file()) or {}
    if not cfg.get("username"):
        cfg["username"] = "admin"
    return cfg

def save_auth_config(username: str, password: str) -> None:
    path = _auth_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, {"username": username, "password_hash": _hash_password(password),
                      "updated_at": int(time.time())})
    try: os.chmod(path, 0o600)
    except Exception: pass

def verify_credentials(user: str, password: str) -> bool:
    cfg = load_auth_config()
    if user != cfg.get("username", "admin"):
        return False
    if cfg.get("password_hash"):
        return _verify_password(password, str(cfg["password_hash"]))
    # 兼容旧版明文
    return hmac.compare_digest(password, str(cfg.get("password", "admin")))

def migrate_plaintext_credentials() -> None:
    """旧版本把密码明文写在 ui_auth.json 里，首次启动时升级为哈希。"""
    cfg = read_json(_auth_file()) or {}
    if not cfg:
        return
    if cfg.get("password_hash"):
        if "password" in cfg:
            cfg.pop("password", None)
            write_json(_auth_file(), cfg)
        return
    save_auth_config(str(cfg.get("username", "admin")), str(cfg.get("password", "admin")))
    log("[auth] 明文密码已升级为 PBKDF2 哈希存储")

def load_or_create_guard_token() -> str:
    try:
        tok = _guard_token_file().read_text(encoding="utf-8").strip()
        if len(tok) >= 32:
            return tok
    except Exception:
        pass
    tok = secrets.token_hex(32)
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _guard_token_file().write_text(tok, encoding="utf-8")
        os.chmod(_guard_token_file(), 0o600)
        log("[auth] 已生成守护令牌 vpngate_data/guard_token")
    except Exception as e:
        log(f"[auth] 守护令牌写入失败: {e}")
    return tok

def check_auth_token(headers) -> bool:
    cookie = headers.get("Cookie","") or ""
    for part in cookie.split(";"):
        part=part.strip()
        if part.startswith("token="):
            tok=part[6:]
            if not tok:
                continue
            # 守护脚本的长效令牌: 不随改密失效，便于无人值守重连
            if GUARD_TOKEN and hmac.compare_digest(tok, GUARD_TOKEN):
                return True
            entry=auth_token_store.get(tok)
            if entry and time.time()-entry<SESSION_TTL:
                return True
            elif entry:
                del auth_token_store[tok]
    return False

def generate_token() -> str:
    tok=secrets.token_hex(32)
    auth_token_store[tok]=time.time()
    return tok

def invalidate_all_sessions() -> None:
    """改完账号密码后清掉所有会话, 强制重新登录(守护令牌不受影响)。"""
    auth_token_store.clear()

def is_login_locked(ip: str) -> int:
    """返回剩余锁定秒数, 0 表示未锁定。"""
    now = time.time()
    fails = [t for t in login_fail_store.get(ip, []) if now - t < LOGIN_FAIL_WINDOW]
    login_fail_store[ip] = fails
    if len(fails) >= MAX_LOGIN_FAILS:
        return int(LOGIN_FAIL_WINDOW - (now - fails[-1])) + 1
    return 0

def record_login_failure(ip: str) -> None:
    login_fail_store.setdefault(ip, []).append(time.time())

def clear_login_failures(ip: str) -> None:
    login_fail_store.pop(ip, None)

def validate_username(name: str) -> str:
    if not name:
        return "账号不能为空"
    if len(name) < 3 or len(name) > 32:
        return "账号长度需在 3~32 个字符之间"
    if not re.match(r"^[A-Za-z0-9_.-]+$", name):
        return "账号只能包含字母、数字、下划线、点、连字符"
    return ""

def validate_password(pwd: str, username: str) -> str:
    if len(pwd) < 8:
        return "密码至少 8 位"
    if pwd.lower() == username.lower():
        return "密码不能与账号相同"
    if len(set(pwd)) == 1:
        return "密码过于简单（不可全部为同一字符）"
    weak = ("12345678", "password", "admin123", "qwertyui", "11111111", "adminadmin")
    if pwd.lower() in weak:
        return "密码过于常见，请更换"
    return ""

def is_default_credentials() -> bool:
    cfg = load_auth_config()
    return cfg.get("username") == "admin" and verify_credentials("admin", "admin")

LOGIN_HTML_CACHE = ""

NUM_CHANNELS = 9
PROXY_BASE_PORT = 47928
# 策略路由表号：通道 i 用 POLICY_TABLE_BASE + i。
# 用 200 段而不是原来的 100 段——100~108 常被各类网络管理工具占用（VPN/防火墙/容器
# 网络），撞上就会出现"规则被别人的清理脚本删掉"或者"我们的规则覆盖别人的"。
# 200~252 是内核留给本地自定义用途的区间，系统不会自动占。
POLICY_TABLE_BASE = int(os.environ.get("VPNGATE_POLICY_TABLE_BASE", "200"))
UI_PORT = 8787
UI_HOST = "::"
LOCAL_PROXY_HOST = "127.0.0.1"
API_URL = "https://www.vpngate.net/api/iphone/"
# 多级节点源，按顺序尝试。9 条通道共用同一个节点池：只有一个源的话，
# vpngate.net 被墙或抽风就是 9 条通道一起没节点可用、重启后连缓存都没有。
API_URLS = [API_URL, "http://www.vpngate.net/api/iphone/"]
FETCH_INTERVAL = int(os.environ.get("FETCH_INTERVAL", "600"))

# === 稳定性参数 ===
WATCHDOG_INTERVAL = int(os.environ.get("WATCHDOG_INTERVAL", "15"))  # 通道巡检间隔(秒)
FAIL_TOLERANCE = int(os.environ.get("FAIL_TOLERANCE", "3"))         # 连续 N 轮探测不通才重连，抵消抖动
RECONNECT_COOLDOWN = int(os.environ.get("RECONNECT_COOLDOWN", "90")) # 同通道两次重连最小间隔(秒)
CONNECT_TIMEOUT = int(os.environ.get("CONNECT_TIMEOUT", "45"))      # 单次建隧道等待上限(秒)

# 「自动分配出口」默认跳过的国家/地区：VPNGate 上的 CN 节点基本都是境内志愿者家宽，
# 拿它当境外出口没有意义，而且通常只有 1 个节点、随时掉线。
# 想连它仍可在面板上手动指定；想改这个行为用 VPNGATE_EXCLUDE_COUNTRIES= 覆盖(逗号分隔，留空=不排除)。
_EXCL_ENV = os.environ.get("VPNGATE_EXCLUDE_COUNTRIES")
EXCLUDE_COUNTRIES = ({c.strip().lower() for c in _EXCL_ENV.split(",") if c.strip()}
                     if _EXCL_ENV is not None else {"china"})

def is_excluded_country(name: str) -> bool:
    low = (name or "").strip().lower()
    return bool(low) and any(low == e or low.startswith(e + " ") for e in EXCLUDE_COUNTRIES)

ROOT_DIR = Path("/opt/michaelvpn")
DATA_DIR = ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
SEEN_FILE = DATA_DIR / "nodes_seen.json"      # 节点首现时间记录（判断"新节点"的基准）
NODES_SNAPSHOT_FILE = DATA_DIR / "nodes_snapshot.json"   # 上次成功拉取的完整节点（含配置，供源不可用时回退）
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
CHANNELS_FILE = DATA_DIR / "channels.json"
IP_CACHE_FILE = DATA_DIR / "ip_cache.json"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"

# === 新节点标记 ===
# 一个节点"首现时间"落在 TTL 内就算新节点。用时间戳而不是"本次刷新新增"来判定，
# 是因为采集是 600 秒一轮：用一次性标记的话，10 分钟后标记就没了，用户根本来不及看。
NEW_NODE_TTL = max(0.0, float(os.environ.get("NEW_NODE_TTL_HOURS", "24")) * 3600)
SEEN_KEEP_DAYS = float(os.environ.get("SEEN_KEEP_DAYS", "30"))   # 首现记录保留天数，防止文件无限长

# === 测速参数 ===
PING_WORKERS = max(1, int(os.environ.get("PING_WORKERS", "32")))       # 延迟测试并发数
PING_TIMEOUT = max(1.0, float(os.environ.get("PING_TIMEOUT", "3")))    # 单个节点 TCP 探测超时(秒)
SPEEDTEST_MAX_NODES = max(1, int(os.environ.get("SPEEDTEST_MAX_NODES", "20")))  # 单次批量真实测速上限

DATA_DIR.mkdir(exist_ok=True, parents=True)
CONFIG_DIR.mkdir(exist_ok=True, parents=True)
if not AUTH_FILE.exists():
    AUTH_FILE.write_text("vpn\nvpn\n")
    AUTH_FILE.chmod(0o600)

# === Channel State ===
class Channel:
    def __init__(self, index: int):
        self.index = index
        self.tun = f"tun{index}"
        self.proxy_port = PROXY_BASE_PORT + index
        self.force_country = ""
        self.force_ip_type = ""
        self.enabled = False
        self.state = "disconnected"
        self.node_id = ""
        self.node_name = ""
        self.node_ip = ""
        self.node_country = ""
        self.node_owner = ""
        self.node_location = ""
        self.node_ip_type = ""
        self.node_ip_reason = ""
        self.node_latency = 0
        self.process: subprocess.Popen[str] | None = None
        self.error = ""
        self.last_heartbeat = 0.0
        self.last_node_data: dict | None = None  # Save last node for reconnect
        self.fail_streak = 0            # 连续探测失败轮数
        self.last_connect_at = 0.0      # 最近一次发起连接的时间(用于重连冷却)
        # 选节点时立即占位, 这样 9 条通道并发选节点时不会撞同一个出口 IP。
        # 连接成功后清空(此时 node_ip 已生效), 断开/失败也清空。
        self.reserved_ip = ""
        self.ip_reused = False          # 本次出口 IP 是否因池子不够而复用了别的通道的 IP
        # --- 测速 ---
        self.speed_testing = False      # 正在测速（前端据此禁用按钮 / 显示"测速中"）
        self.speed_mbps = 0.0           # 实测出口带宽
        self.speed_ttfb_ms = 0
        self.speed_at = 0.0             # 最近一次测速时间戳
        self.speed_error = ""
        self.proxy_error = ""           # 本地代理端口没起来时的原因（启动时探测）
        self.lock = threading.Lock()

    def to_dict(self) -> dict:
        d = {"index": self.index, "tun": self.tun, "proxy_port": self.proxy_port,
             "force_country": self.force_country, "force_ip_type": self.force_ip_type, "enabled": self.enabled, "state": self.state,
             "node_id": self.node_id, "node_name": self.node_name, "node_ip": self.node_ip,
             "node_country": self.node_country, "node_owner": self.node_owner,
             "node_location": self.node_location, "node_ip_type": self.node_ip_type,
             "node_ip_reason": self.node_ip_reason,
             "ip_reused": self.ip_reused, "reserved_ip": self.reserved_ip,
             "node_latency": self.node_latency, "error": self.error,
             "speed_testing": self.speed_testing, "speed_mbps": self.speed_mbps,
             "speed_ttfb_ms": self.speed_ttfb_ms, "speed_at": self.speed_at,
             "speed_error": self.speed_error, "proxy_error": self.proxy_error}
        return d

channels: list[Channel] = [Channel(i) for i in range(NUM_CHANNELS)]
nodes_cache: list[dict[str, Any]] = []
nodes_cache_lock = threading.Lock()
_last_node_ids: set[str] = set()  # Track previous fetch for duplicate detection

# === 新节点追踪（首现时间持久化）===
_seen_nodes: dict[str, float] = {}   # {节点id: 首次出现时间戳}
_seen_lock = threading.Lock()
_new_muted_at = 0.0                  # "清除新标记"的时间点，早于它的首现不再算新

# === 后台任务状态（延迟测试 / 真实测速）===
PING_TASK: dict[str, Any] = {"running": False, "done": 0, "total": 0, "ok": 0, "fail": 0,
                             "started": 0.0, "finished": 0.0, "error": "", "scope": ""}
SPEED_TASK: dict[str, Any] = {"running": False, "done": 0, "total": 0, "current": "",
                              "current_ip": "", "ok": 0, "fail": 0, "started": 0.0,
                              "finished": 0.0, "error": "", "stopped": False, "results": {}}
TASK_LOCK = threading.Lock()
_speed_task_stop = threading.Event()


def log(msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def read_json(path: Path) -> Any:
    try: return json.loads(path.read_text(encoding="utf-8"))
    except: return {}

def write_json(path: Path, data: Any):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def save_channels():
    data = {}
    for ch in channels:
        data[str(ch.index)] = {
            "force_country": ch.force_country,
            "force_ip_type": ch.force_ip_type,
            "enabled": ch.enabled,
        }
    write_json(CHANNELS_FILE, data)

# === 新节点标记 ===
def load_seen_nodes() -> None:
    """从磁盘恢复节点首现记录。

    没有这一步，服务一重启基准就归零，整个池子会被当成"全新"刷屏一遍 ——
    这是做"新节点标记"最容易踩的坑。
    """
    global _seen_nodes, _new_muted_at
    raw = read_json(SEEN_FILE)
    data: dict[str, float] = {}
    muted = 0.0
    if isinstance(raw, dict):
        if isinstance(raw.get("nodes"), dict):      # 当前格式
            src = raw["nodes"]
            try: muted = float(raw.get("muted_at") or 0.0)
            except (TypeError, ValueError): muted = 0.0
        else:                                       # 兼容最朴素的 {id: ts} 格式
            src = raw
        for k, v in src.items():
            try: data[str(k)] = float(v)
            except (TypeError, ValueError): continue
    with _seen_lock:
        _seen_nodes = data
        _new_muted_at = muted
    log(f"[seen] 载入 {len(data)} 条节点首现记录")

def save_seen_nodes() -> None:
    with _seen_lock:
        payload = {"muted_at": _new_muted_at, "nodes": dict(_seen_nodes)}
    try: write_json(SEEN_FILE, payload)
    except Exception as e: log(f"[seen] 保存失败: {e}")

def _prune_seen(current_ids: set[str]) -> None:
    """清理早就消失的节点记录，只保留"当前池里有"和"首现还在保留期内"的。"""
    cutoff = time.time() - SEEN_KEEP_DAYS * 86400
    with _seen_lock:
        dead = [k for k, v in _seen_nodes.items() if k not in current_ids and v < cutoff]
        for k in dead: _seen_nodes.pop(k, None)

def annotate_new_nodes(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    """给节点打 first_seen 标记，并统计本次新增。

    返回 {"new": 本次新出现的条数, "new_ids": [...], "baseline": 是否刚建立基准}。

    建基准那一次会把"新"的水位线一起抬到当前时刻：我们并不知道这批节点是什么时候上线的，
    不抬水位线的话，首现时间全等于"刚刚"，整个池子会被当成新节点刷满一屏。
    """
    global _new_muted_at
    now = time.time()
    res: dict[str, Any] = {"new": 0, "new_ids": [], "baseline": False}
    with _seen_lock:
        baseline = not _seen_nodes
        res["baseline"] = baseline
        if baseline:
            _new_muted_at = now
        for n in nodes:
            nid = str(n.get("id") or "")
            if not nid:
                n["is_new"] = False; n["first_seen"] = 0.0
                continue
            fs = _seen_nodes.get(nid)
            if fs is None:
                _seen_nodes[nid] = now
                n["first_seen"] = now
                n["is_new"] = not baseline
                if not baseline:
                    res["new"] += 1
                    res["new_ids"].append(nid)
            else:
                n["first_seen"] = fs
                n["is_new"] = False
    return res

def is_new_by_ttl(first_seen: float, now: float | None = None) -> bool:
    """"新"徽标的判定：首现时间落在 TTL 之内，且没被"清除新标记"清掉。"""
    if not first_seen or NEW_NODE_TTL <= 0:
        return False
    if first_seen <= _new_muted_at:
        return False
    return (now or time.time()) - first_seen <= NEW_NODE_TTL

def clear_new_marks() -> int:
    """把当前所有节点的"新"标记一次性清掉（保留首现历史，只记一个水位线）。"""
    global _new_muted_at
    with _seen_lock:
        _new_muted_at = time.time()
    save_seen_nodes()
    log("[seen] 已清除全部新节点标记")
    return 0

def persist_nodes() -> None:
    """把内存里的节点池落盘（去掉体积很大的 config_text）。"""
    with nodes_cache_lock:
        stripped = [{k: v for k, v in n.items() if k != "config_text"} for n in nodes_cache]
    try: write_json(NODES_FILE, stripped)
    except Exception as e: log(f"[nodes] 落盘失败: {e}")

def merge_node_metrics(nodes: list[dict[str, Any]]) -> None:
    """把上一轮已经测出来的延迟/带宽按节点 id 合并到新池子里。

    采集是整池替换的，不做合并的话每轮刷新都会把测速结果抹掉 ——
    用户刚测完一轮，10 分钟后就一片空白。
    """
    with nodes_cache_lock:
        old = {n.get("id"): n for n in nodes_cache if n.get("id")}
    for n in nodes:
        o = old.get(str(n.get("id") or ""))
        if not o: continue
        for k in ("tcp_latency", "test_out_mbps", "test_out_at", "test_out_error"):
            if o.get(k) not in (None, ""):
                n[k] = o[k]

def node_test_result(nid: str) -> dict[str, Any]:
    with nodes_cache_lock:
        for n in nodes_cache:
            if str(n.get("id") or "") == nid:
                return {"tcp_latency": n.get("tcp_latency", 0) or 0,
                        "mbps": n.get("test_out_mbps", 0.0) or 0.0,
                        "at": n.get("test_out_at", 0.0) or 0.0,
                        "error": n.get("test_out_error", "") or ""}
    return {}

# === 延迟测试（TCP 握手 RTT，纯探测零流量）===
def start_ping_task(ids: list[str] | None = None) -> dict[str, Any]:
    with TASK_LOCK:
        if PING_TASK["running"]:
            return {"ok": False, "error": "已有延迟测试在进行中"}
        with nodes_cache_lock:
            targets = [(str(n.get("id") or ""), str(n.get("ip") or ""), str(n.get("port") or "443"))
                       for n in nodes_cache if n.get("ip")]
        if ids:
            want = {str(i) for i in ids if i}
            targets = [t for t in targets if t[0] in want]
            scope = "selected"
        else:
            scope = "all"
        if not targets:
            return {"ok": False, "error": "没有可测试的节点"}
        PING_TASK.update({"running": True, "done": 0, "total": len(targets), "ok": 0,
                          "fail": 0, "started": time.time(), "finished": 0.0,
                          "error": "", "scope": scope})
    threading.Thread(target=_ping_worker, args=(targets,), daemon=True).start()
    log(f"[ping] 开始延迟测试 {len(targets)} 个节点")
    return {"ok": True, "total": len(targets), "scope": scope}

def _ping_worker(targets: list[tuple[str, str, str]]) -> None:
    from concurrent.futures import ThreadPoolExecutor
    results: dict[str, int] = {}

    def probe(item: tuple[str, str, str]) -> tuple[str, int]:
        nid, ip, port = item
        try: p = int(port)
        except (TypeError, ValueError): p = 443
        return nid, speedtest_utils.tcp_latency(ip, p, timeout=PING_TIMEOUT)

    try:
        with ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
            for nid, ms in pool.map(probe, targets):
                results[nid] = ms
                with TASK_LOCK:
                    PING_TASK["done"] += 1
                    if ms > 0: PING_TASK["ok"] += 1
                    else: PING_TASK["fail"] += 1
    except Exception as e:
        with TASK_LOCK: PING_TASK["error"] = f"{type(e).__name__}: {e}"
        log(f"[ping] 异常: {e}")

    now = time.time()
    with nodes_cache_lock:
        for n in nodes_cache:
            nid = str(n.get("id") or "")
            if nid in results:
                n["tcp_latency"] = results[nid]
                n["tcp_latency_at"] = now
    persist_nodes()
    with TASK_LOCK:
        PING_TASK["running"] = False
        PING_TASK["finished"] = now
    log(f"[ping] 完成 {PING_TASK['ok']} 通 / {PING_TASK['fail']} 不通")

# === 真实带宽测速 ===
def _proxy_credentials() -> tuple[str | None, str | None]:
    """本机 SOCKS 口的认证信息（跟 proxy_server_multi 读同一组环境变量）。"""
    return (os.environ.get("LOCAL_PROXY_USER") or os.environ.get("LOCAL_PROXY_USERNAME"),
            os.environ.get("LOCAL_PROXY_PASS") or os.environ.get("LOCAL_PROXY_PASSWORD"))

def run_channel_speedtest(ch: Channel) -> dict[str, Any]:
    """经该通道的 SOCKS 口跑一次下载测速。同步，调用方负责放线程里。"""
    u, p = _proxy_credentials()
    res = speedtest_utils.speedtest_via_proxy(LOCAL_PROXY_HOST, ch.proxy_port,
                                              username=u, password=p)
    with ch.lock:
        ch.speed_testing = False
        ch.speed_at = time.time()
        if res.get("ok"):
            ch.speed_mbps = float(res.get("mbps") or 0.0)
            ch.speed_ttfb_ms = int(res.get("ttfb_ms") or 0)
            ch.speed_error = ""
            log(f"[speed] CH{ch.index} {ch.speed_mbps} Mbps (TTFB {ch.speed_ttfb_ms}ms)")
        else:
            ch.speed_mbps = 0.0
            ch.speed_error = str(res.get("error") or "测速失败")[:200]
            log(f"[speed] CH{ch.index} 失败: {ch.speed_error}")
    return res

def start_channel_speedtest(ch: Channel) -> dict[str, Any]:
    if ch.state != "connected":
        return {"ok": False, "error": f"CH{ch.index} 未连接，无法测速"}
    with ch.lock:
        if ch.speed_testing:
            return {"ok": False, "error": f"CH{ch.index} 正在测速中"}
        ch.speed_testing = True
        ch.speed_error = ""
    threading.Thread(target=run_channel_speedtest, args=(ch,), daemon=True).start()
    return {"ok": True, "index": ch.index}

def start_all_channel_speedtest() -> dict[str, Any]:
    """对当前已连接的通道并发测速（每个通道各自走自己的出口）。"""
    started, skipped = [], []
    for ch in channels:
        if ch.state != "connected":
            skipped.append(ch.index); continue
        r = start_channel_speedtest(ch)
        if r.get("ok"): started.append(ch.index)
        else: skipped.append(ch.index)
    if not started:
        return {"ok": False, "error": "没有已连接的通道可测速"}
    log(f"[speed] 并发测速通道 {started}")
    return {"ok": True, "started": started, "skipped": skipped}

def _find_probe_channel() -> Channel | None:
    """找一条可以借来当"测速探针"的空闲通道。

    只挑 disconnected 的；借用前会临时把 enabled 置 False，
    这样外部的守护进程在测速期间就不会来抢这条通道(它靠 /api/status 的 enabled 判断)。
    """
    for ch in channels:
        if ch.state == "disconnected" and not ch.reserved_ip and not ch.enabled:
            return ch
    for ch in channels:
        if ch.state == "disconnected" and not ch.reserved_ip:
            return ch
    return None

def start_node_speed_task(ids: list[str] | None = None, limit: int | None = None) -> dict[str, Any]:
    """对指定节点（或全部新节点）逐个建隧道实测带宽。

    代价说明：每个节点都要完整建一次隧道再拆掉，约 15~30 秒/个，
    所以默认只取 limit 个，且必须有空闲通道可用。
    """
    global _speed_task_stop
    with TASK_LOCK:
        if SPEED_TASK["running"]:
            return {"ok": False, "error": "已有节点测速任务在进行中"}
        with nodes_cache_lock:
            pool = list(nodes_cache)
    if ids:
        want = {str(i) for i in ids if i}
        targets = [n for n in pool if str(n.get("id") or "") in want]
    else:
        now = time.time()
        targets = [n for n in pool if is_new_by_ttl(n.get("first_seen", 0), now)]
        if not targets:
            targets = pool[:SPEEDTEST_MAX_NODES]
    cap = max(1, min(int(limit or SPEEDTEST_MAX_NODES), SPEEDTEST_MAX_NODES))
    targets = [n for n in targets if n.get("config_text")][:cap]
    if not targets:
        return {"ok": False, "error": "没有可测速的节点（节点池为空或未选中）"}
    if _find_probe_channel() is None:
        return {"ok": False, "error": "没有空闲通道可用：9 条通道都在使用中。"
                                     "请先断开一条，或在面板上关掉它的守护自动重连"}
    _speed_task_stop = threading.Event()
    with TASK_LOCK:
        SPEED_TASK.update({"running": True, "done": 0, "total": len(targets), "current": "",
                           "current_ip": "", "ok": 0, "fail": 0, "started": time.time(),
                           "finished": 0.0, "error": "", "stopped": False, "results": {}})
    threading.Thread(target=_node_speed_worker, args=(targets,), daemon=True).start()
    log(f"[speed] 开始节点实测 speedtest，共 {len(targets)} 个")
    return {"ok": True, "total": len(targets)}

def stop_node_speed_task() -> dict[str, Any]:
    if not SPEED_TASK["running"]:
        return {"ok": False, "error": "没有正在进行的测速任务"}
    _speed_task_stop.set()
    log("[speed] 收到停止请求，当前节点测完就收工")
    return {"ok": True}

def _restore_probe_channel(ch: Channel, borrowed_enabled: bool | None) -> None:
    """归还借用的通道：恢复 enabled 并把状态复位到 disconnected。"""
    if borrowed_enabled is not None:
        ch.enabled = borrowed_enabled
        save_channels()

def _node_speed_worker(targets: list[dict[str, Any]]) -> None:
    for node in targets:
        if _speed_task_stop.is_set():
            with TASK_LOCK: SPEED_TASK["stopped"] = True
            break
        nid = str(node.get("id") or "")
        nicename = f"{node.get('ip','')}:{node.get('port','')}"
        with TASK_LOCK:
            SPEED_TASK["current"] = nid
            SPEED_TASK["current_ip"] = nicename
        ch = _find_probe_channel()
        if ch is None:
            with TASK_LOCK: SPEED_TASK["error"] = "空闲通道被占用，任务中断"
            break
        borrowed = ch.enabled
        ok = False
        try:
            with ch.lock:
                ch.enabled = False        # 测速期间别让守护进程来抢这条通道
                ch.speed_testing = True
            ok = connect_channel(ch, node)
            if ok:
                res = run_channel_speedtest(ch)
                if res.get("ok"):
                    mbps = float(res.get("mbps") or 0.0)
                    with nodes_cache_lock:
                        for n in nodes_cache:
                            if str(n.get("id") or "") == nid:
                                n["test_out_mbps"] = mbps
                                n["test_out_at"] = time.time()
                                n["test_out_error"] = ""
                                break
                    with TASK_LOCK:
                        SPEED_TASK["ok"] += 1
                        SPEED_TASK["results"][nid] = {"ok": True, "mbps": mbps,
                                                      "ip": node.get("ip", "")}
                else:
                    err = str(res.get("error") or "测速失败")[:200]
                    with nodes_cache_lock:
                        for n in nodes_cache:
                            if str(n.get("id") or "") == nid:
                                n["test_out_error"] = err
                                n["test_out_at"] = time.time()
                                break
                    with TASK_LOCK:
                        SPEED_TASK["fail"] += 1
                        SPEED_TASK["results"][nid] = {"ok": False, "error": err,
                                                      "ip": node.get("ip", "")}
            else:
                with TASK_LOCK:
                    SPEED_TASK["fail"] += 1
                    SPEED_TASK["results"][nid] = {"ok": False, "ip": node.get("ip", ""),
                                                  "error": ch.error or "建隧道失败"}
        except Exception as e:
            with TASK_LOCK:
                SPEED_TASK["fail"] += 1
                SPEED_TASK["results"][nid] = {"ok": False, "ip": node.get("ip", ""),
                                              "error": f"{type(e).__name__}: {e}"}
        finally:
            with ch.lock:
                ch.speed_testing = False
            try: disconnect_channel(ch)
            except Exception: pass
            _restore_probe_channel(ch, borrowed)
            with TASK_LOCK: SPEED_TASK["done"] += 1
            persist_nodes()

    with TASK_LOCK:
        SPEED_TASK["running"] = False
        SPEED_TASK["finished"] = time.time()
        SPEED_TASK["current"] = ""
        SPEED_TASK["current_ip"] = ""
    log(f"[speed] 结束：成功 {SPEED_TASK['ok']} / 失败 {SPEED_TASK['fail']}")

def stop_process(proc: subprocess.Popen[str] | None):
    if proc is None: return
    try: proc.terminate(); proc.wait(timeout=3)
    except:
        try: proc.kill(); proc.wait(timeout=2)
        except: pass

def _our_config_marker() -> str:
    """识别"本程序启动的 openvpn"的关键字：我们自己的配置目录绝对路径。

    每个通道的配置都落在 CONFIG_DIR/chN.ovpn，openvpn 命令行里必然出现这个路径，
    所以拿它做匹配只可能命中自己启动的进程。
    """
    return str(CONFIG_DIR)

def cleanup_stale_openvpn() -> list[int]:
    """清理上次运行残留的、**属于本程序**的 openvpn 进程。

    原来的实现是一句裸的 `pkill -f openvpn`，会无条件杀掉系统上所有 openvpn。
    这台 VPS 上如果还跑着别的 openvpn（另一个出口、或在手工调试的隧道），
    会被一起干掉，而且不留任何记录——重启服务后才发现别的隧道没了。
    这里改成扫描 /proc，只认命令行里出现我们自己配置目录的那些进程。
    """
    marker = _our_config_marker()
    me = os.getpid()
    victims: list[int] = []
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return victims          # 非 Linux 环境直接跳过
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == me or pid == os.getppid():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue            # 进程刚好退出，或没权限读，跳过
        if not raw:
            continue
        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", "replace")
        if "openvpn" not in cmdline or marker not in cmdline:
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            victims.append(pid)
        except OSError:
            pass
    if not victims:
        return victims
    # 给它们一点时间优雅退出，赖着不走的再强杀，避免下面的建隧道撞 tun 设备
    deadline = time.time() + 3
    while time.time() < deadline:
        alive = [p for p in victims if _pid_alive(p)]
        if not alive:
            break
        time.sleep(0.2)
    for pid in victims:
        if _pid_alive(pid):
            try: os.kill(pid, signal.SIGKILL)
            except OSError: pass
    log(f"[init] 清理残留 openvpn 进程 {len(victims)} 个: {victims}")
    return victims

def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False

def release_slot(ch: Channel) -> None:
    """释放出口 IP 预占。

    连接失败/隧道判死/断开时都必须调用，否则这个 IP 会被其它通道**永久避开**，
    9 条通道的可用池会越用越小。
    """
    ch.reserved_ip = ""
    ch.ip_reused = False

def policy_table(index: int) -> int:
    """通道 index 对应的策略路由表号。

    200~252 是留给本地自定义用途的区间，不像 100 段那样常被各种网络管理工具占用。
    """
    return POLICY_TABLE_BASE + index

def _run_ip(args: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(["ip", *args], capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None             # 没有 ip 命令（非 Linux）或超时

def cleanup_policy_routing(table: int):
    """把该策略表删干净。

    `ip rule del table N` 每次只删**一条**匹配项，多条时会静默留下残余，
    所以必须循环删到删不动为止。原来只调一次，规则残留时会带着旧 tun 设备名
    留在系统里，继续劫持别的东西的路由决策。
    """
    for _ in range(64):        # 上限兜底，永不空转
        r = _run_ip(["rule", "del", "table", str(table)])
        if r is None or r.returncode != 0:
            break
    _run_ip(["route", "flush", "table", str(table)])

def setup_policy_routing(tun_dev: str, table: int) -> bool:
    """建策略路由（默认路由 + oif 规则）。返回是否真的建成功。"""
    cleanup_policy_routing(table)
    try:
        subprocess.run(["ip","route","add","default","dev",tun_dev,"table",str(table)], check=True, timeout=2)
        subprocess.run(["ip","rule","add","oif",tun_dev,"table",str(table)], check=True, timeout=2)
        for p in ["all","default",tun_dev]:
            try: subprocess.run(["sysctl","-w",f"net.ipv4.conf.{p}.rp_filter=2"], capture_output=True, timeout=2)
            except: pass
        log(f"[route {tun_dev}] table {table} OK")
        return True
    except Exception as e:
        log(f"[route {tun_dev}] Failed: {e}")
        return False

def policy_routing_ok(tun_dev: str, table: int) -> bool:
    """回读内核，确认 oif 规则和默认路由都真的落地了。

    不能只看 `ip rule add` 没报错就算完——顺序错位时会出现"面板显示已连接、
    但流量还是从物理网卡直接出去"（出口 IP 与面板不符），这种问题只能靠回读发现。
    """
    r = _run_ip(["rule", "show"])
    if r is None or f"oif {tun_dev}" not in r.stdout or f"lookup {table}" not in r.stdout:
        return False
    r2 = _run_ip(["route", "show", "table", str(table)])
    if r2 is None:
        return False
    return "default" in r2.stdout and tun_dev in r2.stdout

def proxy_port_ready(port: int, tries: int = 3, timeout: float = 1.0) -> bool:
    """本地 SOCKS 代理端口是否真的在监听。

    隧道通了不等于代理可用：代理进程可能因为端口被占早就静默退出了。
    """
    for i in range(max(1, tries)):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=timeout):
                return True
        except OSError:
            if i + 1 < tries:
                time.sleep(0.5)
    return False

def openvpn_cmd(config_file: str, tun_dev: str) -> list[str]:
    cmd = ["openvpn","--config",config_file,"--dev",tun_dev,"--dev-type","tun",
           "--pull-filter","ignore","route-ipv6","--pull-filter","ignore","ifconfig-ipv6",
           "--pull-filter","ignore","inactive",
           "--route-delay","2","--connect-retry-max","999","--connect-timeout","15",
           "--keepalive","10","60",
           "--resolv-retry","infinite",
           "--auth-user-pass",str(AUTH_FILE),"--auth-nocache","--verb","3",
           "--data-ciphers","AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
           "--route-nopull"]
    # 防中间人：要求节点证书的 keyUsage 带 serverAuth。VPNGate 的 <ca> 是内联的，
    # 校验走节点自带证书，不需要额外 CA 文件。
    # 个别节点证书不合规会因此连不上，遇到时设 VPNGATE_STRICT_TLS=0 关掉。
    if os.environ.get("VPNGATE_STRICT_TLS", "1") != "0":
        cmd.extend(["--remote-cert-tls", "server"])
    if Path("/etc/ssl/certs").exists(): cmd.extend(["--capath","/etc/ssl/certs"])
    return cmd

def connect_channel(ch: Channel, node: dict) -> bool:
    with ch.lock:
        stop_process(ch.process); ch.process = None
        cleanup_policy_routing(policy_table(ch.index))
        ch.state = "connecting"
        ch.last_connect_at = time.time()
        ch.fail_streak = 0
        ch.node_id = node.get("id","")
        ch.node_name = node.get("hostname",node.get("ip",""))
        ch.node_ip = node.get("ip",node.get("remote_host",""))
        ch.node_country = node.get("country_long",node.get("country",""))
        ch.node_owner = node.get("owner","")
        ch.node_location = node.get("location","")
        ch.node_ip_type = node.get("ip_type","")
        ch.node_ip_reason = node.get("ip_reason","")
        ch.error = ""
    config_text = node.get("config_text","")
    config_path = CONFIG_DIR / f"ch{ch.index}.ovpn"
    config_path.write_text(config_text)
    cmd = openvpn_cmd(str(config_path), ch.tun)
    log(f"[CH{ch.index}] Starting {ch.tun}...")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        ch.state = "error"; ch.error = str(e); ch.last_node_data = None; release_slot(ch); return False
    ok = False; deadline = time.time() + CONNECT_TIMEOUT; tail = []
    while time.time() < deadline:
        try: line = proc.stdout.readline()
        except: break
        if not line: break
        line = line.strip(); tail.append(line); tail = tail[-20:]
        if "initialization sequence completed" in line.lower(): ok = True; break
        if "auth_failed" in line.lower() or "authentication failed" in line.lower():
            ch.state = "error"; ch.error = "AUTH_FAILED"; ch.last_node_data = None
            release_slot(ch); stop_process(proc); return False
    if not ok:
        stop_process(proc); ch.state = "error"; ch.error = tail[-1][:200] if tail else "timeout"
        release_slot(ch); return False
    # 隧道连通性实测：TCP 优先（ICMP 常被节点丢弃，ping 会误判成"隧道死了"）
    tunnel_ok = False
    for _try in range(4):
        if vpn_utils.probe_tunnel(ch.tun, timeout=3):
            tunnel_ok = True
            break
        time.sleep(1)
    if not tunnel_ok:
        log(f"[CH{ch.index}] Tunnel dead, switching node...")
        stop_process(proc)
        ch.state = "error"
        ch.error = "tunnel unreachable"
        ch.last_node_data = None
        release_slot(ch)
        return False

    # 策略路由必须**先**建好，再对外宣告已连接。
    # 原实现是先置 state="connected" 再 setup_policy_routing，中间那几十毫秒里
    # 走代理的流量会因为 oif 规则还没落地而从物理网卡直接出去（出口 IP 与面板不符）。
    table = policy_table(ch.index)
    if not setup_policy_routing(ch.tun, table) or not policy_routing_ok(ch.tun, table):
        log(f"[CH{ch.index}] 策略路由未生效，放弃本次连接")
        stop_process(proc)
        cleanup_policy_routing(table)
        ch.state = "error"; ch.error = "policy routing not applied"
        ch.last_node_data = None
        release_slot(ch)
        return False

    # 代理端口必须真的在听。隧道通了不代表代理可用：端口被占时代理线程早就静默退出了，
    # 这种情况下面板会显示"9 个通道全部已连接"、实际却有几个根本用不了。
    if not proxy_port_ready(ch.proxy_port):
        log(f"[CH{ch.index}] 本地代理端口 {ch.proxy_port} 无响应，放弃本次连接")
        stop_process(proc)
        cleanup_policy_routing(table)
        ch.state = "error"; ch.error = f"proxy port {ch.proxy_port} not listening"
        ch.last_node_data = None
        release_slot(ch)
        return False

    with ch.lock:
            ch.process = proc
            ch.state = "connected"
            ch.last_heartbeat = time.time()
            ch.last_node_data = node
            ch.fail_streak = 0
            ch.reserved_ip = ""   # 预占转正：node_ip 已生效，无需再占位
    log(f"[CH{ch.index}] Connected! {ch.tun} :{ch.proxy_port} {ch.node_ip} (table {table})")
    return True

def disconnect_channel(ch: Channel):
    with ch.lock:
        stop_process(ch.process); ch.process = None
        cleanup_policy_routing(policy_table(ch.index))
        ch.state = "disconnected"; ch.node_id = ""; ch.node_name = ""; ch.node_ip = ""
        ch.node_country = ""; ch.node_owner = ""; ch.node_location = ""; ch.node_ip_type = ""
        ch.node_ip_reason = ""; ch.node_latency = 0; ch.error = ""; ch.fail_streak = 0
        release_slot(ch)
        # Keep config file for watchdog retry
    log(f"[CH{ch.index}] Disconnected")

def port_bindable(family: int, addr: tuple) -> str:
    """端口能不能绑；返回空串=可用，否则返回原因。"""
    s = None
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(addr)
        return ""
    except OSError as e:
        return str(e)
    finally:
        if s is not None:
            try: s.close()
            except OSError: pass

def preflight_ports() -> dict[str, str]:
    """启动前先探一遍要用的端口，把冲突提前暴露出来。

    9 条通道要占 10 个端口（面板 8787 + 代理 47928~47936）。任一被占，
    服务要么起不来要么某个通道静默失效，日志里只有子线程的一行 print，
    排查起来很绕。这里在主线程里一次探清，直接写进启动日志。
    """
    problems: dict[str, str] = {}
    if port_bindable(socket.AF_INET6, ("::", UI_PORT)) and port_bindable(socket.AF_INET, ("0.0.0.0", UI_PORT)):
        problems["ui"] = f"面板端口 {UI_PORT} 已被占用"
    for ch in channels:
        reason = port_bindable(socket.AF_INET, (LOCAL_PROXY_HOST, ch.proxy_port))
        if reason:
            problems[f"proxy{ch.index}"] = f"代理端口 {ch.proxy_port} 不可用: {reason}"
    return problems

def start_all_proxies() -> dict[int, str]:
    """启动 9 个本地 SOCKS/HTTP 代理，返回 {通道号: 失败原因}，空字典=全部就绪。

    关键改动：监听套接字在**主线程**里按顺序建好，再交给子线程跑 accept 循环。
    原来是每个通道一个子线程各自 bind，绑定失败只在那个线程里 print 一行就 return，
    主进程完全不知情 —— 9 通道下最坏会出现"面板显示 9 个已连接、实际只有 6 个在听"，
    而且从任何界面都看不出来。现在失败会落到 ch.proxy_error，面板直接标红，
    该通道也不会被判定为已连接。
    """
    import proxy_server_multi as proxy
    failed: dict[int, str] = {}
    for ch in channels:
        try:
            listener = proxy.create_proxy_listener(LOCAL_PROXY_HOST, ch.proxy_port)
        except Exception as e:
            msg = f"本地端口 {ch.proxy_port} 绑定失败: {e}"
            failed[ch.index] = msg
            ch.proxy_error = msg
            log(f"[proxy] CH{ch.index} {msg}")
            continue
        ch.proxy_error = ""
        threading.Thread(target=proxy.serve_proxy,
                         args=(listener, LOCAL_PROXY_HOST, ch.proxy_port, ch.tun),
                         daemon=True).start()
        time.sleep(0.05)   # 略微错开，让监听日志按通道顺序打印
    ok = len(channels) - len(failed)
    log(f"[init] 代理端口就绪 {ok}/{len(channels)}" + (f"，失败通道: {sorted(failed)}" if failed else ""))
    return failed

# === Node Fetching ===
_last_fetch_source = ""      # 最近一次节点数据的来源（在线地址 / snapshot / 空）
_snapshot_saved_at = 0.0     # 本地快照的保存时间（内存里记一份，避免状态接口每次都读大文件）

def _parse_vpngate_csv(raw: str) -> list[dict[str, Any]]:
    """解析 VPNGate 返回的 CSV 文本，按"延迟+速度"粗排。"""
    lines = raw.strip().split("\n")
    start = 0
    if lines and lines[0].startswith("*"): start = 1
    if len(lines) <= start + 1: return []
    csv_text = "\n".join(lines[start:])
    reader = csv.DictReader(io.StringIO(csv_text))
    nodes = []; seen = set()
    for row in reader:
        node_id = (row.get("#HostName") or row.get("HostName") or "").strip()
        if not node_id or node_id in seen: continue
        seen.add(node_id)
        ip = (row.get("IP") or "").strip()
        port = (row.get("Port") or "443").strip()
        country = (row.get("CountryLong") or "").strip()
        config_b64 = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
        if not config_b64 or not ip: continue
        try: config_text = base64.b64decode(config_b64).decode("utf-8", errors="replace")
        except: continue
        try: ping_val = int((row.get("Ping") or "0").strip())
        except: ping_val = 0
        speed = (row.get("Speed") or "0").strip()
        try: speed_val = int(speed) if speed else 0
        except: speed_val = 0
        nodes.append({"id":node_id, "ip":ip, "port":port, "country_long":country, "ping":ping_val,
                       "speed":speed_val, "config_text":config_text, "hostname":node_id})
    def score(n):
        p = max(1, n["ping"]) if n["ping"] > 0 else 999
        s = n["speed"] if n["speed"] > 0 else 999
        return p + (s if s < 100 else s * 2)
    nodes.sort(key=score)
    return nodes

def save_nodes_snapshot(nodes: list[dict[str, Any]]) -> None:
    """把这次拉到的节点完整落盘（**含 config_text**）。

    必须留配置文本：回退时拿到的节点没有配置就没法建隧道，等于没回退。
    所以这里不能复用 nodes.json —— 那份是给面板看的，刻意剥离了配置。
    """
    try:
        write_json(NODES_SNAPSHOT_FILE, {"saved_at": time.time(), "nodes": nodes})
        global _snapshot_saved_at
        _snapshot_saved_at = time.time()
    except Exception as e:
        log(f"[fetch] 节点快照写入失败: {e}")

def load_nodes_snapshot() -> tuple[list[dict[str, Any]], float]:
    """读本地节点快照，返回 (可用节点, 保存时间戳)。"""
    global _snapshot_saved_at
    data = read_json(NODES_SNAPSHOT_FILE)
    if not isinstance(data, dict): return [], 0.0
    raw_nodes = data.get("nodes")
    if not isinstance(raw_nodes, list): return [], 0.0
    good = [n for n in raw_nodes if isinstance(n, dict) and n.get("ip") and n.get("config_text")]
    try: saved_at = float(data.get("saved_at") or 0.0)
    except (TypeError, ValueError): saved_at = 0.0
    _snapshot_saved_at = saved_at
    return good, saved_at

def _fetch_raw(url: str, timeout: int = 30) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        log(f"[fetch] {url} 失败: {e}")
        return None

def fetch_nodes() -> list[dict[str, Any]]:
    """取节点：官方 HTTPS → 官方 HTTP → 本地快照。

    只保留一个源的时候，源一挂 9 条通道全部没节点可用；快照这一级保证
    "至少还能用上次那批节点把隧道建起来"，而不是整个面板空掉。
    """
    global _last_fetch_source
    log("[fetch] Fetching nodes...")
    for url in API_URLS:
        raw = _fetch_raw(url)
        if not raw: continue
        nodes = _parse_vpngate_csv(raw)
        if not nodes:
            log(f"[fetch] {url} 返回了 {len(raw)} 字节但解析不出节点，换下一个源")
            continue
        nodes = nodes[:300]        # 与节点池上限对齐
        _last_fetch_source = url
        save_nodes_snapshot(nodes)
        log(f"[fetch] {len(nodes)} nodes from {url}")
        return nodes
    nodes, saved_at = load_nodes_snapshot()
    if nodes:
        age = (time.time() - saved_at) / 3600 if saved_at else -1
        _last_fetch_source = "snapshot"
        tip = f"（快照保存于 {age:.1f} 小时前）" if age >= 0 else ""
        log(f"[fetch] 在线源全部不可用，回退本地快照: {len(nodes)} 个节点{tip}")
        return nodes
    _last_fetch_source = ""
    log("[fetch] 在线源与本地快照都不可用，本次没有节点")
    return []

def refresh_nodes_once(tag: str = "fetch") -> dict[str, Any]:
    """拉一次节点：补全 IP 信息 → 合并上轮指标 → 打新节点标记 → 落盘。

    手动拉取、定时采集、启动时的首次拉取全部走这里，三条路径的标记口径必须一致，
    否则"新节点"会一会儿全亮一会儿全灭。
    """
    global nodes_cache, _last_node_ids
    nodes = fetch_nodes()
    if not nodes:
        return {"total": 0, "new": 0, "new_ids": [], "baseline": False,
                "source": _last_fetch_source}
    try: vpn_utils.enrich_ip_info(nodes)
    except Exception as e: log(f"[enrich] Error: {e}")
    merge_node_metrics(nodes)            # 上轮测出的延迟/带宽不能被整池替换冲掉
    ann = annotate_new_nodes(nodes)
    new_ids = {str(n.get("id") or "") for n in nodes if n.get("id")}
    with nodes_cache_lock: nodes_cache = nodes
    _last_node_ids = new_ids
    _prune_seen(new_ids)
    persist_nodes()
    save_seen_nodes()
    src = "" if _last_fetch_source in ("", "snapshot") else _last_fetch_source
    log(f"[{tag}] {len(nodes)} nodes (new:{ann['new']})"
        + ("  ← 本地快照" if _last_fetch_source == "snapshot" else ""))
    return {"total": len(nodes), "new": ann["new"],
            "new_ids": ann["new_ids"], "baseline": ann["baseline"],
            "source": _last_fetch_source, "url": src}


def manual_fetch() -> dict:
    """手动拉取一次节点。返回 {new, dup, total, baseline, new_ids, source}。

    new    = 本次刷新新出现的节点数（对比持久化的首现记录）
    dup    = 之前就已经见过的节点数
    source = 数据来源；为 "snapshot" 说明在线源全挂了、用的是本地快照
    """
    result: dict[str, Any] = {"new": 0, "dup": 0, "total": 0, "baseline": False,
                              "new_ids": [], "source": ""}
    try:
        r = refresh_nodes_once("manual_fetch")
        result["total"] = r["total"]
        result["new"] = r["new"]
        result["new_ids"] = r.get("new_ids", [])
        result["baseline"] = bool(r.get("baseline"))
        result["source"] = r.get("source", "")
        result["dup"] = max(0, r["total"] - r["new"]) if not r.get("baseline") else 0
    except Exception as e:
        log(f"[manual_fetch] Error: {e}")
    return result


def collector_loop():
    while True:
        try:
            refresh_nodes_once("fetch")
        except Exception as e:
            log(f"[collector] Error: {e}")
        time.sleep(FETCH_INTERVAL)

# === Channel Manager ===
def occupied_map() -> dict[str, int]:
    """{出口 IP: 通道号} —— 正在使用或已被预占的出口。

    这里特意把 reserved_ip 和 state=connecting 也算进来：9 条通道并发选节点时，
    前一条还在握手(最长 35 秒)，如果只看 connected 就会选到同一个 IP。
    """
    out: dict[str, int] = {}
    for c in channels:
        ip = c.reserved_ip or c.node_ip
        if not ip:
            continue
        if c.reserved_ip or c.state in ("connected", "connecting"):
            out[ip] = c.index
    return out


def occupied_ips(exclude_ch: "Channel | None" = None) -> set[str]:
    """已被其它通道占用/预占的出口 IP 集合。"""
    return {ip for ip, idx in occupied_map().items()
            if exclude_ch is None or idx != exclude_ch.index}


def country_supply(ip_type: str = "") -> dict[str, dict[str, int]]:
    """各国节点供给统计，用于面板提示"这个国家还剩多少可用 IP"。

    返回 {国家: {total, residential, mobile, hosting, used}}；used 含预占中的通道。
    """
    with nodes_cache_lock:
        pool = list(nodes_cache)
    used = set(occupied_map())
    try:
        key = {"residential": "residential", "mobile": "mobile", "hosting": "hosting"}[ip_type]
    except KeyError:
        key = ""
    out: dict[str, dict[str, int]] = {}
    for n in pool:
        if key and (n.get("ip_type") or "") != key:
            continue
        cname = (n.get("country_long") or "").strip()
        if not cname:
            continue
        e = out.setdefault(cname, {"total": 0, "residential": 0, "mobile": 0,
                                   "hosting": 0, "used": 0})
        e["total"] += 1
        t = n.get("ip_type") or ""
        if t in e:
            e[t] += 1
        if n.get("ip") in used:
            e["used"] += 1
    return out


def build_assign_plan(targets: list["Channel"], mode: str = "country",
                      ip_type: str = "", country: str = "",
                      fill: bool = False) -> dict:
    """规划一组互不重复的出口节点。

    mode=country: 尽量让每条通道落在不同国家（按该国可用节点数从多到少分配）；
                  国家凑不够时，在剩余节点最多的国家上多开通道，但出口 IP 仍然互不重复。
    mode=same:    所有通道都固定到 country 指定的同一个国家/地区，只要求出口 IP 互不重复；
                  该国可用节点不够时默认只分配够用的条数（fill=True 才用其它国家补满）。
    mode=ip:      不限国家，只保证每条通道拿到一个不同的出口 IP。

    VPNGate 是志愿者网络，有节点的国家通常只有十来个，所以"9 个国家"经常凑不齐 ——
    真正能稳定做到的"9 个不同出口"是"IP 不重复"，这也是本函数的主目标。
    """
    want_country = (country or "").strip()      # mode=same 时指定的固定国家
    with nodes_cache_lock:
        pool = list(nodes_cache)
    warnings: list[str] = []
    note = ""                                   # 成功时的正向说明（前端绿框展示）
    if not pool:
        return {"plan": [], "warnings": ["节点池为空，请先点「获取节点」"],
                "countries": {}, "note": ""}

    if ip_type:
        typed = [n for n in pool if (n.get("ip_type") or "") == ip_type]
        if typed:
            pool = typed
        else:
            warnings.append(f"当前没有「{ip_type}」类型的节点，本次已忽略 IP 类型限制")

    # 本次要重新分配的通道，它们原先占的 IP 可以回收
    target_ids = {c.index for c in targets}
    used: set[str] = set()
    for c in channels:
        if c.index in target_ids:
            continue
        ip = c.reserved_ip or c.node_ip
        if ip and (c.reserved_ip or c.state in ("connected", "connecting")):
            used.add(ip)

    buckets: dict[str, list[dict]] = {}
    excl_buckets: dict[str, list[dict]] = {}    # 被默认排除的国家，只有用户显式点名才启用
    for n in pool:
        cname = (n.get("country_long") or "").strip()
        if not cname:
            continue
        if is_excluded_country(cname):
            excl_buckets.setdefault(cname, []).append(n)
            continue
        buckets.setdefault(cname, []).append(n)
    if not buckets and not excl_buckets:
        return {"plan": [], "warnings": ["节点池里没有可用的国家信息"],
                "countries": {}, "note": ""}

    order = sorted(buckets, key=lambda c: -len(buckets[c]))
    promoted = 0                                # 被显式启用的排除国家节点数

    def free_count(cname: str) -> int:
        """该国当前还有几个没被其它通道占用/预占的 IP。"""
        return sum(1 for n in (buckets.get(cname) or ()) if n.get("ip") not in used)

    def take(cname: str) -> dict | None:
        for n in buckets[cname]:            # 池内已按速度排序，取第一个未占用的即"该国最优可用"
            if n.get("ip") not in used:
                used.add(n["ip"])
                return n
        return None

    picked: list[tuple[str, dict]] = []
    if mode == "same":
        # —— 所有通道固定同一个国家/地区，只要求出口 IP 互不重复 ——
        if not want_country:
            return {"plan": [], "note": "", "countries": country_supply(ip_type),
                    "warnings": ["请先选择要用哪个国家/地区"]}
        low = want_country.lower()
        match = None
        for c in buckets:                       # 精确 -> 忽略大小写 -> 子串
            if c == want_country:
                match = c
                break
        if match is None:
            for c in buckets:
                if c.lower() == low:
                    match = c
                    break
        if match is None:
            for c in buckets:
                if low in c.lower() or c.lower() in low:
                    match = c
                    break
        if match is None:
            for c in excl_buckets:              # 点名的国家在默认排除名单里 -> 尊重显式选择
                if c.lower() == low:
                    match = c
                    buckets[c] = excl_buckets[c]
                    promoted = len(excl_buckets[c])
                    warnings.append(f"「{c}」在默认排除名单里（VPNGate 上的 CN 节点多为境内家宽，"
                                    f"当境外出口通常没有意义），此处按你的明确指定仍然使用")
                    break
        if match is None:
            known = sorted(buckets, key=lambda c: -free_count(c))[:6]
            return {"plan": [], "note": "", "countries": country_supply(ip_type),
                    "warnings": [f"节点池里没有「{want_country}」的节点（可能当前全部离线）"
                                 + (f"；当前在线有节点的国家/地区：{'、'.join(known)}"
                                    if known else "")]}
        need = len(targets)
        while len(picked) < need:               # 先尽力把该国可用 IP 都占上
            n = take(match)
            if not n:
                break
            picked.append((match, n))
        short = need - len(picked)
        if short <= 0:
            note = (f"{need} 条通道全部使用 {match}"
                    f"（该国共 {len(buckets[match])} 个节点），出口 IP 互不重复")
        elif fill:
            others = sorted([c for c in buckets if c != match],
                            key=lambda c: -free_count(c))
            while len(picked) < need:           # 轮转其它国家补满
                progressed = False
                for c in others:
                    if len(picked) >= need:
                        break
                    n2 = take(c)
                    if n2:
                        picked.append((c, n2))
                        progressed = True
                if not progressed:
                    break
            mixed = sorted({c for c, _ in picked if c != match})
            warnings.append(f"「{match}」只有 {need - short} 个未被占用的节点，不够 {need} 条通道；"
                            f"已用 {'、'.join(mixed)} 的节点补满剩余 "
                            f"{len(picked) - (need - short)} 条（出口 IP 仍互不重复）")
            if len(picked) < need:
                warnings.append(f"全站可用节点也不够，仍有 {need - len(picked)} 条通道未分配")
        else:
            enough = [c for c in sorted(buckets, key=lambda c: -free_count(c))
                      if c != match and free_count(c) >= short]
            warnings.append(f"「{match}」当前只有 {need - short} 个未被其它通道占用的节点，"
                            f"填不满 {need} 条通道；未列出的通道保持原样不变")
            if enough:
                warnings.append("可用节点够填满的国家/地区：" + "、".join(
                    f"{c}({free_count(c)})" for c in enough[:6]))
            else:
                warnings.append("当前没有任何国家的可用节点数够填满全部通道：可把"
                                "「出口 IP 类型」放宽为「不限」，或改用「不限国家，只保证出口 IP 互不重复」")
    elif mode == "ip":
        # 轮转各国取，顺手把国家也摊开
        while len(picked) < len(targets):
            progressed = False
            for cname in order:
                if len(picked) >= len(targets):
                    break
                n = take(cname)
                if n:
                    picked.append((cname, n))
                    progressed = True
            if not progressed:
                break
    else:
        for cname in order:                 # 第一轮：一国一条
            if len(picked) >= len(targets):
                break
            n = take(cname)
            if n:
                picked.append((cname, n))
        while len(picked) < len(targets):   # 第二轮：国家用完，在剩余节点最多的国家多开
            best_c, best_free = None, 0
            for cname in order:
                free = sum(1 for n in buckets[cname] if n.get("ip") not in used)
                if free > best_free:
                    best_c, best_free = cname, free
            if not best_c:
                break
            n = take(best_c)
            if not n:
                break
            picked.append((best_c, n))

    plan = []
    for i, (cname, n) in enumerate(picked):
        plan.append({
            "index": targets[i].index,
            "country": cname,
            "node_id": n.get("id", ""),
            "ip": n.get("ip", ""),
            "owner": n.get("owner", ""),
            "location": n.get("location", ""),
            "ip_type": n.get("ip_type", ""),
            "ip_reason": n.get("ip_reason", ""),
            "country_total": len(buckets[cname]),
        })

    excl_left = sum(len(v) for v in excl_buckets.values()) - promoted
    if excl_left > 0:
        warnings.append(f"已跳过 {excl_left} 个 {'/'.join(sorted(EXCLUDE_COUNTRIES))} 节点"
                        f"（如需使用可在面板上手动指定，或设 VPNGATE_EXCLUDE_COUNTRIES=）")
    if len(plan) < len(targets) and mode != "same":
        warnings.append(f"可用节点只剩 {len(plan)} 个，未能填满 {len(targets)} 条通道；"
                        f"建议把部分通道设成「自动选择」或先「获取节点」")
    if mode == "country":
        distinct = [c for c in order if c in {p["country"] for p in plan}]
        if len(distinct) < len(plan):
            warnings.append(
                f"当前在线节点只覆盖 {len(buckets)} 个国家/地区，凑不出 {len(plan)} 个不同国家；"
                f"已在节点较多的 {'、'.join(distinct[:4])} 等处多开通道，出口 IP 互不重复")
        for cname in distinct:
            if len(buckets[cname]) <= 2:
                warnings.append(f"{cname} 只有 {len(buckets[cname])} 个节点，该通道掉线后可能无备选节点")
    return {"plan": plan, "warnings": warnings, "note": note,
            "countries": country_supply(ip_type)}



def _country_candidates(country: str, ip_type: str = "") -> tuple[list[dict], list[dict]]:
    """返回 (该国全部候选, 再叠加 IP 类型过滤后的候选)。country 为空即全量池。"""
    with nodes_cache_lock:
        candidates = list(nodes_cache)
    if not country:
        base = candidates
    else:
        key = country.strip().lower()
        base = [n for n in candidates
                if key in (n.get("country_long") or "").lower()
                or key == (n.get("country") or "").strip().lower()]
    typed = [n for n in base if n.get("ip_type") == ip_type] if ip_type else base
    return base, typed


node_pick_lock = threading.Lock()   # "读占用表 + 预占 IP" 必须原子，否则并发时会撞 IP


def get_best_node_for_country(country: str, ip_type: str = "", exclude_ips: set = None,
                              exclude_ch: "Channel | None" = None,
                              allow_reuse: bool = True) -> dict | None:
    """挑一个出口节点，**优先挑没被其它通道占用的 IP**。

    选定后立刻写入 exclude_ch.reserved_ip 占位，保证并发场景下 9 条通道各拿一个不同 IP。
    只有该国未占用节点耗尽时才会复用(此时该通道会亮"IP重复"提示)。
    """
    with node_pick_lock:
        taken = occupied_ips(exclude_ch)
        if exclude_ips:
            taken |= set(exclude_ips)
        base, typed = _country_candidates(country, ip_type)
        if not base:
            return None

        def choose(pool: list[dict]) -> dict | None:
            free = [n for n in pool if n.get("ip") not in taken]
            if not free:
                return None
            # 只在最快的前若干节点里随机：既保证链路质量，又让各通道自然分散到不同节点
            return random.choice(free[:min(len(free), 12)])

        node = choose(typed) or choose(base)          # 先按 IP 类型，再放宽类型
        reused = False
        if node is None and allow_reuse:
            pool = typed or base                      # 未占用耗尽 -> 复用
            if pool:
                node = random.choice(pool)
                reused = True
        if node is None:
            return None

        if exclude_ch is not None:
            exclude_ch.reserved_ip = node.get("ip", "")
            exclude_ch.ip_reused = reused
    if reused:
        who = f"CH{exclude_ch.index}" if exclude_ch is not None else "?"
        log(f"[{who}] 警告: {country or '自动选择'} 的未占用节点已用尽，"
            f"出口 IP {node.get('ip')} 与其它通道重复")
    return node

def get_node_by_id(node_id: str) -> dict | None:
    with nodes_cache_lock:
        for n in nodes_cache:
            if n.get("id") == node_id: return n
    return None

# === Web UI ===
PAGE_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MichaelVPN 9通道</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f0f13;color:#e0e0e0;font-size:14px}
.hd{padding:16px 20px;border-bottom:1px solid rgba(255,255,255,0.06);display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.hd h1{font-size:18px;font-weight:600}
.bdg{background:#22c55e20;color:#22c55e;font-size:11px;padding:2px 10px;border-radius:10px;border:1px solid #22c55e30}
.nc{margin-left:auto;color:#6b7280;font-size:13px}
.grid{padding:12px 16px;display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:600px){.grid{grid-template-columns:1fr}}
.card{background:#1a1a24;border:1px solid rgba(255,255,255,0.06);border-radius:12px;padding:14px}
.card.on{border-color:#22c55e40;background:#1a2a1e}
.card.bz{border-color:#f59e0b40;background:#2a2418}
.card.fail{border-color:#ef444440;background:#2a1818}
.chf{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.ct{font-size:14px;font-weight:600;display:flex;align-items:center;gap:6px}
.cn{background:#818cf820;color:#818cf8;font-size:10px;padding:2px 8px;border-radius:6px}
.dt{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px}
.dt.g{background:#22c55e;box-shadow:0 0 6px #22c55e60}
.dt.y{background:#f59e0b;box-shadow:0 0 6px #f59e0b60}
.dt.r{background:#ef4444;box-shadow:0 0 6px #ef444460}
.dt.g2{background:#6b7280}
.bd{font-size:12px;color:#9ca3af;line-height:1.7}
.ll{color:#6b7280;font-size:11px}
.ac{display:flex;gap:8px;margin-top:12px}
.tog{display:flex;align-items:center;gap:5px;font-size:11px;color:#6b7280;margin-top:8px;cursor:pointer;user-select:none}
.tog input{cursor:pointer;accent-color:#818cf8}
.ac select{flex:1;background:#0f0f13;border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#e0e0e0;padding:6px 8px;font-size:12px;outline:none}
.ac select:focus{border-color:#818cf8}
.btn{background:#818cf8;border:none;color:#fff;padding:6px 14px;border-radius:8px;font-size:12px;cursor:pointer;font-weight:500}
.btn:hover{background:#6d79e8}
.btn.d{background:#ef4444}.btn.d:hover{background:#dc2626}
.btn:disabled{opacity:.4;cursor:not-allowed}
.i{display:flex;justify-content:space-between;padding:2px 0}
.section{margin:12px 16px}
.ftr{display:flex;gap:10px;margin:8px 16px;flex-wrap:wrap;align-items:center}
.ftr select{background:#0f0f13;border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#e0e0e0;padding:6px 10px;font-size:12px;outline:none}
.ftr select:focus{border-color:#818cf8}
.ftr .btn{padding:6px 12px;font-size:12px}
.tbl{width:100%;border-collapse:collapse;font-size:12px}
.tbl th{text-align:left;padding:8px 10px;color:#6b7280;font-weight:500;border-bottom:1px solid rgba(255,255,255,0.06);white-space:nowrap;position:sticky;top:0;background:#0f0f13;z-index:1}
.tbl td{padding:7px 10px;border-bottom:1px solid rgba(255,255,255,0.03);vertical-align:middle}
.tbl tr:hover{background:rgba(255,255,255,0.02)}
.tbl tr.isnew{background:rgba(34,197,94,0.05)}
.tbl tr.isnew:hover{background:rgba(34,197,94,0.09)}
.sta{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px}
.sta.ok{background:#22c55e15;color:#22c55e}
.sta.no{background:#ef444415;color:#ef4444}
.sta.na{background:#6b728015;color:#6b7280}
.act-cell{display:flex;gap:4px;flex-wrap:wrap}
.act-cell .btn{font-size:11px;padding:3px 8px}
.tp{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px}
.tp.r{background:#22c55e15;color:#22c55e}
.tp.h{background:#f59e0b15;color:#f59e0b}
.tp.m{background:#818cf815;color:#818cf8}
.tp.u{background:#6b728015;color:#6b7280}
.ow{max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bnw{display:inline-block;padding:0 5px;line-height:15px;border-radius:3px;font-size:10px;
     background:rgba(34,197,94,0.15);color:#22c55e;border:1px solid rgba(34,197,94,0.35)}
.mbp{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;background:rgba(129,140,248,0.14);color:#818cf8}
.mbp.g{background:rgba(34,197,94,0.14);color:#22c55e}
.bar{height:4px;background:rgba(255,255,255,0.08);border-radius:2px;overflow:hidden;margin-top:6px}
.bar>i{display:block;height:100%;width:0;background:#22c55e;transition:width .3s}
.job{margin:0 16px 8px;padding:8px 12px;border-radius:8px;background:rgba(129,140,248,0.08);
     border:1px solid rgba(129,140,248,0.22);font-size:12px;color:#c7d2fe}
.cb{width:13px;height:13px;cursor:pointer;accent-color:#22c55e}
.modal{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);z-index:100;align-items:center;justify-content:center}
.modal.show{display:flex}
.modal-c{background:#1a1a24;border:1px solid rgba(255,255,255,0.1);border-radius:16px;padding:24px;min-width:280px;max-width:400px}
.modal-c h3{margin-bottom:12px;font-size:15px}
.modal-c select{width:100%;margin:8px 0;padding:8px;background:#0f0f13;border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#e0e0e0;font-size:13px}
.modal-c .btns{display:flex;gap:8px;justify-content:flex-end;margin-top:12px}
</style>
</head>
<body>
<div class="hd">
  <h1>MichaelVPN</h1>
  <span class="bdg">9通道</span>
  <span class="bdg" id="oc" title="当前各通道出口 IP 占用情况">出口 0/9</span>
  <span class="nc" id="nc">节点: 加载中...</span>
  <button class="btn" style="background:rgba(34,197,94,0.14);border:1px solid rgba(34,197,94,0.3);color:#22c55e" onclick="showAssign()">分配出口</button>
  <button class="btn" style="background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.1);color:#e0e0e0" onclick="showAdmin()">管理员</button>
</div>
<div class="grid" id="grid"></div>

<div class="section" style="margin-top:0">
  <div class="ftr">
    <select id="f_status">
      <option value="">全部节点</option>
      <option value="new">只看新节点</option>
      <option value="available">可用节点</option>
      <option value="failed">失效节点</option>
      <option value="tested">已实测</option>
      <option value="untested">未实测</option>
    </select>
    <select id="f_country"><option value="">所有国家</option></select>
    <select id="f_type"><option value="">所有IP类型</option><option value="residential">住宅IP</option><option value="hosting">机房IP</option></select>
    <select id="f_sort" title="排序方式">
      <option value="">默认排序</option>
      <option value="new">最新发现优先</option>
      <option value="latency">实测延迟最低</option>
      <option value="mbps">实测带宽最高</option>
      <option value="official">官方速度最高</option>
    </select>
    <button class="btn" onclick="refreshNodes()">刷新</button>
    <button class="btn" onclick="fetchNodes()">获取节点</button>
    <button class="btn" id="btnPing" onclick="nodePing()" title="对节点 IP:端口做 TCP 握手探测，并发跑，只测连通与延迟，不产生流量">测延迟</button>
    <button class="btn" id="btnSpeed" onclick="nodeSpeed()" title="借一条空闲通道逐个建隧道实测下载带宽，约 15~30 秒/个">测带宽</button>
    <button class="btn d" id="btnStop" style="display:none" onclick="stopSpeed()">停止测速</button>
    <button class="btn" onclick="clearNew()" title="把当前所有节点的「新」标记清掉（首现时间记录保留）">清除新标记</button>
    <button class="btn" onclick="chSpeedAll()" title="对当前已连接的通道并发测速，各走自己的出口">通道测速</button>
    <span id="rc" style="color:#6b7280;font-size:12px;margin-left:auto"></span>
  </div>
  <div class="job" id="job" style="display:none">
    <span id="job_txt">准备中...</span>
    <div class="bar"><i id="job_bar"></i></div>
  </div>
  <div style="overflow-x:auto">
  <table class="tbl" id="tbl"><thead><tr>
    <th style="width:26px"><input type="checkbox" class="cb" id="ckall" onchange="toggleAllNodes(this.checked)" title="全选/全不选"></th>
    <th>状态</th><th>IP : 端口</th><th>物理位置</th><th>运营主体 / ISP</th><th>IP类型</th>
    <th>实测延迟</th><th>官方速度</th><th>实测带宽</th><th>发现时间</th><th>操作</th>
  </tr></thead><tbody id="tb"></tbody></table>
  </div>
</div>

<div class="modal" id="modal"><div class="modal-c">
  <h3>分配到通道</h3>
  <p style="font-size:12px;color:#9ca3af;margin-bottom:8px" id="m_node_info"></p>
  <select id="m_ch"></select>
  <div class="btns">
    <button class="btn" onclick="switchNode()">确认切换</button>
    <button class="btn d" onclick="closeModal()">取消</button>
  </div>
</div></div>

<script>
var CH=[]; var CUR_NODE=null;
var CUR_USER="";  // 当前登录账号，由 /api/status 回填，用于管理弹窗预填
var _saved={}; // Save dropdown state across renders
var _CS={},_CTRY=[];  // /api/status 带回的国家供给统计，供"全部通道用同一个国家"使用

function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(m){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m];});}

// 出口 IP 与其它通道重复时给个醒目提示（多出口场景下重复 = 白开一条通道）
function dupTag(c,d){
  if(c.ip_dup_with&&c.ip_dup_with.length){
    return ' <span style="color:#f59e0b;font-size:10px" title="与 CH'+c.ip_dup_with.join(', CH')+' 出口相同">IP重复</span>';
  }
  if(c.ip_reused){
    return ' <span style="color:#f59e0b;font-size:10px" title="该国未占用节点已用尽，复用了这条 IP">IP复用</span>';
  }
  return '';
}

function render(d){
  // Preserve current dropdown selections
  var _nCh=(d&&d.channels)?d.channels.length:9;
  for(var i=0;i<_nCh;i++){
    var el=document.getElementById('cs_'+i);if(el)_saved['cs_'+i]=el.value;
    var el2=document.getElementById('ipt_'+i);if(el2)_saved['ipt_'+i]=el2.value;
  }
  CH=d.channels; var g=document.getElementById('grid'),h='';
  for(var i=0;i<CH.length;i++){
    var c=CH[i];
    var cls=c.state==='connected'?'card on':c.state==='connecting'?'card bz':c.state==='error'?'card fail':'card';
    var dt=c.state==='connected'?'g':c.state==='connecting'?'y':c.state==='error'?'r':'g2';
    var st={connected:'已连接',connecting:'连接中',disconnected:'未连接',error:'错误'}[c.state]||c.state;
    var it=c.node_ip_type;
    var ipc=c.node_ip_type==='residential'?'tp r':c.node_ip_type==='hosting'?'tp h':c.node_ip_type==='mobile'?'tp m':'tp u';
    h+='<div class="'+cls+'"><div class="chf"><div class="ct"><span class="cn">CH'+c.index+'</span><span class="dt '+dt+'"></span>'+st+'</div><span style="font-size:10px;color:#6b7280">'+c.tun+'</span></div>';
    h+='<div class="bd"><div class="i"><span class="ll">出口IP</span><span>'+ (c.node_ip||'-') +'</span>'+ dupTag(c,d) +'</div>';
    var ctryShown=c.node_country||c.force_country||'';
    h+='<div class="i"><span class="ll">国家</span><span'+(c.node_country?'':' style="color:#6b7280"')+'>'+ (ctryShown||'-') +'</span></div>';
    h+='<div class="i"><span class="ll">位置</span><span style="max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+ (c.node_location||'-') +'</span></div>';
    h+='<div class="i"><span class="ll">运营主体</span><span class="ow" title="'+c.node_owner+'">'+ (c.node_owner||'-') +'</span></div>';
    h+='<div class="i"><span class="ll">IP类型</span><span'+(ipc?' class="'+ipc+'"':'')+'>'+ (it||'-') +'</span></div>';
    if(c.node_ip_reason) h+='<div class="i"><span class="ll">判定依据</span><span class="ow" title="'+String(c.node_ip_reason).replace(/["<>]/g,'')+'">'+c.node_ip_reason+'</span></div>';
    h+='<div class="i"><span class="ll">延迟</span><span>'+ (c.node_latency>0?c.node_latency+'ms':'-') +'</span></div>';
    if(c.speed_testing){
      h+='<div class="i"><span class="ll">实测带宽</span><span style="color:#818cf8">测速中...</span></div>';
    }else if(c.speed_mbps>0){
      h+='<div class="i"><span class="ll">实测带宽</span><span class="mbp'+(c.speed_mbps>=10?' g':'')+'" title="TTFB '+c.speed_ttfb_ms+'ms · '+fmtAge(Math.round((Date.now()/1000)-(c.speed_at||0)))+'">'+c.speed_mbps.toFixed(2)+' Mbps</span></div>';
    }else if(c.speed_error){
      h+='<div class="i"><span class="ll">实测带宽</span><span style="color:#ef4444;font-size:11px" title="'+esc(c.speed_error)+'">测速失败</span></div>';
    }
    if(c.proxy_error){
      // 本地代理端口没起来：隧道就算通了也没法通过它访问，必须显式标出来，
      // 否则面板看着一切正常、实际这条通道用不了
      h+='<div class="i"><span class="ll">代理</span><span style="color:#ef4444;font-size:11px" title="'+esc(c.proxy_error)+'">端口 '+c.proxy_port+' 未监听</span></div>';
    }else{
      h+='<div class="i"><span class="ll">代理</span><span>:'+c.proxy_port+'</span></div>';
    }
    if(c.error) h+='<div class="i"><span class="ll">错误</span><span style="color:#ef4444">'+c.error+'</span></div>';
    h+='<label class="tog" title="关掉后该通道不再自动重连（等于手动断开）"><input type="checkbox" id="tog_'+c.index+'"'+(c.enabled?' checked':'')+' onchange="toggleChannel('+c.index+')">守护自动重连</label>';
    h+='</div><div class="ac"><select id="cs_'+c.index+'"'+(c.state==='connecting'?' disabled':'')+'>';
    h+='<option value="">自动选择</option>';
    if(d.countries) for(var j=0;j<d.countries.length;j++){
      var co=d.countries[j];
      var sel=(_saved['cs_'+c.index]===co)||(c.force_country===co)?' selected':'';
      var st=(d.country_stats&&d.country_stats[co])||null;
      var lb=co+(st?(' · 剩'+Math.max(0,st.total-st.used)+'/'+st.total):'');  // 该国还剩几个可用节点
      h+='<option value="'+co+'"'+sel+'>'+lb+'</option>';
    }
    h+='</select>';
    var savedIpt=_saved['ipt_'+c.index]||'';
    h+='<select id="ipt_'+c.index+'"'+(c.state==='connecting'?' disabled':'')+'>';
    h+='<option value="">全部IP</option><option value="residential"'+(savedIpt==='residential'||c.force_ip_type==='residential'?' selected':'')+'>住宅</option>';
    h+='<option value="hosting"'+(savedIpt==='hosting'||c.force_ip_type==='hosting'?' selected':'')+'>机房</option>';
    h+='<option value="mobile"'+(savedIpt==='mobile'||c.force_ip_type==='mobile'?' selected':'')+'>移动</option></select>';
    h+='<button class="btn" onclick="connectAuto('+c.index+')"'+(c.state==='connecting'||c.state==='connected'?' disabled':'')+'>连接</button>';
    h+='<button class="btn" onclick="chSpeed('+c.index+')"'+(c.state==='connected'&&!c.speed_testing?'':' disabled')+'>'+(c.speed_testing?'测速中':'测速')+'</button>';
    h+='<button class="btn d" onclick="dc('+c.index+')"'+(c.state!=='connected'||c.speed_testing?' disabled':'')+'>断开</button>';
    h+='</div></div>';
  }
  g.innerHTML=h;
  var ncEl=document.getElementById('nc');
  if(ncEl){
    ncEl.textContent='节点: '+(d.node_count||0)
      +(d.new_node_count>0?(' · 新 '+d.new_node_count):'')
      +(d.nodes_source==='snapshot'?' · 用的是本地快照':'');
    ncEl.style.color=(d.nodes_source==='snapshot')?'#f59e0b':'';   // 回退到快照时给个显眼提示
  }
  _CS=d.country_stats||{}; _CTRY=d.countries||[];
  updateJobs(d);
  var am=document.getElementById('assignModal');
  if(am&&am.classList.contains('show')&&asMode()==='same'){fillCtryOptions();asCtryHint();}
  var ocEl=document.getElementById('oc');
  if(ocEl&&d.outlets){
    var nUsed=Object.keys(d.outlets).length;
    ocEl.textContent='出口 '+nUsed+'/'+CH.length;
    ocEl.style.color=(nUsed<CH.length)?'#6b7280':'#22c55e';
  }
}
async function rf(){try{var r=await fetch('/api/status');if(r.status===401){location.href='/';return}var d=await r.json();if(d.username)CUR_USER=d.username;render(d)}catch(e){}}
async function toggleChannel(i){
  var el=document.getElementById('tog_'+i);
  await fetch('/api/channel/'+i+'/toggle?enabled='+(el.checked?'1':'0'),{method:'POST'});
  if(!el.checked) dc(i);
}
async function connectAuto(i){
  var s=document.getElementById('cs_'+i);var c=s?s.value:'';
  var t=document.getElementById('ipt_'+i);var ip=t?t.value:'';
  await fetch('/api/channel/'+i+'/connect?country='+encodeURIComponent(c)+'&ip_type='+encodeURIComponent(ip),{method:'POST'});
  setTimeout(rf,500)}
async function fetchNodes(){
  document.getElementById('rc').textContent='获取中...';
  try{
    var r=await fetch('/api/fetch_nodes',{method:'POST'});
    var d=await r.json();
    if(d.ok){
      var msg='获取完成: '+d.total+' 节点';
      if(d.baseline) msg+=', 已建立基线';
      if(d.new>0) msg+=', 新增 '+d.new;
      if(d.dup>0) msg+=', 重复 '+d.dup;
      if(d.source==='snapshot') msg+=' ⚠ 在线源不可用，用的是本地快照';
      document.getElementById('rc').textContent=msg;
    }
  }catch(e){}
  setTimeout(refreshNodes,3000);}
async function dc(i){await fetch('/api/channel/'+i+'/disconnect',{method:'POST'});rf()}
rf();setInterval(rf,3000);

function openSwitch(node_id,node_ip,node_country){
  CUR_NODE=node_id;
  document.getElementById('m_node_info').textContent=node_ip+' ('+node_country+')';
  var sel=document.getElementById('m_ch'); sel.innerHTML='';
  for(var i=0;i<CH.length;i++){
    var opt=document.createElement('option'); opt.value=i;
    opt.textContent='CH'+i+' ('+CH[i].tun+')'+(CH[i].state==='connected'?' - '+CH[i].node_ip:' - 未连接');
    sel.appendChild(opt);
  }
  document.getElementById('modal').classList.add('show');
}
async function switchNode(){
  var idx=document.getElementById('m_ch').value;
  await fetch('/api/channel/'+idx+'/connect?node_id='+encodeURIComponent(CUR_NODE),{method:'POST'});
  closeModal(); setTimeout(rf,500);
}
function closeModal(){document.getElementById('modal').classList.remove('show');CUR_NODE=null}

// ===== 节点仓：新节点标记 / 延迟测试 / 带宽测速 =====
var CK={};          // 勾选的节点 id
var _wasRunning=false;

function fmtAge(s){
  if(s===null||s===undefined||s<0) return '-';
  if(s<60) return s+' 秒前';
  if(s<3600) return Math.floor(s/60)+' 分钟前';
  if(s<86400) return Math.floor(s/3600)+' 小时前';
  return Math.floor(s/86400)+' 天前';
}
function fmtBps(bps){          // VPNGate 官方 Speed 字段单位是 bps
  if(!bps||bps<=0) return '-';
  var m=Number(bps)/1e6;
  if(m>=1000) return (m/1000).toFixed(2)+' Gbps';
  if(m>=1) return m.toFixed(1)+' Mbps';
  return (m*1000).toFixed(0)+' Kbps';
}
function ckNode(el){
  var id=el.getAttribute('data-nid');
  if(el.checked) CK[id]=1; else delete CK[id];
}
function toggleAllNodes(on){
  var boxes=document.querySelectorAll('#tb .cb');
  for(var i=0;i<boxes.length;i++){
    boxes[i].checked=on;
    var id=boxes[i].getAttribute('data-nid');
    if(on) CK[id]=1; else delete CK[id];
  }
}
function checkedIds(){
  var out=[]; for(var k in CK) if(CK[k]) out.push(k); return out;
}

async function refreshNodes(){
  var st=document.getElementById('f_status').value;
  var ct=document.getElementById('f_country').value;
  var tp=document.getElementById('f_type').value;
  var so=document.getElementById('f_sort').value;
  var q='?filter='+st+'&country='+encodeURIComponent(ct)+'&ip_type='+encodeURIComponent(tp)+'&sort='+so;
  try{
    var r=await fetch('/api/nodes'+q); var d=await r.json();
    var tb=document.getElementById('tb'),h='';
    for(var i=0;i<d.nodes.length;i++){
      var n=d.nodes[i];
      var av=n.available?'sta ok':'sta no';
      var avt=n.available?'可用':'不可用';
      var ipc=n.ip_type==='residential'?'tp r':n.ip_type==='hosting'?'tp h':n.ip_type==='mobile'?'tp m':'tp u';
      var newTag=n.is_new?(' <span class="bnw" title="首现于 '+fmtAge(n.new_age_s)+'">新</span>'):'';
      h+='<tr class="'+(n.is_new?'isnew':'')+'">';
      h+='<td><input type="checkbox" class="cb" data-nid="'+esc(n.id)+'"'+(CK[n.id]?' checked':'')+' onchange="ckNode(this)"></td>';
      h+='<td><span class="sta '+av+'">'+avt+'</span></td>';
      h+='<td>'+newTag+n.ip+':'+n.port+'</td>';
      h+='<td class="ow" title="'+esc(n.location)+'">'+(n.location||'-')+'</td>';
      h+='<td class="ow" title="'+esc(n.owner)+'">'+(n.owner||'-')+'</td>';
      var tip=(n.ip_reason||'')+(n.is_vpn_exit?' / VPN出口IP':'');
      tip=String(tip).replace(/["<>]/g,'');
      h+='<td>'+(n.ip_type?'<span class="'+ipc+'" title="'+tip+'">'+(n.ip_type==='residential'?'住宅':n.ip_type==='hosting'?'机房':n.ip_type)+'</span>':'-')+'</td>';
      // 实测延迟：测过但不通给红色"不通"，没测过是灰色 "-"
      if(n.tcp_latency>0) h+='<td>'+n.tcp_latency+' ms</td>';
      else if(n.tcp_latency_at) h+='<td><span style="color:#ef4444">不通</span></td>';
      else h+='<td><span style="color:#4b5563">-</span></td>';
      h+='<td>'+(n.speed>0?fmtBps(n.speed):'<span style="color:#4b5563">-</span>')+'</td>';
      // 实测带宽（真实建隧道跑出来的）
      if(n.test_out_at&&n.test_out_mbps>0) h+='<td><span class="mbp'+(n.test_out_mbps>=10?' g':'')+'">'+n.test_out_mbps.toFixed(2)+' Mbps</span></td>';
      else if(n.test_out_at&&n.test_out_error) h+='<td><span style="color:#ef4444;font-size:10px" title="'+esc(n.test_out_error)+'">失败</span></td>';
      else h+='<td><span style="color:#4b5563">未测</span></td>';
      h+='<td>'+(n.first_seen?'<span style="color:'+(n.is_new?'#22c55e':'#6b7280')+'" title="'+new Date(n.first_seen*1000).toLocaleString()+'">'+fmtAge(n.new_age_s)+'</span>':'-')+'</td>';
      h+='<td class="act-cell">';
      if(n.available) h+='<button class="btn" onclick="openSwitch(\''+n.id+'\',\''+n.ip+':'+n.port+'\',\''+(n.country_long||'')+'\')">切换</button>';
      else h+='<button class="btn" disabled>切换</button>';
      h+='</td></tr>';
    }
    tb.innerHTML=h;
    var extra='';
    if(d.nodes.length) extra=' · 新 '+d.nodes.filter(function(x){return x.is_new}).length;
    document.getElementById('rc').textContent='共 '+d.total+' 个节点 (显示 '+d.nodes.length+')'+extra;
  }catch(e){}
}

async function doPost(url){
  try{ var r=await fetch(url,{method:'POST'}); var d=await r.json(); return d; }catch(e){ return {ok:false,error:String(e)} }
}
async function nodePing(){
  var ids=checkedIds();
  var q=ids.length?('?ids='+encodeURIComponent(ids.join(','))):'';
  var d=await doPost('/api/nodes/ping'+q);
  if(!d.ok) alert(d.error||'启动失败'); else document.getElementById('job').style.display='';
}
async function nodeSpeed(){
  var ids=checkedIds();
  var q=ids.length?('?ids='+encodeURIComponent(ids.join(','))):'';
  var tip=ids.length?('将占用一条空闲通道，依次为勾选的 '+ids.length+' 个节点实测带宽，'
                     +'每个约 15~30 秒，期间该通道不可用。'):
                    '未勾选任何节点，将实测「新节点」（最多 20 个）。将占用一条空闲通道，'
                     +'每个节点约 15~30 秒，期间该通道不可用。';
  if(!confirm(tip+'\n\n继续？')) return;
  var d=await doPost('/api/nodes/speedtest'+q);
  if(!d.ok) alert(d.error||'启动失败'); else document.getElementById('job').style.display='';
}
async function stopSpeed(){
  var d=await doPost('/api/nodes/speedtest_stop');
  if(!d.ok) alert(d.error||'停止失败');
}
async function clearNew(){
  var d=await doPost('/api/nodes/clear_new');
  if(d.ok){ refreshNodes(); } else alert(d.error||'失败');
}
async function chSpeed(i){
  var d=await doPost('/api/channel/'+i+'/speedtest');
  if(!d.ok) alert(d.error||'启动失败');
}
async function chSpeedAll(){
  var d=await doPost('/api/channels/speedtest');
  if(!d.ok) alert(d.error||'启动失败');
}
function updateJobs(d){
  var job=document.getElementById('job');
  var txt=document.getElementById('job_txt');
  var bar=document.getElementById('job_bar');
  var btnStop=document.getElementById('btnStop');
  var btnSpeed=document.getElementById('btnSpeed');
  var btnPing=document.getElementById('btnPing');
  if(!job) return;
  var pt=d.ping_task||{}, st=d.speed_task||{};
  var running=!!(pt.running||st.running);
  var lines=[], pct=0;
  if(pt.running){
    pct=pt.total?(pt.done/pt.total*100):0;
    lines.push('延迟测试 '+pt.done+'/'+pt.total+'（通 '+pt.ok+' · 不通 '+pt.fail+'）');
  }
  if(st.running){
    pct=st.total?(st.done/st.total*100):0;
    lines.push('带宽测速 '+st.done+'/'+st.total+(st.current_ip?(' · 当前 '+st.current_ip):''));
  }
  btnStop.style.display=st.running?'':'none';
  btnSpeed.disabled=running; btnPing.disabled=running;
  if(running){
    _wasRunning=true;
    job.style.display=''; txt.textContent=lines.join('    |    '); bar.style.width=pct+'%';
  }else if(_wasRunning){
    _wasRunning=false;
    job.style.display=''; txt.textContent='任务已完成，正在刷新结果...'; bar.style.width='100%';
    setTimeout(function(){ if(!_wasRunning){ job.style.display='none'; bar.style.width='0'; } },4000);
    refreshNodes();
  }else{
    job.style.display='none';
  }
}
async function loadCountries(){
  try{
    var r=await fetch('/api/status'); var d=await r.json();
    var sel=document.getElementById('f_country');
    if(d.countries) for(var i=0;i<d.countries.length;i++){var o=document.createElement('option');o.value=d.countries[i];o.textContent=d.countries[i];sel.appendChild(o)}
  }catch(e){}
}
['f_status','f_country','f_type','f_sort'].forEach(function(id){
  var el=document.getElementById(id);
  if(el) el.addEventListener('change',refreshNodes);
});
loadCountries(); refreshNodes();
</script>

<div class="modal" id="adminModal"><div class="modal-c">
  <h3>修改管理账号 / 密码</h3>
  <div class="fg" style="margin-bottom:12px"><label>当前账号</label><input type="text" id="a_user" autocomplete="username" style="width:100%;padding:8px;background:#0f0f13;border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#e0e0e0;font-size:13px;outline:none"></div>
  <div class="fg" style="margin-bottom:12px"><label>当前密码</label><input type="password" id="a_pass" autocomplete="current-password" style="width:100%;padding:8px;background:#0f0f13;border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#e0e0e0;font-size:13px;outline:none"></div>
  <div style="height:1px;background:rgba(255,255,255,0.08);margin:14px 0"></div>
  <div class="fg" style="margin-bottom:12px"><label>新账号 <span style="color:#6b7280">（留空则不修改）</span></label><input type="text" id="a_newuser" autocomplete="off" placeholder="3~32 位，字母/数字/_.-" style="width:100%;padding:8px;background:#0f0f13;border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#e0e0e0;font-size:13px;outline:none"></div>
  <div class="fg" style="margin-bottom:12px"><label>新密码 <span style="color:#6b7280">（留空则只改账号）</span></label><input type="password" id="a_newpass" autocomplete="new-password" placeholder="至少 8 位" style="width:100%;padding:8px;background:#0f0f13;border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#e0e0e0;font-size:13px;outline:none"></div>
  <div class="fg" style="margin-bottom:12px"><label>确认新密码</label><input type="password" id="a_newpass2" autocomplete="new-password" style="width:100%;padding:8px;background:#0f0f13;border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#e0e0e0;font-size:13px;outline:none"></div>
  <div style="color:#6b7280;font-size:11px;line-height:1.6">修改成功后所有登录状态会立即失效，需要用新账号密码重新登录；守护脚本使用独立令牌，不受影响。</div>
  <div class="btns" style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px">
    <button class="btn" id="a_submit" onclick="changePwd()">确认修改</button>
    <button class="btn" style="background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.1);color:#e0e0e0" onclick="logout()">退出登录</button>
    <button class="btn d" onclick="document.getElementById('adminModal').classList.remove('show')">取消</button>
  </div>
  <div id="a_msg" style="color:#22c55e;font-size:12px;margin-top:8px;display:none"></div>
</div></div>

<div class="modal" id="assignModal"><div class="modal-c" style="max-width:760px">
  <h3>给通道分配出口</h3>
  <div style="color:#6b7280;font-size:11px;line-height:1.7;margin-bottom:12px">
    VPNGate 是志愿者网络，在线节点覆盖的国家/地区常常凑不满 9 个。三种方式都保证
    <span style="color:#22c55e">出口 IP 互不重复</span>；应用后会按序错峰重连。
  </div>
  <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:10px;font-size:12px">
    <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
      <input type="radio" name="as_mode" value="country" checked onchange="asModeUI();previewAssign()">
      尽量分到不同国家/地区<span style="color:#6b7280">（国家不够时，在节点较多的国家上多开通道）</span>
    </label>
    <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
      <input type="radio" name="as_mode" value="same" onchange="asModeUI();previewAssign()">
      全部通道用同一个国家/地区<span style="color:#6b7280">（只要该国 IP 够摊开，9 条出口互不相同）</span>
    </label>
    <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
      <input type="radio" name="as_mode" value="ip" onchange="asModeUI();previewAssign()">
      不限国家，只保证出口 IP 互不重复
    </label>
  </div>
  <div id="as_ctry_row" style="display:none;flex-direction:column;gap:6px;margin-bottom:10px">
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <span style="font-size:12px;color:#9ca3af">固定国家/地区</span>
      <select id="as_ctry" onchange="previewAssign()" style="min-width:230px;padding:6px 8px;background:#0f0f13;border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#e0e0e0;font-size:12px;outline:none"></select>
      <span id="as_ctry_hint" style="font-size:11px;color:#6b7280"></span>
    </div>
    <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:11px;color:#9ca3af">
      <input type="checkbox" id="as_fill" onchange="previewAssign()">
      该国节点不够时，用其它国家/地区补满剩余通道（出口 IP 仍不重复）
    </label>
  </div>
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px">
    <span style="font-size:12px;color:#9ca3af">出口 IP 类型</span>
    <select id="as_ipt" onchange="previewAssign()" style="padding:6px 8px;background:#0f0f13;border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#e0e0e0;font-size:12px;outline:none">
      <option value="">不限</option><option value="residential">住宅</option><option value="hosting">机房</option><option value="mobile">移动</option>
    </select>
    <span style="font-size:12px;color:#9ca3af">分配通道数</span>
    <select id="as_count" onchange="previewAssign()" style="padding:6px 8px;background:#0f0f13;border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#e0e0e0;font-size:12px;outline:none">
      <option value="">全部</option><option value="4">前 4 条</option><option value="6">前 6 条</option>
    </select>
    <button class="btn" style="background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.1);color:#e0e0e0" onclick="previewAssign()">重新规划</button>
  </div>
  <div id="as_body" style="max-height:42vh;overflow:auto"></div>
  <div class="btns" style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px">
    <button class="btn" id="as_apply" onclick="applyAssign()">应用并连接</button>
    <button class="btn d" onclick="document.getElementById('assignModal').classList.remove('show')">取消</button>
  </div>
  <div id="as_msg" style="font-size:12px;margin-top:8px;display:none"></div>
</div></div>

<script>
var _assignPlan=null;
function needCount(){   // 本次要分配到几条通道
  var v=document.getElementById('as_count').value;
  if(v)return parseInt(v,10);
  return (CH&&CH.length)?CH.length:9;
}
function freeOf(co){    // 该国还剩几个没被占用的节点
  var st=_CS[co];return st?Math.max(0,(st.total||0)-(st.used||0)):0;
}
function fillCtryOptions(){   // 用 /api/status 的国家供给填"固定国家"下拉，够用的排前面
  var sel=document.getElementById('as_ctry');if(!sel)return;
  var cur=sel.value;
  var arr=(_CTRY||[]).slice();
  arr.sort(function(a,b){return freeOf(b)-freeOf(a)});
  var h='';
  for(var i=0;i<arr.length;i++){
    var co=arr[i],st=_CS[co]||null;
    h+='<option value="'+esc(co)+'">'+esc(co)+(st?(' · 可用 '+freeOf(co)+'/'+st.total):'')+'</option>';
  }
  sel.innerHTML=h;
  if(cur&&arr.indexOf(cur)>=0)sel.value=cur;   // 保留用户已选
  else if(arr.length)sel.value=arr[0];         // 否则默认选可用最多的那个（别依赖浏览器隐式选中）
}
function asCtryHint(){
  var sel=document.getElementById('as_ctry'),el=document.getElementById('as_ctry_hint');
  if(!sel||!el)return;
  var co=sel.value,st=_CS[co],need=needCount();
  if(!co||!st){el.textContent='';return}
  var fr=freeOf(co);
  el.innerHTML='可用 <b style="color:'+(fr>=need?'#22c55e':'#f59e0b')+'">'+fr+'</b> 个，本次需要 '+need+' 条';
}
function asModeUI(){
  var m=asMode();
  document.getElementById('as_ctry_row').style.display=(m==='same')?'flex':'none';
  if(m==='same'){fillCtryOptions();asCtryHint();}
}
function showAssign(){
  document.getElementById('assignModal').classList.add('show');
  var m=document.getElementById('as_msg');m.style.display='none';
  var start=function(){asModeUI();previewAssign()};
  if(_CTRY&&_CTRY.length){start();return}
  fetch('/api/status').then(function(r){return r.ok?r.json():null}).then(function(d){
    if(d&&d.country_stats){_CS=d.country_stats;_CTRY=d.countries||[]}
    start();
  }).catch(function(){start()});
}
function asMode(){
  var r=document.querySelector('input[name="as_mode"]:checked');
  return r?r.value:'country';
}
function asQ(){
  var same=asMode()==='same';
  var cs=document.getElementById('as_ctry');
  var fl=document.getElementById('as_fill');
  return 'mode='+asMode()+'&ip_type='+encodeURIComponent(document.getElementById('as_ipt').value)
       +'&count='+encodeURIComponent(document.getElementById('as_count').value)
       +'&country='+encodeURIComponent(same&&cs?cs.value:'')
       +'&fill='+((same&&fl&&fl.checked)?'1':'0');
}
function asMsgA(t,ok){
  var m=document.getElementById('as_msg');m.style.display='block';
  m.style.color=ok?'#22c55e':'#ef4444';m.textContent=t;
}
async function previewAssign(){
  var body=document.getElementById('as_body');
  if(asMode()==='same'){fillCtryOptions();asCtryHint();}
  body.innerHTML='<div style="color:#6b7280;font-size:12px">正在规划...</div>';
  try{
    var r=await fetch('/api/channels/auto_assign?dry_run=1&'+asQ(),{method:'POST'});
    if(r.status===401){location.href='/';return}
    var d=await r.json();
    if(!d.ok||!d.plan||!d.plan.length){
      body.innerHTML='<div style="color:#ef4444;font-size:12px">'+esc(d.error||'规划失败')+'</div>';return;
    }
    _assignPlan=d.plan;
    var h='<table style="width:100%;border-collapse:collapse;font-size:12px">';
    h+='<thead><tr style="color:#6b7280;text-align:left"><th style="padding:6px 4px">通道</th><th>国家/地区</th><th>出口 IP</th><th>运营主体</th><th>该国节点</th></tr></thead><tbody>';
    var cnt={};
    for(var i=0;i<d.plan.length;i++){
      var p=d.plan[i];cnt[p.country]=(cnt[p.country]||0)+1;
      h+='<tr style="border-top:1px solid rgba(255,255,255,0.06)"><td style="padding:6px 4px">CH'+p.index+'</td><td>'+esc(p.country)+'</td><td>'+esc(p.ip)+'</td><td>'+esc(p.owner||'-')+'</td><td>'+p.country_total+'</td></tr>';
    }
    h+='</tbody></table>';
    var nC=Object.keys(cnt).length,shared=0;
    for(var k in cnt)if(cnt[k]>1)shared++;
    h+='<div style="margin-top:10px;font-size:11px;color:#6b7280">共 '+d.plan.length+' 条通道，覆盖 '+nC+' 个国家/地区，出口 IP 互不重复'+(shared?('（其中 '+shared+' 个国家被多条通道共用）'):'')+'。</div>';
    if(d.note){
      h+='<div style="margin-top:8px;padding:8px 10px;border-radius:8px;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.25);color:#22c55e;font-size:11px;line-height:1.7">'+esc(d.note)+'</div>';
    }
    var lack=needCount()-d.plan.length;
    if(lack>0){
      h+='<div style="margin-top:8px;padding:8px 10px;border-radius:8px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.25);color:#ef4444;font-size:11px;line-height:1.7">还有 '+lack+' 条通道没有可分配的出口，应用后这些通道会保持原样。勾上"用其它国家补满"或改选「不限国家」就能填满。</div>';
    }
    if(d.warnings&&d.warnings.length){
      var ws='';for(var j=0;j<d.warnings.length;j++)ws+='· '+esc(d.warnings[j])+'<br>';
      h+='<div style="margin-top:10px;padding:8px 10px;border-radius:8px;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.25);color:#f59e0b;font-size:11px;line-height:1.75">'+ws+'</div>';
    }
    body.innerHTML=h;
  }catch(e){body.innerHTML='<div style="color:#ef4444;font-size:12px">规划失败: '+esc(e)+'</div>';}
}
async function applyAssign(){
  if(!_assignPlan||!_assignPlan.length){asMsgA('请先规划',false);return}
  var btn=document.getElementById('as_apply');btn.disabled=true;btn.textContent='下发中...';
  var plan=_assignPlan.map(function(p){return p.index+':'+p.node_id}).join(',');
  try{
    var r=await fetch('/api/channels/auto_assign?'+asQ()+'&plan='+encodeURIComponent(plan),{method:'POST'});
    var d=await r.json();
    if(d.ok){
      asMsgA('已下发 '+(d.applied||[]).length+' 条通道，正在按序建立隧道（每条间隔 3 秒）...',true);
      setTimeout(function(){document.getElementById('assignModal').classList.remove('show');rf()},2500);
    }else{asMsgA(d.error||'下发失败',false)}
  }catch(e){asMsgA('下发失败: '+e,false)}
  btn.disabled=false;btn.textContent='应用并连接';
}
function showAdmin(){
  document.getElementById("adminModal").classList.add("show");
  var m=document.getElementById("a_msg");m.style.display="none";
  document.getElementById("a_pass").value="";
  document.getElementById("a_newpass").value="";
  document.getElementById("a_newpass2").value="";
  document.getElementById("a_newuser").value="";
  document.getElementById("a_user").value=CUR_USER||"";
}
function aMsg(t,ok){
  var m=document.getElementById("a_msg");m.style.display="block";
  m.style.color=ok?"#22c55e":"#ef4444";m.textContent=t;
}
async function changePwd(){
  var u=document.getElementById("a_user").value.trim();
  var p=document.getElementById("a_pass").value;
  var nu=document.getElementById("a_newuser").value.trim();
  var n=document.getElementById("a_newpass").value;
  var n2=document.getElementById("a_newpass2").value;
  if(!u||!p){aMsg("请先填写当前账号和当前密码",false);return}
  if(!nu&&!n){aMsg("新账号和新密码至少填写一项",false);return}
  if(nu&&!/^[A-Za-z0-9_.-]{3,32}$/.test(nu)){aMsg("新账号需 3~32 位，只能含字母/数字/_.-",false);return}
  if(n&&n.length<8){aMsg("新密码至少 8 位",false);return}
  if(n&&n2&&n!==n2){aMsg("两次输入的新密码不一致",false);return}
  if(n&&n===p){aMsg("新密码不能与当前密码相同",false);return}
  var btn=document.getElementById("a_submit");btn.disabled=true;btn.textContent="提交中...";
  try{
    var r=await fetch("/api/admin/credentials",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({username:u,password:p,new_username:nu,new_password:n,confirm_password:n2})});
    var d=await r.json();
    if(d.ok){
      aMsg("修改成功！请使用新账号密码重新登录",true);
      setTimeout(function(){location.href="/";},1800);
    }else{aMsg(d.error||"修改失败",false)}
  }catch(e){aMsg("请求失败: "+e,false)}
  btn.disabled=false;btn.textContent="确认修改";
}
async function logout(){
  try{await fetch("/api/logout",{method:"POST"})}catch(e){}
  location.href="/";
}
</script>
</body>
</html>"""

# === Web Server ===
class Handler(BaseHTTPRequestHandler):
    def send_json(self, data: Any, status: int = HTTPStatus.OK):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def log_message(self, fmt, *args): pass

    def read_params(self) -> dict:
        """读取请求体，兼容 form-urlencoded 与 JSON。"""
        try:
            length = int(self.headers.get("Content-Length", 0))
        except Exception:
            length = 0
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        if "application/json" in (self.headers.get("Content-Type") or "").lower():
            try:
                d = json.loads(raw or "{}")
                return {k: [str(v)] for k, v in d.items()} if isinstance(d, dict) else {}
            except Exception:
                return {}
        return urllib.parse.parse_qs(raw)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if not check_auth_token(self.headers):
            # API 路径统一返回 401 JSON，别把 HTML 登录页丢给调用方(会破坏 JSON 解析)
            if path.startswith("/api/"):
                self.send_json({"ok":False,"error":"unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            global LOGIN_HTML_CACHE
            if not LOGIN_HTML_CACHE:
                try:
                    LOGIN_HTML_CACHE = open(str(DATA_DIR / "login.html")).read()
                except:
                    LOGIN_HTML_CACHE = "<html><body><h2>Login page not found</h2></body></html>"
            err = params.get("error", [""])[0]
            if err == "locked":
                err_text = "失败次数过多，请稍后再试"
            elif err == "changed":
                err_text = "账号或密码已修改，请重新登录"
            else:
                err_text = "账号或密码错误"
            body = LOGIN_HTML_CACHE.replace("${error_display}", "block" if err else "none")\
                                   .replace("${error_text}", err_text).encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length",str(len(body)))
            self.end_headers(); self.wfile.write(body)
            return

        if path in ("/","/index.html"):
            html = PAGE_HTML.replace("{channels_json}",json.dumps([c.to_dict() for c in channels]))
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length",str(len(html.encode())))
            self.end_headers(); self.wfile.write(html.encode())
        elif path == "/api/status":
            now_ts = time.time()
            with nodes_cache_lock:
                countries = sorted(set(n.get("country_long","") for n in nodes_cache if n.get("country_long")))
                node_count = len(nodes_cache)
                new_node_count = sum(1 for n in nodes_cache if is_new_by_ttl(n.get("first_seen", 0), now_ts))
                newest_at = max([n.get("first_seen", 0) for n in nodes_cache] or [0])
                tested_count = sum(1 for n in nodes_cache if n.get("test_out_at"))
                latency_count = sum(1 for n in nodes_cache if n.get("tcp_latency"))
            chs = [c.to_dict() for c in channels]
            # 标记出口 IP 撞车的通道：多出口场景下重复 IP 等于白开一条通道
            seen_out: dict[str, list[int]] = {}
            for c in chs:
                ip = c.get("node_ip") or c.get("reserved_ip")
                if ip: seen_out.setdefault(ip, []).append(c["index"])
            for c in chs:
                ip = c.get("node_ip") or c.get("reserved_ip")
                c["ip_dup_with"] = [i for i in seen_out.get(ip, []) if i != c["index"]] if ip else []
            with TASK_LOCK:
                ping_task = dict(PING_TASK)
                speed_task = dict(SPEED_TASK)
            speed_task.pop("results", None)   # 明细单独走 /api/nodes/speedtest
            self.send_json({"channels":chs,"countries":countries,
                            "country_stats":country_supply(),
                            "outlets":occupied_map(),
                            "node_count":node_count,"username":load_auth_config().get("username","admin"),
                            "default_credentials":is_default_credentials(),
                            "new_node_count":new_node_count,
                            "newest_node_at":newest_at,
                            "new_node_ttl":NEW_NODE_TTL,
                            "tested_count":tested_count,
                            "latency_count":latency_count,
                            "ping_task":ping_task,
                            "speed_task":speed_task,
                            "nodes_source":_last_fetch_source,
                            "nodes_snapshot_at":_snapshot_saved_at,
                            "policy_table_base":POLICY_TABLE_BASE})
        elif path == "/api/nodes":
            filter_type = params.get("filter",[""])[0]
            country = params.get("country",[""])[0]
            ip_type = params.get("ip_type",[""])[0]
            sort_by = params.get("sort",[""])[0]
            now_ts = time.time()
            with nodes_cache_lock:
                nodes = list(nodes_cache)
            result = []
            for n in nodes:
                ip = n.get("ip","")
                port = n.get("port","443")
                available = n.get("ping",999) > 0 and n.get("ping",999) < 999  # rough availability
                # Actually check: the node has config_text means it has a config
                available = bool(n.get("config_text"))
                n_country = n.get("country_long","")
                n_ip_type = n.get("ip_type","")
                first_seen = float(n.get("first_seen") or 0)
                is_new = is_new_by_ttl(first_seen, now_ts)
                if country and country.lower() not in n_country.lower(): continue
                if ip_type and n_ip_type != ip_type: continue
                if filter_type == "available" and not available: continue
                if filter_type == "failed" and available: continue
                if filter_type == "new" and not is_new: continue
                if filter_type == "tested" and not n.get("test_out_at"): continue
                if filter_type == "untested" and n.get("test_out_at"): continue
                result.append({
                    "id": n.get("id",""), "ip": ip, "port": port,
                    "country_long": n_country, "available": available,
                    "location": n.get("location",""), "owner": n.get("owner",""),
                    "ip_type": n_ip_type, "asn": n.get("asn",""),
                    "ip_reason": n.get("ip_reason",""),
                    "is_vpn_exit": n.get("is_vpn_exit", False),
                    "is_new": is_new,
                    "first_seen": first_seen,
                    "new_age_s": int(max(0, now_ts - first_seen)) if first_seen else 0,
                    "ping": n.get("ping", 0) or 0,            # VPNGate 官方延迟(来自日本节点)
                    "speed": n.get("speed", 0) or 0,          # VPNGate 官方带宽(bps，上线时测的)
                    "tcp_latency": n.get("tcp_latency", 0) or 0,   # 本机实测 TCP 延迟
                    "tcp_latency_at": n.get("tcp_latency_at", 0) or 0,
                    "test_out_mbps": n.get("test_out_mbps", 0) or 0,
                    "test_out_at": n.get("test_out_at", 0) or 0,
                    "test_out_error": n.get("test_out_error", "") or "",
                })
            if sort_by == "new":
                result.sort(key=lambda x: x["first_seen"], reverse=True)
            elif sort_by == "latency":
                # 没测到的排最后，别让 0 混在"最快"里
                result.sort(key=lambda x: (x["tcp_latency"] if x["tcp_latency"] > 0 else 10 ** 9))
            elif sort_by == "mbps":
                result.sort(key=lambda x: x["test_out_mbps"] if x["test_out_at"] else -1,
                            reverse=True)
            elif sort_by == "official":
                result.sort(key=lambda x: x["speed"], reverse=True)
            # 与节点池上限(300)对齐，避免"看不见的节点却被自动选中"
            self.send_json({"nodes":result[:300], "total":len(result)})
        elif path == "/api/nodes/speedtest":
            # 批量真实测速的完整明细（含每个节点的成功/失败原因）
            with TASK_LOCK:
                task = dict(SPEED_TASK)
            self.send_json(task)
        elif path == "/api/nodes/ping":
            with TASK_LOCK:
                task = dict(PING_TASK)
            self.send_json(task)
        else:
            self.send_json({"error":"not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # 除登录/登出接口外，所有写操作必须已登录。
        # 原来 do_POST 完全没有鉴权，任何人从公网都能调 connect/disconnect/toggle，
        # 等于把 9 条通道的控制权敞开。
        if path not in ("/api/login", "/api/logout") and not check_auth_token(self.headers):
            self.send_json({"ok": False, "error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        # Logout
        if path == "/api/logout":
            cookie = self.headers.get("Cookie","") or ""
            for part in cookie.split(";"):
                part = part.strip()
                if part.startswith("token="):
                    auth_token_store.pop(part[6:], None)
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Set-Cookie", "token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
            self.send_header("Location", "/")
            self.end_headers()
            return

        # Login POST endpoint
        if path == "/api/login":
            ip = self.client_address[0]
            locked = is_login_locked(ip)
            if locked:
                log(f"[auth] 登录被限速 from {ip} ({locked}s)")
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/?error=locked")
                self.end_headers()
                return
            try:
                p = self.read_params()
                user = (p.get("username", [""])[0] or "").strip()
                pwd = (p.get("password", [""])[0] or "").strip()
                if verify_credentials(user, pwd):
                    clear_login_failures(ip)
                    tok = generate_token()
                    self.send_response(HTTPStatus.FOUND)
                    self.send_header("Set-Cookie", f"token={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400")
                    self.send_header("Location", "/")
                    self.end_headers()
                else:
                    record_login_failure(ip)
                    log(f"[auth] 登录失败 user={user!r} from {ip}")
                    self.send_response(HTTPStatus.FOUND)
                    self.send_header("Location", "/?error=1")
                    self.end_headers()
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, HTTPStatus.BAD_REQUEST)
            return

        if re.match(r"^/api/channel/\d+/toggle$", path):
            m2 = re.match(r"/api/channel/(\d+)/toggle", path)
            if m2:
                idx2 = int(m2.group(1))
                if idx2 < 0 or idx2 >= NUM_CHANNELS:
                    self.send_json({"error": "out of range"}, HTTPStatus.BAD_REQUEST)
                    return
                en = params.get("enabled",["0"])[0] == "1"
                channels[idx2].enabled = en
                save_channels()
                self.send_json({"ok":True, "enabled": en})
                return

        if path == "/api/fetch_nodes":
            res = manual_fetch()
            self.send_json({"ok": True, "new": res["new"], "dup": res["dup"],
                            "total": res["total"], "baseline": res["baseline"],
                            "new_ids": res["new_ids"], "source": res.get("source", "")})
            return

        # --- 清空"新"标记（首现历史保留，只挪水位线）---
        if path == "/api/nodes/clear_new":
            with nodes_cache_lock:
                cnt = sum(1 for n in nodes_cache if is_new_by_ttl(n.get("first_seen", 0)))
            clear_new_marks()
            self.send_json({"ok": True, "cleared": cnt})
            return

        # --- 延迟测试：对节点 IP:端口做 TCP 握手 RTT，并发跑，零流量 ---
        if path == "/api/nodes/ping":
            ids_q = (params.get("ids", [""])[0] or "").strip()
            ids = [x.strip() for x in ids_q.split(",") if x.strip()] if ids_q else None
            res = start_ping_task(ids)
            self.send_json(res, HTTPStatus.OK if res.get("ok") else HTTPStatus.CONFLICT)
            return

        # --- 真实带宽测速：借一条空闲通道逐个建隧道实测 ---
        if path == "/api/nodes/speedtest":
            ids_q = (params.get("ids", [""])[0] or "").strip()
            ids = [x.strip() for x in ids_q.split(",") if x.strip()] if ids_q else None
            limit_q = (params.get("limit", [""])[0] or "").strip()
            limit = int(limit_q) if limit_q.isdigit() else None
            res = start_node_speed_task(ids, limit)
            self.send_json(res, HTTPStatus.OK if res.get("ok") else HTTPStatus.CONFLICT)
            return

        if path == "/api/nodes/speedtest_stop":
            res = stop_node_speed_task()
            self.send_json(res, HTTPStatus.OK if res.get("ok") else HTTPStatus.CONFLICT)
            return

        # --- 通道测速：直接走该通道自己的 SOCKS 口，不影响其它通道 ---
        if path == "/api/channels/speedtest":
            res = start_all_channel_speedtest()
            self.send_json(res, HTTPStatus.OK if res.get("ok") else HTTPStatus.CONFLICT)
            return

        m_speed = re.match(r"^/api/channel/(\d+)/speedtest$", path)
        if m_speed:
            i_speed = int(m_speed.group(1))
            if i_speed < 0 or i_speed >= NUM_CHANNELS:
                self.send_json({"ok": False, "error": "out of range"}, HTTPStatus.BAD_REQUEST)
                return
            res = start_channel_speedtest(channels[i_speed])
            self.send_json(res, HTTPStatus.OK if res.get("ok") else HTTPStatus.CONFLICT)
            return

        # 修改管理账号 / 密码（旧路径 /api/admin/change_password 保留兼容）
        if path in ("/api/admin/credentials", "/api/admin/change_password"):
            ip = self.client_address[0]
            try:
                p = self.read_params()
                legacy = path.endswith("change_password")
                user = (p.get("username", [""])[0] or "").strip()
                pwd = (p.get("password", [""])[0] or "").strip()
                new_user = (p.get("new_username", [""])[0] or "").strip()
                new_pwd = (p.get("new_password", [""])[0] or "").strip()
                confirm = (p.get("confirm_password", [""])[0] or "").strip()

                locked = is_login_locked(ip)
                if locked:
                    self.send_json({"ok": False, "error": f"尝试次数过多，请 {locked} 秒后再试"},
                                   HTTPStatus.TOO_MANY_REQUESTS)
                    return
                if not verify_credentials(user, pwd):
                    record_login_failure(ip)
                    log(f"[auth] 修改凭据: 当前账号密码校验失败 user={user!r} from {ip}")
                    self.send_json({"ok": False, "error": "当前账号或密码错误"}, HTTPStatus.UNAUTHORIZED)
                    return
                if legacy and not new_pwd:
                    self.send_json({"ok": False, "error": "密码至少 8 位"}, HTTPStatus.BAD_REQUEST)
                    return
                if not new_user and not new_pwd:
                    self.send_json({"ok": False, "error": "新账号和新密码至少填写一项"}, HTTPStatus.BAD_REQUEST)
                    return

                cfg = load_auth_config()
                cur_user = str(cfg.get("username", "admin"))
                final_user = new_user or cur_user
                if new_user:
                    err = validate_username(new_user)
                    if err:
                        self.send_json({"ok": False, "error": err}, HTTPStatus.BAD_REQUEST)
                        return
                if new_pwd:
                    if confirm and confirm != new_pwd:
                        self.send_json({"ok": False, "error": "两次输入的新密码不一致"}, HTTPStatus.BAD_REQUEST)
                        return
                    err = validate_password(new_pwd, final_user)
                    if err:
                        self.send_json({"ok": False, "error": err}, HTTPStatus.BAD_REQUEST)
                        return
                    if hmac.compare_digest(new_pwd, pwd):
                        self.send_json({"ok": False, "error": "新密码不能与当前密码相同"}, HTTPStatus.BAD_REQUEST)
                        return
                    final_pwd = new_pwd
                else:
                    # 只改账号：沿用当前密码重新哈希落盘
                    final_pwd = pwd
                    if final_user == cur_user:
                        self.send_json({"ok": False, "error": "新账号与当前账号相同"}, HTTPStatus.BAD_REQUEST)
                        return

                clear_login_failures(ip)
                save_auth_config(final_user, final_pwd)
                invalidate_all_sessions()   # 所有已登录会话立即失效，强制重新登录
                log(f"[auth] 管理凭据已更新: 账号 {cur_user} -> {final_user}"
                    + ("，密码已同步变更" if new_pwd else "") + f"，来源 {ip}")
                self.send_json({"ok": True, "username": final_user, "password_changed": bool(new_pwd),
                                "message": "修改成功，请使用新账号密码重新登录"})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, HTTPStatus.BAD_REQUEST)
            return

        # 一键分配：为每条通道规划一个互不重复的出口
        #   mode=country 尽量每条通道一个国家(国家不够时在节点多的国家多开, IP 仍不重复)
        #   mode=same    所有通道固定 country 指定的同一个国家(只要求 9 个出口 IP 互不相同)
        #   mode=ip      不限国家, 只保证 9 个出口 IP 互不相同
        #   fill=1       mode=same 时该国节点不够则用其它国家补满剩余通道
        #   dry_run=1    只返回方案供确认, 不实际连线
        if path == "/api/channels/auto_assign":
            mode = (params.get("mode",["country"])[0] or "country").strip()
            ip_type = (params.get("ip_type",[""])[0] or "").strip()
            country = (params.get("country",[""])[0] or "").strip()
            fill = params.get("fill",["0"])[0] == "1"
            dry = params.get("dry_run",["0"])[0] == "1"
            scope = (params.get("count",[""])[0] or "").strip()
            plan_q = (params.get("plan",[""])[0] or "").strip()
            targets = channels
            if scope.isdigit():
                targets = channels[:max(1, min(NUM_CHANNELS, int(scope)))]
            res = None
            if not dry and plan_q:
                # 前端把预览过的方案带回来，避免"预览一套、应用另一套"
                items = []
                for pair in plan_q.split(","):
                    if ":" not in pair:
                        continue
                    a, b = pair.split(":", 1)
                    if not a.strip().isdigit() or not b.strip():
                        continue
                    node = get_node_by_id(b.strip())
                    if not node:
                        continue
                    items.append({"index":int(a.strip()), "node_id":b.strip(),
                                  "country":node.get("country_long",""),
                                  "ip":node.get("ip",""),
                                  "ip_type":node.get("ip_type","")})
                if items:
                    res = {"plan": items, "warnings": []}
            if res is None:
                res = build_assign_plan(targets, mode, ip_type, country, fill)
            if not res["plan"]:
                self.send_json({"ok":False, "error":"；".join(res["warnings"]) or "没有可用节点",
                                "warnings":res["warnings"]}, HTTPStatus.SERVICE_UNAVAILABLE)
                return
            if dry:
                self.send_json({"ok":True, "dry_run":True, "plan":res["plan"],
                                "warnings":res["warnings"], "note":res.get("note",""),
                                "countries":res["countries"]})
                return
            applied, failed = [], []
            for i, item in enumerate(res["plan"]):
                ch = channels[item["index"]]
                node = get_node_by_id(item["node_id"]) or get_best_node_for_country(
                    item["country"], item["ip_type"], exclude_ch=ch)
                if not node:
                    failed.append({"index":item["index"], "country":item["country"],
                                   "error":"节点已失效且无备选"})
                    continue
                # 先断开原连接，否则错峰重连会看到 connected 直接跳过
                disconnect_channel(ch)
                ch.force_country = item["country"]
                ch.force_ip_type = ip_type          # 未指定类型则不限，重连时备选更多
                ch.reserved_ip = node.get("ip","")
                ch.enabled = True
                save_channels()
                threading.Thread(target=_delayed_connect, args=(ch, node, i * 3), daemon=True).start()
                applied.append({"index":item["index"], "country":item["country"],
                                "ip":node.get("ip",""), "owner":node.get("owner",""),
                                "ip_type":node.get("ip_type","")})
            log(f"[assign] mode={mode} 已下发 {len(applied)} 条通道的出口分配")
            self.send_json({"ok":True, "applied":applied, "failed":failed,
                            "warnings":res["warnings"]})
            return

        m = re.match(r"^/api/channel/(\d+)/(connect|disconnect)$", path)
        if not m: self.send_json({"error":"not found"}, HTTPStatus.NOT_FOUND); return
        idx = int(m.group(1)); action = m.group(2)
        if idx < 0 or idx >= NUM_CHANNELS: self.send_json({"error":"out of range"}, HTTPStatus.BAD_REQUEST); return
        ch = channels[idx]
        # 测速进行中不准动这条通道：拆隧道会让测速结果变成 0，看起来像节点有问题
        if ch.speed_testing:
            self.send_json({"ok": False, "error": f"CH{idx} 正在测速，请等它测完再操作"},
                           HTTPStatus.CONFLICT)
            return
        if action == "disconnect":
            disconnect_channel(ch)
            # 国家/IP 类型的设定保留：断开只是想停这条通道，不是想清掉它的固定出口配置
            save_channels()
            self.send_json({"ok":True,"channel":ch.to_dict()})
        else:
            node_id = params.get("node_id",[None])[0]
            country = params.get("country",[""])[0]
            ip_type = params.get("ip_type",[""])[0]
            if node_id:
                node = get_node_by_id(node_id)
                if not node: self.send_json({"error":"node not found"}, HTTPStatus.NOT_FOUND); return
                dup = occupied_ips(ch)
                if node.get("ip","") in dup:
                    self.send_json({"ok":False,"error":"该节点出口 IP 已被 CH%d 占用" % dup[node["ip"]]},
                                   HTTPStatus.CONFLICT)
                    return
                # Also set force_country so watchdog can auto-reconnect
                node_country = node.get("country_long","")
                if node_country: ch.force_country = node_country
                node_iptype = node.get("ip_type","")
                if node_iptype: ch.force_ip_type = node_iptype
                ch.reserved_ip = node.get("ip","")
                ch.enabled = True
                save_channels()
            else:
                node = get_best_node_for_country(country, ip_type, exclude_ch=ch)
                if not node: self.send_json({"error":"No nodes"}, HTTPStatus.SERVICE_UNAVAILABLE); return
                # 显式提交就生效：country 传空表示"自动选择"，即不限国家
                ch.force_country = country
                ch.force_ip_type = ip_type
                ch.enabled = True
                save_channels()
            ok = connect_channel(ch, node)
            self.send_json({"ok":ok,"channel":ch.to_dict()})

# === Main ===
def _delayed_connect(ch: Channel, node: dict, delay: float):
    """错峰重连：等待期间若别的路径已经把它连上了，就不要再抢同一个 tun。"""
    try:
        time.sleep(delay)
        with ch.lock:
            if ch.state == "connecting" or ch.state == "connected":
                return
        connect_channel(ch, node)
    except Exception as e:
        log(f"[WD CH{ch.index}] delayed connect error: {e}")


def channel_watchdog():
    """通道巡检：进程存活 + 隧道实测连通性，连续多轮不通才重连。"""
    while True:
        time.sleep(WATCHDOG_INTERVAL)
        for ch in channels:
            try:
                # 先取快照，探测动作不持锁，避免把面板操作卡住
                with ch.lock:
                    state = ch.state
                    proc = ch.process
                    tun = ch.tun
                    force_country = ch.force_country
                    enabled = ch.enabled
                    last_connect_at = ch.last_connect_at

                if state == "connecting":
                    continue

                if state == "connected":
                    proc_alive = True
                    try:
                        if proc is None or proc.poll() is not None:
                            proc_alive = False
                    except Exception:
                        proc_alive = False

                    if proc_alive and vpn_utils.probe_tunnel(tun, timeout=3):
                        ch.fail_streak = 0
                        continue

                    # 单次抖动不算死：连续 FAIL_TOLERANCE 轮探测不通才动手
                    ch.fail_streak = getattr(ch, "fail_streak", 0) + 1
                    reason = "进程退出" if not proc_alive else "隧道不通"
                    if ch.fail_streak < FAIL_TOLERANCE:
                        log(f"[WD CH{ch.index}] {reason} ({ch.fail_streak}/{FAIL_TOLERANCE})，继续观察")
                        continue
                    ch.fail_streak = 0
                    with ch.lock:
                        stop_process(ch.process)
                        ch.process = None
                        cleanup_policy_routing(policy_table(ch.index))
                        ch.state = "disconnected"
                        ch.last_node_data = None
                    log(f"[WD CH{ch.index}] {reason} 连续 {FAIL_TOLERANCE} 轮，准备重连")

                with ch.lock:
                    state = ch.state
                if state in ("disconnected", "error") and force_country and enabled:
                    if time.time() - last_connect_at < RECONNECT_COOLDOWN:
                        continue
                    # 优先连回同一个节点（出口 IP 不变）
                    node = None
                    last = ch.last_node_data
                    dup = occupied_ips(ch)
                    if last and last.get("config_text"):
                        if last.get("ip","") in dup:
                            log(f"[WD CH{ch.index}] 原节点 {last.get('ip','')} 已被 CH{dup[last['ip']]} 占用，改选新节点")
                        else:
                            node = last
                            ch.reserved_ip = last.get("ip","")
                            log(f"[WD CH{ch.index}] Retry same node {last.get('ip','')}")
                    if node is None:
                        node = get_best_node_for_country(force_country, ch.force_ip_type, exclude_ch=ch)
                    if node:
                        log(f"[WD CH{ch.index}] Reconnect {force_country} {ch.force_ip_type}")
                        delay = ch.index * 2  # 错峰，避免 9 条隧道同时抢带宽
                        threading.Thread(target=_delayed_connect, args=(ch, node, delay), daemon=True).start()
                    else:
                        log(f"[WD CH{ch.index}] No node for {force_country} {ch.force_ip_type}")
            except Exception as e:
                log(f"[WD CH{ch.index}] Error: {e}")

def main():
    log("=== MichaelVPN 9-Channel Manager + Node UI ===")
    global GUARD_TOKEN
    migrate_plaintext_credentials()
    GUARD_TOKEN = load_or_create_guard_token()
    load_seen_nodes()   # 必须在采集线程启动前恢复基准，否则重启会把整池节点当成新节点刷一遍
    if is_default_credentials():
        log("[auth] 提醒: 面板仍是默认账号 admin/admin，请登录后点右上角\"管理员\"修改")
    # 清理上次运行残留：只动**本程序启动的** openvpn。
    # 原实现是一句裸的 pkill -f openvpn，会把这台机器上别的 openvpn（另一个出口、
    # 或正在手工调试的隧道）一起干掉，而且不留痕迹。
    cleanup_stale_openvpn()
    for ch in channels:
        # tun 设备已经随进程消失，但上次写的 ip rule/route 会留在内核里继续劫持流量
        cleanup_policy_routing(policy_table(ch.index))
    port_problems = preflight_ports()
    for msg in port_problems.values():
        log(f"[init] 端口预检: {msg}")
    ch_cfg = read_json(CHANNELS_FILE)
    for ch in channels:
        c = ch_cfg.get(str(ch.index),{})
        ch.force_country = c.get("force_country","")
        ch.force_ip_type = c.get("force_ip_type","")
        ch.enabled = c.get("enabled", bool(ch.force_country))
    proxy_failures = start_all_proxies()
    if proxy_failures:
        log(f"[init] 警告: {len(proxy_failures)} 个通道的本地代理没起来，"
            f"这些通道即使隧道通了也无法通过代理访问（面板会标红）")
    threading.Thread(target=collector_loop, daemon=True).start()
    log("[init] Collector started")
    threading.Thread(target=channel_watchdog, daemon=True).start()
    log("[init] Watchdog started")
    time.sleep(2)
    # 首次采集（走统一入口，保证新节点标记与后续每轮口径一致）
    init_fetch = refresh_nodes_once("init")
    if not init_fetch.get("total"):
        log("[init] 警告: 首次节点采集为空（网络不通或节点源不可用），"
            "守护进程会在下一轮重试；也可在面板点\"获取节点\"")
    for ch in channels:
        if ch.force_country:
            node = get_best_node_for_country(ch.force_country, ch.force_ip_type, exclude_ch=ch)
            if node:
                threading.Thread(target=connect_channel, args=(ch,node), daemon=True).start()
                time.sleep(2)
    class DualStackServer(ThreadingHTTPServer):
        allow_reuse_address = True
    log(f"[UI] http://{UI_HOST}:{UI_PORT}/")
    try:
        server = DualStackServer((UI_HOST, UI_PORT), Handler); server.serve_forever()
    except Exception:
        server = DualStackServer(("0.0.0.0", UI_PORT), Handler); server.serve_forever()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--set-credentials", "--set-password"):
        # 忘记面板密码时的救援入口(需要服务器 root 权限):
        #   python3 vpngate9_multi.py --set-credentials 新账号 新密码
        #   只改密码: python3 vpngate9_multi.py --set-password 新密码
        args = sys.argv[2:]
        new_user = args[0].strip() if len(args) >= 2 else load_auth_config().get("username", "admin")
        new_pwd = (args[1] if len(args) >= 2 else (args[0] if args else "")).strip()
        err = validate_username(new_user) or validate_password(new_pwd, new_user)
        if err:
            print(f"参数不合法: {err}")
            sys.exit(1)
        save_auth_config(new_user, new_pwd)
        load_or_create_guard_token()
        print(f"已更新管理凭据: 账号 {new_user}")
        print("请重启面板生效: systemctl restart michaelvpn")
        sys.exit(0)
    main()

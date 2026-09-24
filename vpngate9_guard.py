#!/usr/bin/env python3
# vpngate9 通道守护脚本（稳定版）
# 功能:
#   1) 定时检查 9 个通道, 发现"假连接"(面板显示 connected 但 SOCKS5 实测拿不到出口IP)自动换节点
#   2) 可选: 定时主动轮换出口 IP (ROTATE_EVERY)
#   3) 每个通道沿用它在面板里设置的国家 / IP 类型; 面板没设置就交给服务端自动挑
#   4) 连续 N 轮拿不到流量才动手, 避免网络抖动误判
# 部署: cp vpngate9_guard.py /opt/michaelvpn/ && systemctl restart vpngate9-guard

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PANEL = os.environ.get("PANEL", "http://127.0.0.1:8787")
AUTH_FILE = os.environ.get("VPNGATE_UI_AUTH", "/opt/michaelvpn/vpngate_data/ui_auth.json")
GUARD_TOKEN_FILE = os.environ.get("VPNGATE_GUARD_TOKEN_FILE", "/opt/michaelvpn/vpngate_data/guard_token")
NUM_CHANNELS = 9
PROXY_BASE_PORT = 47928
CHECK_EVERY = 60            # 每 60 秒检查一轮
ROTATE_EVERY = 30           # 每 30 轮主动换节点切 IP (0=不主动切)
FAIL_TOLERANCE = 2          # 连续 N 轮 SOCKS 测不出流量才判定假连接
RECONNECT_COOLDOWN = 120    # 同一通道两次重连的最小间隔(秒), 防止反复抖动
SOCKS_TEST_URL = "http://api.ipify.org"
SOCKS_TEST_TIMEOUT = 8

# 通道已掉线(state != connected)时是否也由本脚本重连。
# 默认 False: 掉线由面板内置 watchdog(盯进程+隧道探测)负责, 本脚本只管
# "假连接"和定时轮换 —— 两条链路各管一段, 不会同时去抢同一个 tun。
# 如果面板 watchdog 被你关掉了, 把它改成 True。
HANDLE_DISCONNECTED = False

cookie = ""
_warned: set[str] = set()


def warn_once(msg: str) -> None:
    if msg not in _warned:
        _warned.add(msg)
        print("[warn] " + msg, flush=True)


def _load_guard_token() -> str:
    """面板生成的守护长效令牌。改面板账号密码不会让它失效，守护也就不怕改密。"""
    try:
        with open(GUARD_TOKEN_FILE, encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


def _load_credentials() -> tuple[str, str]:
    """兜底: 面板还没生成令牌时，用 ui_auth.json 里的明文(仅旧版有)或环境变量登录。"""
    env_user = os.environ.get("VPNGATE_USER", "")
    env_pass = os.environ.get("VPNGATE_PASS", "")
    try:
        with open(AUTH_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        return (env_user or cfg.get("username", "admin"),
                env_pass or str(cfg.get("password") or ""))
    except Exception:
        return env_user or "admin", env_pass


USER, PASS = _load_credentials()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # 登录返回 302, 不跟随, 直接从响应头取 token


def _parse_cookie(resp) -> None:
    global cookie
    for h, v in resp.getheaders():
        if h.lower() == "set-cookie":
            for part in v.split(";"):
                if part.strip().startswith("token="):
                    cookie = part.strip()


def login() -> None:
    global cookie, USER, PASS
    tok = _load_guard_token()
    if tok:
        cookie = "token=" + tok
        return
    # 每次都重读磁盘: 面板改账号/密码后能自动跟上, 也兼容令牌文件后生成的情况
    USER, PASS = _load_credentials()
    if not PASS:
        warn_once("未找到守护令牌 %s，且 %s 里没有可用的密码；"
                  "请确认新版面板已启动过（它会自动生成令牌），或用 VPNGATE_USER/VPNGATE_PASS 指定"
                  % (GUARD_TOKEN_FILE, AUTH_FILE))
        return
    data = urllib.parse.urlencode({"username": USER, "password": PASS}).encode()
    req = urllib.request.Request(PANEL + "/api/login", data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        opener = urllib.request.build_opener(NoRedirect)
        _parse_cookie(opener.open(req, timeout=10))
    except urllib.error.HTTPError as e:
        _parse_cookie(e)
    except Exception:
        pass
    if not cookie:
        warn_once("登录面板失败(账号或密码不对?): %s" % AUTH_FILE)


def api(path, data=None, method="GET"):
    global cookie
    if not cookie:
        login()
        if not cookie:
            return None
    headers = {"Cookie": cookie}
    if data is not None:
        data = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(PANEL + path, data=data, headers=headers, method=method)
    try:
        return json.loads(urllib.request.urlopen(req, timeout=20).read().decode())
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            cookie = ""   # token 失效, 下一轮重新登录
            warn_once("面板返回 %d: 守护令牌或账号密码无效; 若刚改过面板密码, "
                      "请确认 %s 存在且与面板 vpngate_data/guard_token 一致" % (e.code, GUARD_TOKEN_FILE))
        return None
    except Exception:
        return None


def test_socks(port: int):
    """实测 socks5 端口能不能拿到出口 IP, 返回 IP 或 None"""
    try:
        out = subprocess.run(
            ["curl", "-s", "--max-time", str(SOCKS_TEST_TIMEOUT),
             "-x", "socks5://127.0.0.1:%d" % port, SOCKS_TEST_URL],
            capture_output=True, text=True, timeout=SOCKS_TEST_TIMEOUT + 5)
        ip = (out.stdout or "").strip()
        if ip and "." in ip and " " not in ip and len(ip) <= 45:
            return ip
    except Exception:
        pass
    return None


def reconnect(idx: int, country: str, ip_type: str, node_id=None):
    """按通道自己的国家/IP类型重连; 不传国家时由服务端在节点池里随机挑。"""
    q = {"country": country or "", "ip_type": ip_type or ""}
    if node_id:
        q["node_id"] = node_id
    return api("/api/channel/%d/connect?%s" % (idx, urllib.parse.urlencode(q)), method="POST")


def main() -> None:
    global cookie   # 面板无响应时要真的把会话清掉(否则下一轮 api() 不会重新登录)
    tok_mode = bool(_load_guard_token())
    print("vpngate9 guard start: %d channels, every %ds, handle_disconnected=%s, auth=%s"
          % (NUM_CHANNELS, CHECK_EVERY, HANDLE_DISCONNECTED,
             "guard_token" if tok_mode else "account/password"), flush=True)
    if not tok_mode:
        warn_once("未使用守护令牌, 改用账号密码登录; 面板改密后需同步 %s, "
                  "或升级面板让它生成 %s" % (AUTH_FILE, GUARD_TOKEN_FILE))

    round_n = 0
    fail_streak: dict[int, int] = {}
    last_fix: dict[int, float] = {}

    while True:
        round_n += 1
        T = time.strftime("%H:%M:%S")
        st = api("/api/status")
        if not st:
            print("[%s] 面板无响应, 重新登录后重试" % T, flush=True)
            cookie = ""
            time.sleep(CHECK_EVERY)
            continue

        do_rotate = (ROTATE_EVERY > 0 and round_n % ROTATE_EVERY == 0)

        for ch in st.get("channels", []):
            # 关键修复: 先取出 idx 再做任何判断。
            # 原版在赋值之前就用 idx 打印日志, 遇到第一个被禁用的通道会直接
            # NameError 让守护进程崩掉(systemd 又不断重启, 等于守护失效)。
            idx = ch.get("index")
            if idx is None:
                continue
            if not ch.get("enabled", True):
                continue

            state = ch.get("state")
            port = PROXY_BASE_PORT + idx
            need = False
            reason = ""

            if state == "connected":
                ip = test_socks(port)
                if ip:
                    fail_streak[idx] = 0
                    print("[%s] CH%d OK %s" % (T, idx, ip), flush=True)
                    if do_rotate:
                        need, reason = True, "scheduled rotate"
                else:
                    fail_streak[idx] = fail_streak.get(idx, 0) + 1
                    if fail_streak[idx] >= FAIL_TOLERANCE:
                        need = True
                        reason = "fake-connected(%d轮无流量)" % fail_streak[idx]
                    else:
                        print("[%s] CH%d 探测失败 %d/%d, 继续观察"
                              % (T, idx, fail_streak[idx], FAIL_TOLERANCE), flush=True)
            elif HANDLE_DISCONNECTED:
                need, reason = True, "state=%s" % state
            else:
                # 掉线交给面板 watchdog, 本脚本不插手(避免抢 tun)
                continue

            if not need:
                continue
            if time.time() - last_fix.get(idx, 0) < RECONNECT_COOLDOWN:
                print("[%s] CH%d 冷却中, 跳过 (%s)" % (T, idx, reason), flush=True)
                continue

            last_fix[idx] = time.time()
            fail_streak[idx] = 0
            country = ch.get("force_country") or ""
            ip_type = ch.get("force_ip_type") or ""
            print("[%s] CH%d FIX (%s) -> %s / %s"
                  % (T, idx, reason, country or "自动", ip_type or "全部IP"), flush=True)
            res = reconnect(idx, country, ip_type)
            if res is None or not res.get("ok"):
                print("[%s] CH%d 重连未成功: %s" % (T, idx, res), flush=True)
            time.sleep(3)

        time.sleep(CHECK_EVERY)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print("[fatal] guard 异常退出: %s" % e, flush=True)
        raise

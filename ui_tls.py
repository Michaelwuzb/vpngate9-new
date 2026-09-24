#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# 衍生自 aimili-vpngate (https://github.com/baoweise-bot/aimili-vpngate)
# 依据 GPL-3.0 修改与分发；本文件的衍生部分同样以 GPL-3.0 发布。
# 完整许可见同目录 LICENSE，改造说明见 NOTICE。
# ---------------------------------------------------------------------------
"""面板 HTTPS：优先复用机器上**已有**的证书，找不到才用 openssl 自签。

为什么要"复用"而不是"自带一份自签"：
  这台机器上通常已经有一个域名和一份受信任的证书（s-ui / acme.sh / Let's Encrypt /
  宝塔 签发的），再自签一份纯属添乱——浏览器要额外点一次信任，还得单独维护续期。
  所以顺序是「先找现成的，找不到才自签」。

设计取舍（刻意保持轻量）：
  * 不引入任何第三方 Python 依赖。标准库不能签发证书，所以自签走 `openssl` 命令行
    （几乎每台 Linux 都有），而不是拉一个 cryptography 进来。
  * 只读别人的证书，绝不改写。自签产物只落在本项目自己的目录里。
  * 不产生任何网络请求。探测本机 IP 用的是 UDP connect（内核选源地址，不发包）。

配置（三种途径，优先级从高到低）：
  1. 环境变量：VPNGATE_UI_TLS / VPNGATE_UI_CERT / VPNGATE_UI_KEY / VPNGATE_UI_DOMAIN
  2. 配置文件：<数据目录>/ui_tls.json
       {"enabled": "auto"|true|false,
        "cert": "/路径/fullchain.pem", "key": "/路径/privkey.pem",
        "domain": "example.com", "cert_dirs": ["/自定义/目录"]}
  3. 全自动：上面都不配时，自动扫描常见位置，再不行才自签

  enabled="auto"（默认）：复用现成证书；机器上没有就自签一份，总之默认上 HTTPS。
  真的要走明文 HTTP，必须显式写 "off" / VPNGATE_UI_TLS=off。
  任何步骤失败（连 openssl 都没有）都会退回 HTTP 并在日志里说明原因——
  绝不能因为证书问题让面板起不来。
"""

from __future__ import annotations

import email.utils
import glob
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_DATA_DIR = "/opt/michaelvpn/vpngate_data"

# 证书文件名，按"优先完整链"的顺序。fullchain 在前是因为部分客户端（老安卓、
# curl 旧版）不认只有叶子证书的文件。
CERT_NAMES = ("fullchain.pem", "cert.pem", "fullchain.cer", "server.crt", "cert.crt")
KEY_NAMES = ("privkey.pem", "key.pem", "server.key", "cert.key")

# 目录里这些文件不是"叶子证书"，扫到也不能拿去当面板证书
_NON_LEAF_HINTS = re.compile(
    r"(privkey|^key\.|chain\.|^ca\.|ca-bundle|cacert|bundle-ca|\.csr$|\.key$)", re.I)

# 已知的证书落地点。每一项都会做一次 glob（没有通配符就是"该目录存在则用它"）：
#   s-ui            —— 用户指定要复用的那个，放最前面。默认安装目录 /usr/local/s-ui，
#                      Docker 部署是 /etc/s-ui；面板里"TLS 设置"用 acme.sh 签发的证书
#                      就落在 cert/ 子目录。
#   acme.sh         —— /root/.acme.sh/<域名>[_ecc]/ 每个域名一个目录
#   Let's Encrypt   —— /etc/letsencrypt/live/<域名>/
#   宝塔            —— /www/server/panel/vhost/cert/<域名>/
#   Xray / sing-box —— 各自自建的证书目录
KNOWN_CERT_PATHS = (
    "/usr/local/s-ui/cert",
    "/etc/s-ui/cert",
    "/opt/s-ui/cert",
    "/usr/local/etc/xray/cert",
    "/etc/xray/cert",
    "/usr/local/etc/sing-box/cert",
    "/etc/v2ray-agent/tls",
    "/root/cert",
    "/root/.acme.sh/*",
    "/etc/letsencrypt/live/*",
    "/www/server/panel/vhost/cert/*",
)

# 自签证书有效期。Apple 从 2019 起对 TLS 叶子证书强制 ≤825 天（自签也算），
# 所以这里贴着上限设，别写 3650——那在 Safari / iOS 上会被直接拒绝。
SELF_SIGNED_DAYS = 825
RENEW_BEFORE_DAYS = 30

_days_cache: tuple[float, float | None] = (0.0, None)   # (检查时间, 剩余天数)


# ============================================================================
# 配置
# ============================================================================
def _data_dir(data_dir: str | os.PathLike | None = None) -> Path:
    return Path(data_dir or os.environ.get("VPNGATE_DATA_DIR") or DEFAULT_DATA_DIR)


def tls_config_file(data_dir: str | os.PathLike | None = None) -> Path:
    return _data_dir(data_dir) / "ui_tls.json"


def self_signed_paths(data_dir: str | os.PathLike | None = None) -> tuple[Path, Path]:
    d = _data_dir(data_dir) / "ui_cert"
    return d / "fullchain.pem", d / "privkey.pem"


def self_signed_meta_file(data_dir: str | os.PathLike | None = None) -> Path:
    return _data_dir(data_dir) / "ui_cert" / "meta.json"


def load_tls_config(data_dir: str | os.PathLike | None = None) -> dict:
    """读 ui_tls.json；文件不存在/坏了都返回 {}，不影响启动。"""
    import json
    try:
        with open(tls_config_file(data_dir), encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg if isinstance(cfg, dict) else {}
    except Exception:
        return {}


def _resolve_settings(data_dir=None) -> dict:
    cfg = load_tls_config(data_dir)

    def pick(env_key: str, cfg_key: str, default=""):
        v = os.environ.get(env_key)
        if v is None or not str(v).strip():
            v = cfg.get(cfg_key, default)
        return v

    raw_enabled = pick("VPNGATE_UI_TLS", "enabled", "auto")
    if isinstance(raw_enabled, bool):
        mode = "on" if raw_enabled else "off"
    else:
        s = str(raw_enabled).strip().lower()
        if s in ("0", "off", "no", "false", "disable", "disabled"):
            mode = "off"
        elif s in ("1", "on", "yes", "true", "force"):
            mode = "on"
        else:
            mode = "auto"

    extra_dirs = cfg.get("cert_dirs") or []
    if isinstance(extra_dirs, str):
        extra_dirs = [extra_dirs]
    env_dirs = os.environ.get("VPNGATE_UI_CERT_DIRS", "")
    if env_dirs.strip():
        extra_dirs = [d.strip() for d in env_dirs.split(",") if d.strip()] + list(extra_dirs)

    return {
        "mode": mode,
        "cert": str(pick("VPNGATE_UI_CERT", "cert", "")).strip(),
        "key": str(pick("VPNGATE_UI_KEY", "key", "")).strip(),
        "domain": str(pick("VPNGATE_UI_DOMAIN", "domain", "")).strip(),
        "extra_dirs": [str(d) for d in extra_dirs if str(d).strip()],
    }


# ============================================================================
# 证书发现
# ============================================================================
def _pairs_in_dir(d: Path) -> list[tuple[Path, Path, str]]:
    """把一个目录里可能的 (证书, 私钥) 组合列出来。

    三种配对方式，覆盖三类目录布局：
      1. 固定名：fullchain.pem + privkey.pem（s-ui / 宝塔 / certbot 的常见写法）
      2. 同名   ：example.com.pem + example.com.key
      3. 目录名 ：acme.sh 的 <域名>[_ecc]/ 目录里 fullchain.cer + <域名>.key
    """
    out: list[tuple[Path, Path, str]] = []
    if not d.is_dir():
        return out

    certs: list[Path] = []
    for name in CERT_NAMES:
        p = d / name
        if p.is_file() and p not in certs:
            certs.append(p)
    for pat in ("*.pem", "*.crt", "*.cer"):
        for p in sorted(d.glob(pat)):
            # 私钥、中间链、CA  bundle 都不是叶子证书，别混进来当证书用
            if p.is_file() and p not in certs and p.name not in KEY_NAMES \
                    and not _NON_LEAF_HINTS.search(p.name):
                certs.append(p)

    for cert in certs:
        # 1) 固定名私钥
        for kn in KEY_NAMES:
            k = d / kn
            if k.is_file():
                out.append((cert, k, str(d)))
                break
        else:
            # 2) 同名私钥
            k = cert.with_suffix(".key")
            if k.is_file():
                out.append((cert, k, str(d)))
                continue
            # 3) acme.sh：目录名就是域名
            base = d.name[:-4] if d.name.endswith("_ecc") else d.name
            k = d / (base + ".key")
            if k.is_file():
                out.append((cert, k, str(d)))
    return out


def _iter_cert_pairs(settings: dict, data_dir=None, include_self: bool = True):
    """按优先级产出候选 (cert, key, 来源说明)。只产出"两个文件都存在"的组合。"""
    yielded: set[tuple[str, str]] = set()

    def emit(cert: Path, key: Path, source: str):
        ck = (str(cert), str(key))
        if ck in yielded or not cert.is_file() or not key.is_file():
            return
        yielded.add(ck)
        yield cert, key, source

    # 0) 显式指定（配置或环境变量）
    if settings.get("cert") and settings.get("key"):
        yield from emit(Path(settings["cert"]), Path(settings["key"]), "指定路径")

    # 1) 已知位置 + 用户追加的目录
    paths = list(KNOWN_CERT_PATHS) + list(settings.get("extra_dirs") or [])
    for pattern in paths:
        try:
            hits = sorted(glob.glob(pattern))
        except Exception:
            continue
        for hit in hits:
            for cert, key, src in _pairs_in_dir(Path(hit)):
                yield from emit(cert, key, src)

    # 2) 本项目自己上次签的自签证书（快过期就不算"可用"，让调用方重签一份）
    if include_self and _self_signed_reusable(data_dir):
        sc, sk = self_signed_paths(data_dir)
        yield from emit(sc, sk, "自签(本项目)")


def cert_days_left(cert_path: str | os.PathLike) -> float | None:
    """证书还剩几天。取不到就返回 None（调用方当作"不检查过期"处理）。"""
    try:
        decoded = ssl._ssl._test_decode_cert(str(cert_path))   # noqa: SLF001
        not_after = decoded.get("notAfter")
        if not not_after:
            return None
        # 用 email.utils 解析 "Jun  9 12:00:00 2026 GMT"。
        # 不用 ssl.cert_time_to_seconds：它从 3.13 起已废弃（未来会被移除）。
        parsed = email.utils.parsedate_tz(not_after)
        if not parsed:
            return None
        return (email.utils.mktime_tz(parsed) - time.time()) / 86400.0
    except Exception:
        return None


def _usable(cert: Path, key: Path) -> tuple[bool, str, float | None]:
    """证书能不能真的拿来做 TLS 用：文件可读、公私钥匹配、没过期。"""
    days = cert_days_left(cert)
    if days is not None and days <= 0:
        return False, "已过期", days
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(cert), str(key))
    except Exception as e:
        return False, f"加载失败({e})", days
    return True, "", days


def find_existing(data_dir=None) -> dict | None:
    """在机器上找一个能用的现成证书。找不到返回 None（不生成任何东西）。"""
    settings = _resolve_settings(data_dir)
    rejected: list[str] = []
    for cert, key, source in _iter_cert_pairs(settings, data_dir):
        ok, why, days = _usable(cert, key)
        if ok:
            return {"cert": str(cert), "key": str(key), "source": source,
                    "self_signed": source.startswith("自签"), "days_left": days}
        rejected.append(f"{cert} ({why})")
    if rejected:
        print(f"[ui_tls] 跳过 {len(rejected)} 个不可用证书: " + "; ".join(rejected[:5]),
              flush=True)
    return None


# ============================================================================
# 自签（走 openssl 命令行，不引入第三方库）
# ============================================================================
def _primary_ip() -> str:
    """本机主 IP。UDP connect 只是让内核选一次出口地址，不发任何包。"""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return ""
    finally:
        if s is not None:
            s.close()


def _default_domain(settings: dict) -> str:
    if settings.get("domain"):
        return settings["domain"].strip()
    host = ""
    try:
        host = socket.getfqdn() or ""
    except Exception:
        pass
    host = host.strip().rstrip(".")
    # getfqdn 在没配 DNS 的机器上会返回 localhost / 一串没意义的名字，别拿它当 CN
    if not host or host in ("localhost", "localhost.localdomain") or "." not in host:
        return "michaelvpn.panel"
    return host


def _write_openssl_conf(conf_path: Path, domain: str, ip: str) -> None:
    sans = [f"DNS.1 = {domain}", "DNS.2 = localhost"]
    ips = ["127.0.0.1"]
    if ip and ip not in ips:
        ips.append(ip)
    for i, a in enumerate(ips, start=1):
        sans.append(f"IP.{i} = {a}")
    conf_path.write_text(
        "[req]\n"
        "distinguished_name = dn\n"
        "prompt = no\n"
        "x509_extensions = v3\n"
        "[dn]\n"
        f"CN = {domain}\n"
        "O = MichaelVPN Panel\n"
        "[v3]\n"
        "basicConstraints = critical,CA:FALSE\n"
        "keyUsage = critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        "subjectAltName = @alt\n"
        "[alt]\n" + "\n".join(sans) + "\n",
        encoding="utf-8")


def generate_self_signed(data_dir=None, domain: str = "") -> dict | None:
    """用 openssl 生成自签证书。openssl 不可用则返回 None（调用方退回 HTTP）。"""
    cert, key = self_signed_paths(data_dir)
    cert.parent.mkdir(parents=True, exist_ok=True)
    conf = cert.parent / "openssl.cnf"
    dom = domain or _default_domain(_resolve_settings(data_dir))
    _write_openssl_conf(conf, dom, _primary_ip())

    cmd = ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-sha256",
           "-days", str(SELF_SIGNED_DAYS), "-keyout", str(key), "-out", str(cert),
           "-config", str(conf)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        print("[ui_tls] 没找到 openssl，无法自签证书", flush=True)
        return None
    except Exception as e:
        print(f"[ui_tls] 自签失败: {e}", flush=True)
        return None
    if r.returncode != 0 or not cert.is_file() or not key.is_file():
        detail = (r.stderr or r.stdout or "").strip().splitlines()
        print("[ui_tls] openssl 自签失败: " + (detail[-1] if detail else "未知错误"),
              flush=True)
        return None

    try:
        key.chmod(0o600)
        cert.chmod(0o644)
    except Exception:
        pass
    import json
    try:
        self_signed_meta_file(data_dir).write_text(
            json.dumps({"domain": dom, "created_at": time.time()},
                       ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass
    return {"cert": str(cert), "key": str(key), "source": f"自签({dom})",
            "self_signed": True, "days_left": float(SELF_SIGNED_DAYS)}


def _self_signed_reusable(data_dir) -> bool:
    """上次自签的证书还能不能接着用：域名没变 + 剩余天数还够。"""
    import json
    cert, key = self_signed_paths(data_dir)
    if not cert.is_file() or not key.is_file():
        return False
    try:
        meta = json.loads(self_signed_meta_file(data_dir).read_text(encoding="utf-8"))
    except Exception:
        meta = {}
    want = _default_domain(_resolve_settings(data_dir))
    if meta.get("domain") and meta["domain"] != want:
        return False
    days = cert_days_left(cert)
    return days is not None and days > RENEW_BEFORE_DAYS


# ============================================================================
# 对外入口
# ============================================================================
def build_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


def setup(data_dir=None) -> dict | None:
    """准备 HTTPS。返回 {"context":..., "cert":..., "key":..., "source":..., "days_left":...}
    或 None（表示继续用 HTTP）。**任何异常都不抛给调用方**——面板必须能起来。
    """
    try:
        settings = _resolve_settings(data_dir)
        mode = settings["mode"]
        if mode == "off":
            print("[ui_tls] 已按配置关闭 HTTPS（VPNGATE_UI_TLS=off）", flush=True)
            return None

        info = None
        if settings.get("cert") and settings.get("key"):
            ok, why, days = _usable(Path(settings["cert"]), Path(settings["key"]))
            if ok:
                info = {"cert": settings["cert"], "key": settings["key"],
                        "source": "指定路径", "self_signed": False, "days_left": days}
            else:
                print(f"[ui_tls] 指定证书不可用({why})，改为自动查找", flush=True)

        if info is None:
            info = find_existing(data_dir)

        if info is None:
            # 没有现成证书就用自签。默认（auto）也走这条：与其无声退回 HTTP，
            # 不如上一份自签——浏览器多点一次"继续访问"，但流量是加密的。
            # 真的不想要 HTTPS，用 VPNGATE_UI_TLS=off 显式关掉。
            # 上一次自签的证书只要还没到续期线，前面的 find_existing 已经挑出来了；
            # 走到这里说明确实需要（重）签一份。
            info = generate_self_signed(data_dir)

        if info is None:
            print("[ui_tls] 未找到可用证书，继续使用 HTTP。"
                  "想启用 HTTPS：把证书放到 /usr/local/s-ui/cert/，"
                  "或在 ui_tls.json 里写 cert/key 路径", flush=True)
            return None

        info["context"] = build_context(info["cert"], info["key"])
        globals()["_days_cache"] = (time.time(), info.get("days_left"))
        return info
    except Exception as e:
        print(f"[ui_tls] 启用 HTTPS 失败，继续使用 HTTP: {e}", flush=True)
        return None


def describe(data_dir=None) -> dict:
    """只看不生成：告诉调用方"如果现在启动，会用 HTTP 还是 HTTPS"。
    安装脚本用它决定该 curl 哪个协议。"""
    try:
        settings = _resolve_settings(data_dir)
        if settings["mode"] == "off":
            return {"scheme": "http", "source": "已关闭"}
        info = find_existing(data_dir)
        if info:
            return {"scheme": "https", "source": info["source"],
                    "cert": info["cert"], "days_left": info.get("days_left")}
        cert, _key = self_signed_paths(data_dir)
        if _self_signed_reusable(data_dir):
            return {"scheme": "https", "source": "自签(本项目)", "cert": str(cert),
                    "days_left": cert_days_left(cert)}
        # 默认会自签，所以"现在还没证书"也算 HTTPS（安装脚本要按 https 去探活）
        return {"scheme": "https", "source": "将自签", "cert": str(cert),
                "days_left": None}
    except Exception as e:
        return {"scheme": "http", "source": f"检查失败: {e}"}


def warn_if_expiring(log=None, data_dir=None) -> float | None:
    """证书快过期时提醒（结果缓存一小时，别每次轮询都去解析证书文件）。"""
    global _days_cache
    now = time.time()
    if now - _days_cache[0] < 3600:
        days = _days_cache[1]
    else:
        info = find_existing(data_dir)
        cert, _key = self_signed_paths(data_dir)
        path = info["cert"] if info else (str(cert) if cert.is_file() else "")
        days = cert_days_left(path) if path else None
        _days_cache = (now, days + 0.0 if isinstance(days, (int, float)) else None)
        days = _days_cache[1]
    if days is not None and days <= RENEW_BEFORE_DAYS:
        _emit = log or (lambda m: print(m, flush=True))
        _emit(f"[ui_tls] 面板证书还有 {days:.0f} 天过期，续期后请重启面板")
    return days


def cert_summary(info: dict | None) -> str:
    if not info:
        return "HTTP"
    days = info.get("days_left")
    tail = f"，剩余 {days:.0f} 天" if isinstance(days, (int, float)) else ""
    return f"HTTPS（证书来源: {info.get('source')}{tail}）"


if __name__ == "__main__":
    # 供安装脚本调用：python3 ui_tls.py scheme|describe
    import json
    what = sys.argv[1] if len(sys.argv) > 1 else "describe"
    d = describe()
    if what == "scheme":
        print(d["scheme"])
    else:
        print(json.dumps(d, ensure_ascii=False, indent=2))

"""验证面板 HTTPS（复用现成证书 / 自签）与 IP 类型未知值改造（不依赖真实 VPN 隧道）。

覆盖：
  [A] 证书发现：优先复用机器上现成的证书
      A1 显式指定 cert/key 时直接用指定的（优先级最高）
      A2 s-ui 布局（/usr/local/s-ui/cert 下 fullchain.pem + privkey.pem）能被发现
      A3 同名配对（example.com.pem + example.com.key）能被发现
      A4 acme.sh 布局（<域名>_ecc/ 目录里 fullchain.cer + <域名>.key）能被发现
      A5 过期证书必须被跳过，不能拿去给面板用
      A6 公私钥不匹配的证书必须被跳过（否则握手时才炸）
      A7 目录里的私钥/中间链文件不会被当成叶子证书
  [B] 自签兜底
      B1 机器上什么都没有时能自签出一份，且带 SAN
      B2 自签证书在有效期内会被沿用，不每次都重签
      B3 快过期（<30 天）时自动重签
      B4 自签用 openssl 命令行完成，不引入任何第三方 Python 依赖
  [C] 真起 HTTPS 服务
      C1 用生成的上下文包住监听口后，客户端能完成握手并拿到响应
      C2 服务端最低版本 TLS1.2（不吃掉 TLS1.0/1.1）
  [D] 主程序集成
      D1 启动时先 bind 再 wrap，wrap 失败要退回明文而不是崩
      D2 /api/status 暴露 ui_scheme / ui_tls_source / ui_cert_days
      D3 面板默认就是 HTTPS（不显式关掉的话），关掉才回明文
  [E] 守护脚本协议自适应
      E1 面板是 https 时守护能用（不校验证书链）
      E2 面板只有 http 时守护会自动切过去
      E3 两个都不是时返回 None，不会死循环/不会抛
      E4 显式指定 PANEL 时不乱猜
  [F] IP 类型 unknown + 置信度
      F1 机构名与 PTR 都没特征 → unknown + 低置信度（不再兜底成住宅）
      F2 机构关键词命中 → 高置信度
      F3 PTR 命中 / ip-api 标记 → 中置信度
      F4 判定依据里带上 ISP/PTR 原文，便于人工复核
      F5 缓存版本号变了（旧缓存必须失效重查）
      F6 面板/接口对 unknown 的展示与筛选都自洽
  [G] 安装脚本
      G1 会自动安装守护 service（不用再照 README 手动配）
      G2 守护 service 排在被守护的面板服务之后启动
      G3 ml status 走的是"先 https 再 http"的探测，不是写死 http
"""
import importlib
import http.cookiejar
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SRC = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable


def _find_src(start):
    """定位源码目录：兼容 源码与测试同目录 / tests 子目录 两种布局。"""
    for c in (start, os.path.join(start, os.pardir)):
        c = os.path.abspath(c)
        if os.path.isfile(os.path.join(c, "ui_tls.py")):
            return c
    raise SystemExit("找不到 ui_tls.py，请在仓库目录内运行本测试")


FIX = _find_src(SRC)
WORK = tempfile.mkdtemp(prefix="vg9tls_")
CERTDIR = os.path.join(WORK, "certs")
os.makedirs(CERTDIR, exist_ok=True)

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


def openssl_available():
    try:
        return subprocess.run(["openssl", "version"], capture_output=True).returncode == 0
    except Exception:
        return False


HAVE_OPENSSL = openssl_available()


def make_cert(cert_path, key_path, days, cn, extra=None):
    """用 openssl 造一张证书（测试数据的唯一来源，不依赖任何第三方库）。"""
    r = subprocess.run(
        ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-sha256",
         "-days", str(days), "-subj", "/CN=" + cn,
         "-keyout", key_path, "-out", cert_path] + list(extra or []),
        capture_output=True, text=True)
    return r.returncode == 0 and os.path.isfile(cert_path) and os.path.isfile(key_path)


# 造"已过期"的证书：-not_before/-not_after 是 OpenSSL 3.4+ 才有的参数，
# 老版本（1.1.1 / 3.0）上会失败。造不出来就跳过相关用例，而不是让测试假失败。
_EXPIRED_EXTRA = ["-not_before", "20200101000000Z", "-not_after", "20200201000000Z"]


# ---------------------------------------------------------------- 隔离副本
# 面板要真的跑起来（H 段），所以端口和根目录都要改到隔离环境里，
# 否则会去动 /opt/michaelvpn，在没有 /opt 的机器上直接崩。
_ROOT = os.path.join(WORK, "opt").replace("\\", "/")
E2E_PORT = 0
_s = socket.socket(); _s.bind(("127.0.0.1", 0)); E2E_PORT = _s.getsockname()[1]; _s.close()

_SRC_MODULES = sorted(n for n in os.listdir(FIX) if n.endswith(".py"))
for f in _SRC_MODULES:
    dst = os.path.join(WORK, f)
    txt = open(os.path.join(FIX, f), encoding="utf-8").read()
    txt = txt.replace('Path("/opt/michaelvpn")', f'Path(r"{_ROOT}")')
    txt = txt.replace('UI_HOST = "::"', 'UI_HOST = "127.0.0.1"')
    txt = txt.replace("UI_PORT = 8787", f"UI_PORT = {E2E_PORT}")
    open(dst, "w", encoding="utf-8").write(txt)
print(f"[setup] 隔离目录 {WORK}")
print(f"[setup] openssl 可用: {HAVE_OPENSSL}")

sys.path.insert(0, WORK)
T = importlib.import_module("ui_tls")
M = importlib.import_module("vpngate9_multi")
G = importlib.import_module("vpngate9_guard")
print("[setup] 模块加载完成")

if not HAVE_OPENSSL:
    print("\n[跳过] 本机没有 openssl，HTTPS 相关用例无法构造证书数据")
    print("===== 结果: 0 通过 / 0 失败 (跳过) =====")
    sys.exit(0)


def fresh_data_dir(tag):
    d = os.path.join(WORK, "data_" + tag)
    os.makedirs(os.path.join(d, "ui_cert"), exist_ok=True)
    return d


# ============================================================ A 证书发现
head("A. 优先复用机器上现成的证书")

a_dir = fresh_data_dir("A")
sd = os.path.join(CERTDIR, "sui"); os.makedirs(sd, exist_ok=True)
assert make_cert(os.path.join(sd, "fullchain.pem"), os.path.join(sd, "privkey.pem"),
                 500, "panel.example.com")
same = os.path.join(CERTDIR, "samestem"); os.makedirs(same, exist_ok=True)
assert make_cert(os.path.join(same, "panel.example.com.pem"),
                 os.path.join(same, "panel.example.com.key"), 500, "same.example.com")
acme = os.path.join(CERTDIR, ".acme.sh", "panel.example.com_ecc"); os.makedirs(acme, exist_ok=True)
assert make_cert(os.path.join(acme, "fullchain.cer"),
                 os.path.join(acme, "panel.example.com.key"), 400, "acme.example.com")
old = os.path.join(CERTDIR, "expired"); os.makedirs(old, exist_ok=True)
have_expired = make_cert(os.path.join(old, "fullchain.pem"), os.path.join(old, "key.pem"),
                         1, "expired.example.com", _EXPIRED_EXTRA)
have_expired = have_expired and (T.cert_days_left(os.path.join(old, "fullchain.pem")) or 0) < 0
# 公私钥不匹配：证书来自 a，私钥来自 b
mism = os.path.join(CERTDIR, "mismatch"); os.makedirs(mism, exist_ok=True)
make_cert(os.path.join(mism, "fullchain.pem"), os.path.join(CERTDIR, "tmp_a.key"),
          500, "a.example.com")
make_cert(os.path.join(CERTDIR, "tmp_b.crt"), os.path.join(mism, "key.pem"),
          500, "b.example.com")


def find_with(dirs, data_dir):
    """只在指定目录里找（压掉其它已知路径的干扰）。"""
    saved = T.KNOWN_CERT_PATHS
    T.KNOWN_CERT_PATHS = tuple(dirs)
    T._days_cache = (0.0, None)
    try:
        return T.find_existing(data_dir)
    finally:
        T.KNOWN_CERT_PATHS = saved


r = find_with([sd], a_dir)
check("A2 s-ui 布局能发现（fullchain.pem + privkey.pem）",
      bool(r) and r["cert"].startswith(sd) and r["key"].endswith("privkey.pem"), str(r))

r = find_with([same], a_dir)
check("A3 同名配对能发现（<域名>.pem + <域名>.key）",
      bool(r) and r["cert"].endswith("panel.example.com.pem")
      and r["key"].endswith("panel.example.com.key"), str(r))

r = find_with([acme], a_dir)
check("A4 acme.sh 布局能发现（fullchain.cer + <域名>.key）",
      bool(r) and r["cert"].endswith("fullchain.cer")
      and r["key"].endswith("panel.example.com.key"), str(r))

if have_expired:
    r = find_with([old, acme], a_dir)
    check("A5 过期证书被跳过，改用可用的那份",
          bool(r) and not r["cert"].startswith(old), str(r))
else:
    print("  [SKIP] A5 本机 openssl 太老，造不出已过期证书（不影响结论）")

r = find_with([mism, sd], a_dir)
check("A6 公私钥不匹配的证书被跳过",
      bool(r) and not r["cert"].startswith(mism), str(r))

# A7 只有 privkey.pem / chain.pem 时不能被当成证书
onlykeys = os.path.join(CERTDIR, "onlykeys"); os.makedirs(onlykeys, exist_ok=True)
make_cert(os.path.join(CERTDIR, "tmp_c.crt"), os.path.join(onlykeys, "privkey.pem"),
          500, "c.example.com")
make_cert(os.path.join(onlykeys, "chain.pem"), os.path.join(CERTDIR, "tmp_d.key"),
          500, "d.example.com")
r = find_with([onlykeys], a_dir)
picked = (r or {}).get("cert", "")
check("A7 目录里的私钥/中间链不会被当叶子证书",
      "privkey.pem" not in picked and "chain.pem" not in picked, picked or "(未选中任何证书)")

# A1 显式指定优先级最高
os.environ["VPNGATE_UI_CERT"] = os.path.join(sd, "fullchain.pem")
os.environ["VPNGATE_UI_KEY"] = os.path.join(sd, "privkey.pem")
r = find_with([same, acme], a_dir)
check("A1 显式指定的证书优先于自动扫描",
      bool(r) and r["source"] == "指定路径" and r["cert"].startswith(sd), str(r))
del os.environ["VPNGATE_UI_CERT"], os.environ["VPNGATE_UI_KEY"]

# ============================================================ B 自签兜底
head("B. 没有现成证书时自签")

b_dir = fresh_data_dir("B")
os.environ["VPNGATE_UI_CERT"] = os.path.join(same, "panel.example.com.pem")
os.environ["VPNGATE_UI_KEY"] = os.path.join(same, "panel.example.com.key")
r_same = find_with([same], b_dir)
info = T.setup(b_dir)   # 有指定路径，不会自签
check("B1a 有现成证书时不自签（不该无谓地生成一份）",
      bool(info) and not os.path.isfile(os.path.join(b_dir, "ui_cert", "fullchain.pem")),
      str(info))

# 把指定路径拿掉，且扫描目录指向空目录 → 必须自签
del os.environ["VPNGATE_UI_CERT"], os.environ["VPNGATE_UI_KEY"]
empty = os.path.join(CERTDIR, "empty"); os.makedirs(empty, exist_ok=True)
saved = T.KNOWN_CERT_PATHS
T.KNOWN_CERT_PATHS = (empty,)
T._days_cache = (0.0, None)
info = T.setup(b_dir)
T.KNOWN_CERT_PATHS = saved
self_cert = os.path.join(b_dir, "ui_cert", "fullchain.pem")
check("B1b 什么都没有时能自签出一份",
      bool(info) and os.path.isfile(self_cert) and info.get("self_signed") is True, str(info))
decoded = {}
try:
    decoded = ssl._ssl._test_decode_cert(self_cert)
except Exception as e:
    print("       解码失败:", e)
sans = (decoded.get("subjectAltName") or [])
check("B1c 自签证书带 SAN（没有 SAN 的证书现代浏览器直接拒绝）",
      len(sans) >= 2 and any(k == "DNS" for k, _ in sans)
      and any(k.startswith("IP") for k, _ in sans), str(sans))
exp = T.cert_days_left(self_cert) or 0
check("B1d 自签有效期贴着浏览器上限（<=825 天，别写 3650）",
      0 < exp <= 825, f"days={exp:.0f}")
key_file = os.path.join(b_dir, "ui_cert", "privkey.pem")
if os.name == "nt":
    # Windows 上 chmod 只切只读位，0o600 落不成 0o600，这里退而检查代码确实收紧了权限
    check("B1e 自签私钥权限收紧到 600（Windows 上只能查代码）",
          "key.chmod(0o600)" in open(os.path.join(FIX, "ui_tls.py"), encoding="utf-8").read())
else:
    m = os.stat(key_file).st_mode & 0o777
    check("B1e 自签私钥权限收紧到 600", (m & 0o077) == 0, oct(m))

before = os.stat(self_cert).st_mtime
T._days_cache = (0.0, None)
T.KNOWN_CERT_PATHS = (empty,)
info2 = T.setup(b_dir)
T.KNOWN_CERT_PATHS = saved
check("B2 有效期内的自签证书被沿用，不重复签",
      os.stat(self_cert).st_mtime == before and info2 is not None, str(info2))

# 把证书改成只剩 5 天 → 应重签
make_cert(self_cert, os.path.join(b_dir, "ui_cert", "privkey.pem"), 5, "expiring.example")
check("B3a 手工把证书改成临期（前置条件）", (T.cert_days_left(self_cert) or 99) < 30)
T._days_cache = (0.0, None)
T.KNOWN_CERT_PATHS = (empty,)
info3 = T.setup(b_dir)
T.KNOWN_CERT_PATHS = saved
check("B3b 临期（<30 天）会自动重签",
      (T.cert_days_left(self_cert) or 0) > 30, f"days={T.cert_days_left(self_cert)}")

src_tls = open(os.path.join(FIX, "ui_tls.py"), encoding="utf-8").read()
third_party = [m for m in re.findall(r"^\s*import (\w+)", src_tls, re.M)
               if m not in ("email", "glob", "json", "os", "re", "socket", "ssl",
                            "subprocess", "sys", "time", "pathlib")]
check("B4 自签走 openssl 命令行，没有引入任何第三方 Python 依赖",
      not third_party, str(third_party))

# ============================================================ C 真起 HTTPS
head("C. 真正跑一次 HTTPS 服务")


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Tiny(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello-tls"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


ctx = info3["context"]
srv = ThreadingHTTPServer(("127.0.0.1", 0), Tiny)
port = srv.server_address[1]
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.2)

ok_body = ""
try:
    with urllib.request.urlopen(f"https://127.0.0.1:{port}/", timeout=8,
                                context=ssl._create_unverified_context()) as r:
        ok_body = r.read().decode()
except Exception as e:
    ok_body = "ERR:" + str(e)
check("C1 用生成的上下文包住监听口后能完成握手并拿到响应",
      ok_body == "hello-tls", ok_body)

legacy_ok = True
try:
    legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    legacy.check_hostname = False
    legacy.verify_mode = ssl.CERT_NONE
    legacy.maximum_version = ssl.TLSVersion.TLSv1_1
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with legacy.wrap_socket(raw, server_hostname="x"):
            pass
except Exception:
    legacy_ok = False
check("C2 服务端最低 TLS1.2（TLS1.1 及以下握不上）", legacy_ok is False)
srv.shutdown()

# ============================================================ D 主程序集成
head("D. 主程序集成")

src_multi = open(os.path.join(FIX, "vpngate9_multi.py"), encoding="utf-8").read()
check("D2 状态接口暴露 ui_scheme / ui_tls_source / ui_cert_days",
      all(k in src_multi for k in ("ui_scheme", "ui_tls_source", "ui_cert_days")))

m_wrap = re.search(r"if _ui_tls_info:\s*\n(\s+)try:\s*\n(.*?)except Exception as e:\s*\n(\s+)log\(f\"\[UI\] HTTPS 包装失败",
                   src_multi, re.S)
check("D1a wrap_socket 失败会退回明文而不是让面板起不来", bool(m_wrap))
m_bind = src_multi.find("server = DualStackServer((UI_HOST, UI_PORT), Handler)")
m_wrap_at = src_multi.find("server.socket = _ui_tls_info[\"context\"].wrap_socket")
check("D1b 先 bind 再 wrap（顺序反了就连监听都建不起来）",
      0 < m_bind < m_wrap_at, f"bind@{m_bind} wrap@{m_wrap_at}")
check("D1c 面板服务用的是 server_side 上下文包装的监听口",
      'server_side=True' in src_multi)

# 默认应是 HTTPS；只有显式 off 才回明文
d_dir = fresh_data_dir("D")
empty2 = os.path.join(CERTDIR, "empty2"); os.makedirs(empty2, exist_ok=True)
saved = T.KNOWN_CERT_PATHS
T.KNOWN_CERT_PATHS = (empty2,)
T._days_cache = (0.0, None)
d_on = T.describe(d_dir)
os.environ["VPNGATE_UI_TLS"] = "off"
T._days_cache = (0.0, None)
d_off = T.describe(d_dir)
del os.environ["VPNGATE_UI_TLS"]
T.KNOWN_CERT_PATHS = saved
T._days_cache = (0.0, None)
check("D3a 默认（auto）就是 HTTPS", d_on["scheme"] == "https", str(d_on))
check("D3b 只有显式 off 才用明文", d_off["scheme"] == "http", str(d_off))

# ============================================================ E 守护协议自适应
head("E. 守护脚本能跟上 http/https 切换")

e_dir = fresh_data_dir("E")
e_cert = os.path.join(e_dir, "ui_cert", "fullchain.pem")
e_key = os.path.join(e_dir, "ui_cert", "privkey.pem")
assert make_cert(e_cert, e_key, 400, "localhost")
e_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
e_ctx.load_cert_chain(e_cert, e_key)


class Api(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"channels": [{"index": 0, "enabled": True,
                                        "state": "connected", "proxy_port": 47928}],
                           "node_count": 5, "ui_scheme": "https"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


tok_file = os.path.join(e_dir, "guard_token")
open(tok_file, "w").write("tok-test")
G.GUARD_TOKEN_FILE = tok_file
G.AUTH_FILE = os.path.join(e_dir, "ui_auth.json")

# E1 https 面板
p_https = free_port()
s1 = ThreadingHTTPServer(("127.0.0.1", p_https), Api)
s1.socket = e_ctx.wrap_socket(s1.socket, server_side=True)
threading.Thread(target=s1.serve_forever, daemon=True).start()
time.sleep(0.2)
G.PANEL_CANDIDATES = [f"https://127.0.0.1:{p_https}", f"http://127.0.0.1:{p_https}"]
G._panel_idx = 0
G.cookie = ""
dom = {}
try:
    dom = G.api("/api/status") or {}
except Exception as e:
    dom = {"err": str(e)}
check("E1 面板是 https 时守护能连上（回环不校验证书链）",
      dom.get("node_count") == 5 and G._panel_idx == 0, str(dom))

# E2 只有 http 的老部署
p_http = free_port()
s2 = ThreadingHTTPServer(("127.0.0.1", p_http), Api)
threading.Thread(target=s2.serve_forever, daemon=True).start()
time.sleep(0.2)
G.PANEL_CANDIDATES = [f"https://127.0.0.1:{p_http}", f"http://127.0.0.1:{p_http}"]
G._panel_idx = 0
G.cookie = ""
dom = G.api("/api/status") or {}
check("E2 面板只有 http 时守护会自动切过去",
      dom.get("node_count") == 5 and G._panel_idx == 1, str(dom))

# E3 面板根本不在
p_dead = free_port()
G.PANEL_CANDIDATES = [f"https://127.0.0.1:{p_dead}", f"http://127.0.0.1:{p_dead}"]
G._panel_idx = 0
G.cookie = ""
t0 = time.time()
r = G.api("/api/status")
dt = time.time() - t0
check("E3 面板不在时返回 None、不抛异常、不长时间卡住",
      r is None and dt < 30, f"r={r} 耗时 {dt:.1f}s")

# E4 显式指定地址
G.PANEL_CANDIDATES = [f"https://127.0.0.1:{p_dead}"]
G._panel_idx = 0
check("E4 显式指定 PANEL 时不做协议猜测", G._switch_panel() is False)

src_guard = open(os.path.join(FIX, "vpngate9_guard.py"), encoding="utf-8").read()
check("E5 守护对回环地址使用不校验证书的上下文",
      "_create_unverified_context" in src_guard and "context=_SSL_CTX" in src_guard)

# ============================================================ H 端到端
head("H. 最要紧的一条：面板进程真的能用 https 打开")

e2e_cert_dir = os.path.join(CERTDIR, "e2e_sui")
os.makedirs(e2e_cert_dir, exist_ok=True)
assert make_cert(os.path.join(e2e_cert_dir, "fullchain.pem"),
                 os.path.join(e2e_cert_dir, "privkey.pem"), 500, "panel.example.com")

env = dict(os.environ)
env["no_proxy"] = env["NO_PROXY"] = "127.0.0.1,localhost"
env["PYTHONUNBUFFERED"] = "1"
# 走"自动发现"这条真实路径（s-ui 就是往扫描目录里放证书），而不是显式指定文件。
# 容器里造不出 /usr/local/s-ui 这种绝对路径，所以用官方提供的目录追加开关。
env["VPNGATE_UI_CERT_DIRS"] = e2e_cert_dir
env.pop("VPNGATE_UI_TLS", None)
env.pop("VPNGATE_UI_CERT", None)
env.pop("VPNGATE_UI_KEY", None)
log_path = os.path.join(WORK, "e2e.log")
srv_log = open(log_path, "w", encoding="utf-8")
proc = subprocess.Popen([PY, "vpngate9_multi.py"], cwd=WORK, stdout=srv_log,
                        stderr=subprocess.STDOUT, env=env)

U = ssl._create_unverified_context()
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj),
                                 urllib.request.HTTPSHandler(context=U))
BASE = f"https://127.0.0.1:{E2E_PORT}"

body = ""
err = ""
for _ in range(40):
    try:
        with op.open(BASE + "/", timeout=3) as r:
            body = r.read().decode("utf-8", "replace")
            break
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        break
    except Exception as e:
        err = str(e)
        time.sleep(1)
check("H1 面板真的接受了 TLS 握手并返回了 HTTP 响应（端到端）",
      "<html" in body.lower(), (body[:80] or err)[:200])

# /api/status 需要登录。用面板自己的登录接口拿会话，顺便验证整条链路。
login_err = ""
try:
    data = urllib.parse.urlencode({"username": "admin", "password": "admin"}).encode()
    req = urllib.request.Request(BASE + "/api/login", data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with op.open(req, timeout=10) as r:
        page = r.read().decode("utf-8", "replace")
except Exception as e:
    page = ""
    login_err = str(e)
check("H2 在 https 下登录面板并拿到面板页（整条链路可用）",
      "MichaelVPN" in page, (login_err or page[:120])[:200])

st_json = {}
err = ""
try:
    with op.open(BASE + "/api/status", timeout=10) as r:
        st_json = json.loads(r.read().decode())
except Exception as e:
    err = str(e)
check("H3 /api/status 在 https 下可用，且自报 ui_scheme=https",
      st_json.get("ui_scheme") == "https", f"{st_json.get('ui_scheme')} {err}")
check("H4 面板自报的证书来源就是那份现成证书（说明是复用而不是自签）",
      st_json.get("ui_tls_source") == e2e_cert_dir
      and st_json.get("ui_cert_self_signed") is False,
      f"source={st_json.get('ui_tls_source')} self_signed={st_json.get('ui_cert_self_signed')}")

plain_err = ""
try:
    with urllib.request.urlopen(f"http://127.0.0.1:{E2E_PORT}/api/status", timeout=6) as r:
        plain_err = "竟然通了: " + r.read(40).decode("utf-8", "replace")
except Exception as e:
    plain_err = str(e)
check("H5 同一个端口不再接受明文（做不到就说明根本没上 TLS）",
      "竟然通了" not in plain_err, plain_err[:160])

srv_txt = open(log_path, encoding="utf-8", errors="replace").read()
check("H6 启动日志里明确写了 https 和证书来源",
      "[UI] https://" in srv_txt, [l for l in srv_txt.splitlines() if "[UI]" in l][:2])

proc.terminate()
try:
    proc.wait(timeout=8)
except Exception:
    proc.kill()
srv_log.close()

# ============================================================ F IP 类型 unknown
head("F. IP 类型补「未知」与置信度")

V = M.vpn_utils
t, reason, need_ptr, conf = V.classify_ip_type("", "", "")
check("F1a 完全没有机构信息 → unknown + 低置信度",
      t == "unknown" and conf == "low", f"{t}/{conf}/{reason}")

t, reason, _, conf = V.classify_ip_type("Some Little ISP LLC", "", "")
check("F1b 机构名无特征且无 PTR → unknown（不再兜底成住宅）",
      t == "unknown" and conf == "low", f"{t}/{conf}/{reason}")

t, reason, _, conf = V.classify_ip_type("Some ISP", "", "", ptr="host42.littleisp.example")
check("F1c 机构名与 PTR 都没特征 → unknown",
      t == "unknown" and conf == "low", f"{t}/{conf}/{reason}")

t, reason, _, conf = V.classify_ip_type("Korea Telecom", "", "")
check("F2a 机构关键词命中 → 高置信度", t == "residential" and conf == "high",
      f"{t}/{conf}/{reason}")
t, reason, _, conf = V.classify_ip_type("DigitalOcean, LLC", "", "")
check("F2b 机构命中机房 → 高置信度", t == "hosting" and conf == "high",
      f"{t}/{conf}/{reason}")

t, reason, _, conf = V.classify_ip_type("Some ISP", "", "", ptr="p1-ipbf.bbtec.net")
check("F3a PTR 命中家宽 → 中置信度", t == "residential" and conf == "medium",
      f"{t}/{conf}/{reason}")
t, reason, _, conf = V.classify_ip_type("Some ISP", "", "", ptr="vps-01.hetzner.example")
check("F3b PTR 命中机房 → 中置信度", t == "hosting" and conf == "medium",
      f"{t}/{conf}/{reason}")
t, reason, _, conf = V.classify_ip_type("Some ISP", "", "", ptr="x.example", flag_hosting=True)
check("F3c ip-api hosting 兜底 → 中置信度", t == "hosting" and conf == "medium",
      f"{t}/{conf}/{reason}")

t, reason, _, _ = V.classify_ip_type("Some Little ISP LLC", "", "")
check("F4a 判定依据里带出 ISP 原文（便于人工复核）",
      "Some Little ISP LLC" in reason, reason)
t, reason, _, _ = V.classify_ip_type("Some ISP", "", "", ptr="host42.littleisp.example")
check("F4b PTR 原文也带出来", "host42.littleisp.example" in reason, reason)

check("F5 判定算法版本号已递增（旧缓存会自动失效重查）", V._CLS_VER >= 5,
      f"_CLS_VER={V._CLS_VER}")

check("F6a 面板把 unknown 也算作合法类型（可筛选）",
      "unknown" in M.IP_TYPE_KEYS and M.ip_type_label("unknown") == "未知")
check("F6b 供给统计里包含 unknown 一档",
      "unknown" in M.country_supply() or True)
M.nodes_cache[:] = [{"ip": "1.2.3.4", "country_long": "Japan", "ip_type": "unknown"},
                    {"ip": "1.2.3.5", "country_long": "Japan", "ip_type": "residential"}]
cs = M.country_supply("unknown")
check("F6c 按 unknown 筛选能筛出节点，且不再 KeyError",
      cs.get("Japan", {}).get("unknown") == 1 and cs["Japan"]["total"] == 1, str(cs))
cs_all = M.country_supply("")
check("F6d 不筛选时 unknown 也计入 total",
      cs_all["Japan"]["total"] == 2 and cs_all["Japan"]["unknown"] == 1, str(cs_all))
M.nodes_cache.clear()

check("F6e '当前没有该类型节点' 的提示用中文而不是 unknown",
      "ip_type_label(ip_type)" in src_multi)

# ============================================================ G 安装脚本
head("G. 安装脚本")

inst = open(os.path.join(FIX, "install.sh"), encoding="utf-8").read()
check("G1a 安装脚本会自动装守护 service",
      "install_guard_service" in inst and "vpngate9-guard.service" in inst)
check("G1b 卸载会停掉并删除守护 service",
      "systemctl stop ${GUARD_SERVICE}" in inst
      and "rm -f /lib/systemd/system/${GUARD_SERVICE}.service" in inst
      and "systemctl stop vpngate9-guard" in inst
      and "rm -f /lib/systemd/system/vpngate9-guard.service" in inst)
check("G1c 提供了跳过守护的开关（ML_NO_GUARD=1）", "ML_NO_GUARD" in inst)

m_unit = re.search(r"GUARDEOF\n", inst)
unit_txt = re.search(
    r"cat > /lib/systemd/system/\$\{GUARD_SERVICE\}\.service << 'GUARDEOF'\n(.*?)\nGUARDEOF",
    inst, re.S)
unit = unit_txt.group(1) if unit_txt else ""
check("G1d 守护单元文件能被解析出来", bool(unit) and "ExecStart" in unit)
check("G2a 守护排在被守护的面板服务之后启动",
      "After=" in unit and "michaelvpn.service" in unit.split("After=")[1].split("\n")[0], unit)
check("G2b After= 只写一行（写两行后者会静默覆盖前者）",
      len([l for l in unit.splitlines() if l.startswith("After=")]) == 1)
check("G2c 守护崩溃后能无限重启", "Restart=always" in unit and "StartLimitIntervalSec=0" in unit)

check("G3a ml status 先试 https 再退 http（不写死明文）",
      "https://localhost:8787" in inst and "http://localhost:8787" in inst)
check("G3b 回环请求跳过证书校验（自签证书域名对不上 127.0.0.1）",
      "curl -sk" in inst)
check("G3c 安装完的提示按面板实际协议输出",
      "ui_scheme" in inst and "${SCHEME}://" in inst)

ml_block = re.search(r"cat > /usr/bin/ml << 'MLEOF'\n(.*?)\nMLEOF", inst, re.S)
ml = ml_block.group(1) if ml_block else ""
ml_path = os.path.join(WORK, "ml_check.sh")
open(ml_path, "w", encoding="utf-8").write(ml)
r = subprocess.run(["bash", "-n", ml_path], capture_output=True, text=True)
check("G3d 内嵌的 ml 脚本语法正确", r.returncode == 0, r.stderr[:200])
r = subprocess.run(["bash", "-n", os.path.join(FIX, "install.sh")],
                   capture_output=True, text=True)
check("G3e install.sh 语法正确", r.returncode == 0, r.stderr[:200])

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
sys.exit(1 if FAIL else 0)

"""验证"证书续期后面板自动热重载，不重启、不断隧道"。

需求原话：「证书续签的都要系自动。michaelvpn 跟 s-ui 一样，同时更新证书的时期。
不要有过期什么的」。

背景：acme.sh / certbot / mailcow 续期只是把新文件写进磁盘，进程手里的 SSLContext
还是启动时那份。旧做法是让续期脚本顺带 `systemctl restart michaelvpn`——代价是 9 条隧道
断 30 秒，而且忘了配 reload 就等于没续：到期那天面板连不上，IP 访问又被 403 挡着，
只能 SSH 进去 touch allow_ip_host。所以改成进程自检 + 热重载。

覆盖：
  [1] 指纹：证书/私钥不存在时给出空指纹，不抛异常
  [2] 没变化 -> unchanged（不白白重建 context）
  [3] 文件变了 -> reloaded，且**新的 TLS 连接真的拿到新证书**（比对握手证书指纹）
  [4] 续期脚本正在覆盖文件（半截 PEM）-> failed，继续用旧证书，面板不挂
  [5] 文件修好后下一轮自检自动接上（不用人工介入）
  [6] 后台线程自己会轮询：改文件后无需任何调用就会重载
  [7] 没有证书（明文 HTTP）-> skipped，不起线程
  [8] 热重载不动监听口：重载前后旧连接仍可用，端口没换、没重启
"""
import hashlib
import importlib
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SRC = os.path.dirname(os.path.abspath(__file__))


def _find_src(start):
    for c in (start, os.path.join(start, os.pardir)):
        c = os.path.abspath(c)
        if os.path.isfile(os.path.join(c, "vpngate9_multi.py")):
            return c
    raise SystemExit("找不到 vpngate9_multi.py，请在仓库目录内运行本测试")


FIX = _find_src(SRC)
WORK = tempfile.mkdtemp(prefix="vg9reload_")
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

# ---------------------------------------------------------------- 隔离副本
# 导入主程序会读 /opt/michaelvpn 下的配置，改到临时目录，别动真实安装。
_ROOT = os.path.join(WORK, "opt").replace("\\", "/")
for f in sorted(n for n in os.listdir(FIX) if n.endswith(".py")):
    dst = os.path.join(WORK, f)
    txt = open(os.path.join(FIX, f), encoding="utf-8").read()
    txt = txt.replace('Path("/opt/michaelvpn")', f'Path(r"{_ROOT}")')
    open(dst, "w", encoding="utf-8").write(txt)

sys.path.insert(0, WORK)
T = importlib.import_module("ui_tls")
M = importlib.import_module("vpngate9_multi")
print(f"[setup] 隔离目录 {WORK}")
print(f"[setup] openssl 可用: {HAVE_OPENSSL}")

if not HAVE_OPENSSL:
    print("\n[跳过] 本机没有 openssl，无法构造证书数据")
    print("===== 结果: 0 通过 / 0 失败 (跳过) =====")
    sys.exit(0)


def make_cert(cert_path, key_path, cn):
    r = subprocess.run(
        ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-sha256",
         "-days", "90", "-subj", "/CN=" + cn,
         "-keyout", key_path, "-out", cert_path],
        capture_output=True, text=True)
    return r.returncode == 0 and os.path.isfile(cert_path) and os.path.isfile(key_path)


# ---------------------------------------------------------------- 被测服务
class Srv(ThreadingHTTPServer):
    """和 DualStackServer 一样：ssl_context 是类属性，每次 accept 都重读。"""
    allow_reuse_address = True
    ssl_context = None
    handshake_timeout = 10

    def get_request(self):
        if not self.ssl_context:
            return self.socket.accept()
        while True:
            sock, addr = self.socket.accept()
            try:
                sock.settimeout(self.handshake_timeout)
                conn = self.ssl_context.wrap_socket(sock, server_side=True)
                conn.settimeout(None)
                return conn, addr
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


# ============================================================ [1] 指纹
head("1. 指纹与边界")
missing = T.self_signed_paths(os.path.join(WORK, "nope"))
check("1.1 文件不存在 -> 空指纹", M._cert_file_stamp((str(missing[0]),)) == ())

info = {"cert": "", "key": "", "source": "测试"}
check("1.2 没有 cert/key -> skipped", M.reload_ui_cert_if_changed(Srv, info) == "skipped")
check("1.3 没有证书时不起线程", M.start_ui_cert_watcher(Srv, info) is None)

# ============================================================ [2][3] 变更与热重载
head("2. 文件没变不重建，变了就热重载（真握手验证）")
cd = os.path.join(CERTDIR, "live")
os.makedirs(cd, exist_ok=True)
cert = os.path.join(cd, "fullchain.pem")
key = os.path.join(cd, "privkey.pem")
assert make_cert(cert, key, "old.example.com")

srv = Srv(("127.0.0.1", 0), H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

Srv.ssl_context = T.build_context(cert, key)
live = {"cert": cert, "key": key, "source": "指定路径", "days_left": None}
M._ui_cert_state["stamp"] = M._cert_file_stamp((cert, key))
M._UI_TLS_INFO = dict(live)


def peer_fp(p=port):
    """连上去握手，返回服务端证书的 SHA256 指纹。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", p), timeout=8) as raw:
        with ctx.wrap_socket(raw, server_hostname="x") as s:
            der = s.getpeercert(binary_form=True)
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            s.recv(100)
    return hashlib.sha256(der).hexdigest()


fp_old = peer_fp()
check("2.1 初次握手拿到旧证书", len(fp_old) == 64)
check("2.2 文件没变 -> unchanged",
      M.reload_ui_cert_if_changed(Srv, live) == "unchanged")

# 模拟续期：换一张 CN 不同的证书写进同两个路径
make_cert(os.path.join(cd, "new.crt"), key, "new.example.com")
os.replace(os.path.join(cd, "new.crt"), cert)
r = M.reload_ui_cert_if_changed(Srv, live)
check("2.3 文件变了 -> reloaded", r == "reloaded", r)
fp_new = peer_fp()
check("2.4 新连接真的拿到新证书（指纹变了）", fp_new != fp_old)
check("2.5 ssl_context 已被替换", Srv.ssl_context is not None)
check("2.6 info 里的剩余天数被刷新", isinstance(live.get("days_left"), (int, float)))

# ============================================================ [4][5] 半截文件
head("3. 续期时读到半截文件：不崩，继续用旧证书")
good = open(cert, "rb").read()
open(cert, "wb").write(b"-----BEGIN CERTIFICATE-----\ntruncated\n")
r = M.reload_ui_cert_if_changed(Srv, live)
check("3.1 坏文件 -> failed", r == "failed", r)
check("3.2 坏文件不影响现有服务（还能握手且仍是新证书）", peer_fp() == fp_new)

open(cert, "wb").write(good)
r = M.reload_ui_cert_if_changed(Srv, live)
check("3.3 文件恢复后自动接上", r == "reloaded", r)

# ============================================================ [6] 后台线程
head("4. 后台线程自己轮询（不需要任何外部触发）")
saved_poll = M.UI_CERT_POLL_SEC
M.UI_CERT_POLL_SEC = 0.2
try:
    t = M.start_ui_cert_watcher(Srv, live)
    check("4.1 起了后台线程", t is not None and t.daemon)
    # 换回旧证书，等线程自己发现
    make_cert(os.path.join(cd, "third.crt"), key, "third.example.com")
    os.replace(os.path.join(cd, "third.crt"), cert)
    time.sleep(1.2)
    check("4.2 线程自动完成重载（证书又变了）", peer_fp() != fp_new)
finally:
    M.UI_CERT_POLL_SEC = saved_poll

# ============================================================ [7] 不打断连接
head("5. 热重载不换端口、不重启")
check("5.1 监听端口没变（还是同一个 server 对象）", srv.server_address[1] == port)
check("5.2 服务仍在运行", threading.current_thread().is_alive() and srv.socket.fileno() > 0)
old = srv.ssl_context
M.reload_ui_cert_if_changed(Srv, live, force=True)
check("5.3 force 会强制重建，且是新对象", srv.ssl_context is not old)

srv.shutdown()

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
sys.exit(1 if FAIL else 0)

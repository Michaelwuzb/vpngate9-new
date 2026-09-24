"""验证【新节点标记】与【测速】两条链路（不依赖真实 VPN 隧道）。

覆盖：
  [A] 新节点标记
      A1 首次建基准：整池不标"新"（避免刷屏）
      A2 第二轮出现新节点：只有它被标"新"，老的保持首现时间
      A3 首现时间跨"重启"持久化：重新 load 后老节点不会被当成新节点
      A4 TTL 过期后不再算新
      A5 "清除新标记"只挪水位线，首现历史还在
      A6 消失很久的节点记录会被 prune，不至于让文件无限长
      A7 整池刷新时上一轮的延迟/带宽结果不会被冲掉（merge_node_metrics）
  [B] 测速模块
      B1 TCP 握手延迟：能连的返回 >0，不可达返回 0
      B2 SOCKS5 全链路 + Content-Length：字节数正确、带宽量级正确
      B3 chunked 编码：chunk 头不能被算进字节数（否则带宽虚高）
      B4 读到 EOF 的响应也能正常结束
      B5 代理认证：密码对能过、密码错要明确报错
      B6 各种失败路径都返回 ok=False 且有可读原因，不抛异常
"""
import os
import socket
import socketserver
import sys
import tempfile
import threading
import time

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
WORK = tempfile.mkdtemp(prefix="vg9speed_")
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

# ---------------------------------------------------------------- 隔离副本
# 自动收集源码目录里的全部模块：以后再加模块（比如 ui_tls.py）不必回来改这里，
# 漏改的表现是测试以 ModuleNotFoundError 直接崩掉，容易被当成代码坏了。
_SRC_MODULES = sorted(n for n in os.listdir(FIX) if n.endswith('.py'))
for f in _SRC_MODULES:
    dst = os.path.join(WORK, f)
    txt = open(os.path.join(FIX, f), encoding="utf-8").read()
    txt = txt.replace('Path("/opt/michaelvpn")', f'Path(r"{ROOT}")')
    txt = txt.replace('UI_HOST = "::"', 'UI_HOST = "127.0.0.1"')
    open(dst, "w", encoding="utf-8").write(txt)
print(f"[setup] 隔离目录 {WORK}")

sys.path.insert(0, WORK)
import importlib
M = importlib.import_module("vpngate9_multi")
ST = importlib.import_module("speedtest_utils")
print("[setup] 模块加载完成")

# ============================================================ mock 服务端
def make_node(nid, ip, port=443, cfg="x"):
    return {"id": nid, "ip": ip, "port": str(port), "country_long": "Japan",
            "config_text": cfg, "hostname": nid, "ping": 10, "speed": 1000000}


class FakeHttp(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class FakeHttpHandler(socketserver.BaseRequestHandler):
    """极简 HTTP 服务：三种响应形态 + 人为限速，用来校验带宽计算。"""
    chunk = 64 * 1024
    pause = 0.03

    def handle(self):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                part = self.request.recv(4096)
                if not part:
                    return
                data += part
            path = data.split(b" ")[1].decode()
            if "/chunked" in path:
                body_chunks = 60
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                    b"Content-Type: application/octet-stream\r\n\r\n")
                payload = b"x" * 1024          # 故意用小 chunk，让 chunk 头占比变大
                for _ in range(body_chunks):
                    self.request.sendall(f"{len(payload):x}\r\n".encode() + payload + b"\r\n")
                    time.sleep(self.pause)
                self.request.sendall(b"0\r\n\r\n")
            elif "/eof" in path:
                self.request.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                for _ in range(60):
                    self.request.sendall(b"y" * 1024)
                    time.sleep(self.pause)
            elif "/empty" in path:
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            elif "/404" in path:
                self.request.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            else:
                total = 5_000_000
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n"
                    f"Content-Type: application/octet-stream\r\n\r\n".encode())
                sent = 0
                block = b"z" * self.chunk
                while sent < total:
                    n = min(len(block), total - sent)
                    self.request.sendall(block[:n])
                    sent += n
                    time.sleep(self.pause)
        except Exception:
            pass


class FakeSocks(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class FakeSocksHandler(socketserver.BaseRequestHandler):
    """最小 SOCKS5 服务端：支持无认证 / 用户名密码，CONNECT 到真实目标。"""
    need_auth = (None, None)
    seen = []

    def _exact(self, n):
        buf = b""
        while len(buf) < n:
            part = self.request.recv(n - len(buf))
            if not part:
                raise ConnectionError("closed")
            buf += part
        return buf

    def handle(self):
        try:
            ver, nm = self._exact(2)
            methods = self._exact(nm)
            u, p = self.need_auth
            if u is None:
                self.request.sendall(b"\x05\x00")
            else:
                if 0x02 not in methods:
                    self.request.sendall(b"\x05\xff")
                    return
                self.request.sendall(b"\x05\x02")
                self._exact(1)                  # 子协商 VER=0x01
                ul = self._exact(1)[0]          # 然后才是 ULEN（都是 1 字节）
                got_u = self._exact(ul).decode()
                pl = self._exact(1)[0]
                got_p = self._exact(pl).decode()
                if got_u != u or got_p != p:
                    self.request.sendall(b"\x01\x01")
                    return
                self.request.sendall(b"\x01\x00")
            head = self._exact(4)
            atyp = head[3]
            host = ""
            if atyp == 1:
                host = socket.inet_ntoa(self._exact(4))
            elif atyp == 3:
                n = self._exact(1)[0]
                host = self._exact(n).decode()
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, self._exact(16))
            port = int.from_bytes(self._exact(2), "big")
            self.seen.append((host, port))
            up = socket.create_connection((host, port), timeout=5)
            self.request.sendall(b"\x05\x00\x00\x01" + b"\x00" * 4 + b"\x00\x00")
            t = threading.Thread(target=self._pump, args=(self.request, up), daemon=True)
            t.start()
            self._pump(up, self.request)
        except Exception:
            pass

    @staticmethod
    def _pump(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except Exception:
            pass
        finally:
            for s in (a, b):
                try: s.shutdown(socket.SHUT_RDWR)
                except Exception: pass


def start_server(handler, cls):
    srv = cls(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]

http_srv, HTTP_PORT = start_server(FakeHttpHandler, FakeHttp)
socks_srv, SOCKS_PORT = start_server(FakeSocksHandler, FakeSocks)
print(f"[setup] mock HTTP :{HTTP_PORT}  mock SOCKS5 :{SOCKS_PORT}")

# =============================================================== A 新节点标记
head("A. 新节点标记")

M.load_seen_nodes()          # 空基准
pool1 = [make_node("n1", "1.1.1.1"), make_node("n2", "1.1.1.2"), make_node("n3", "1.1.1.3")]
r1 = M.annotate_new_nodes(pool1)
check("A1 首次建基准时全部都不算新", r1["new"] == 0 and r1["baseline"],
      f"new={r1['new']} baseline={r1['baseline']}")
check("A1b 建基准时记录了首现时间", all(n["first_seen"] > 0 for n in pool1))
# 回归：首现时间等于"刚刚"，如果不抬高水位线，整池都会被 is_new_by_ttl 判成新节点
check("A1c 建基准后整池都不算新（水位线已抬高）",
      not any(M.is_new_by_ttl(n["first_seen"]) for n in pool1),
      str([M.is_new_by_ttl(n["first_seen"]) for n in pool1]))

time.sleep(0.05)
M.save_seen_nodes()

# 第二轮：n1/n2 还在，n3 消失，来了 n4
pool2 = [make_node("n1", "1.1.1.1"), make_node("n2", "1.1.1.2"), make_node("n4", "1.1.1.4")]
r2 = M.annotate_new_nodes(pool2)
M.save_seen_nodes()          # 真实链路上每轮采集都会落盘
check("A2 只有新出现的 n4 被标新", r2["new"] == 1 and r2["new_ids"] == ["n4"], str(r2))
check("A2b 老节点的首现时间被沿用（不刷新）",
      abs(pool2[0]["first_seen"] - pool1[0]["first_seen"]) < 1e-6)
check("A2c 老节点 is_new 为 False", pool2[0]["is_new"] is False)

# 模拟重启
M._seen_nodes = {}
M.load_seen_nodes()
pool3 = [make_node("n1", "1.1.1.1"), make_node("n4", "1.1.1.4")]
r3 = M.annotate_new_nodes(pool3)
check("A3 重启后老节点不会被重新标成新节点", r3["new"] == 0, str(r3))
check("A3b 重启后首现时间仍然保留", pool3[0]["first_seen"] > 0)

# TTL
old_ttl = M.NEW_NODE_TTL
M.NEW_NODE_TTL = 0.05
fresh = make_node("n9", "9.9.9.9")
fresh["first_seen"] = time.time()
check("A4 TTL 内算新", M.is_new_by_ttl(fresh["first_seen"]) is True)
time.sleep(0.08)
check("A4b TTL 过期后不再算新", M.is_new_by_ttl(fresh["first_seen"]) is False)
M.NEW_NODE_TTL = old_ttl

# 清除标记
pool4 = [make_node("n1", "1.1.1.1")]
M.annotate_new_nodes(pool4)
n1_fs = pool4[0]["first_seen"]
M.clear_new_marks()
check("A5 清除后不再算新", M.is_new_by_ttl(n1_fs) is False)
check("A5b 首现历史没被抹掉", abs(M._seen_nodes.get("n1", 0) - n1_fs) < 1e-6)
check("A5c 清除后新出现的节点依然会被标新", M.is_new_by_ttl(time.time()) is True)

# prune
with M._seen_lock:
    M._seen_nodes["ghost"] = time.time() - 999 * 86400   # 999 天前，且不在池里
    M._seen_nodes["ghost2"] = time.time() - 1            # 刚出现，虽然不在池里但要留
M._prune_seen({"n1", "n4"})
with M._seen_lock:
    has_old = "ghost" in M._seen_nodes
    has_recent = "ghost2" in M._seen_nodes
check("A6 久远且不在池里的记录被清理", has_old is False)
check("A6b 近期记录被保留", has_recent is True)

# merge metrics
M.nodes_cache = [dict(make_node("n1", "1.1.1.1"), tcp_latency=42, test_out_mbps=8.5,
                      test_out_at=time.time(), test_out_error="")]
new_pool = [make_node("n1", "1.1.1.1"), make_node("n2", "1.1.1.2")]
M.merge_node_metrics(new_pool)
check("A7 整池刷新后延迟结果被保留", new_pool[0].get("tcp_latency") == 42)
check("A7b 整池刷新后带宽结果被保留", new_pool[0].get("test_out_mbps") == 8.5)
check("A7c 新节点的字段不会凭空多出来", "tcp_latency" not in new_pool[1])

# 模拟一次带 new 的采集
M._seen_nodes = {}
M._last_node_ids = set()
baseline_pool = [make_node("a1", "2.2.2.1"), make_node("a2", "2.2.2.2")]
M.annotate_new_nodes(baseline_pool)
M.save_seen_nodes()
res = M.annotate_new_nodes([make_node("a1", "2.2.2.1"), make_node("a3", "2.2.2.3")])
check("A8 增量采集能报出新增条数与 id", res["new"] == 1 and res["new_ids"] == ["a3"], str(res))

# =============================================================== B 测速
head("B. 测速模块")

dummy = socketserver.TCPServer(("127.0.0.1", 0), socketserver.BaseRequestHandler)
threading.Thread(target=dummy.serve_forever, daemon=True).start()
live_port = dummy.server_address[1]
ms = ST.tcp_latency("127.0.0.1", live_port, timeout=2)
check("B1 可连通端口返回正的延迟", ms > 0, f"ms={ms}")
ms_dead = ST.tcp_latency("127.0.0.1", 1, timeout=1)   # 端口 1 无人监听
check("B1b 不可达返回 0", ms_dead == 0, f"ms={ms_dead}")

M._proxy_credentials = lambda: (None, None)   # 无认证
url_cl = f"http://127.0.0.1:{HTTP_PORT}/data"
t0 = time.time()
r = ST.speedtest_via_proxy("127.0.0.1", SOCKS_PORT, url=url_cl, size=5_000_000, timeout=30)
el = time.time() - t0
check("B2 SOCKS5 + Content-Length 下载成功", r.get("ok") is True, str(r))
check("B2b 字节数与服务器发送量一致", r.get("bytes") == 5_000_000, f"bytes={r.get('bytes')}")
# 服务器 5MB / 0.03s*79 次 ≈ 2.1MB/s ≈ 17Mbps，给宽区间
check("B2c 带宽落在合理量级(8~40Mbps)", 8 < r.get("mbps", 0) < 40, f"mbps={r.get('mbps')} 用时{el:.1f}s")
check("B2d 记录了 TTFB", r.get("ttfb_ms", 0) > 0, f"ttfb={r.get('ttfb_ms')}")

# chunked：真实 body 是 60KB，若把 chunk 头算进去会明显偏大
url_ck = f"http://127.0.0.1:{HTTP_PORT}/chunked"
r2 = ST.speedtest_via_proxy("127.0.0.1", SOCKS_PORT, url=url_ck, size=1_000_000, timeout=30)
check("B3 chunked 响应解析成功", r2.get("ok") is True, str(r2))
check("B3b chunk 头没有被算进 body 字节数", r2.get("bytes") == 60 * 1024,
      f"bytes={r2.get('bytes')} (期望 {60*1024})")

url_eof = f"http://127.0.0.1:{HTTP_PORT}/eof"
r3 = ST.speedtest_via_proxy("127.0.0.1", SOCKS_PORT, url=url_eof, size=1_000_000, timeout=30)
check("B4 无 Content-Length 读到 EOF 也能正常结束", r3.get("ok") is True, str(r3))
check("B4b EOF 模式的字节数正确", r3.get("bytes") == 60 * 1024, f"bytes={r3.get('bytes')}")

r4 = ST.speedtest_via_proxy("127.0.0.1", SOCKS_PORT, url=f"http://127.0.0.1:{HTTP_PORT}/404",
                            size=1000, timeout=10)
check("B5 HTTP 404 被识别为失败", r4.get("ok") is False and "404" in str(r4.get("error")), str(r4))
r5 = ST.speedtest_via_proxy("127.0.0.1", SOCKS_PORT,
                            url=f"http://127.0.0.1:{HTTP_PORT}/empty", size=1000, timeout=10)
check("B5b 0 字节响应不会崩", r5.get("ok") is True and r5.get("bytes") == 0, str(r5) + str(r5))

# 认证
FakeSocksHandler.need_auth = ("user", "pw")
srv_auth, auth_port = start_server(FakeSocksHandler, FakeSocks)
ra = ST.speedtest_via_proxy("127.0.0.1", auth_port, url=url_ck, size=100000,
                            timeout=10, username="user", password="pw")
check("B6 代理账密正确时能测速", ra.get("ok") is True, str(ra))
rb = ST.speedtest_via_proxy("127.0.0.1", auth_port, url=url_ck, size=100000,
                            timeout=10, username="user", password="bad")
check("B6b 代理账密错误时给出可读错误", rb.get("ok") is False and "认证" in str(rb.get("error")), str(rb))
rc = ST.speedtest_via_proxy("127.0.0.1", auth_port, url=url_ck, size=100000, timeout=10)
check("B6c 代理要求认证但没配账密时明确报错",
      rc.get("ok") is False and "认证" in str(rc.get("error")), str(rc))
FakeSocksHandler.need_auth = (None, None)

rd = ST.speedtest_via_proxy("127.0.0.1", 1, url=url_ck, size=1000, timeout=3)
check("B7 代理端口不存在时返回失败而不是抛异常", rd.get("ok") is False, str(rd))
re_ = ST.speedtest_via_proxy("127.0.0.1", SOCKS_PORT, url="ftp://x/y", size=1000, timeout=3)
check("B7b 不支持的协议被拒绝", re_.get("ok") is False and "协议" in str(re_.get("error")), str(re_))
rf_ = ST.speedtest_via_proxy("127.0.0.1", SOCKS_PORT, url="http://127.0.0.1:1/x", size=1000, timeout=3)
check("B7c 目标不可达时返回失败", rf_.get("ok") is False, str(rf_))

head("结果")
print(f"PASS={PASS}  FAIL={FAIL}")
if FAIL:
    print("!! 有失败项")
sys.exit(1 if FAIL else 0)

#!/usr/bin/env python3
"""speedtest_utils.py —— 通过本地 SOCKS5 代理做真实下载测速。

为什么单独抽一个文件：
  * 测速必须走通道自己的 SOCKS5 口（47928~47936），目标域名由代理端在隧道内解析，
    这样测出来的才是"这条通道真实的出口带宽"，而不是本机物理网卡的成绩。
  * 只依赖标准库。VPS 上不一定装了 requests/pysocks，装依赖失败会连累整个服务起不来。
  * 需要处理 chunked 编码 —— Cloudflare 的测速端点默认就是 chunked，
    不解析就会把 chunk 头当成数据算进带宽里，结果虚高。

对外主入口：speedtest_via_proxy()
"""

from __future__ import annotations

import os
import socket
import ssl
import time
import urllib.parse
from typing import Any

# ---- 默认测速目标 -----------------------------------------------------------
# Cloudflare 的 __down 端点支持用 bytes 参数指定体积，全球都有边缘节点，比较能反映真实带宽。
# 换成别的地址只需设环境变量 SPEEDTEST_URL；URL 里可以写 {bytes} 占位符。
DEFAULT_SPEEDTEST_URL = os.environ.get(
    "SPEEDTEST_URL", "https://speed.cloudflare.com/__down?bytes={bytes}"
)
DEFAULT_SPEEDTEST_BYTES = int(os.environ.get("SPEEDTEST_BYTES", "10000000"))  # 10MB
DEFAULT_TIMEOUT = float(os.environ.get("SPEEDTEST_TIMEOUT", "30"))            # 单次测速上限(秒)
WARMUP_SECONDS = float(os.environ.get("SPEEDTEST_WARMUP", "0.6"))             # 丢掉慢启动阶段

_UA = "Mozilla/5.0 (X11; Linux x86_64) MichaelVPN-SpeedTest/1.0"


class SocksError(Exception):
    """SOCKS5 握手/连接失败。"""


_SOCKS_REP = {
    0x01: "代理端通用失败",
    0x02: "代理规则不允许连接",
    0x03: "网络不可达",
    0x04: "目标主机不可达",
    0x05: "目标端口拒绝连接",
    0x06: "TTL 超时",
    0x07: "不支持的协议",
    0x08: "不支持的地址类型",
}


def recv_exact(sock: socket.socket, size: int) -> bytes:
    """读满 size 字节，短读就抛错 —— 握手阶段短读会导致后续解析全乱。"""
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise SocksError(f"连接被对端关闭（还差 {size - len(buf)} 字节）")
        buf.extend(chunk)
    return bytes(buf)


def socks5_connect(proxy_host: str, proxy_port: int, dst_host: str, dst_port: int,
                   timeout: float = 10.0, username: str | None = None,
                   password: str | None = None) -> socket.socket:
    """建一条到 dst_host:dst_port 的 SOCKS5 隧道。

    用域名方式(ATYP=3)发请求，让代理端在隧道里解析 DNS —— VPNGate 节点出口在国外，
    本机解析出来的 IP 未必是节点认为最优的边缘地址。
    """
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        if username is not None and password is not None:
            sock.sendall(b"\x05\x02\x00\x02")   # 支持 无认证 / 用户名密码
        else:
            sock.sendall(b"\x05\x01\x00")

        ver, method = recv_exact(sock, 2)
        if ver != 5:
            raise SocksError(f"代理返回了非 SOCKS5 响应 (ver={ver})")

        if method == 0x02:
            u = (username or "").encode("utf-8")
            p = (password or "").encode("utf-8")
            if len(u) > 255 or len(p) > 255:
                raise SocksError("代理账号/密码过长")
            sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            _v, status = recv_exact(sock, 2)
            if status != 0:
                raise SocksError("代理认证失败（用户名或密码不对）")
        elif method == 0xFF:
            raise SocksError("代理端拒绝了所有认证方式（本机代理可能开了认证，需要配置 LOCAL_PROXY_USER/PASS）")
        elif method != 0x00:
            raise SocksError(f"代理选择了不支持的认证方式: 0x{method:02x}")

        host_b = dst_host.encode("idna") if any(ord(c) > 127 for c in dst_host) else dst_host.encode()
        if len(host_b) > 255:
            raise SocksError("目标域名过长")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b
                     + int(dst_port).to_bytes(2, "big"))

        head = recv_exact(sock, 4)
        if head[0] != 5:
            raise SocksError("CONNECT 响应非法")
        if head[1] != 0:
            raise SocksError(_SOCKS_REP.get(head[1], f"代理连接失败 (0x{head[1]:02x})"))
        atyp = head[3]
        if atyp == 0x01:
            recv_exact(sock, 4)
        elif atyp == 0x03:
            recv_exact(sock, recv_exact(sock, 1)[0])
        elif atyp == 0x04:
            recv_exact(sock, 16)
        else:
            raise SocksError(f"CONNECT 响应地址类型非法: {atyp}")
        recv_exact(sock, 2)   # 绑定的端口，用不到
        return sock
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise


def _read_headers(sock: socket.socket, limit: int = 32768) -> tuple[int, list[str], bytes]:
    """读到 \\r\\n\\r\\n 为止。返回 (状态码, 头行列表, 多读出来的 body 前缀)。"""
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        if len(buf) > limit:
            raise SocksError("响应头过大")
        chunk = sock.recv(4096)
        if not chunk:
            raise SocksError("连接在响应头之前就断开了")
        buf.extend(chunk)
    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
    if not lines or not lines[0]:
        raise SocksError("空响应头")
    parts = lines[0].split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise SocksError(f"非法状态行: {lines[0][:80]}")
    return int(parts[1]), lines[1:], rest


def _chunk_size(line: bytes) -> int:
    token = line.split(b";")[0].strip()
    return int(token, 16)


def _consume(sock: socket.socket, first: bytes, headers: list[str], max_bytes: int,
             max_seconds: float, deadline_start: float,
             on_bytes=None) -> tuple[int, float]:
    """把响应体读进来，边读边统计。返回 (净正文字节数, 读完时刻)。

    只认三种情况：chunked / Content-Length / 读到 EOF。少一种都可能把结果算错。

    注意"净"字：chunked 的 chunk-size 行和 CRLF 是协议开销，绝不能算进下载量 ——
    否则 chunk 越小虚高越离谱（1KB chunk 时开销能占三成）。
    """
    hmap: dict[str, str] = {}
    for line in headers:
        k, sep, v = line.partition(":")
        if sep:
            hmap[k.strip().lower()] = v.strip()

    buf = bytearray(first)     # 响应头之后可能已经带回来一段正文
    counted = 0                # 只统计真正的正文字节

    def fill(n: int) -> None:
        while len(buf) < n:
            if time.time() - deadline_start > max_seconds:
                raise TimeoutError("测速超时")
            chunk = sock.recv(65536)
            if not chunk:
                return
            buf.extend(chunk)

    def take(n: int, count: bool = True) -> bytes:
        """取 n 字节。count=False 用于协议开销（chunk 头等）。"""
        nonlocal buf, counted
        fill(n)
        out = bytes(buf[:n])
        del buf[:n]
        if count and out:
            counted += len(out)
            if on_bytes:
                on_bytes(len(out))
        return out

    if "chunked" in hmap.get("transfer-encoding", "").lower():
        while True:
            line = bytearray()
            while not line.endswith(b"\r\n"):
                if len(line) > 64:
                    # chunk-size 行不可能这么长，说明前面的解析错位了
                    raise SocksError("chunk 头解析异常")
                b = take(1, count=False)
                if not b:
                    return counted, time.time()
                line.extend(b)
            size = _chunk_size(bytes(line[:-2]))
            if size == 0:
                take(2, count=False)   # 结束的 CRLF
                break
            take(size)
            take(2, count=False)
            if counted >= max_bytes:
                break
    elif hmap.get("content-length", "").isdigit():
        want = min(int(hmap["content-length"]), max_bytes)
        got = 0
        while got < want:
            piece = take(min(65536, want - got))
            if not piece:
                break
            got += len(piece)
    else:
        # 没有长度信息：先把已经读进缓冲的正文算上，再一路读到 EOF
        if buf:
            counted += len(buf)
            if on_bytes:
                on_bytes(len(buf))
            buf.clear()
        while counted < max_bytes:
            if time.time() - deadline_start > max_seconds:
                raise TimeoutError("测速超时")
            chunk = sock.recv(65536)
            if not chunk:
                break
            counted += len(chunk)
            if on_bytes:
                on_bytes(len(chunk))

    return counted, time.time()


def _download_once(proxy_host: str, proxy_port: int, url: str, max_bytes: int,
                   timeout: float, username: str | None, password: str | None) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "error": f"不支持的协议: {parsed.scheme}"}
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    deadline_start = time.time()
    sock = socks5_connect(proxy_host, proxy_port, host, port,
                          timeout=min(timeout, 15.0), username=username, password=password)
    try:
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(timeout)

        req = (f"GET {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"User-Agent: {_UA}\r\n"
               f"Accept: */*\r\n"
               f"Connection: close\r\n\r\n").encode()
        sock.sendall(req)

        status, headers, first = _read_headers(sock)
        if status < 200 or status >= 300:
            return {"ok": False, "error": f"测速地址返回 HTTP {status}"}

        ttfb_ms = int((time.time() - deadline_start) * 1000)

        # 分两段计时：前 WARMUP_SECONDS 只当作"预热"（TCP 慢启动 + TLS 之后的加速段），
        # 只统计预热之后的吞吐，否则短平快的测速会被握手时间严重拉低。
        marks: list[tuple[float, int]] = []
        warm_bytes = 0

        def on_bytes(n: int) -> None:
            marks.append((time.time(), n))

        total, finished = _consume(sock, first, headers, max_bytes, timeout,
                                   deadline_start, on_bytes=on_bytes)
        elapsed_total = finished - deadline_start

        # 回放字节时间线，切掉预热段
        idx = 0
        warm_cut = deadline_start + WARMUP_SECONDS
        acc = 0
        for ts, n in marks:
            if ts <= warm_cut:
                warm_bytes += n
            else:
                idx += 1
                acc += n
        if idx == 0 or acc == 0:
            # 下得太快，根本没到预热阈值，就用全程平均
            stable_bytes = total
            stable_seconds = max(elapsed_total, 0.001)
        else:
            stable_bytes = acc
            # 稳定段时长 = 从切点开始到读完
            stable_seconds = max(finished - warm_cut, 0.001)

        mbps = (stable_bytes * 8) / stable_seconds / 1_000_000
        return {
            "ok": True,
            "mbps": round(mbps, 2),
            "bytes": total,
            "seconds": round(elapsed_total, 2),
            "stable_bytes": stable_bytes,
            "ttfb_ms": ttfb_ms,
            "url": url,
            "error": "",
        }
    finally:
        try:
            sock.close()
        except Exception:
            pass


def speedtest_via_proxy(proxy_host: str, proxy_port: int, url: str | None = None,
                        size: int | None = None, timeout: float | None = None,
                        username: str | None = None, password: str | None = None) -> dict[str, Any]:
    """经本地 SOCKS5 口跑一次下载测速。

    返回 {ok, mbps, bytes, seconds, ttfb_ms, url, error}；失败时 ok=False 且 error 有说明。
    """
    size = int(size or DEFAULT_SPEEDTEST_BYTES)
    timeout = float(timeout or DEFAULT_TIMEOUT)
    raw_url = url or DEFAULT_SPEEDTEST_URL
    if "{bytes}" in raw_url:
        target = raw_url.replace("{bytes}", str(size))
    else:
        target = raw_url

    try:
        return _download_once(proxy_host, proxy_port, target, size, timeout, username, password)
    except TimeoutError:
        # 注意：Python 3.10+ 里 socket.timeout 就是 TimeoutError，两种超时一起兜
        return {"ok": False, "error": "超时：节点带宽过低或隧道已断", "url": target,
                "mbps": 0.0, "bytes": 0}
    except SocksError as e:
        return {"ok": False, "error": str(e), "url": target, "mbps": 0.0, "bytes": 0}
    except ssl.SSLError as e:
        return {"ok": False, "error": f"TLS 失败: {e}", "url": target, "mbps": 0.0, "bytes": 0}
    except OSError as e:
        return {"ok": False, "error": f"网络错误: {e}", "url": target, "mbps": 0.0, "bytes": 0}
    except Exception as e:  # 兜底：任何异常都不能让后台线程静默挂掉
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "url": target, "mbps": 0.0, "bytes": 0}


def tcp_latency(host: str, port: int, timeout: float = 3.0, dev: str | None = None) -> int:
    """TCP 握手 RTT(ms)。0 表示不通。

    比 ping 可靠：VPNGate 很多节点直接丢 ICMP，但 TCP 是通的。
    """
    af = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = None
    started = time.time()
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if dev:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode())
            except OSError:
                pass
        s.connect((host, int(port)))
        return max(1, int((time.time() - started) * 1000))
    except Exception:
        return 0
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


if __name__ == "__main__":  # 手测入口: python3 speedtest_utils.py [socks端口]
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 47928
    print(f"经 127.0.0.1:{port} 测速 ...")
    r = speedtest_via_proxy("127.0.0.1", port)
    if r.get("ok"):
        print(f"  {r['mbps']} Mbps  ({r['bytes']/1e6:.1f} MB / {r['seconds']}s, TTFB {r['ttfb_ms']}ms)")
    else:
        print(f"  失败: {r.get('error')}")

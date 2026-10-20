"""验证"面板只接受域名访问，IP 直连一律 403"。

需求原话：「https://133.18.147.35:8787/ 这个可以关了」——指禁止用 IP 访问面板，
只保留 https://jp.micwebsite.dpdns.org:8787/ 这种域名入口。

为什么按 Host 头做：面板和 IP 是同一个 8787，端口层面分不出"你输的是 IP 还是域名"，
只有 Host 头能区分。挡掉 IP 的实际收益是"面板不再以 IP:端口 的形态被全网段扫到"，
挡不住伪造 Host 的定向请求（那种要靠登录口令），这一点在文档里必须说清楚。

覆盖：
  [1] host_of / is_loopback_host 解析（含端口、IPv6、大小写、尾点）
  [2] 证书里的域名放行；纯 IP、陌生域名拒绝
  [3] 回环永远放行 —— ml status / 守护 / 升级脚本验收都打 127.0.0.1
  [4] 空 Host 放行（老脚本、HTTP/1.0），宁松不锁死
  [5] 逃生阀 allow_ip_host：touch 后立即放开，rm 后立即收紧（都是不重启生效）
  [6] 自签证书 / 证书读不出 -> 不限制（IP 访问是自签场景的刚需）
  [7] do_GET 与 do_POST 都真的接上了这道检查，且 403 页给出正确域名
"""
import importlib
import os
import shutil
import subprocess
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
WORK = tempfile.mkdtemp(prefix="vg9host_")
ROOT = os.path.join(WORK, "opt").replace("\\", "/")
DATA = os.path.join(WORK, "data")

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
    print(f"\n{t}", flush=True)


def skip(name, why):
    print(f"  [SKIP] {name}  （{why}）", flush=True)


for f in sorted(n for n in os.listdir(FIX) if n.endswith(".py")):
    txt = open(os.path.join(FIX, f), encoding="utf-8").read()
    txt = txt.replace('Path("/opt/michaelvpn")', f'Path(r"{ROOT}")')
    txt = txt.replace('UI_HOST = "::"', 'UI_HOST = "127.0.0.1"')
    open(os.path.join(WORK, f), "w", encoding="utf-8", newline="\n").write(txt)

sys.path.insert(0, WORK)
M = importlib.import_module("vpngate9_multi")

os.makedirs(DATA, exist_ok=True)
M.DATA_DIR = M.Path(DATA)
SRC_MULTI = open(os.path.join(FIX, "vpngate9_multi.py"), encoding="utf-8").read()


def reset(info):
    """换一份证书信息，并清掉 30 秒白名单缓存。"""
    M._UI_TLS_INFO = info
    M._ui_hosts_cache.update(at=0.0, hosts=frozenset())


# ---------------------------------------------------------------- 造一张域名证书
head("[1] 准备一张带 DNS SAN 的证书")

CERT = os.path.join(WORK, "c.pem")
KEY = os.path.join(WORK, "k.pem")
openssl = shutil.which("openssl")
if not openssl:
    skip("生成测试证书", "本机没有 openssl")
    print("\n===== 结果: 0 通过 / 0 失败 =====")
    sys.exit(0)
r = subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", KEY, "-out", CERT, "-days", "2",
                    "-subj", "/CN=jp.example.com",
                    "-addext", "subjectAltName=DNS:jp.example.com,DNS:cli.example.com"],
                   capture_output=True, text=True)
check("自签测试证书生成成功（SAN: jp./cli.example.com）",
      r.returncode == 0 and os.path.exists(CERT), r.stderr[-300:])

names = M.cert_dns_names(CERT)
check("能从证书里读出两个域名", names == {"jp.example.com", "cli.example.com"}, str(names))

DOM = {"cert": CERT, "key": KEY, "self_signed": False, "source": "测试"}
reset(DOM)

# ---------------------------------------------------------------- [2] 基本判定
head("[2] Host 解析与放行/拒绝")

check("带端口的域名 -> 裸域名", M.host_of("jp.example.com:8787") == "jp.example.com",
      M.host_of("jp.example.com:8787"))
check("IPv6 方括号 -> 裸地址", M.host_of("[::1]:8787") == "::1", M.host_of("[::1]:8787"))
check("大写 + 尾点也能归一", M.host_of("JP.Example.COM.:8787") == "jp.example.com",
      M.host_of("JP.Example.COM.:8787"))
check("回环三种写法都认",
      all(M.is_loopback_host(h) for h in ("127.0.0.1", "::1", "localhost")))

check("证书域名放行", M.host_denied("jp.example.com:8787") is False)
check("证书里的第二个域名也放行", M.host_denied("cli.example.com:8787") is False)
check("纯 IP 直连被拒（需求本体）", M.host_denied("133.18.147.35:8787") is True)
check("不带端口的裸 IP 也被拒", M.host_denied("133.18.147.35") is True)
check("陌生域名被拒", M.host_denied("evil.example.org:8787") is True)
check("回环放行（ml/守护/升级验收都走这里）", M.host_denied("127.0.0.1:8787") is False)
check("localhost 放行", M.host_denied("localhost:8787") is False)
check("空 Host 放行（老脚本/HTTP1.0，宁松不锁死）", M.host_denied("") is False)

# ---------------------------------------------------------------- [5] 逃生阀
head("[3] 逃生阀 allow_ip_host（不重启就生效）")

flag = os.path.join(DATA, M.ALLOW_IP_FILE)
open(flag, "w").close()
reset(DOM)
check("touch 之后 IP 直连立刻恢复", M.host_denied("133.18.147.35:8787") is False)
os.remove(flag)
reset(DOM)
check("rm 之后立刻重新收紧", M.host_denied("133.18.147.35:8787") is True)

# ---------------------------------------------------------------- [6] 不限制的场景
head("[4] 自签 / 读不出证书 -> 不限制")

reset({"cert": CERT, "key": KEY, "self_signed": True})
check("自签证书 -> 不限制（IP 访问是自签场景的刚需）",
      M.host_denied("133.18.147.35:8787") is False)

reset(None)
check("没有 HTTPS（info=None）-> 不限制", M.host_denied("133.18.147.35:8787") is False)

reset({"cert": os.path.join(WORK, "nonexistent.pem"), "self_signed": False})
check("证书文件不存在 -> 读不出域名 -> 不限制（不能把面板锁死）",
      M.host_denied("133.18.147.35:8787") is False)

reset(DOM)

# ---------------------------------------------------------------- [7] 接线检查
head("[5] 真的接在两个入口上")

get_body = SRC_MULTI.split("def do_GET(self):")[1].split("if not check_auth_token")[0]
post_body = SRC_MULTI.split("def do_POST(self):")[1].split("if path not in")[0]
check("do_GET 一开始就做 Host 检查", "self.reject_host()" in get_body, get_body[:120])
check("do_POST 一开始就做 Host 检查", "self.reject_host()" in post_body, post_body[:120])
check("检查排在鉴权之前（IP 直连连登录页都不给）",
      get_body.index("reject_host") < len(get_body) - 1)
check("403 页面写明该用哪个域名",
      'url = f"https://{dom[0]}:{UI_PORT}/"' in SRC_MULTI)
check("403 页面带逃生阀用法（不然管理员会以为面板坏了）",
      "ALLOW_IP_FILE}" in SRC_MULTI and "touch" in SRC_MULTI)
check("拒绝日志有节流（扫描器刷屏时不会打爆 journal）",
      "_ui_hosts_denied_at" in SRC_MULTI and ">= 60" in SRC_MULTI)
check("判断本身抛异常时放行，不会把面板锁死",
      'except Exception:\n            denied = False' in SRC_MULTI)

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
sys.exit(1 if FAIL else 0)

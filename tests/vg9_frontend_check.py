"""校验内联前端：两个 script 块的语法，以及这次新增的交互函数是否都在。

为什么要单独查一遍：面板的 HTML/JS 全是一个大字符串，Python 语法检查盖不到它，
少个括号只有浏览器打开才发现。用 node --check 提前拦住。
"""
import os
import re
import subprocess
import sys
import tempfile

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
WORK = tempfile.mkdtemp(prefix="vg9js_")
ROOT = os.path.join(WORK, "opt").replace("\\", "/")

# 自动收集源码目录里的全部模块：以后再加模块（比如 ui_tls.py）不必回来改这里，
# 漏改的表现是测试以 ModuleNotFoundError 直接崩掉，容易被当成代码坏了。
_SRC_MODULES = sorted(n for n in os.listdir(FIX) if n.endswith('.py'))
for f in _SRC_MODULES:
    txt = open(os.path.join(FIX, f), encoding="utf-8").read()
    txt = txt.replace('Path("/opt/michaelvpn")', 'Path(r"%s")' % ROOT)
    txt = txt.replace('UI_HOST = "::"', 'UI_HOST = "127.0.0.1"')
    open(os.path.join(WORK, f), "w", encoding="utf-8").write(txt)

sys.path.insert(0, WORK)
import vpngate9_multi as M      # noqa: E402

html = M.PAGE_HTML.replace("{channels_json}", "[]")
scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
print(f"script 块数: {len(scripts)}")

ok = True
for i, s in enumerate(scripts):
    p = os.path.join(WORK, f"s{i}.js")
    open(p, "w", encoding="utf-8").write(s)
    r = subprocess.run(["node", "--check", p], capture_output=True, text=True)
    print(f"  block{i}: {'语法 OK' if r.returncode == 0 else '语法错误'}")
    if r.returncode != 0:
        ok = False
        print(r.stderr[:1500])

NEED = ["fmtAge", "fmtBps", "ckNode", "toggleAllNodes", "checkedIds", "nodePing",
        "nodeSpeed", "stopSpeed", "clearNew", "chSpeed", "chSpeedAll", "updateJobs"]
for name in NEED:
    present = f"function {name}(" in html
    print(f"  {name:<16} {'已定义' if present else '!! 缺失'}")
    ok = ok and present

# 关键元素/文案
for kw in ("测延迟", "测带宽", "清除新标记", "通道测速", "只看新节点", "实测带宽",
           "实测延迟", "发现时间", 'class="cb"', "bnw", "job_bar"):
    present = kw in html
    print(f"  {kw:<12} {'已就位' if present else '!! 缺失'}")
    ok = ok and present

# 回调都得能对上：onclick 里引用的函数必须存在
for fn in set(re.findall(r'onclick="([A-Za-z_$][\w$]*)\(', html)):
    present = f"function {fn}(" in html
    if not present:
        print(f"  !! onclick 引用了不存在的函数: {fn}")
        ok = False

print("\n结果:", "全部通过" if ok else "存在问题")
sys.exit(0 if ok else 1)

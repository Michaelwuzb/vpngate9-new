"""验证守护服务（vpngate9-guard）的两件事：默认不主动轮换、老机器可单独补装。

背景（用户实际遇到的现象）：
    三台机器升级后，只有最新全量安装的那台显示「守护 vpngate9-guard: active」，
    另外两台显示「未安装」。原因不是升级失败，而是早期 install.sh 还不带这个
    systemd 单元，而升级脚本只换代码、不动 systemd。

顺带发现的行为问题：
    ROTATE_EVERY 默认 30（60 秒一轮 → 每 30 分钟把 9 条通道的出口 IP 全部换一遍），
    会把已经稳定跑着的住宅 IP 打乱，也让「锁定在某县」的通道被迫重选。
    默认改成 0（只在假连接/连不上时动手），想轮换的显式给环境变量。

覆盖：
  [1] 默认值 = 0（不主动轮换）
  [2] 环境变量覆盖：30 生效；0/空/非数字/负数 一律安全回落到 0
  [3] 轮换判定的短路：ROTATE_EVERY=0 时不会算模（也不会 ZeroDivisionError）
  [4] install.sh 的 unit 带 Environment=VPNGATE_ROTATE_EVERY=0
  [5] install.sh 支持 --guard-only：只写单元+重启，不碰依赖/代码/数据
  [6] --guard-only 找不到守护脚本时报错退出，不假装成功
  [7] 升级脚本在「未安装」时给出可执行的补装命令（而不是含糊的"可忽略"）
"""
import os
import re
import subprocess
import sys

SRC = os.path.dirname(os.path.abspath(__file__))


def _find_src(start):
    for c in (start, os.path.join(start, os.pardir)):
        c = os.path.abspath(c)
        if os.path.isfile(os.path.join(c, "vpngate9_guard.py")):
            return c
    raise SystemExit("找不到 vpngate9_guard.py，请在仓库目录内运行本测试")


FIX = _find_src(SRC)
GUARD = os.path.join(FIX, "vpngate9_guard.py")
INSTALL = os.path.join(FIX, "install.sh")
UPGRADE = os.path.join(FIX, "vg9_server_upgrade.sh")

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


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def guard_var(env_value):
    """在子进程里读一遍 ROTATE_EVERY —— 直接比对"进程最终看到的值"，
    而不是去 grep 源码文本（那种断言挡不住写错的解析逻辑）。"""
    env = {k: v for k, v in os.environ.items() if k != "VPNGATE_ROTATE_EVERY"}
    if env_value is not None:
        env["VPNGATE_ROTATE_EVERY"] = env_value
    r = subprocess.run(
        [sys.executable, "-c", "import vpngate9_guard as g; print(g.ROTATE_EVERY)"],
        cwd=FIX, env=env, capture_output=True, text=True,
    )
    if r.returncode != 0:
        return f"<崩溃: {r.stderr.strip().splitlines()[-1] if r.stderr.strip() else '?'}>"
    return r.stdout.strip()


# ============================================================ [1] 默认值
head("[1] 默认不主动轮换")
check("不给环境变量时 ROTATE_EVERY = 0", guard_var(None) == "0",
      f"实际 {guard_var(None)}")

# ============================================================ [2] 环境变量
head("[2] 环境变量覆盖（含脏值兜底）")
check("=30 -> 30（想要主动轮换的人能开回来）", guard_var("30") == "30", guard_var("30"))
check("=0 -> 0", guard_var("0") == "0", guard_var("0"))
check("空字符串 -> 0（不崩）", guard_var("") == "0", guard_var(""))
check("非数字 abc -> 0（不崩）", guard_var("abc") == "0", guard_var("abc"))
check("负数 -5 -> 0（不崩、不当成每轮都换）", guard_var("-5") == "0", guard_var("-5"))
check("带空格 ' 7 ' -> 7（systemd 里手写容易多空格）", guard_var(" 7 ") == "7", guard_var(" 7 "))

# ============================================================ [3] 短路
head("[3] 轮换判定的短路保护")
src = read(GUARD)
check("判定处保留 ROTATE_EVERY > 0 的短路（0 时不做 % 运算）",
      re.search(r"ROTATE_EVERY\s*>\s*0\s+and\s+.*ROTATE_EVERY", src) is not None)

# 直接从源码里把判定表达式抠出来 eval —— 模拟真实那行，而不是另写一份等价逻辑
_line = next((l for l in src.splitlines() if "do_rotate" in l and "=" in l), "")
_expr = _line.split("=", 1)[1].strip() if _line else ""
try:
    _off = eval(_expr, {"ROTATE_EVERY": 0, "round_n": 30})       # noqa: S307
except Exception as e:                                            # noqa: BLE001
    _off = f"<抛异常 {type(e).__name__}>"
try:
    _on = eval(_expr, {"ROTATE_EVERY": 30, "round_n": 30})       # noqa: S307
except Exception as e:                                            # noqa: BLE001
    _on = f"<抛异常 {type(e).__name__}>"
check("ROTATE_EVERY=0 时第 30 轮不轮换（且不抛 ZeroDivisionError）", _off is False,
      f"实际 {_off!r}，表达式 {_expr!r}")
check("ROTATE_EVERY=30 时第 30 轮仍会轮换（功能没被删掉）", _on is True,
      f"实际 {_on!r}")

# ============================================================ [4] unit
head("[4] systemd 单元里显式关掉轮换")
unit = src_install = read(INSTALL)
m = re.search(r"\[Service\](.*?)ExecStart=/usr/bin/python3 /opt/michaelvpn/vpngate9_guard\.py",
              unit, re.S)
check("guard 单元里能找到 Environment=VPNGATE_ROTATE_EVERY=0",
      bool(m) and "Environment=VPNGATE_ROTATE_EVERY=0" in m.group(1),
      "unit 段里没写 Environment")
check("Environment 写在 ExecStart 之前（写在后面 systemd 也不认，但这里保持整齐）",
      bool(m) and "Environment=VPNGATE_ROTATE_EVERY=0" in m.group(1))

# ============================================================ [5] --guard-only
head("[5] --guard-only 只补装单元")
g = re.search(r"--guard-only.*?\nfi\n", src_install, re.S)
body = g.group(0) if g else ""
check("install.sh 有 --guard-only 分支", bool(body))
check("分支里调用了 install_guard_service", "install_guard_service" in body)
check("分支里会重启/启动守护", "systemctl restart ${GUARD_SERVICE}" in body)
check("分支里没有重装依赖（不调用 install_deps）", "install_deps" not in body)
check("分支里没有重拉代码（不调用 deploy_code）", "deploy_code" not in body)
check("分支里没有动数据目录（不碰 vpngate_data）", "vpngate_data" not in body)
check("分支结束后 exit 0（不会继续跑完整安装）", "exit 0" in body)

# ============================================================ [6] 缺文件
head("[6] 守护脚本不存在时明确失败")
check("--guard-only 先检查 vpngate9_guard.py 是否存在",
      "vpngate9_guard.py" in body and "请先完整安装" in body)
check("缺文件时 exit 1（不假装成功）", re.search(r"请先完整安装.*?exit 1", body, re.S) is not None)

# ============================================================ [7] 升级脚本提示
head("[7] 升级报告给出可执行的补装命令")
up = read(UPGRADE)
check("升级脚本的\"未安装\"提示带上 --guard-only",
      "--guard-only" in up and "未安装" in up)
check("提示里带具体路径（cd 到安装目录再跑）", "cd $INSTALL_DIR" in up)

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
sys.exit(1 if FAIL else 0)

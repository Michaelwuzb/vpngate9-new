#!/bin/bash
# ============================================================================
# MichaelVPN / vpngate9 —— 服务端「原地升级」脚本
#
# 干什么：
#   把 /opt/michaelvpn 上的旧版本原地升级到 GitHub 仓库最新版，并且顺手处理
#   **git pull 不会碰到的那些东西**：
#     - systemd 单元（新版新增了 network-online / 无限重启 / LimitNOFILE）
#     - /usr/bin/ml 管理命令（新版支撑 HTTPS 与 guard 子命令）
#     - vpngate_data/login.html 登录页（安装脚本只在文件不存在时才写，升级路径永远走不到）
#     - 旧版写在内核里的策略路由表（100~108 → 新版 200~208，旧规则不清会继续劫持路由）
#
# 用法（在服务器上执行；root 直登或用免密 sudo 的普通用户都行）：
#   bash vg9_server_upgrade.sh                 # 完整升级（备份 / 编译门禁 / 测试 / 验收）
#   sudo -n bash vg9_server_upgrade.sh --check # 普通用户（如 debian）显式提权体检
#
# 从本机（Windows Git Bash）上传并执行：
#   tr -d '\r' < vg9_server_upgrade.sh | ssh -i ~/.ssh/<key> <user>@<HOST> 'cat > ~/vg9-upgrade.sh'
#   ssh -i ~/.ssh/<key> <user>@<HOST> 'sudo -n bash ~/vg9-upgrade.sh --check'
#
# 设计原则：
#   - **先比对、后动手**：任何一项都没差异就一个字节都不改、不重启（可安全重复执行）
#   - 备份只做在真正要变更之前；任何一步失败立刻停
#   - 清理内核态的操作幂等；验收打真实流量（经代理实测出口 IP），不是只看端口在听
# ============================================================================
set -u

INSTALL_DIR="${VPNGATE_INSTALL_DIR:-/opt/michaelvpn}"
SERVICE="michaelvpn"
GUARD_SERVICE="vpngate9-guard"
PANEL_PORT="${VPNGATE_UI_PORT:-8787}"
PROXY_FROM=47928
PROXY_TO=47936
BRANCH="${VPNGATE_BRANCH:-main}"
# 历史版本（<= 9775cbe）用的策略表号段；新版用 200~208，由代码里 POLICY_TABLE_BASE 决定
LEGACY_TABLES="$(seq 100 108)"
BACKUP_POINTER=/root/.last-vg9-backup
TARGET_INSTALL_SH=""
ART_UNIT=""; ART_ML=""; ART_LOGIN=""      # 从远端 install.sh 提取的仓库外产物

MODE=upgrade
SKIP_TESTS=0
CODE_CHANGED=0; UNIT_CHANGED=0; ML_CHANGED=0; LOGIN_CHANGED=0; ROUTING_CHANGED=0

G='\033[0;32m'; Y='\033[0;33m'; R='\033[0;31m'; C='\033[0;36m'; N='\033[0m'
log()  { echo -e "${C}==>${N} $*"; }
ok()   { echo -e "    ${G}OK${N}   $*"; }
warn() { echo -e "    ${Y}注意${N} $*"; }
err()  { echo -e "    ${R}错误${N} $*"; }
die()  { err "$*"; exit 1; }
fmt()  { printf '    %-30s %s\n' "$1" "$2"; }

usage() {
    cat <<'USAGE'
用法（在服务器上执行；root 直登或用免密 sudo 的普通用户都行）：
  bash vg9_server_upgrade.sh                 # 完整升级
  bash vg9_server_upgrade.sh --check         # 只体检（含真实出口测试），零变更
  bash vg9_server_upgrade.sh --skip-tests    # 跳过测试套件
  bash vg9_server_upgrade.sh --rollback      # 回滚到上一次备份

非 root 登录（如 debian）且配置了免密 sudo 时，本脚本会自动提权重跑；
若 sudo 需要密码，请手动用 sudo 执行。

环境变量可覆盖：VPNGATE_INSTALL_DIR / VPNGATE_UI_PORT / VPNGATE_BRANCH
USAGE
}

for a in "$@"; do
    case "$a" in
        --check)       MODE=check ;;
        --skip-tests)  SKIP_TESTS=1 ;;
        --rollback)    MODE=rollback ;;
        -h|--help)     usage; exit 0 ;;
        *)             die "未知参数: $a（用 --help 看用法）" ;;
    esac
done

# git 清掉可能残留的失效代理配置：有代理但代理没开时 git 会直接失败，而 GitHub 通常直连可用。
# 仓库若是私有的，凭据仍走 credential helper。
git_c() { git -c http.proxy= -c https.proxy= "$@"; }

api() {
    local tok; tok=$(cat "$INSTALL_DIR/vpngate_data/guard_token" 2>/dev/null)
    curl -sk --max-time "${2:-10}" -H "Cookie: token=$tok" "https://127.0.0.1:${PANEL_PORT}$1" 2>/dev/null
}

# 从 install.sh 里抠出内嵌脚本 / 模板：保证与仓库一致，绝不手抄
extract_heredoc() {   # $1=源文件 $2=起始标记 $3=结束标记
    python3 - "$1" "$2" "$3" <<'PY'
import re, sys
src = open(sys.argv[1], encoding='utf-8').read()
start, end = sys.argv[2], sys.argv[3]
m = re.search(re.escape(start) + r"\n(.*?)\n" + re.escape(end) + r"\s*(?:\n|$)", src, re.S)
if not m:
    sys.exit("在 install.sh 里找不到起始标记: " + start)
sys.stdout.write(m.group(1) + "\n")
PY
}

# 目标版本的三个仓库外产物（都读「远端目标提交」里的 install.sh，而不是当前工作区）
art_unit()  { extract_heredoc "$TARGET_INSTALL_SH" \
                "cat > /lib/systemd/system/\${SERVICE_NAME}.service << 'SERVICEEOF'" "SERVICEEOF"; }
art_ml()    { extract_heredoc "$TARGET_INSTALL_SH" \
                "cat > /usr/bin/ml << 'MLEOF'" "MLEOF"; }
art_login() { extract_heredoc "$TARGET_INSTALL_SH" \
                'cat > "$INSTALL_DIR/vpngate_data/login.html" << '"'"'LOGINEOF'"'"'' "LOGINEOF"; }

clean_routing_tables() {   # $1...=表号
    for t in "$@"; do
        # ip rule del table N 每次只删一条匹配项，必须循环删到删不动
        while ip rule del table "$t" 2>/dev/null; do :; done
        ip route flush table "$t" 2>/dev/null || true
    done
}
count_rules() { ip rule show | grep -cE "lookup $1\$" || true; }

# 非 root 登录（如 debian/ubuntu 用户）+ 免密 sudo 时自动提权重跑一次。
# 显式提权优先：本来就用 `sudo -n bash xxx.sh` 跑的，这里 id -u 已是 0，不会进这个分支。
#
# ⚠️ 调用方必须写成 ensure_root "$@"：函数内的 $@ 是**函数自己的参数**而非脚本参数，
#    漏了就丢参数（实测把 --check 静默变成 upgrade，条件一变就会误做完整升级）。
ensure_root() {
    [ "$(id -u)" = "0" ] && return 0
    if [ "${VG9_SUDO_REEXEC:-0}" != "1" ] && sudo -n true 2>/dev/null; then
        # 提权重跑要按路径再执行一次，`bash <(curl ...)` 那种进程替换（$0=/dev/fd/63）
        # 在新进程里读不到，必须拦下来给个明确提示，否则只会看到莫名其妙的报错
        if [ ! -f "$0" ]; then
            die "当前是非 root 且脚本不是磁盘上的文件（$0）。
        请先保存再执行：
          curl -Ls -o ~/vg9-upgrade.sh <raw-url>/vg9_server_upgrade.sh && bash ~/vg9-upgrade.sh $*
        或直接提权运行：sudo -n bash $0 $*"
        fi
        log "当前用户 $(id -un) 非 root，但免密 sudo 可用 —— 自动提权重跑（参数: $*）"
        VG9_SUDO_REEXEC=1 exec sudo -n env VG9_SUDO_REEXEC=1 \
            VPNGATE_INSTALL_DIR="$INSTALL_DIR" \
            VPNGATE_UI_PORT="$PANEL_PORT" \
            VPNGATE_BRANCH="$BRANCH" \
            bash "$0" "$@"
    fi
    die "需要 root。请用 sudo 执行：sudo -n bash $0 $*（或给 $(id -un) 配置免密 sudo）"
}

# ---------------------------------------------------------------- 0) 体检
preflight() {
    log "环境体检"
    ensure_root "$@"
    [ -d "$INSTALL_DIR/.git" ] || die "$INSTALL_DIR 不是 git 仓库；本脚本只用于 install.sh 装出来的部署"
    command -v git >/dev/null || die "缺 git"
    command -v python3 >/dev/null || die "缺 python3"
    command -v openvpn >/dev/null || warn "没找到 openvpn（服务可能起不来）"
    command -v openssl >/dev/null || warn "没找到 openssl（面板自签证书会不可用）"

    ok "python3: $(python3 -V 2>&1)"
    ok "当前提交: $(cd "$INSTALL_DIR" && git rev-parse --short HEAD)"
    ok "服务状态: $(systemctl is-active "$SERVICE" 2>/dev/null || echo 未运行)"
    ok "策略路由: $(count_rules '10[0-8]') 条旧表(100~108) / $(count_rules '20[0-8]') 条新表(200~208)"

    ( cd "$INSTALL_DIR" && git_c fetch --quiet origin "$BRANCH" ) \
        || die "git fetch 失败（检查服务器到 GitHub 的网络）"
    TARGET_INSTALL_SH=$(mktemp /tmp/vg9-installsh.XXXXXX)
    ( cd "$INSTALL_DIR" && git_c show "origin/$BRANCH:install.sh" ) > "$TARGET_INSTALL_SH" 2>/dev/null \
        || die "取不到远端 install.sh"
    ok "远端 $BRANCH: $(cd "$INSTALL_DIR" && git rev-parse --short origin/"$BRANCH")"
    command -v node >/dev/null && ok "node 可用（前端测试会一并跑）" || warn "没装 node，前端单测会跳过"
    ok "磁盘: $(df -h / | awk 'NR==2{print $4" 可用"}')   内存: $(free -h | awk 'NR==2{print $3"/"$2}')"
}

# ---------------------------------------------------------------- 1) 比对（决定要不要动手）
plan() {
    log "比对差异（有差异才动手）"
    local cur tgt
    cur=$( cd "$INSTALL_DIR" && git rev-parse HEAD )
    tgt=$( cd "$INSTALL_DIR" && git rev-parse origin/"$BRANCH" )
    if [ "$cur" != "$tgt" ]; then
        CODE_CHANGED=1
        # 只有 HEAD 是远端祖先时才能快进，否则要人工介入
        if ( cd "$INSTALL_DIR" && git merge-base --is-ancestor HEAD "$tgt" ); then
            ok "代码: $(echo "$cur" | cut -c1-7) → $(echo "$tgt" | cut -c1-7)（可快进）"
            ( cd "$INSTALL_DIR" && git log --oneline "$cur..$tgt" | sed 's/^/          /' )
        else
            die "HEAD 不是远端祖先（可能有本地提交），不能快进合并。先人工处理：cd $INSTALL_DIR && git status"
        fi
    else
        ok "代码已是最新 ($(echo "$cur" | cut -c1-7))"
    fi

    # 仓库外产物的差异比对。提取失败必须当场停 —— 否则会跑到「停服」之后才炸，
    # 服务停在半路。
    local tmp
    tmp=$(art_unit)  || die "从远端 install.sh 提取 systemd 单元失败"
    ART_UNIT="$tmp"
    tmp=$(art_ml)    || die "从远端 install.sh 提取 ml 失败"
    ART_ML="$tmp"
    tmp=$(art_login) || die "从远端 install.sh 提取登录页模板失败"
    ART_LOGIN="$tmp"

    if [ "$ART_UNIT" = "$(cat "/lib/systemd/system/$SERVICE.service" 2>/dev/null)" ]; then
        ok "systemd 单元已是最新"
    else
        UNIT_CHANGED=1; ok "systemd 单元需要更新"
    fi

    if [ "$ART_ML" = "$(cat /usr/bin/ml 2>/dev/null)" ]; then
        ok "/usr/bin/ml 已是最新"
    else
        ML_CHANGED=1; ok "/usr/bin/ml 需要更新"
    fi

    if [ "$ART_LOGIN" = "$(cat "$INSTALL_DIR/vpngate_data/login.html" 2>/dev/null)" ]; then
        ok "登录页已是最新"
    elif grep -q "<title>MichaelVPN" "$INSTALL_DIR/vpngate_data/login.html" 2>/dev/null; then
        LOGIN_CHANGED=1; ok "登录页需要更新（是旧版自带模板）"
    else
        warn "登录页看起来被自定义过，不覆盖（需要自己合并 install.sh 的 LOGINEOF 段）"
    fi

    local legacy; legacy=$(count_rules '10[0-8]')
    if [ "$legacy" != "0" ]; then
        ROUTING_CHANGED=1; ok "旧策略路由表有 $legacy 条规则需要清理（100~108 → 新版 200~208）"
    else
        ok "旧策略路由表本来就干净"
    fi
}

# 只要有任何一处需要变更，就得走一次「停服 → 改 → 启服」：
#   - 代码/单元/ml 变了自然要重启
#   - 旧策略路由表必须在**服务停止后**清理，否则会打断正在跑的隧道
#   - 登录页在面板里是首次访问时读入内存并缓存的，不重启改不生效
any_change() { [ "$CODE_CHANGED$UNIT_CHANGED$ML_CHANGED$LOGIN_CHANGED$ROUTING_CHANGED" != "00000" ]; }

# ---------------------------------------------------------------- 2) 备份
do_backup() {
    local ts bk; ts=$(date +%Y%m%d-%H%M%S); bk=/root/vg9-backup-$ts
    log "备份到 $bk"
    mkdir -p "$bk"; echo "$bk" > "$BACKUP_POINTER"
    ( cd "$INSTALL_DIR" && git rev-parse HEAD > "$bk/commit.before.txt" \
        && git log --oneline -1 >> "$bk/commit.before.txt" )
    tar czf "$bk/vpngate_data.tar.gz" -C "$INSTALL_DIR" vpngate_data
    cp /usr/bin/ml "$bk/ml.before" 2>/dev/null || true
    cp "/lib/systemd/system/$SERVICE.service" "$bk/$SERVICE.service.before" 2>/dev/null || true
    cp "$INSTALL_DIR/vpngate_data/login.html" "$bk/login.html.before" 2>/dev/null || true
    ip rule show > "$bk/ip-rule.before.txt"
    for t in $LEGACY_TABLES; do
        echo "-- table $t --" >> "$bk/ip-route.before.txt"
        ip route show table "$t" >> "$bk/ip-route.before.txt" 2>&1
    done
    ok "数据 $(du -h "$bk/vpngate_data.tar.gz" | cut -f1) + 单元 + ml + 登录页 + 路由快照 已保存"
    ok "回滚: bash $0 --rollback"
}

# ---------------------------------------------------------------- 3) 拉代码
do_pull() {
    log "拉取新代码"
    ( cd "$INSTALL_DIR" && git_c checkout -- . ) 2>/dev/null || true   # 清掉遗留的权限位改动
    ( cd "$INSTALL_DIR" && git_c merge --ff-only origin/"$BRANCH" >/dev/null ) \
        || die "快进合并失败。回滚: bash $0 --rollback"
    ok "现在: $(cd "$INSTALL_DIR" && git log --oneline -1)"
}

# ---------------------------------------------------------------- 4) 编译门禁
do_compile_gate() {
    log "编译门禁（在目标机 Python 上验，别只在开发机验）"
    ( cd "$INSTALL_DIR" && python3 -m py_compile ./*.py ) \
        || die "编译失败，请勿继续。回滚: bash $0 --rollback"
    ok "$(cd "$INSTALL_DIR" && ls ./*.py | wc -l) 个模块编译通过"
}

# ---------------------------------------------------------------- 5) 测试
do_tests() {
    if [ "$SKIP_TESTS" = "1" ]; then warn "按参数跳过测试套件"; return; fi
    [ -d "$INSTALL_DIR/tests" ] || { warn "没有 tests 目录，跳过"; return; }
    log "跑项目自带测试（在目标机上验环境）"
    local failed=0 t out
    for t in vg9_stability_test.py vg9_assign_test.py vg9_seen_speed_test.py; do
        [ -f "$INSTALL_DIR/tests/$t" ] || continue
        out=$( cd "$INSTALL_DIR" && timeout 420 python3 "tests/$t" 2>&1 \
               | grep -E "^(===== 结果|PASS=)" | tail -1 )
        printf '    %-28s %s\n' "$t:" "${out:-（没拿到结果）}"
        case "$out" in *"FAIL=0"*|*"0 失败"*) : ;; *) failed=1 ;; esac
    done
    if command -v node >/dev/null && [ -f "$INSTALL_DIR/tests/vg9_frontend_check.py" ]; then
        if ( cd "$INSTALL_DIR" && timeout 200 python3 tests/vg9_frontend_check.py >/dev/null 2>&1 ); then
            printf '    %-28s %s\n' "vg9_frontend_check.py:" "通过"
        else
            printf '    %-28s %s\n' "vg9_frontend_check.py:" "失败"; failed=1
        fi
    fi
    [ "$failed" = "0" ] && ok "测试全过" || warn "有测试失败，请人工确认后再决定是否继续"
}

# ---------------------------------------------------------------- 6) 内核态迁移
do_routing_migration() {
    log "迁移内核态：清掉旧版策略路由表 100~108"
    local before after; before=$(count_rules '10[0-8]')
    clean_routing_tables $LEGACY_TABLES
    after=$(count_rules '10[0-8]')
    ok "100~108 的 rule: $before → $after 条"
    ok "现在指向: $(ip rule show | grep -oE 'lookup 2[0-9][0-9]' | sort -u | tr '\n' ' ')"
}

# ---------------------------------------------------------------- 7) 仓库外产物
# 内容在 plan() 阶段就已经从远端 install.sh 提取好了（ART_UNIT / ART_ML / ART_LOGIN）
sync_artifacts() {
    log "同步 git 拉不到的仓库外产物"

    if [ "$UNIT_CHANGED" = "1" ]; then
        local cur; cur=$(cat "/lib/systemd/system/$SERVICE.service" 2>/dev/null || echo "")
        printf '%s\n' "$ART_UNIT" > "/lib/systemd/system/$SERVICE.service"
        systemctl daemon-reload
        ok "systemd 单元已更新"
        diff <(printf '%s\n' "$cur") <(printf '%s\n' "$ART_UNIT") | grep '^>' | sed 's/^> /         新增: /' || true
    else
        ok "systemd 单元无需变更"
    fi

    if [ "$ML_CHANGED" = "1" ]; then
        printf '%s\n' "$ART_ML" > /usr/bin/ml && chmod +x /usr/bin/ml
        bash -n /usr/bin/ml || die "/usr/bin/ml 语法错误，已停止"
        ok "/usr/bin/ml 已更新"
    else
        ok "/usr/bin/ml 无需变更"
    fi

    if [ "$LOGIN_CHANGED" = "1" ]; then
        cp "$INSTALL_DIR/vpngate_data/login.html" "$(cat "$BACKUP_POINTER")/login.html.before" 2>/dev/null || true
        printf '%s\n' "$ART_LOGIN" > "$INSTALL_DIR/vpngate_data/login.html"
        ok "登录页已更新（旧版已备份）"
    else
        ok "登录页无需变更"
    fi
}

# ---------------------------------------------------------------- 8) 启停
stop_service() {
    log "停止服务（9 条隧道会断，这就是停机窗口）"
    systemctl stop "$SERVICE" 2>/dev/null || true
    sleep 3
    ok "状态: $(systemctl is-active "$SERVICE" 2>/dev/null || echo inactive)   残留 tun: $(ip -o link show type tun 2>/dev/null | wc -l)"
}

start_and_wait() {
    log "启动并等待通道就绪（最多 180 秒）"
    systemctl start "$SERVICE" || die "启动失败，看 'journalctl -u $SERVICE -n 50'"
    local n=0
    for _ in $(seq 1 36); do
        sleep 5
        n=$(api /api/status 6 | python3 -c \
            'import sys,json;print(sum(1 for c in json.load(sys.stdin)["channels"] if c["state"]=="connected"))' \
            2>/dev/null || echo 0)
        [ "$n" = "9" ] && break
    done
    ok "已连接 $n/9 条通道"
    [ "$n" = "9" ] || warn "未全部就绪：单通道偶发 AUTH_FAILED 属节点侧问题，面板会自动轮换重连"
}

# ---------------------------------------------------------------- 9) 验收
verify() {
    log "验收（含经代理的真实出口测试）"
    local st; st=$(api /api/status 12)
    if [ -z "$st" ] || ! echo "$st" | grep -q channels; then
        # 分清「面板真的没起来」和「面板在跑但它是升级前的旧版」——
        # 旧版没有 guard_token 机制，/api/* 全需鉴权，裸请求必然 401。
        # 把这种情况报成"面板没起来"会误导人以为服务挂了，其实一切正常。
        local code
        code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 \
               "https://127.0.0.1:${PANEL_PORT}/api/status" 2>/dev/null)
        { [ -z "$code" ] || [ "$code" = "000" ]; } && code=$(curl -s -o /dev/null -w '%{http_code}' \
               --max-time 8 "http://127.0.0.1:${PANEL_PORT}/api/status" 2>/dev/null)
        if [ "$code" = "401" ] && [ ! -s "$INSTALL_DIR/vpngate_data/guard_token" ]; then
            warn "面板在运行，但它是升级前的旧版 —— 旧版无 guard_token 机制，/api/* 全需鉴权，"
            warn "因此此处读不到通道表属正常（正式升级后会生成 guard_token，届时才有完整验收）。"
            warn "旧版机器请直接执行正式升级，而非 --check。"
            return 0
        fi
        err "读不到 /api/status（HTTP ${code:-无响应}）：面板没起来，或已生成的 guard_token 失效"
        return 1
    fi
    echo "$st" | python3 -c '
import json, socket, struct, sys
d = json.load(sys.stdin)
print("    面板协议  : %s   证书来源: %s" % (d.get("ui_scheme"), d.get("ui_tls_source") or "-"))
print("    策略表基准: %s   节点数: %s   节点来源: %s"
      % (d.get("policy_table_base"), d.get("node_count"), d.get("nodes_source") or "-"))
print("    " + "-" * 68)
agree = fail = 0
for c in d["channels"]:
    head = "    CH%-2s %-11s %-14s %-16s %s" % (
        c["index"], c["state"], (c.get("node_country") or "-")[:14],
        (c.get("node_ip") or "-"), c.get("error") or "")
    if c["state"] != "connected":
        print(head); continue
    got = ""
    try:
        s = socket.create_connection(("127.0.0.1", c["proxy_port"]), timeout=12); s.settimeout(12)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 握手被拒")
        h = b"api.ipify.org"
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", 80))
        r = s.recv(4)
        if len(r) < 4 or r[1] != 0:
            raise RuntimeError("CONNECT code=%s" % (r[1] if len(r) > 1 else "?"))
        atyp = r[3]
        if atyp == 1:
            s.recv(4)
        elif atyp == 3:
            s.recv(s.recv(1)[0])
        elif atyp == 4:
            s.recv(16)
        s.recv(2)
        s.sendall(b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
        buf = b""
        while True:
            ch = s.recv(4096)
            if not ch:
                break
            buf += ch
        got = buf.split(b"\r\n\r\n", 1)[-1].decode(errors="replace").strip()
        s.close()
    except Exception as e:
        got = "失败(%s)" % e
    if got == (c.get("node_ip") or ""):
        agree += 1; mark = "OK"
    else:
        fail += 1; mark = "!!"
    print(head + "   实际出口=%-16s %s" % (got, mark))
print("    " + "-" * 68)
print("    真实出口与面板标注一致: %d 条 / 异常 %d 条" % (agree, fail))
'
    echo
    fmt "systemd 服务:"  "$(systemctl is-active "$SERVICE")  ($(systemctl is-enabled "$SERVICE" 2>/dev/null))"
    fmt "旧策略表 100~108:" "$(count_rules '10[0-8]') 条 rule（应为 0）"
    fmt "策略表 200~208:"   "$(count_rules '20[0-8]') 条 rule（应为 9）"
    fmt "代理端口 ${PROXY_FROM}~${PROXY_TO}:" "$(ss -tln | grep -cE ":479[23][0-9]") 个（应为 9）"
    fmt "openvpn 进程:"     "$(pgrep -c openvpn 2>/dev/null || echo 0)"
    fmt "面板监听:"         "$(ss -tln | grep -E ":$PANEL_PORT " | awk '{print $4}' | tr '\n' ' ')"
    local gstate
    if [ -f "/lib/systemd/system/$GUARD_SERVICE.service" ] || [ -f "/etc/systemd/system/$GUARD_SERVICE.service" ]; then
        gstate=$(systemctl is-active "$GUARD_SERVICE" 2>/dev/null || echo 已停止)
    else
        gstate="未安装（新安装脚本会默认装上；可手动启用或忽略）"
    fi
    fmt "守护 $GUARD_SERVICE:" "$gstate"
    fmt "工作区改动:"       "$(cd "$INSTALL_DIR" && git status --short | wc -l) 个（应为 0）"
    fmt "运行提交:"         "$(cd "$INSTALL_DIR" && git log --oneline -1)"
}

# ---------------------------------------------------------------- 回滚
do_rollback() {
    [ -f "$BACKUP_POINTER" ] || die "没有备份记录（$BACKUP_POINTER 不存在）"
    local bk; bk=$(cat "$BACKUP_POINTER")
    [ -d "$bk" ] || die "备份目录不存在: $bk"
    log "从 $bk 回滚"
    echo "    代码 -> $(head -1 "$bk/commit.before.txt" | cut -c1-10) / 数据目录 / systemd 单元 / ml / 登录页"
    read -r -p "    确认回滚？[y/N] " ans
    [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { echo "已取消"; exit 0; }

    systemctl stop "$SERVICE" 2>/dev/null || true
    clean_routing_tables $LEGACY_TABLES $(seq 200 208)

    ( cd "$INSTALL_DIR" && { git_c checkout -- . 2>/dev/null || true; } \
      && git reset --hard "$(head -1 "$bk/commit.before.txt")" >/dev/null ) || die "代码回滚失败"
    ok "代码已回到 $(cd "$INSTALL_DIR" && git log --oneline -1)"

    if [ -f "$bk/vpngate_data.tar.gz" ]; then
        mv "$INSTALL_DIR/vpngate_data" "$INSTALL_DIR/vpngate_data.failed.$(date +%s)"
        tar xzf "$bk/vpngate_data.tar.gz" -C "$INSTALL_DIR"
        ok "数据目录已恢复（升级后那份保留为 vpngate_data.failed.*）"
    fi
    [ -f "$bk/$SERVICE.service.before" ] && cp "$bk/$SERVICE.service.before" "/lib/systemd/system/$SERVICE.service" \
        && systemctl daemon-reload && ok "systemd 单元已恢复"
    [ -f "$bk/ml.before" ] && cp "$bk/ml.before" /usr/bin/ml && chmod +x /usr/bin/ml && ok "ml 已恢复"
    [ -f "$bk/login.html.before" ] && cp "$bk/login.html.before" "$INSTALL_DIR/vpngate_data/login.html" \
        && ok "登录页已恢复"

    systemctl start "$SERVICE"
    start_and_wait
    verify
    ok "回滚完成"
    exit 0
}

# ================================================================ 主流程
ensure_root "$@"     # 非 root + 免密 sudo → 在打印横幅前就提权重跑，避免横幅重复
echo
echo "==================================================================="
echo "  MichaelVPN / vpngate9 服务端升级   $(date '+%F %T')   模式: $MODE"
echo "==================================================================="
echo

[ "$MODE" = "rollback" ] && do_rollback

preflight "$@"
echo
plan
echo

if [ "$MODE" = "check" ]; then
    verify
    echo
    log "体检完成（--check 零变更）"
    any_change && echo "    有差异待处理，正式升级: bash $0" || echo "    一切已是最新，无需升级"
    exit 0
fi

if ! any_change; then
    log "代码与所有仓库外产物都无需变更 —— 不重启服务，直接做一次验收"
    echo
    verify
    echo
    echo "==================================================================="
    echo "  已是最新版本，未做任何变更（服务全程未重启）。"
    echo "==================================================================="
    exit 0
fi

do_backup
do_pull
do_compile_gate
do_tests
echo

stop_service
do_routing_migration
sync_artifacts
echo

start_and_wait
echo
verify

log "收尾"
[ -n "$TARGET_INSTALL_SH" ] && rm -f "$TARGET_INSTALL_SH"
# 测试脚本常 tempfile.mkdtemp 后不删，顺手看一眼
leftover=$(ls -d /tmp/vg9* 2>/dev/null | tr '\n' ' ')
[ -n "$leftover" ] && warn "测试留下的临时目录: $leftover （可删）" || ok "/tmp 无残留"

echo
echo "==================================================================="
echo "  升级完成。备份在 $(cat "$BACKUP_POINTER")"
echo "  回滚: bash $0 --rollback        状态: ml status"
echo "  注意: 面板默认走 HTTPS，浏览器用 https://<域名或IP>:${PANEL_PORT}/"
echo "        （证书复用机器上已有的那份；用 IP 访问会提示域名不匹配，属正常）"
echo "==================================================================="

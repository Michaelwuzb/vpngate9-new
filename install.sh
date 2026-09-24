#!/bin/bash
# ---------------------------------------------------------------------------
# 衍生自 aimili-vpngate (https://github.com/baoweise-bot/aimili-vpngate)
# 依据 GPL-3.0 修改与分发；本文件的衍生部分同样以 GPL-3.0 发布。
# 完整许可见同目录 LICENSE，改造说明见 NOTICE。
# ---------------------------------------------------------------------------
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

if [ "$(id -u)" != "0" ]; then echo -e "${RED}必须以 root 权限运行${NC}"; exit 1; fi

INSTALL_DIR="/opt/michaelvpn"
SERVICE_NAME="michaelvpn"
# 默认装 vpngate9-new（完整版：源码 + tests/ + docs/）。
# 想装别的分支/仓库: bash install.sh <owner> <repo>
REPO_OWNER="${1:-Michaelwuzb}"
REPO_NAME="${2:-vpngate9-new}"
BRANCH="main"

# 策略路由表号：通道 i 用 200+i（主程序里的 POLICY_TABLE_BASE=200）。
# 卸载时必须清干净：tun 设备会随进程消失，但 ip rule/route 会留在内核里，
# 继续把别人的流量往已经不存在的设备上引。
cleanup_policy_routing() {
    for t in $(seq 200 208); do
        # ip rule del 每次只删一条匹配项，必须循环删到删不动
        while ip rule del table "$t" 2>/dev/null; do :; done
        ip route flush table "$t" 2>/dev/null || true
    done
}

# === 卸载功能 ===
if [ "${1:-}" = "uninstall" ] || [ "${1:-}" = "卸载" ]; then
    echo -e "${YELLOW}正在卸载 MichaelVPN...${NC}"
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    systemctl disable ${SERVICE_NAME} 2>/dev/null || true
    rm -f /lib/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload
    cleanup_policy_routing
    rm -rf "$INSTALL_DIR"
    rm -f /usr/bin/ml
    rm -f /etc/sysctl.d/99-${SERVICE_NAME}.conf
    pkill -f "vpngate9_multi\|proxy_server_multi" 2>/dev/null || true
    echo -e "${GREEN}卸载完成！${NC}"
    exit 0
fi

detect_distro() {
    if [ -f /etc/os-release ]; then . /etc/os-release; OS=$ID; else OS=$(uname -s | tr '[:upper:]' '[:lower:]'); fi
    case "$OS" in
        ubuntu|debian|linuxmint|pop|kali|raspbian) PKG_MANAGER="apt-get" ;;
        alpine) PKG_MANAGER="apk"; OS="alpine" ;;
        centos|rhel|rocky|almalinux|fedora|oraclelinux)
            command -v dnf &>/dev/null && PKG_MANAGER="dnf" || PKG_MANAGER="yum"; OS="centos" ;;
        arch|manjaro) PKG_MANAGER="pacman"; OS="arch" ;;
        opensuse*|suse*) PKG_MANAGER="zypper"; OS="opensuse" ;;
        *) echo -e "${RED}不支持: $OS${NC}"; exit 1 ;;
    esac
    echo -e "${GREEN}系统: $OS${NC}"
}

install_deps() {
    echo -e "${CYAN}[1/4] 安装依赖...${NC}"
    case "$PKG_MANAGER" in
        apt-get) apt-get update -qq && apt-get install -y -qq openvpn curl git ca-certificates iptables iproute2 psmisc python3 2>/dev/null ;;
        apk) apk update -q && apk add openvpn curl git ca-certificates iptables iproute2 psmisc python3 bash 2>/dev/null ;;
        dnf|yum) $PKG_MANAGER install -y epel-release 2>/dev/null || true; $PKG_MANAGER install -y openvpn curl git ca-certificates iptables iproute psmisc python3 2>/dev/null ;;
        pacman) pacman -S --noconfirm openvpn curl git ca-certificates iptables iproute2 psmisc python 2>/dev/null ;;
        zypper) zypper install -y openvpn curl git ca-certificates iptables iproute2 psmisc python3 2>/dev/null ;;
    esac
    echo -e "${GREEN}  OK${NC}"
}

deploy_code() {
    echo -e "${CYAN}[2/4] 部署代码...${NC}"
    if [ -d "$INSTALL_DIR" ]; then
        cd "$INSTALL_DIR" && git fetch --all 2>/dev/null || true && git reset --hard origin/$BRANCH 2>/dev/null || true
    else
        git clone --depth 1 -b "$BRANCH" "https://github.com/${REPO_OWNER}/${REPO_NAME}.git" "$INSTALL_DIR"
    fi

    # Generate login page
    mkdir -p "$INSTALL_DIR/vpngate_data"
    if [ ! -f "$INSTALL_DIR/vpngate_data/login.html" ]; then
        cat > "$INSTALL_DIR/vpngate_data/login.html" << 'LOGINEOF'
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MichaelVPN 登录</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f0f13;color:#e0e0e0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#1a1a24;border:1px solid rgba(255,255,255,0.08);border-radius:20px;padding:40px;width:360px}
.logo{font-size:24px;font-weight:700;text-align:center;margin-bottom:8px;color:#f0f0f5}
.sub{text-align:center;color:#6b7280;font-size:13px;margin-bottom:28px}
.fg{margin-bottom:16px}
.fg label{display:block;font-size:12px;color:#9ca3af;margin-bottom:6px}
.fg input{width:100%;padding:10px 14px;background:#0f0f13;border:1px solid rgba(255,255,255,0.1);border-radius:10px;color:#e0e0e0;font-size:14px;outline:none}
.fg input:focus{border-color:#818cf8}
.btn{width:100%;padding:10px;background:#818cf8;border:none;border-radius:10px;color:#fff;font-size:14px;font-weight:500;cursor:pointer}
.btn:hover{background:#6d79e8}
.err{color:#ef4444;font-size:13px;text-align:center;margin-top:10px}
</style>
</head>
<body>
<div class="card">
<div class="logo">MichaelVPN</div>
<div class="sub">9通道 VPN 管理面板</div>
<form method="post" action="/api/login">
<div class="fg"><label>管理账号</label><input type="text" name="username" required autocomplete="username"></div>
<div class="fg"><label>安全密码</label><input type="password" name="password" required autocomplete="current-password"></div>
<button class="btn" type="submit">登录</button>
<div class="err" style="display:${error_display}">${error_text}</div>
</form>
</div>
</body>
</html>
LOGINEOF
    fi

    # Generate default auth if missing
    # 首次启动时面板会把它自动升级成 PBKDF2 哈希(明文只在首次存在)
    if [ ! -f "$INSTALL_DIR/vpngate_data/ui_auth.json" ]; then
        echo '{"username":"admin","password":"admin"}' > "$INSTALL_DIR/vpngate_data/ui_auth.json"
    fi
    # 若存在旧的明文格式, 启动前先就地升级为哈希
    python3 - "$INSTALL_DIR" << 'PYEOF' 2>/dev/null || true
import json, os, secrets, hashlib, sys
d = sys.argv[1]; p = os.path.join(d, "vpngate_data", "ui_auth.json")
try:
    cfg = json.load(open(p, encoding="utf-8"))
except Exception:
    sys.exit(0)
if cfg.get("password_hash") or "password" not in cfg:
    sys.exit(0)
salt = secrets.token_hex(16)
dk = hashlib.pbkdf2_hmac("sha256", str(cfg.get("password", "admin")).encode(), bytes.fromhex(salt), 200000)
cfg = {"username": cfg.get("username", "admin"),
       "password_hash": "pbkdf2_sha256$200000$%s$%s" % (salt, dk.hex())}
open(p, "w", encoding="utf-8").write(json.dumps(cfg, ensure_ascii=False, indent=2))
print("  ui_auth.json 明文密码已升级为哈希")
PYEOF

    chmod -R 755 "$INSTALL_DIR"
    # 面板凭据与守护令牌都不能全机可读
    chmod 600 "$INSTALL_DIR/vpngate_data/ui_auth.json" 2>/dev/null || true
    chmod 600 "$INSTALL_DIR/vpngate_data/guard_token" 2>/dev/null || true
    echo -e "${GREEN}  OK${NC}"
}

install_service() {
    echo -e "${CYAN}[3/4] 配置服务...${NC}"
    cat > /lib/systemd/system/${SERVICE_NAME}.service << 'SERVICEEOF'
[Unit]
Description=MichaelVPN 9-Channel VPN Gateway
After=network.target network-online.target
Wants=network-online.target
# 崩溃后允许无限重启（默认 5 次/10 秒 就会被 systemd 放弃）
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=/opt/michaelvpn
ExecStart=/usr/bin/python3 /opt/michaelvpn/vpngate9_multi.py
Restart=always
RestartSec=5
# 9 个代理端口 + 99 个隧道相关连接，默认 1024 会不够
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SERVICEEOF
    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME} 2>/dev/null || true
    echo -e "${GREEN}  OK${NC}"
}

install_ml() {
    echo -e "${CYAN}[4/4] 创建 ml 命令...${NC}"
    cat > /usr/bin/ml << 'MLEOF'
#!/bin/bash
case "${1:-status}" in
    start)   systemctl start michaelvpn 2>/dev/null ;;
    stop)    systemctl stop michaelvpn 2>/dev/null ;;
    restart) systemctl restart michaelvpn 2>/dev/null ;;
    uninstall|卸载)
        echo -e "\033[0;33m正在卸载 MichaelVPN...\033[0m"
        systemctl stop michaelvpn 2>/dev/null || true
        systemctl disable michaelvpn 2>/dev/null || true
        rm -f /lib/systemd/system/michaelvpn.service
        systemctl daemon-reload
        # 清掉 9 条通道写的策略路由（tun 没了但 ip rule 还在，会劫持其它程序的流量）
        for t in $(seq 200 208); do
            while ip rule del table "$t" 2>/dev/null; do :; done
            ip route flush table "$t" 2>/dev/null || true
        done
        rm -rf /opt/michaelvpn
        rm -f /usr/bin/ml
        rm -f /etc/sysctl.d/99-michaelvpn.conf
        pkill -f "vpngate9_multi\|proxy_server_multi" 2>/dev/null || true
        echo -e "\033[0;32m卸载完成！\033[0m" ;;
    status)
        echo "=== MichaelVPN 9-Channel ==="
        curl -s http://localhost:8787/api/status | python3 -c "
import sys,json
d=json.load(sys.stdin)
for c in d['channels']:
    s=c['state']; co=c.get('node_country') or '-'; ip=c.get('node_ip') or '-'
    print(f'CH{c[\"index\"]}: {s:15s} {co:20s} IP={ip:16s} :{c[\"proxy_port\"]}')
print(f'--- {d[\"node_count\"]} nodes ---')" 2>/dev/null || systemctl status michaelvpn --no-pager ;;
    logs)    journalctl -u michaelvpn --no-pager -n 50 -f ;;
    passwd|改密)
        shift
        if [ $# -eq 0 ]; then
            echo "用法: ml passwd <新密码>              只改密码"
            echo "      ml passwd <新账号> <新密码>    同时改账号和密码"
            echo "      (更推荐登录面板 → 右上角\"管理员\"里修改)"
            exit 1
        fi
        python3 /opt/michaelvpn/vpngate9_multi.py --set-credentials "$@" || exit 1
        systemctl restart michaelvpn 2>/dev/null ;;
    *)       echo "用法: ml {start|stop|restart|status|logs|passwd|uninstall}" ;;
esac
MLEOF
    chmod +x /usr/bin/ml
    echo -e "${GREEN}  OK${NC}"
}

configure_network() {
    echo -e "${CYAN}配置网络...${NC}"
    cat > /etc/sysctl.d/99-${SERVICE_NAME}.conf << 'SYSCTLEOF'
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
SYSCTLEOF
    for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 2 > "$f" 2>/dev/null || true; done
    echo -e "${GREEN}  OK${NC}"
}

echo -e "${CYAN}============================"
echo "  MichaelVPN 9-Channel 部署"
echo "============================${NC}"
detect_distro
install_deps
deploy_code
install_service
install_ml
configure_network

echo ""
echo -e "${GREEN}部署完成！启动服务...${NC}"
systemctl start ${SERVICE_NAME} 2>/dev/null || true
sleep 3
systemctl is-active ${SERVICE_NAME} &>/dev/null && echo -e "${GREEN}服务运行中${NC}" || echo -e "${YELLOW}检查: systemctl status michaelvpn${NC}"
PUBLIC_IP=$(curl -s --connect-timeout 5 api64.ipify.org 2>/dev/null || curl -s --connect-timeout 5 api.ipify.org 2>/dev/null || echo "<VPS_IP>")
echo ""
echo -e "  Web UI:    ${CYAN}http://${PUBLIC_IP}:8787/${NC}"
echo -e "  默认账号:  ${CYAN}admin${NC}"
echo -e "  默认密码:  ${CYAN}admin${NC}"
echo -e "  ${YELLOW}请登录后点右上角\"管理员\"立即修改账号和密码${NC} (改完需重新登录)"
echo -e "  忘记密码:  ${CYAN}ml passwd <新密码>${NC}  或  ${CYAN}ml passwd <新账号> <新密码>${NC}"
echo -e "  代理端口:  ${CYAN}47928~47936${NC} (tun0~tun8)"
echo -e "  策略路由:  ${CYAN}table 200~208${NC} (卸载时自动清理)"
echo -e "  状态:      ${CYAN}ml status${NC}"
echo -e "  日志:      ${CYAN}ml logs${NC}"
echo -e "  卸载:      ${CYAN}ml uninstall${NC}"

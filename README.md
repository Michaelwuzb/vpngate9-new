# MichaelVPN 9-Channel

> 基于 VPNGate 的 9 通道独立出口 VPN 网关
> 每个通道拥有独立的 OpenVPN 隧道、虚拟网卡(tun)、代理端口和出站 IP

---

## 🚀 一键安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Michaelwuzb/vpngate9/main/install.sh)
```

安装后访问 `http://<VPS_IP>:8787/` 进入管理面板。
默认账号密码从 `ui_auth.json` 读取，可在 `/opt/michaelvpn/vpngate_data/ui_auth.json` 中修改。

## 🗑️ 一键卸载

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Michaelwuzb/vpngate9/main/install.sh) uninstall
```

卸载所有文件和服务。

---

## 💡 快速使用

### 1. 登录管理面板

浏览器打开 `http://<VPS_IP>:8787/`，输入账号密码登录。

### 2. 获取节点

点击 **获取节点** 按钮拉取 VPNGate 可用节点。

### 3. 连接通道

每个通道(CH0~CH8)可独立选择国家 + IP类型(住宅/机房/移动)：

- 选好国家 + IP类型 → 点击 **连接**（下拉里会显示该国「剩 X/Y」个可用节点）
- 想让 9 条通道各拿一个不同出口，或让 9 条通道全用同一个国家 → 点右上角 **分配出口** 一键规划（见下）
- 或从下方节点表直接点 **切换** → 选目标通道
- 每个通道有独立出口 IP，撞 IP 时卡片上会标红提示

### 4. 使用代理

| 通道 | tun | 代理端口 | SOCKS5 |
|------|-----|---------|--------|
| CH0 | tun0 | 47928 | socks5://127.0.0.1:47928 |
| CH1 | tun1 | 47929 | socks5://127.0.0.1:47929 |
| CH2 | tun2 | 47930 | socks5://127.0.0.1:47930 |
| CH3 | tun3 | 47931 | socks5://127.0.0.1:47931 |
| CH4 | tun4 | 47932 | socks5://127.0.0.1:47932 |
| CH5 | tun5 | 47933 | socks5://127.0.0.1:47933 |
| CH6 | tun6 | 47934 | socks5://127.0.0.1:47934 |
| CH7 | tun7 | 47935 | socks5://127.0.0.1:47935 |
| CH8 | tun8 | 47936 | socks5://127.0.0.1:47936 |

```bash
# 示例：通过 CH0 (日本) 访问
export http_proxy=http://127.0.0.1:47928
export https_proxy=http://127.0.0.1:47928
curl ifconfig.me  # 显示日本 IP
```

---

## 🎛️ 管理命令

```bash
ml status   # 查看9通道状态
ml restart  # 重启服务
ml logs     # 查看实时日志
ml stop     # 停止服务
ml start    # 启动服务
ml passwd <新密码>            # 改面板密码（忘记密码时的救援入口）
ml passwd <新账号> <新密码>    # 同时改面板账号和密码
```

---

## ⚙️ 核心功能

### 9通道独立管理
- 每个通道独立 OpenVPN 连接
- 独立虚拟网卡 (tun0~tun8)
- 独立 HTTP/SOCKS5 代理端口 (47928~47936)
- 独立策略路由表，互不冲突

### 多出口分配：每个通道一个独立出口

每条通道卡片上都有**独立的国家/地区下拉**，所以「CH0=日本、CH1=美国、CH2=越南」这种配置直接就能做 ——
选好之后点该卡片的「连接」，设置会写入 `channels.json`，重启后依然生效。

点击右上角 **分配出口**，可以一键规划全部通道，三种方式：

| 方式 | 说明 |
|------|------|
| 尽量分到不同国家/地区 | 按各国在线节点数从多到少，一条通道一个国家；国家凑不够时在节点较多的国家上多开 |
| **全部通道用同一个国家/地区** | 你指定一个国家（下拉里按「可用节点数」从多到少排，默认选可用最多的），9 条通道全部从这个国家取节点，只要该国可用 IP 够摊开，**9 个出口 IP 互不相同** |
| 不限国家，只保证出口 IP 互不重复 | 不管国家，只保证 9 个出口 IP 各不相同 |

选「同一个国家」时：

- 下拉里的国家名后面直接写**可用数/总数**，右侧还会提示“可用 N 个，本次需要 M 条”
- 该国可用 IP **不够** M 条时**不会硬凑**：预览里红色的那行告诉你还差几条，并列出哪些国家的可用节点数够填满；
  没被分到的通道保持原样不变
- 勾上「**该国节点不够时，用其它国家/地区补满剩余通道**」，才会拿别的国家把剩下的通道补齐（出口 IP 仍然不重复）
- 示例：`Japan` 通常有 40 个左右节点，9 条通道全给日本完全没问题；`Viet Nam` 常常只有 2 个，
  这时要么勾补满、要么改用「不限国家」

三种方式都会先给出**预览表格**（通道 / 国家 / 出口 IP / 运营主体 / 该国节点数）与风险提示，确认后才下发并按序错峰重连。

> **关于「9 个不同国家」的现实约束**
> VPNGate 是志愿者网络，在线节点覆盖的国家/地区**经常不足 9 个**（实测某日：全站仅 10 个国家，
> 其中只有 4 个国家的节点数 ≥ 5）。所以「9 条通道 = 9 个不同国家」能不能成立取决于当天在线情况；
> 预览里会如实告诉你差多少、哪几个国家只有 1~2 个节点（掉线后无备选）。
> 真正稳定能做到的是 **9 个互不相同的出口 IP**，这也是分配功能的硬保证。

**出口不重复是怎么保证的**

- 选到节点的**那一刻就预占出口 IP**（不是等隧道建好才算）。原实现只统计 `state=connected` 的通道，
  前一条还在握手（最长 45 秒）时后一条就会选到同一个 IP，启动时几乎必然撞车。
- 候选池是**该国全部节点**（原来只在最快的 30 个里 `random.choice`），所以日本 40 多个节点能真正摊开用。
- 连接失败 / 隧道判死会立即**释放预占**，不会让一个连不上的 IP 把其它通道挡住。
- 万一某国未占用节点真的用尽：会复用该 IP 并在这条通道上标 **IP复用**；两条通道撞同一 IP 时标 **IP重复**。
  卡片区顶部的 **出口 N/9** 让这件事一眼可见。
- 「选节点 + 预占」全程持锁，并发点连接、watchdog 重连、守护脚本重连都不会互相抢同一个 IP。

**默认跳过中国节点**：VPNGate 上的 CN 节点基本都是境内志愿者家宽，拿它当境外出口没有意义，且通常只有 1 个节点。
自动分配会跳过（手动指定仍然可以）。改法：`VPNGATE_EXCLUDE_COUNTRIES=china,xxx`（留空表示不排除）。

### 节点管理与筛选
- **全部节点 / 只看新节点 / 可用节点 / 失效节点 / 已实测 / 未实测** 筛选
- **国家筛选**：日本、韩国、美国、泰国等
- **IP类型筛选**：住宅IP / 机房IP / 移动网络
- **排序**：最新发现优先 / 实测延迟最低 / 实测带宽最高 / 官方速度最高
- 每个节点显示：物理位置、运营主体(ISP)、ASN、IP类型、**实测延迟、官方速度、实测带宽、发现时间**
- IP类型旁边鼠标悬停可看到**判定依据**（例如"机构关键词命中宽带运营商(softbank)"）

### 新节点标记（刷新出来的新节点会被标出来）
- 后台每 `FETCH_INTERVAL`（默认 600 秒）刷新一次节点池，**首次见到的节点会记下时间**，
  在表格里给它打上绿色「新」徽标 + 浅绿底行
- 「发现时间」列显示每个节点是多久之前第一次出现的；筛选 **只看新节点** 可把这一轮新上线的挑出来
- 首现记录落在 `vpngate_data/nodes_seen.json`，**重启不会丢**，所以不会出现"一重启整屏都变成新节点"
- 默认 **24 小时**内算新（`NEW_NODE_TTL_HOURS` 可调）；看腻了点 **清除新标记** 一键清掉，
  之后的真·新节点照样会亮（清标记只挪水位线，首现历史不动）
- 顶部「节点: N · 新 M」直接显示当前有多少个新节点

### 节点测速

面板上有三个入口，测的东西完全不同，别混：

| 入口 | 测什么 | 怎么测 | 影响 |
|---|---|---|---|
| 节点表 **测延迟** | 节点 IP:端口 的 TCP 握手 RTT | 32 并发直连探测，**零流量** | 不碰任何通道，几秒~几十秒 |
| 节点表 **测带宽** | 真实下载带宽 | 借一条**空闲通道**建隧道，经它的 SOCKS 口实测下载 | 占用 1 条空闲通道，约 15~30 秒/个 |
| 通道卡片 **测速** | 该通道当前出口的真实带宽 | 直接走这条通道自己的 SOCKS 口，不用另建隧道 | 只影响该通道，十几秒 |

- **测带宽**：先在表格里勾选节点（不勾选则默认测「新节点」，单次最多 20 个）。任务串行跑，
  进度条显示第几个 / 总共几个 / 正在测哪个 IP，随时可点 **停止** 收工
- 测带宽必须有一条**空闲通道**；9 条全忙会明确拒绝并提示先断开一条。被借用的通道在测速期间
  临时退出守护管理（`enabled` 临时置 False），**测完自动还原**，不会弄乱它的配置
- 实测结果写回节点表并落盘，**下一轮节点刷新不会把它冲掉**；失败的节点记下失败原因
- **通道测速** 可一键对所有已连接通道**并发**测速，每条通道走自己的出口，互不干扰
- 三列数字怎么读：
  - **实测延迟** —— 从这台服务器到节点 IP 的真实 RTT。比官方 Ping 字段靠谱（官方那个是从日本测的）
  - **官方速度** —— VPNGate 在节点上线时测的带宽，仅作参考，经常严重虚高
  - **实测带宽** —— 真拿这条隧道下载跑出来的速度，**这个才是能不能用的依据**

### IP 信息富集
- 物理位置（国家、地区、城市）
- 运营主体 / ISP（如 KDDI、SoftEther、LG Uplus）
- IP 类型（住宅、机房、移动）
- 数据来源：ip-api.com + 本地 PTR 反查

> **IP 类型是怎么判的（重要）**
>
> 不能直接用 ip-api 的 `hosting` / `proxy` 字段：
> - `proxy=true` 只说明"这是个 VPN/代理出口"。VPNGate 的节点**不论宿主是家宽还是机房，这个字段几乎都是 true**，拿它当机房判据会把 SoftBank、KT 这些家宽全部误标成"机房IP"。
> - `hosting` 字段漏报严重：实测 98 个节点里只有 2 个为 true，连 DigitalOcean、SoftEther 自家服务器都标 false。
>
> 所以本项目改为「ASN/机构关键词 + PTR 反向域名特征」为主：
> 1. 先看 ASN/ISP/机构名里的移动运营商特征 → 移动
> 2. 再看云/机房/IDC 特征（digitalocean、softether、hosted、hosting…）→ 机房
> 3. 再看消费级宽带运营商特征（softbank、kddi、korea telecom、virgin media…）→ 住宅
> 4. 关键词判不出来的（一般是小运营商），再做一次 PTR 反查，看是不是 `*.bbtec.net`、`*.dynamic.*`、`*-pool-*` 这类家宽/动态池特征
> 5. 都没结论时才退回 ip-api 标记，最后默认按住宅处理
>
> 判定规则在 `vpn_utils.py` 顶部的关键词表里，想加自己的 ISP 直接往对应元组里塞就行；
> 改完把 `_CLS_VER` 加一，旧缓存会自动失效并重新查询。

### 安全登录
- 账号密码认证，密码以 **PBKDF2-SHA256 哈希**存储（旧版明文会在首次启动时自动升级）
- Cookie 会话管理（24小时有效期）
- **GET 与 POST 接口都校验会话**（写操作未登录一律 401；`/api/*` 未登录返回 401 JSON）
- 登录失败限速：同一 IP 连续 5 次失败锁定 5 分钟（改密接口同样受限）

### 修改管理账号 / 密码
登录面板 → 右上角 **管理员**：
- **当前账号 + 当前密码**：校验身份
- **新账号**（留空不改）：3~32 位，仅字母/数字/`_`/`.`/`-`
- **新密码**（留空不改）：至少 8 位，不能与账号相同、不能是常见弱口令
- **确认新密码**：两次必须一致

改完后**所有登录会话立即失效**，需用新凭据重新登录；**守护脚本使用独立令牌，不受影响**。

忘记密码时在服务器上执行：
```bash
ml passwd <新密码>              # 只改密码
ml passwd <新账号> <新密码>      # 账号密码一起改
```

> 面板同时提供 **退出登录** 按钮（清除当前会话）。
> 想要 9 个代理通道安全，记得同时用防火墙只放行可信来源的 47928~47936：
> `ufw allow from <你的IP> to any port 47928:47936 proto tcp`

---

## ⚠️ 常见问题

### Web UI 无法访问
- 检查防火墙：`ufw allow 8787/tcp && ufw allow 47928/tcp`
- 云服务商安全组放行 8787、47928~47936 端口

### 节点列表为空
- 检查 DNS：`echo "nameserver 8.8.8.8" > /etc/resolv.conf`
- 或手动点击 **获取节点** 按钮

### 忘了面板账号 / 密码
```bash
ml passwd <新密码>              # 只改密码
ml passwd <新账号> <新密码>      # 账号密码一起改
```
改完立即生效（无需重启）。面板还会在启动日志里提示"仍在使用默认 admin/admin"。

### 改完账号密码后，守护脚本会失效吗
不会。守护脚本用的是独立的 `vpngate_data/guard_token`，改面板凭据、清会话都不影响它。
若日志里出现 `[warn] 面板返回 401`，说明令牌文件丢了/不一致，把面板重启一次会自动生成新的。

### IP类型显示不准（比如家宽被标成"机房"）

- 已修复根因：旧版把 ip-api 的 `proxy=true`（"这是 VPN 出口"标记）当成机房判据，导致 SoftBank / KT 这类家宽全被标成机房。
- 现在改为按机构关键词 + PTR 判定，并把判定依据显示在面板上。
- 某个小众运营商仍判错时：在 `vpn_utils.py` 的 `RESIDENTIAL_ISP_KEYS` / `HOSTING_KEYS` 里补关键词，然后把 `_CLS_VER` 加一（旧缓存会自动失效重查）。
- 想立刻强制重判：删掉 `/opt/michaelvpn/vpngate_data/ip_cache.json`，再点面板"刷新"。

### 9 条通道会出现完全相同的出口 IP 吗

正常情况不会：选到节点的瞬间就预占了出口 IP，连失败也会立刻释放。
只有「同一国家当前可用节点数 < 需要的通道数」时才可能复用，此时卡片上会标 **IP复用**（本国节点用尽）
或 **IP重复**（与某条通道撞了）。想让 9 条通道最大化分散，点右上角 **分配出口** 选「尽量分到不同国家/地区」；
想让 9 条通道全走同一个国家（比如全是日本），选「全部通道用同一个国家/地区」—— 只要该国可用节点数 ≥ 9 就能做到 IP 全不同。

### 为什么自动分配只给我 8 个国家，剩下 1 条要和别人共用国家

因为当天在线的节点只覆盖这么多国家。想凑满 9 个不同国家，只能等 VPNGate 上出现更多国家的中继；
否则建议让那条通道也去别的国家（出口 IP 仍然是独立的，不影响使用）。

### TUN/TAP 设备错误
- LXC/OpenVZ VPS 需要在控制面板启用 TUN/TAP

---

## 📦 文件结构

```
/opt/michaelvpn/
├── vpngate9_multi.py      # 9通道管理器
├── proxy_server_multi.py  # 多通道代理
├── vpn_utils.py           # IP信息富集
├── speedtest_utils.py     # 测速（SOCKS5 + HTTP 下载，纯标准库）
├── vpngate9_guard.py      # 通道守护脚本（可选）
├── install.sh             # 部署脚本
├── vpngate_data/
│   ├── login.html         # 登录页面
│   ├── ui_auth.json       # 管理账号 + 密码哈希（chmod 600）
│   ├── guard_token        # 守护脚本长效令牌（chmod 600，面板启动时自动生成）
│   ├── ip_cache.json      # IP 信息缓存
│   ├── nodes_seen.json    # 节点首现时间记录（判断"新节点"的基准）
│   └── nodes.json         # 节点缓存（含实测延迟 / 实测带宽，刷新时按 id 合并保留）
```

---

## 📢 社区

- Telegram: [@arestemple](https://t.me/arestemple)

---

## 🛡️ 通道守护脚本 (vpngate9_guard.py)

自动保活 9 通道：定时检查，发现 `error` / 假连接（connected 但 socks5 实测无流量）自动换节点重连。

### 安装

```bash
cp vpngate9_guard.py /opt/michaelvpn/vpngate9_guard.py
cat > /etc/systemd/system/vpngate9-guard.service << 'EOF'
[Unit]
Description=vpngate9 channel guard (auto-reconnect / rotate)
After=network.target michaelvpn.service
Requires=michaelvpn.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/michaelvpn/vpngate9_guard.py
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now vpngate9-guard
```

### 行为说明

- 每 60 秒检查一轮 9 通道
- **假连接检测**：面板显示 `connected` 但 SOCKS5 实测拿不到出口 IP → 连续 2 轮都拿不到才换节点（避免网络抖动误伤）
- **每个通道沿用它在面板里设置的国家 / IP类型**，不再统一改成日本（旧版本硬编码了 `country=Japan&ip_type=residential`，会把 9 条通道的出口全变成日本）
- **掉线（state != connected）默认交给面板内置 watchdog 处理**，守护脚本只管"假连接"和定时轮换 —— 两条链路各管一段，不会同时去抢同一个 tun。如果你的面板 watchdog 被关掉了，把脚本顶部的 `HANDLE_DISCONNECTED` 改成 `True`
- **手动关闭的通道（面板卡片上的"守护自动重连"勾掉，即 enabled=False）不会被动重连**
- **认证走面板生成的守护令牌** `/opt/michaelvpn/vpngate_data/guard_token`（面板启动时自动生成，权限 600）。
  所以**面板里改账号密码、清会话，都不会让守护失联**（旧版读 ui_auth.json 明文，改密后要同步改脚本）
- 兜底：若令牌文件不存在，会退回用 `ui_auth.json` 里的账号密码（仅旧版明文格式）或环境变量
  `VPNGATE_USER` / `VPNGATE_PASS` 登录；登录失败/令牌无效会在日志里打出 `[warn]` 提示
- 同一通道两次重连之间有 `RECONNECT_COOLDOWN` 冷却，避免反复抖动
- 日志：`journalctl -u vpngate9-guard -f`

### 可调参数（脚本顶部 / 环境变量）

| 变量 | 默认 | 说明 |
|------|------|------|
| `CHECK_EVERY` | 60 | 检查间隔（秒） |
| `ROTATE_EVERY` | 30 | 每 N 轮主动换节点切 IP（0=不主动切） |
| `FAIL_TOLERANCE` | 2 | 连续 N 轮测不到流量才判定假连接 |
| `RECONNECT_COOLDOWN` | 120 | 同通道两次重连最小间隔（秒） |
| `HANDLE_DISCONNECTED` | False | 是否连"掉线"也由本脚本重连 |
| `PANEL` | `http://127.0.0.1:8787` | 面板地址（环境变量） |
| `GUARD_TOKEN_FILE` | `/opt/michaelvpn/vpngate_data/guard_token` | 守护令牌（环境变量 `VPNGATE_GUARD_TOKEN_FILE`） |
| `AUTH_FILE` | `/opt/michaelvpn/vpngate_data/ui_auth.json` | 兜底凭据文件（环境变量 `VPNGATE_UI_AUTH`） |

---

## 🔬 新节点标记 / 测速的可调参数

给 `michaelvpn.service` 加 `Environment=` 即可覆盖（改完 `systemctl daemon-reload && systemctl restart michaelvpn`）。

| 变量 | 默认 | 说明 |
|------|------|------|
| `FETCH_INTERVAL` | 600 | 节点池刷新间隔（秒） |
| `NEW_NODE_TTL_HOURS` | 24 | 首现多久之内算"新节点"，`0` = 关闭新节点标记 |
| `SEEN_KEEP_DAYS` | 30 | 首现记录保留天数（清理久远记录，防止文件无限长） |
| `PING_WORKERS` | 32 | 延迟测试并发数 |
| `PING_TIMEOUT` | 3 | 单个节点 TCP 探测超时（秒） |
| `SPEEDTEST_MAX_NODES` | 20 | 单次批量测带宽的节点数上限 |
| `SPEEDTEST_URL` | `https://speed.cloudflare.com/__down?bytes={bytes}` | 测速目标地址，`{bytes}` 会被替换成 `SPEEDTEST_BYTES` |
| `SPEEDTEST_BYTES` | 10000000 | 单次下载的字节数（10MB） |
| `SPEEDTEST_TIMEOUT` | 30 | 单次测速最长耗时（秒） |
| `SPEEDTEST_WARMUP` | 0.6 | 丢掉开头这段（TCP 慢启动/TLS 握手）再算稳定带宽，避免结果被握手时间拉低 |

> 测速默认打 Cloudflare 的 `__down` 端点。想换成别的地址（比如自建测速服务器）就设 `SPEEDTEST_URL`，
> URL 里写 `{bytes}` 占位符即可；不想让目标站感知到大流量，可以把 `SPEEDTEST_BYTES` 调小。

> 本地 SOCKS 口若开了认证（`LOCAL_PROXY_USER` / `LOCAL_PROXY_PASS`），测速会自动带上同一组凭据，
> 不需要额外配置。

---

*基于 baoweise-bot/aimili-vpngate 改造，增加9通道多路出站支持*

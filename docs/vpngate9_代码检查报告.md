# vpngate9 代码检查报告

仓库：https://github.com/Michaelwuzb/vpngate9 （main 分支，已拉到本地 `./vpngate9/` 核对源码）

---

## 一、先回答：到底拉多少个节点？

**拉取的是 VPNGate 全量公开节点，代码没有设"取几个"的参数。**

数据源：`vpngate9_multi.py:47` → `https://www.vpngate.net/api/iphone/`（官方 iPhone CSV 接口，**不带 limit 参数**，返回当前所有在线志愿者节点）。

实测（2026-09-24 抓取该接口）：

| 项目 | 数值 |
|---|---|
| 接口实际返回节点 | **98 个**（会波动，历史区间大致 60~200） |
| 日本 44 / 韩国 32 / 泰国 8 / 美国 4 / 俄罗斯 3 / 越南 2 / 英国 2 / 秘鲁 1 / 缅甸 1 / 中国 1 | — |
| IP 类型分布（ip-api 判定） | 机房 hosting 60 / 住宅 residential 37 / 移动 mobile 1 |
| 日本节点的类型分布 | 机房 33 / **住宅 10** / 移动 1 |

代码里三层"数量闸门"（都不等于通道数 9）：

| 位置 | 限制 | 说明 |
|---|---|---|
| `vpngate9_multi.py:275` | `nodes = nodes[:300]` | 节点池上限 300（先按 score 排序再截断）。当前 98 个，**基本不会触发** |
| `vpngate9_multi.py:685` | `result[:200]` | `/api/nodes` 只返回前 200 条 → 面板表格最多显示 200 个 |
| `vpngate9_multi.py:346` | `filtered[:min(30, len(filtered))]` | **自动选节点只在"该国+该IP类型"的前 30 个里随机** |

结论：**9 = 出口通道数，不是节点数。节点是"全量拉取"**，日常就是几十到一两百个，跟 9 没关系。

⚠️ 但有个隐性耦合要注意：如果 9 个通道都指定「日本 + 住宅IP」，今天可选池只有 **10 个** IP（`used_ips` 只排除当前已连接的 IP，保证不了不撞车），一个节点挂了就可能连环失败。要 9 个稳定独立出口，建议**分散到不同国家**（日本 44 + 韩国 32 就够撑 9 条，且别把 ip_type 卡死在"住宅"）。

---

## 二、发现的问题（按严重程度）

### P0-1　守护脚本有一个必崩 Bug：`idx` 先用后定义

`vpngate9_guard.py:115-121`

```python
for ch in channels:
    if not ch.get("enabled", True):
        print(f"[{T}] CH{idx} SKIP (manually disabled)", flush=True)   # ← idx 还没赋值
        continue
    idx = ch["index"]                                                  # ← 赋值在这里
```

- 只要**第一个被检查到的通道是关闭状态**（例如用 `/api/channel/0/toggle?enabled=0` 关掉 CH0），就会抛 `NameError: name 'idx' is not defined`。
- `main()` 没有 try/except，进程直接退出；systemd 是 `Restart=always`，于是**每 10 秒崩一次、无限重启**——守护彻底失效，而且日志里全是 Traceback。
- 即使没崩（关的不是第一个），打印的通道号也是**上一个通道的编号**，日志错位。

**修复（把赋值提到判断之前）：**

```python
for ch in channels:
    idx = ch["index"]
    if not ch.get("enabled", True):
        print(f"[{T}] CH{idx} SKIP (manually disabled)", flush=True)
        continue
```

---

### P0-2　面板所有写操作接口没有鉴权（可被公网任意调用）

`vpngate9_multi.py:631` 的 `do_GET` **有** `check_auth_token`；
但 `vpngate9_multi.py:689` 的 `do_POST` **从头到尾没有鉴权**，直接开始处理 `/api/login`，然后是：

- `POST /api/channel/{0-8}/connect`、`/disconnect`、`/toggle` → 任何人可远程踢线、改通道、调度你的出口
- `POST /api/fetch_nodes` → 任意触发全量拉取 + ip-api 批量查询（消耗配额）
- `POST /api/admin/change_password` → 虽然要旧密码，但**没有失败限速**，可离线爆破（`vpn_utils.py:614` 还专门写了端口占用的中文诊断码，说明作者是认真做过排障设计的，这处纯属漏了）

而 UI 监听 `UI_HOST = "::"`（双栈全网）+ 默认 `admin/admin`，等于把控制面直接摆在公网。

**修复（在 `do_POST` 里，`/api/login` 之后、其它分支之前插入）：**

```python
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # 未登录一律拒绝（登录接口本身除外）
        if path != "/api/login" and not check_auth_token(self.headers):
            self.send_json({"ok": False, "error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        ...
```

（面板的 `fetch` 是同源请求，Cookie 会正常带上，功能不受影响。）

---

### P0-3　守护脚本硬编码「日本 + 住宅」，会把 9 条通道全改成日本

`vpngate9_guard.py:70 / 74`

```python
d = api("/api/nodes?country=Japan&ip_type=residential")
path = f"/api/channel/{idx}/connect?country=Japan&ip_type=residential"
```

后端 `connect` 里有 `if country: ch.force_country = country`（`vpngate9_multi.py:785-786`），所以：

- 守护一旦介入重连，**该通道原来的国家设置被覆盖成日本**，"每通道独立出口国家"的多出口设计被破坏；
- `ROTATE_EVERY=30` 定时轮换时也是换日本节点 → 9 个出口**全变成日本**；
- 日本住宅IP 池今天只有 10 个，9 条通道挤在 10 个 IP 上，撞车概率极高。

**修复：让守护沿用通道自己保存的国家/类型**（`/api/status` 的 `to_dict()` 已经返回了 `force_country` / `force_ip_type`）：

```python
def reconnect(idx, country="", ip_type="", node_id=None):
    q = {"country": country, "ip_type": ip_type}
    if node_id:
        q["node_id"] = node_id
    return api(f"/api/channel/{idx}/connect?" + urllib.parse.urlencode(q), method="POST")
```

```python
            if need:
                print(f"[{T}] CH{idx} FIX ({reason}) -> reconnect", flush=True)
                reconnect(idx, ch.get("force_country", ""), ch.get("force_ip_type", ""))
                time.sleep(3)
```

顺带删掉 `vpngate9_guard.py:114` 的 `nodes = get_nodes() if (do_rotate or True) else []` ——`(do_rotate or True)` 恒为真，等于**每 60 秒都白拉一次全量节点 + 一次 ip-api 批量查询**，纯浪费。上面的改法不需要它（服务端会自己在池里随机挑，本身就是"换 IP"）。

---

### P1-1　面板缺"通道开关"，README 的用法做不到

`toggleChannel()`（`vpngate9_multi.py:504-507`）读的是 `document.getElementById('tog_'+i)`，但**整个页面从没渲染过 `tog_*` 这个元素** → 面板上没有开关控件。

后果：README 和守护脚本都写"手动关闭的通道不会被重连，用面板开关关掉"，但用户**在 UI 上根本关不了**，只能用 curl 打 `/api/channel/N/toggle`。`enabled` 这个字段因此几乎是个死开关。

**修复（在卡片渲染里补一行，位置在 `vpngate9_multi.py:484` 那行 `.ac` 之前）：**

```js
h+='<label style="display:flex;align-items:center;gap:5px;font-size:11px;color:#6b7280;margin-top:8px">'
 +'<input type="checkbox" id="tog_'+c.index+'" '+(c.enabled?'checked':'')+' onchange="toggleChannel('+c.index+')">'
 +'守护启用</label>';
```

---

### P1-2　前端硬编码 6，CH6~CH8 的下拉选择会被冲掉

`vpngate9_multi.py:463`

```js
for(var i=0;i<6;i++){          // ← 6 通道时代的遗留
```

`render()` 每 3 秒被轮询调用一次并重写整块 `innerHTML`，只保存前 6 个通道的下拉框状态 → **CH6/CH7/CH8 用户刚选的国家/IP类型会被 3 秒轮询重置**（点在"连接"之前就会丢）。

**修复：**

```js
for(var i=0;i<d.channels.length;i++){
```

---

### P1-3　面板判活用 `ping -I tunX 8.8.8.8`，容易把好节点误判成死节点

`vpngate9_multi.py:193-207`（连接后的连通性测试，最多 3 次 ping 失败即整条判失败）和 `:817-830`（watchdog，5 次 ping 全部失败即断开重连）。

问题：VPNGate 很多节点**限制/丢弃 ICMP**，隧道其实能正常跑 TCP，但 ping 不通。结果就是"明明可用却反复被判死→换节点→再判死"，表现成通道一直闪断。守护脚本用 `curl -x socks5://... api.ipify.org` 做判活，方向是对的。

**建议：把面板的判活也改成 SOCKS 层实测**（或 ping 失败时再用隧道内 TCP 连一次 8.8.8.8:53 兜底），别只信 ICMP。这条需要在你的 VPS 上实测确认，属于经验性风险。

---

### P1-4　两套守护同时重连，可能抢同一个 tun

系统里有两条自动重连链路：面板内 `channel_watchdog()`（`vpngate9_multi.py:793`，每 10 秒，优先连回 `last_node_data` 同一节点）和外部 `vpngate9_guard.py`（每 60 秒，换新节点）。两者都会调 `/api/channel/N/connect`，存在竞态：一个正在建隧道时另一个又来一次 `stop_process()` + 换节点，`connect_channel` 内部虽然有 `ch.lock` 串行化，但**结果是谁最后写的算谁的**，容易出现"刚连上又被切"。

**建议：二选一。**要么只用 guard（把面板 watchdog 的自动重连分支关掉，只保留进程存活检测），要么只用面板 watchdog。

---

### P1-5　节点数显示与实际可看不一致

`/api/nodes` 截断 200，但节点池是 300，自动选节点会从 300 里挑 → **面板上"看不见"的节点也可能被连上**（`total` 字段报的是过滤后总数，所以用户至少能看到数字对不上）。当前 98 个不会触发，VPNGate 高峰期会。

**修复：`vpngate9_multi.py:685` 的 `result[:200]` 改成 `result[:300]`**，或加前端分页。

---

### P2　零碎的遗留与加固项

| 位置 | 问题 | 修复 |
|---|---|---|
| `vpngate9_multi.py:872` | 日志 `"[init] 6 proxies started"`，实际 9 个 | `log(f"[init] {len(channels)} proxies started")` |
| `vpngate9_multi.py:851` | 注释 "so 6 channels don't fight" | 改为 9 |
| `vpngate9_multi.py:830` | 注释说 "2 pings failed"，实际循环 5 次（`:818`） | 注释同步 |
| `vpngate9_multi.py:799` | watchdog 全程持有 `ch.lock`，期间做最多 5 次 ping（每个最多 5s）→ 面板点"连接"最多被卡 ~25 秒 | 健康检查放到锁外，或用局部快照 |
| `vpngate9_multi.py:799` | 9 通道 × 每 10 秒 5 次 ping ≈ 峰值 4.5 ping/s，再加 guard 每轮 9 次串行 curl（每个超时 10s，最坏 90s+）→ 低配 VPS 负担重，且 guard 实际周期被拉长到 150s 以上，不是 60s | 降频：ping 判活改 1 次 + 抽检；guard 内 `curl` 并行或用短超时（3s） |
| `vpngate9_guard.py:9` | `USER/PASS` 硬编码 `admin/admin`，改密码后 guard 静默失效（只在日志刷 re-login，无告警） | 改为读 `/opt/michaelvpn/vpngate_data/ui_auth.json` |
| `vpngate9_multi.py:47/875` | 面板 `UI_HOST="::"` 全网监听 + 明文 HTTP + 默认口令 | 至少改 8787 只监听 `127.0.0.1` 走 Nginx/SSH 隧道；强制首次改密码 |
| `proxy_server_multi.py:417-424` | 绑定失败时**回退到 `0.0.0.0`**。默认 `LOCAL_PROXY_HOST="127.0.0.1"` 走不到这条路径，但一旦有人把它改成 `"::"`，9 个 SOCKS5 端口会直接暴露到公网（`proxy_auth` 默认关闭） | 删掉 0.0.0.0 回退，绑定失败就报错退出 |
| `vpngate9_multi.py:747` | `ui_auth.json` 明文存密码且未设 0600（对比：`AUTH_FILE` 设了 0600） | `chmod 600 ui_auth.json` |

---

## 三、优先级建议

1. **先修 P0-1**（guard 的 `idx`）——这是唯一会让进程直接崩掉的 Bug。
2. **再修 P0-2**（POST 无鉴权）——面板在公网，这是最危险的一处。
3. **然后 P0-3 + P1-4**——让守护沿用各通道自己的国家，并让两套守护只保留一套，否则 9 条通道的"独立出口"会被守护慢慢抹平成同一批日本节点。
4. 剩下的是体验/加固项，可批量改。

---

## 四、本次核查的原始数据（可复现）

```bash
# 拉全量节点
curl -s -A "Mozilla/5.0" "https://www.vpngate.net/api/iphone/" | wc -l
# → 101 行 = 1 行 *vpn_servers + 1 行列头 + 98 个节点

# 国家分布（跳过前两行）
curl -s -A "Mozilla/5.0" "https://www.vpngate.net/api/iphone/" \
  | awk -F, 'NR>2 && NF>3 {print $6}' | sort | uniq -c | sort -rn
```

抓取时间：2026-09-24。节点数每天波动，绝对值以你实际运行时面板显示的 `节点: N` 为准。

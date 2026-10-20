# 测试脚本

对着仓库里的源码跑，**不需要 VPS、不需要 openvpn**。

真实建隧道那条路在开发机上跑不通（Windows 没有 openvpn、也没有 TUN），所以涉及建隧道的
用例是靠本地起的 mock SOCKS5 + HTTP 服务来验证协议栈和带宽计算的。真机上第一次用
面板的「测带宽」时，建议先挑 1~2 个节点试，确认数字合理再批量跑。

## 运行

在**仓库根目录**执行：

```bash
# 1. 新节点标记逻辑 + 测速模块（含 mock SOCKS5 对端、chunked/EOF/限速场景）  37 项
python tests/vg9_seen_speed_test.py

# 2. 多出口分配逻辑（国家 / IP类型 / 同一国家 三种模式）                    36 项
python tests/vg9_assign_test.py

# 3. 前端 JS 语法 + 函数/元素/onclick 引用完整性（用 node --check）
python tests/vg9_frontend_check.py

# 4. 前端 DOM stub 单测（node，无需浏览器）                                 44 项
node tests/vg9_frontend_test.js

# 5. 端到端：起真实面板实例 + mock VPNGate 节点源                          61 项
python tests/vg9_new_speed_http_test.py

# 6. 端到端：分配接口（含登录态、并发、dry_run）                            44 项
python tests/vg9_assign_http_test.py

# 7. 面板 HTTPS（证书发现 / 自签 / 端到端 https）+ IP 类型未知值             63 项
python tests/vg9_https_test.py

# 8. 失败节点短期跳过 + 国家无货时放宽到全池 + 通道指数退避（修"某通道无限重连"）  26 项
python tests/vg9_node_pick_test.py

# 9. 精确到县（都道府县）：名称归一 / 固定递补顺序 / 就近降级 / 降级后锁定不回切  62 项
python tests/vg9_region_test.py

# 10. 端到端：/api/regions + auto_assign?region= + 页面县选择器/顺序提示      38 项
python tests/vg9_region_http_test.py
```

依赖只有 Python 3 标准库和 Node.js（第 3、4 项需要）。Linux 上把 `python` 换成 `python3`。
第 7 项需要 `openssl` 命令行（用来造测试证书和验证自签）；机器上没有 openssl 时它会自己
跳过相关用例并明确打印 `[SKIP]`，不算失败。

## 几点说明

- 脚本会**自动定位源码目录**，放在 `tests/` 下、或和源码同目录，都能直接跑。
- 所有脚本都会把源码复制到临时目录再改硬编码路径（`/opt/michaelvpn` → 临时目录），
  **不会在真实盘上创建目录，也不会碰你的实盘配置**。源码模块是**自动收集**的
  （`os.listdir(FIX)` 取全部 `*.py`），所以以后新增模块不用回来改测试。
- 后三个端到端用例会监听本地端口起临时实例，跑完自动关闭并清理。
- 端到端用例把 `vpn_utils.enrich_ip_info` 打了桩，避免依赖外网 IP 富化接口。
  **例外**：第 10 项（精确到县）必须用真实 IP 情报才有县数据，所以它不打桩；
  拿不到县数据时会打印 `[SKIP]` 并跳过县相关断言，不会误报失败。
- 第 5、6 项只测 HTTP 接口，会显式设 `VPNGATE_UI_TLS=off`（面板现在默认开 HTTPS，
  否则明文请求连不上）；HTTPS 本身由第 7 项覆盖。
- 第 9 项是纯函数测试，用合成节点（自带经纬度）跑，**不联网**：行政区判定不该受节点源可用性影响。
- 第 9 项同时覆盖"降级后锁定"：`region_lock` 一旦落下，目标县恢复可用也不会被选回去
  （只有显式传 `locked=""`、或重新分配时才解除），这是防止出口 IP 反复跳的关键行为。

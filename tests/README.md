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

# 4. 前端 DOM stub 单测（node，无需浏览器）                                 40 项
node tests/vg9_frontend_test.js

# 5. 端到端：起真实面板实例 + mock VPNGate 节点源                          61 项
python tests/vg9_new_speed_http_test.py

# 6. 端到端：分配接口（含登录态、并发、dry_run）                            44 项
python tests/vg9_assign_http_test.py
```

依赖只有 Python 3 标准库和 Node.js（第 3、4 项需要）。Linux 上把 `python` 换成 `python3`。

## 几点说明

- 脚本会**自动定位源码目录**，放在 `tests/` 下、或和源码同目录，都能直接跑。
- 所有脚本都会把源码复制到临时目录再改硬编码路径（`/opt/michaelvpn` → 临时目录），
  **不会在真实盘上创建目录，也不会碰你的实盘配置**。
- 后两个端到端用例会监听本地端口起临时实例，跑完自动关闭并清理。
- 端到端用例把 `vpn_utils.enrich_ip_info` 打了桩，避免依赖外网 IP 富化接口。

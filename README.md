# Xray 管理脚本

版本：v1.0.4-fix38  
支持系统：Ubuntu 20.04/22.04, CentOS 7/8, Debian 10/11（需 systemd）  
依赖工具：curl, jq, nginx, uuid-runtime, qrencode, snapd/certbot, netcat, unzip, dnsutils  
运行权限：需 root 权限

## 功能介绍

### 1. 核心功能
#### Xray 安装与管理
- 全新安装 Xray，支持多种协议：
  - VLESS+WS+TLS
  - VMess+WS+TLS
  - VLESS+gRPC+TLS
  - VLESS+TCP+TLS
- 检查 Xray 版本，支持安装最新版或指定版本。
- 配置 Xray 服务，包括日志、inbound 和 outbound 设置。

### 2. 用户管理
- **新建用户**：生成 UUID，支持设置月费、年费、永久或自定义到期时间。
- **用户续期**：支持基于用户名或 UUID 续期，时间计算正确。
- **查看链接**：显示 VLESS/VMess 链接、二维码、订阅链接及 Clash 配置链接。
- **用户列表**：列出所有用户信息（ID、用户名、UUID、到期时间、流量、状态）。
- **删除用户**：支持用户名或 UUID 删除，重启服务生效。
- **检查并禁用过期用户**：自动禁用过期用户，删除超期不活跃用户。

### 3. 协议管理
- 支持动态调整 Xray 使用的协议，重启服务生效。

### 4. 流量统计
- 显示用户已用流量，定期更新（每 8 小时，通过 crontab）。

### 5. 备份与恢复
- **创建备份**：备份 Xray 配置、用户信息和证书。
- **恢复备份**：支持恢复并可选更换域名。

### 6. 证书管理
- 查看证书信息（域名、申请时间、到期时间、剩余天数）。
- 自动申请和配置 LetsEncrypt SSL 证书。

### 7. 脚本管理
- **安装脚本**：创建服务并设置开机自启。
- **卸载脚本**：清理所有相关文件和服务。

### 8. 订阅功能
- **订阅链接**：生成格式：https://$DOMAIN/subscribe/$USERNAME.yml
  - 支持 VLESS 和 VMess 协议，直接输出节点链接。
  - 自动检查链接可用性，若失败则修复（权限、Nginx 配置、证书等）。
- **Clash 配置链接**：生成格式：https://$DOMAIN/clash/$USERNAME.yml
  - 输出 Clash YAML 格式配置文件，支持所有协议（VLESS+WS, VMess+WS, VLESS+gRPC, VLESS+TCP）。
  - 确保 Clash 客户端可直接导入使用。
- **到期时间显示**：在订阅和 Clash 链接后显示对应用户的到期时间（如“永久”或“2025-03-26 14:00:00”）。

### 9. 多子域名支持
- **域名验证**：根据当前 VPS IP（通过 curl ifconfig.me 获取）验证输入域名。
- 支持 Cloudflare 多子域名对应多 VPS（如 1.changkaiyuan.xyz -> 69.166.235.121）。
- 用户需输入与当前服务器 IP 匹配的域名。

### 10. 界面与交互
- **主菜单**：显示 Xray 状态（运行中为黄色，已停止为红色）。
- 提供 8 个选项：
  1. 安装
  2. 用户管理
  3. 协议管理
  4. 流量统计
  5. 备份恢复
  6. 查看证书
  7. 卸载
  8. 退出

### 11. 文件与路径
- **配置文件**：
  - Xray 配置：`/usr/local/etc/xray/config.json`
  - 用户数据：`/usr/local/etc/xray/users.json`
  - Nginx 配置：`/etc/nginx/conf.d/xray.conf`
- **订阅文件**：
  - 普通订阅：`/var/www/subscribe/$USERNAME.yml`
  - Clash 配置：`/var/www/clash/$USERNAME.yml`
- **日志**：
  - `/usr/local/var/log/xray/{access.log, error.log}`
- **备份**：`/var/backups/xray/`

### 12. 安全性与权限
- **文件权限**：
  - 配置和日志文件：`chmod 600`，归属 root:root。
  - 订阅和 Clash 文件：`chmod 644`，归属 www-data:www-data。
- **防火墙**：
  - 自动开放 80、443 和 49152-49159 端口（支持 ufw 或 firewalld）。
- **锁机制**：
  - 使用 `flock` 防止并发修改配置文件。

### 13. 其他特性
- **状态检查**：自动检测系统、Xray 状态和服务运行情况。
- **错误处理**：检查依赖、配置测试、服务启动失败时提供日志。
- **定时任务**：
  - 流量统计每 8 小时更新。
  - 过期用户检查每日运行。

## 安装与使用

```
bash <(curl -sL https://github.com/sinian-liu/xray_sub//raw/main/install.sh)
```
```
wget https://raw.githubusercontent.com/sinian-liu/ceshi/main/ceshi.sh -O ceshi.sh && chmod +x ceshi.sh && ./ceshi.sh
```

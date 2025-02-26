#!/bin/bash
# Xray 高级管理脚本
# 版本: v1.0.4-fix38
# 支持系统: Ubuntu 20.04/22.04, CentOS 7/8, Debian 10/11 (systemd)

XRAY_CONFIG="/usr/local/etc/xray/config.json"
USER_DATA="/usr/local/etc/xray/users.json"
NGINX_CONF="/etc/nginx/conf.d/xray.conf"
SUBSCRIPTION_DIR="/var/www/subscribe"
CLASH_DIR="/var/www/clash"
BACKUP_DIR="/var/backups/xray"
CERTS_DIR="/etc/letsencrypt/live"
LOG_DIR="/usr/local/var/log/xray"
SCRIPT_NAME="xray-menu"
LOCK_FILE="/tmp/xray_users.lock"
XRAY_SERVICE_NAME="xray"
XRAY_BIN="/usr/local/bin/xray"
INSTALL_DIR="/root/v2ray"
SCRIPT_PATH="$INSTALL_DIR/xray-install.sh"
SETTINGS_CONF="/usr/local/etc/xray/settings.conf"

declare DOMAIN WS_PATH VMESS_PATH GRPC_SERVICE TCP_PATH PROTOCOLS PORTS BASE_PORT UUID DELETE_THRESHOLD_DAYS SERVER_IP

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[36m'
NC='\033[0m'

main_menu() {
    init_environment
    while true; do
        echo -e "${GREEN}==== Xray高级管理脚本 ====${NC}"
        echo -e "${GREEN}服务器推荐：https://my.frantech.ca/aff.php?aff=4337${NC}"
        echo -e "${GREEN}VPS评测官方网站：https://www.1373737.xyz/${NC}"
        echo -e "${GREEN}YouTube频道：https://www.youtube.com/@cyndiboy7881${NC}"
        XRAY_STATUS=$(systemctl is-active "$XRAY_SERVICE_NAME" 2>/dev/null || echo "未安装")
        if [ "$XRAY_STATUS" = "active" ]; then
            XRAY_STATUS_TEXT="${YELLOW}Xray状态: 运行中${NC}"
        else
            XRAY_STATUS_TEXT="${RED}Xray状态: 已停止${NC}"
        fi
        PROTOCOL_TEXT=""
        if [ ${#PROTOCOLS[@]} -gt 0 ]; then
            for PROTOCOL in "${PROTOCOLS[@]}"; do
                case "$PROTOCOL" in
                    1) PROTOCOL_TEXT="$PROTOCOL_TEXT VLESS+WS+TLS" ;;
                    2) PROTOCOL_TEXT="$PROTOCOL_TEXT VMess+WS+TLS" ;;
                    3) PROTOCOL_TEXT="$PROTOCOL_TEXT VLESS+gRPC+TLS" ;;
                    4) PROTOCOL_TEXT="$PROTOCOL_TEXT VLESS+TCP+TLS (HTTP/2)" ;;
                esac
            done
            PROTOCOL_TEXT="| 使用协议:${PROTOCOL_TEXT}"
        else
            PROTOCOL_TEXT="| 未配置协议"
        fi
        echo -e "$XRAY_STATUS_TEXT $PROTOCOL_TEXT\n"
        echo -e "1. 全新安装\n2. 用户管理\n3. 协议管理\n4. 流量统计\n5. 备份恢复\n6. 查看证书\n7. 卸载脚本\n8. 退出脚本"
        read -p "请选择操作 [1-8]（回车退出）: " CHOICE
        [ -z "$CHOICE" ] && exit 0
        case "$CHOICE" in
            1) install_xray ;;
            2) user_management ;;
            3) protocol_management ;;
            4) traffic_stats ;;
            5) backup_restore ;;
            6) view_certificates ;;
            7) uninstall_script ;;
            8) exit 0 ;;
            *) echo -e "${RED}无效选择!${NC}" ;;
        esac
    done
}

detect_system() {
    . /etc/os-release
    OS_NAME="$ID"
    OS_VERSION="$VERSION_ID"
    case "$OS_NAME" in
        ubuntu|debian) PKG_MANAGER="apt";;
        centos) [ "$OS_VERSION" -ge 8 ] && PKG_MANAGER="dnf" || PKG_MANAGER="yum";;
        *) echo -e "${RED}不支持的系统: $OS_NAME${NC}"; exit 1;;
    esac
    ps -p 1 -o comm= | grep -q systemd || { echo -e "${RED}需要 systemd!${NC}"; exit 1; }
    for i in {1..30}; do
        STATE=$(systemctl is-system-running 2>/dev/null)
        [ "$STATE" = "running" ] || [ "$STATE" = "degraded" ] && break
        sleep 1
    done
    [ "$STATE" != "running" ] && [ "$STATE" != "degraded" ] && exit 1
    SERVER_IP=$(curl -s ifconfig.me)
}

detect_xray_service() {
    XRAY_SERVICE_NAME="xray"
}

init_environment() {
    [ "$EUID" -ne 0 ] && { echo -e "${RED}请使用 root 权限运行!${NC}"; exit 1; }
    mkdir -p "$LOG_DIR" "$SUBSCRIPTION_DIR" "$CLASH_DIR" "$BACKUP_DIR" "/usr/local/etc/xray" || exit 1
    chmod 770 "$LOG_DIR" "$SUBSCRIPTION_DIR" "$CLASH_DIR" "$BACKUP_DIR" "/usr/local/etc/xray"
    chown root:root "$LOG_DIR" "$SUBSCRIPTION_DIR" "$CLASH_DIR" "$BACKUP_DIR" "/usr/local/etc/xray"
    touch "$LOG_DIR/access.log" "$LOG_DIR/error.log"
    chmod 660 "$LOG_DIR/access.log" "$LOG_DIR/error.log"
    chown root:root "$LOG_DIR/access.log" "$LOG_DIR/error.log"
    [ ! -s "$USER_DATA" ] || ! jq -e . "$USER_DATA" >/dev/null 2>&1 && { echo '{"users": []}' > "$USER_DATA"; chmod 600 "$USER_DATA"; chown root:root "$USER_DATA"; }
    [ ! -f "$XRAY_CONFIG" ] && { echo '{"log": {"loglevel": "debug", "access": "'"$LOG_DIR/access.log"'", "error": "'"$LOG_DIR/error.log"'"}, "inbounds": [], "outbounds": [{"protocol": "freedom"}]}' > "$XRAY_CONFIG"; chmod 600 "$XRAY_CONFIG"; chown root:root "$XRAY_CONFIG"; }
    detect_system
    detect_xray_service
    load_config
    [ -f "$SETTINGS_CONF" ] && DELETE_THRESHOLD_DAYS=$(grep "DELETE_THRESHOLD_DAYS" "$SETTINGS_CONF" | cut -d'=' -f2)
    exec 200>$LOCK_FILE
    trap 'rm -f tmp.json; flock -u 200; rm -f $LOCK_FILE' EXIT
}

load_config() {
    [ -f "$NGINX_CONF" ] && grep -q "server_name" "$NGINX_CONF" && {
        DOMAIN=$(grep "server_name" "$NGINX_CONF" | awk '{print $2}' | sed 's/;//' | head -n 1)
        WS_PATH=$(grep "location /xray_ws_" "$NGINX_CONF" | awk -F' ' '{print $2}' | head -n 1)
        VMESS_PATH=$(grep "location /vmess_ws_" "$NGINX_CONF" | awk -F' ' '{print $2}' | head -n 1)
        GRPC_SERVICE=$(grep "location /grpc_" "$NGINX_CONF" | awk -F' ' '{print $2}' | sed 's#/##g' | head -n 1)
        TCP_PATH=$(grep "location /tcp_" "$NGINX_CONF" | awk -F' ' '{print $2}' | head -n 1)
    }
    [ -f "$XRAY_CONFIG" ] && jq -e . "$XRAY_CONFIG" >/dev/null 2>&1 && {
        PROTOCOLS=()
        PORTS=()
        while read -r port protocol; do
            PORTS+=("$port")
            case "$protocol" in
                "vless"|"vmess") 
                    network=$(jq -r ".inbounds[] | select(.port == $port) | .streamSettings.network" "$XRAY_CONFIG")
                    case "$network" in
                        "ws") [[ "$protocol" == "vless" ]] && PROTOCOLS+=(1) || PROTOCOLS+=(2) ;;
                        "grpc") PROTOCOLS+=(3) ;;
                        "http") PROTOCOLS+=(4) ;;
                    esac ;;
            esac
        done < <(jq -r '.inbounds[] | [.port, .protocol] | join(" ")' "$XRAY_CONFIG")
    }
}

configure_domain() {
    echo -e "${GREEN}[配置域名...]${NC}"
    local retries=3
    while [ $retries -gt 0 ]; do
        read -p "请输入当前 VPS 对应的域名（示例：1.changkaiyuan.xyz）: " DOMAIN
        DOMAIN_IP=$(dig +short "$DOMAIN" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
        [ "$DOMAIN_IP" = "$SERVER_IP" ] && { echo "域名验证通过! 当前服务器 IP: $SERVER_IP"; break; }
        retries=$((retries - 1))
        echo -e "${RED}域名 $DOMAIN 解析到的 IP ($DOMAIN_IP) 与当前服务器 IP ($SERVER_IP) 不匹配! 剩余重试次数: $retries${NC}"
        read -p "是否重试? [y/N]: " RETRY
        [[ ! "$RETRY" =~ ^[Yy] ]] && exit 1
    done
    [ $retries -eq 0 ] && { echo -e "${RED}域名验证多次失败! 请确保输入的域名正确解析到当前服务器 IP${NC}"; exit 1; }
}

check_and_set_domain() {
    [ -z "$DOMAIN" ] && configure_domain
}

install_dependencies() {
    echo -e "${GREEN}[安装依赖...]${NC}"
    case "$PKG_MANAGER" in
        apt) apt update && apt install -y curl jq nginx uuid-runtime qrencode snapd netcat-openbsd unzip dnsutils || exit 1
             [ ! -f /usr/bin/certbot ] && { systemctl enable snapd; systemctl start snapd; snap install --classic certbot; ln -sf /snap/bin/certbot /usr/bin/certbot; }
             ;;
        yum|dnf) $PKG_MANAGER update -y && $PKG_MANAGER install -y curl jq nginx uuid-runtime qrencode nc unzip bind-utils || exit 1
                 [ ! -f /usr/bin/certbot ] && $PKG_MANAGER install -y certbot python3-certbot-nginx
                 ;;
    esac
    systemctl start nginx || exit 1
}

check_xray_version() {
    echo -e "${GREEN}[检查Xray版本...]${NC}"
    CURRENT_VERSION=$(xray --version 2>/dev/null | grep -oP 'Xray \K[0-9]+\.[0-9]+\.[0-9]+' || echo "未安装")
    if [ "$CURRENT_VERSION" = "未安装" ] || ! command -v xray >/dev/null; then
        LATEST_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.tag_name' | sed 's/v//' || echo "unknown")
        [ "$LATEST_VERSION" = "unknown" ] && { bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) || exit 1; }
        echo "当前版本: 未安装，最新版本: $LATEST_VERSION"
        read -p "是否安装最新版本? [y/N]: " UPDATE
        if [[ "$UPDATE" =~ ^[Yy] ]]; then
            bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) || exit 1
        else
            VERSIONS=("25.2.21" "25.1.0" "25.0.0" "24.12.0" "24.11.0" "1.7.5")
            for i in "${!VERSIONS[@]}"; do echo "$((i+1)). ${VERSIONS[$i]}"; done
            read -p "请选择版本（q 退出）: " VERSION_CHOICE
            [[ "$VERSION_CHOICE" =~ ^[qQ]$ ]] && exit 0
            [[ "$VERSION_CHOICE" =~ ^[0-9]+$ ]] && [ "$VERSION_CHOICE" -le ${#VERSIONS[@]} ] && {
                SELECTED_VERSION="${VERSIONS[$((VERSION_CHOICE-1))]}"
                [ "$SELECTED_VERSION" = "1.7.5" ] && {
                    curl -L -o /tmp/xray-v1.7.5.zip "https://github.com/sinian-liu/v2ray-agent-2.5.73/releases/download/v1.7.5/xray-linux-64.zip" && unzip -o /tmp/xray-v1.7.5.zip -d /tmp/xray-v1.7.5 && mv /tmp/xray-v1.7.5/xray /usr/local/bin/xray && chmod +x /usr/local/bin/xray && rm -rf /tmp/xray-v1.7.5*
                } || bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) -v "v$SELECTED_VERSION" || exit 1
            }
        fi
        command -v xray >/dev/null || { echo -e "${RED}Xray 未安装!${NC}"; exit 1; }
    fi
}

check_firewall() {
    BASE_PORT=49152
    command -v ufw >/dev/null && ufw status | grep -q "Status: active" && { ufw allow 80; ufw allow 443; ufw allow 49152:49159/tcp; }
    command -v firewall-cmd >/dev/null && firewall-cmd --state | grep -q "running" && { firewall-cmd --permanent --add-port=80/tcp; firewall-cmd --permanent --add-port=443/tcp; firewall-cmd --permanent --add-port=49152-49159/tcp; firewall-cmd --reload; }
}

check_ports() {
    PORTS=()
    for i in "${!PROTOCOLS[@]}"; do
        PORT=$((BASE_PORT + i))
        while lsof -i :$PORT >/dev/null 2>&1; do PORT=$((PORT + 1)); done
        PORTS[$i]=$PORT
    done
}

apply_ssl() {
    local retries=3
    while [ $retries -gt 0 ]; do
        certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" && break
        retries=$((retries - 1))
        sleep 5
    done
    [ $retries -eq 0 ] && exit 1
}

configure_nginx() {
    WS_PATH="/xray_ws_$(openssl rand -hex 4)"
    GRPC_SERVICE="grpc_$(openssl rand -hex 4)"
    VMESS_PATH="/vmess_ws_$(openssl rand -hex 4)"
    TCP_PATH="/tcp_$(openssl rand -hex 4)"
    [ -f "$NGINX_CONF" ] && ! grep -q "Xray 配置" "$NGINX_CONF" && mv "$NGINX_CONF" "$NGINX_CONF.bak.$(date +%F_%H%M%S)"
    # 移除默认站点以避免冲突
    rm -f /etc/nginx/sites-enabled/default
    cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate $CERTS_DIR/$DOMAIN/fullchain.pem;
    ssl_certificate_key $CERTS_DIR/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    access_log /var/log/nginx/xray_access.log;
    error_log /var/log/nginx/xray_error.log info;
    location /subscribe/ {
        root /var/www;
        autoindex off;
    }
    location /clash/ {
        root /var/www;
        autoindex off;
    }
EOF
    for i in "${!PROTOCOLS[@]}"; do
        PROTOCOL=${PROTOCOLS[$i]}
        PORT=${PORTS[$i]}
        case "$PROTOCOL" in
            1) echo "    location $WS_PATH { proxy_pass http://127.0.0.1:$PORT; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection \"Upgrade\"; proxy_set_header Host \$host; }" >> "$NGINX_CONF" ;;
            2) echo "    location $VMESS_PATH { proxy_pass http://127.0.0.1:$PORT; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection \"Upgrade\"; proxy_set_header Host \$host; }" >> "$NGINX_CONF" ;;
            3) echo "    location /$GRPC_SERVICE { grpc_pass grpc://127.0.0.1:$PORT; }" >> "$NGINX_CONF" ;;
            4) echo "    location $TCP_PATH { proxy_pass http://127.0.0.1:$PORT; proxy_http_version 2.0; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; }" >> "$NGINX_CONF" ;;
        esac
    done
    echo "}" >> "$NGINX_CONF"
    nginx -t && systemctl restart nginx || { nginx -t; cat /var/log/nginx/xray_error.log | tail -n 20; exit 1; }
    # 确保订阅和 Clash 目录权限正确
    chown -R www-data:www-data "$SUBSCRIPTION_DIR" "$CLASH_DIR"
    chmod -R 755 "$SUBSCRIPTION_DIR" "$CLASH_DIR"
}

check_subscription() {
    echo -e "${GREEN}[检查订阅配置...]${NC}"
    local SUBSCRIPTION_URL="https://$DOMAIN/subscribe/$USERNAME.yml"
    local CLASH_URL="https://$DOMAIN/clash/$USERNAME.yml"
    # 测试订阅链接
    if curl -s --head --insecure "$SUBSCRIPTION_URL" | grep -q "200 OK"; then
        echo -e "${GREEN}订阅链接 $SUBSCRIPTION_URL 可正常访问${NC}"
    else
        echo -e "${YELLOW}订阅链接 $SUBSCRIPTION_URL 不可访问，尝试修复...${NC}"
        # 检查文件是否存在
        if [ ! -f "$SUBSCRIPTION_DIR/$USERNAME.yml" ]; then
            echo -e "${RED}订阅文件 $SUBSCRIPTION_DIR/$USERNAME.yml 不存在${NC}"
            exit 1
        fi
        # 检查 Nginx 配置
        nginx -t || { echo -e "${RED}Nginx 配置错误${NC}"; cat /var/log/nginx/xray_error.log | tail -n 20; exit 1; }
        # 检查证书
        if [ ! -f "$CERTS_DIR/$DOMAIN/fullchain.pem" ] || [ ! -f "$CERTS_DIR/$DOMAIN/privkey.pem" ]; then
            echo -e "${YELLOW}SSL 证书缺失，重新生成...${NC}"
            apply_ssl
        fi
        # 检查 HTTP 重定向
        if ! curl -s --head "http://$DOMAIN/subscribe/$USERNAME.yml" | grep -q "301 Moved Permanently"; then
            echo -e "${YELLOW}HTTP 重定向未生效，修复默认站点...${NC}"
            rm -f /etc/nginx/sites-enabled/default
        fi
        # 重启 Nginx
        systemctl restart nginx
        # 再次测试
        if curl -s --head --insecure "$SUBSCRIPTION_URL" | grep -q "200 OK"; then
            echo -e "${GREEN}订阅链接修复成功${NC}"
        else
            echo -e "${RED}订阅链接仍不可访问，请检查网络或防火墙设置${NC}"
            exit 1
        fi
    fi
    # 测试 Clash 链接
    if curl -s --head --insecure "$CLASH_URL" | grep -q "200 OK"; then
        echo -e "${GREEN}Clash 配置链接 $CLASH_URL 可正常访问${NC}"
    else
        echo -e "${YELLOW}Clash 配置链接 $CLASH_URL 不可访问，尝试修复...${NC}"
        if [ ! -f "$CLASH_DIR/$USERNAME.yml" ]; then
            echo -e "${RED}Clash 文件 $CLASH_DIR/$USERNAME.yml 不存在${NC}"
            exit 1
        fi
        systemctl restart nginx
        if curl -s --head --insecure "$CLASH_URL" | grep -q "200 OK"; then
            echo -e "${GREEN}Clash 配置链接修复成功${NC}"
        else
            echo -e "${RED}Clash 配置链接仍不可访问，请检查网络或防火墙设置${NC}"
            exit 1
        fi
    fi
}

create_default_user() {
    USERNAME="自用"
    UUID=$(uuidgen)
    while jq -r ".users[] | .uuid" "$USER_DATA" | grep -q "$UUID"; do UUID=$(uuidgen); done
    EXPIRE_DATE="永久"
    flock -x 200
    jq --arg name "$USERNAME" --arg uuid "$UUID" --arg expire "$EXPIRE_DATE" \
       '.users += [{"id": (.users | length + 1), "name": $name, "uuid": $uuid, "expire": $expire, "used_traffic": 0, "status": "启用"}]' \
       "$USER_DATA" > tmp.json && mv tmp.json "$USER_DATA"
    chmod 600 "$USER_DATA"
    chown root:root "$USER_DATA"
    SUBSCRIPTION_FILE="$SUBSCRIPTION_DIR/$USERNAME.yml"
    CLASH_FILE="$CLASH_DIR/$USERNAME.yml"
    > "$SUBSCRIPTION_FILE"
    > "$CLASH_FILE"
    for PROTOCOL in "${PROTOCOLS[@]}"; do
        case "$PROTOCOL" in
            1) echo "vless://$UUID@$DOMAIN:443?encryption=none&security=tls&type=ws&path=$WS_PATH&sni=$DOMAIN&host=$DOMAIN#$USERNAME" >> "$SUBSCRIPTION_FILE"
               cat >> "$CLASH_FILE" <<EOF
proxies:
  - name: "$USERNAME"
    type: vless
    server: $DOMAIN
    port: 443
    uuid: $UUID
    network: ws
    tls: true
    udp: true
    sni: $DOMAIN
    ws-opts:
      path: $WS_PATH
      headers:
        Host: $DOMAIN
EOF
               ;;
            2) echo "vmess://$(echo -n '{\"v\":\"2\",\"ps\":\"$USERNAME\",\"add\":\"$DOMAIN\",\"port\":\"443\",\"id\":\"$UUID\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"$DOMAIN\",\"path\":\"$VMESS_PATH\",\"tls\":\"tls\",\"sni\":\"$DOMAIN\"}' | base64 -w 0)" >> "$SUBSCRIPTION_FILE"
               cat >> "$CLASH_FILE" <<EOF
proxies:
  - name: "$USERNAME"
    type: vmess
    server: $DOMAIN
    port: 443
    uuid: $UUID
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    udp: true
    sni: $DOMAIN
    ws-opts:
      path: $VMESS_PATH
      headers:
        Host: $DOMAIN
EOF
               ;;
            3) echo "vless://$UUID@$DOMAIN:443?encryption=none&security=tls&type=grpc&serviceName=$GRPC_SERVICE&sni=$DOMAIN#$USERNAME" >> "$SUBSCRIPTION_FILE"
               cat >> "$CLASH_FILE" <<EOF
proxies:
  - name: "$USERNAME"
    type: vless
    server: $DOMAIN
    port: 443
    uuid: $UUID
    network: grpc
    tls: true
    udp: true
    sni: $DOMAIN
    grpc-opts:
      grpc-service-name: $GRPC_SERVICE
EOF
               ;;
            4) echo "vless://$UUID@$DOMAIN:443?encryption=none&security=tls&type=http&path=$TCP_PATH&sni=$DOMAIN&host=$DOMAIN#$USERNAME" >> "$SUBSCRIPTION_FILE"
               cat >> "$CLASH_FILE" <<EOF
proxies:
  - name: "$USERNAME"
    type: vless
    server: $DOMAIN
    port: 443
    uuid: $UUID
    network: http
    tls: true
    udp: true
    sni: $DOMAIN
    http-opts:
      path: $TCP_PATH
      headers:
        Host: $DOMAIN
EOF
               ;;
        esac
    done
    chmod 644 "$SUBSCRIPTION_FILE" "$CLASH_FILE"
    chown www-data:www-data "$SUBSCRIPTION_FILE" "$CLASH_FILE"
    flock -u 200
}

configure_xray() {
    cat > "$XRAY_CONFIG" <<EOF
{
    "log": {"loglevel": "debug", "access": "$LOG_DIR/access.log", "error": "$LOG_DIR/error.log"},
    "inbounds": [],
    "outbounds": [{"protocol": "freedom"}]
}
EOF
    chmod 600 "$XRAY_CONFIG"
    chown root:root "$XRAY_CONFIG"
    [ -z "$UUID" ] && { echo -e "${RED}错误: 未定义 UUID${NC}"; exit 1; }
    for i in "${!PROTOCOLS[@]}"; do
        PROTOCOL=${PROTOCOLS[$i]}
        PORT=${PORTS[$i]}
        case "$PROTOCOL" in
            1) jq ".inbounds += [{\"port\": $PORT, \"protocol\": \"vless\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}], \"decryption\": \"none\"}, \"streamSettings\": {\"network\": \"ws\", \"wsSettings\": {\"path\": \"$WS_PATH\"}}}]" "$XRAY_CONFIG" > tmp.json ;;
            2) jq ".inbounds += [{\"port\": $PORT, \"protocol\": \"vmess\", \"settings\": {\"clients\": [{\"id\": \"$UUID\", \"alterId\": 0}]}, \"streamSettings\": {\"network\": \"ws\", \"wsSettings\": {\"path\": \"$VMESS_PATH\"}}}]" "$XRAY_CONFIG" > tmp.json ;;
            3) jq ".inbounds += [{\"port\": $PORT, \"protocol\": \"vless\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}], \"decryption\": \"none\"}, \"streamSettings\": {\"network\": \"grpc\", \"grpcSettings\": {\"serviceName\": \"$GRPC_SERVICE\"}}}]" "$XRAY_CONFIG" > tmp.json ;;
            4) jq ".inbounds += [{\"port\": $PORT, \"protocol\": \"vless\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}], \"decryption\": \"none\"}, \"streamSettings\": {\"network\": \"http\", \"httpSettings\": {\"path\": \"$TCP_PATH\", \"host\": [\"$DOMAIN\"]}}}]" "$XRAY_CONFIG" > tmp.json ;;
        esac
        [ $? -ne 0 ] || ! jq -e . tmp.json >/dev/null 2>&1 && { echo -e "${RED}生成 inbound 失败!${NC}"; cat tmp.json; rm -f tmp.json; exit 1; }
        mv tmp.json "$XRAY_CONFIG"
    done
    chmod 600 "$XRAY_CONFIG"
    chown root:root "$XRAY_CONFIG"
    $XRAY_BIN -test -config "$XRAY_CONFIG" >/dev/null 2>&1 || { echo -e "${RED}Xray 配置测试失败!${NC}"; $XRAY_BIN -test -config "$XRAY_CONFIG"; cat "$XRAY_CONFIG"; exit 1; }
}

start_services() {
    systemctl stop "$XRAY_SERVICE_NAME" nginx >/dev/null 2>&1
    $XRAY_BIN -test -config "$XRAY_CONFIG" >/dev/null 2>&1 || { echo -e "${RED}Xray 配置无效!${NC}"; $XRAY_BIN -test -config "$XRAY_CONFIG"; cat "$XRAY_CONFIG"; exit 1; }
    systemctl daemon-reload
    systemctl enable "$XRAY_SERVICE_NAME" >/dev/null 2>&1
    systemctl restart "$XRAY_SERVICE_NAME" || { echo -e "${RED}Xray 服务启动失败!${NC}"; systemctl status "$XRAY_SERVICE_NAME"; cat "$LOG_DIR/error.log"; exit 1; }
    sleep 3
    systemctl is-active "$XRAY_SERVICE_NAME" >/dev/null || { echo -e "${RED}Xray 服务未运行!${NC}"; systemctl status "$XRAY_SERVICE_NAME"; cat "$LOG_DIR/error.log"; exit 1; }
    systemctl restart nginx || { nginx -t; cat /var/log/nginx/xray_error.log | tail -n 20; exit 1; }
    sleep 3
    systemctl is-active nginx >/dev/null && systemctl is-active "$XRAY_SERVICE_NAME" >/dev/null || { echo "Nginx: $(systemctl is-active nginx)"; echo "Xray: $(systemctl is-active "$XRAY_SERVICE_NAME")"; cat "$LOG_DIR/error.log"; exit 1; }
    for PORT in "${PORTS[@]}"; do nc -z 127.0.0.1 "$PORT" >/dev/null 2>&1 || { netstat -tuln | grep xray; cat "$LOG_DIR/error.log"; exit 1; }; done
}

install_xray() {
    detect_system
    check_firewall
    echo -e "${GREEN}[选择安装的协议]${NC}"
    echo -e "1. VLESS+WS+TLS (推荐)\n2. VMess+WS+TLS\n3. VLESS+gRPC+TLS\n4. VLESS+TCP+TLS (HTTP/2)"
    read -p "请选择 (多选用空格分隔, 默认1): " -a PROTOCOLS
    [ ${#PROTOCOLS[@]} -eq 0 ] && PROTOCOLS=(1)
    check_ports
    install_dependencies
    configure_domain
    apply_ssl
    create_default_user
    configure_nginx
    check_xray_version
    configure_xray
    cat > /etc/systemd/system/$XRAY_SERVICE_NAME.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStartPre=/bin/mkdir -p $LOG_DIR
ExecStartPre=/bin/chown -R root:root $LOG_DIR
ExecStartPre=/bin/chmod -R 770 $LOG_DIR
ExecStartPre=/bin/touch $LOG_DIR/access.log $LOG_DIR/error.log
ExecStartPre=/bin/chown root:root $LOG_DIR/access.log $LOG_DIR/error.log
ExecStartPre=/bin/chmod 660 $LOG_DIR/access.log $LOG_DIR/error.log
ExecStartPre=/bin/chown root:root $XRAY_CONFIG
ExecStartPre=/bin/chmod 600 $XRAY_CONFIG
ExecStart=$XRAY_BIN run -config $XRAY_CONFIG
Restart=on-failure
RestartSec=5
User=root
Group=root
LimitNPROC=10000
LimitNOFILE=1000000
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 /etc/systemd/system/$XRAY_SERVICE_NAME.service
    systemctl daemon-reload
    start_services
    check_subscription
    show_user_link
    echo -e "\n安装完成! 输入 'v' 打开管理菜单"
}

show_user_link() {
    echo -e "${GREEN}[显示用户链接...]${NC}"
    check_and_set_domain
    EXPIRE_DATE=$(jq -r ".users[] | select(.name == \"$USERNAME\") | .expire" "$USER_DATA")
    for PROTOCOL in "${PROTOCOLS[@]}"; do
        case "$PROTOCOL" in
            1) VLESS_WS_LINK="vless://$UUID@$DOMAIN:443?encryption=none&security=tls&type=ws&path=$WS_PATH&sni=$DOMAIN&host=$DOMAIN#$USERNAME"
               echo "[二维码 (VLESS+WS+TLS)]:"; qrencode -t ansiutf8 "$VLESS_WS_LINK" || echo -e "${YELLOW}二维码失败${NC}"
               echo -e "\n链接地址 (VLESS+WS+TLS):\n$VLESS_WS_LINK" ;;
            2) VMESS_LINK="vmess://$(echo -n '{\"v\":\"2\",\"ps\":\"$USERNAME\",\"add\":\"$DOMAIN\",\"port\":\"443\",\"id\":\"$UUID\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"$DOMAIN\",\"path\":\"$VMESS_PATH\",\"tls\":\"tls\",\"sni\":\"$DOMAIN\"}' | base64 -w 0)"
               echo "[二维码 (VMess+WS+TLS)]:"; qrencode -t ansiutf8 "$VMESS_LINK" || echo -e "${YELLOW}二维码失败${NC}"
               echo -e "\n链接地址 (VMess+WS+TLS):\n$VMESS_LINK" ;;
            3) VLESS_GRPC_LINK="vless://$UUID@$DOMAIN:443?encryption=none&security=tls&type=grpc&serviceName=$GRPC_SERVICE&sni=$DOMAIN#$USERNAME"
               echo "[二维码 (VLESS+gRPC+TLS)]:"; qrencode -t ansiutf8 "$VLESS_GRPC_LINK" || echo -e "${YELLOW}二维码失败${NC}"
               echo -e "\n链接地址 (VLESS+gRPC+TLS):\n$VLESS_GRPC_LINK" ;;
            4) VLESS_TCP_LINK="vless://$UUID@$DOMAIN:443?encryption=none&security=tls&type=http&path=$TCP_PATH&sni=$DOMAIN&host=$DOMAIN#$USERNAME"
               echo "[二维码 (VLESS+TCP+TLS)]:"; qrencode -t ansiutf8 "$VLESS_TCP_LINK" || echo -e "${YELLOW}二维码失败${NC}"
               echo -e "\n链接地址 (VLESS+TCP+TLS):\n$VLESS_TCP_LINK" ;;
        esac
    done
    echo -e "\n订阅链接（使用主域名）:\nhttps://$DOMAIN/subscribe/$USERNAME.yml"
    echo -e "Clash 配置链接:\nhttps://$DOMAIN/clash/$USERNAME.yml"
    echo -e "${GREEN}账号到期时间: $EXPIRE_DATE${NC}"
    echo -e "${GREEN}请使用主域名订阅链接以确保兼容性和证书有效性${NC}"
}

disable_expired_users() {
    echo -e "${GREEN}=== 检查并禁用过期用户 ===${NC}"
    check_and_set_domain
    [ ${#PROTOCOLS[@]} -eq 0 ] || [ ! -f "$XRAY_CONFIG" ] && { echo -e "${RED}未检测到 Xray 配置${NC}"; return; }
    [ ! -s "$USER_DATA" ] || ! jq -e . "$USER_DATA" >/dev/null 2>&1 && {
        LATEST_BACKUP=$(ls -t "$USER_DATA.bak."* 2>/dev/null | head -n 1)
        [ -n "$LATEST_BACKUP" ] && jq -e . "$LATEST_BACKUP" >/dev/null 2>&1 && cp "$LATEST_BACKUP" "$USER_DATA" || { echo '{"users": []}' > "$USER_DATA"; chmod 600 "$USER_DATA"; chown root:root "$USER_DATA"; return; }
    }
    flock -x 200
    TODAY=$(date +%s)
    [ -z "$DELETE_THRESHOLD_DAYS" ] && { read -p "请输入不活跃用户删除阈值（天，默认 365）： " DELETE_THRESHOLD_DAYS; DELETE_THRESHOLD_DAYS=${DELETE_THRESHOLD_DAYS:-365}; echo "DELETE_THRESHOLD_DAYS=$DELETE_THRESHOLD_DAYS" > "$SETTINGS_CONF"; }
    THRESHOLD_TIME=$((TODAY - DELETE_THRESHOLD_DAYS * 86400))
    EXPIRED_USERS=$(jq -r ".users[] | select(.expire != \"永久\" and (.expire | strptime(\"%Y-%m-%d %H:%M:%S\") | mktime) < $TODAY and .status == \"启用\") | .uuid" "$USER_DATA")
    INACTIVE_USERS=$(jq -r ".users[] | select(.status == \"禁用\" and (.expire != \"永久\" and (.expire | strptime(\"%Y-%m-%d %H:%M:%S\") | mktime) < $THRESHOLD_TIME)) | .uuid" "$USER_DATA")
    if [ -n "$EXPIRED_USERS" ] || [ -n "$INACTIVE_USERS" ]; then
        cp "$XRAY_CONFIG" "$XRAY_CONFIG.bak.$(date +%F_%H%M%S)"
        cp "$USER_DATA" "$USER_DATA.bak.$(date +%F_%H%M%S)"
        for UUID in $EXPIRED_USERS; do
            jq --arg uuid "$UUID" '.users[] | select(.uuid == $uuid) | .status = "禁用"' "$USER_DATA" > tmp.json && mv tmp.json "$USER_DATA"
            for i in $(seq 0 $((${#PROTOCOLS[@]} - 1))); do jq --arg uuid "$UUID" ".inbounds[$i].settings.clients -= [{\"id\": \$uuid}]" "$XRAY_CONFIG" > tmp.json && mv tmp.json "$XRAY_CONFIG"; done
        done
        for UUID in $INACTIVE_USERS; do
            jq "del(.users[] | select(.uuid == \"$UUID\"))" "$USER_DATA" > tmp.json && mv tmp.json "$USER_DATA"
            for i in $(seq 0 $((${#PROTOCOLS[@]} - 1))); do jq --arg uuid "$UUID" ".inbounds[$i].settings.clients -= [{\"id\": \$uuid}]" "$XRAY_CONFIG" > tmp.json && mv tmp.json "$XRAY_CONFIG"; done
            echo "用户 UUID $UUID 已超过 $DELETE_THRESHOLD_DAYS 天未续费，已删除"
        done
        [ ! -e "$USER_DATA" ] || ! jq -e . "$USER_DATA" >/dev/null 2>&1 || [ ! -e "$XRAY_CONFIG" ] || ! jq -e . "$XRAY_CONFIG" >/dev/null 2>&1 && { cp "$USER_DATA.bak.$(date +%F_%H%M%S)" "$USER_DATA"; cp "$XRAY_CONFIG.bak.$(date +%F_%H%M%S)" "$XRAY_CONFIG"; exit 1; }
        chmod 600 "$USER_DATA" "$XRAY_CONFIG"
        chown root:root "$USER_DATA" "$XRAY_CONFIG"
        systemctl restart "$XRAY_SERVICE_NAME" || { systemctl status "$XRAY_SERVICE_NAME"; cat "$LOG_DIR/error.log"; exit 1; }
        echo "操作完成并重启 Xray。"
    else
        echo "无过期或需删除用户。"
    fi
    (crontab -l 2>/dev/null; echo "0 0 * * * bash $SCRIPT_PATH --disable-expired") | crontab -
    flock -u 200
}

user_management() {
    exec 200>$LOCK_FILE
    check_and_set_domain
    [ ${#PROTOCOLS[@]} -eq 0 ] || [ ! -f "$XRAY_CONFIG" ] && { echo -e "${YELLOW}未检测到 Xray 配置${NC}"; return; }
    while true; do
        echo -e "${BLUE}用户管理菜单${NC}"
        echo -e "1. 新建用户\n2. 用户续期\n3. 查看链接\n4. 用户列表\n5. 删除用户\n6. 检查并禁用过期用户\n7. 返回主菜单"
        read -p "请选择操作（回车返回主菜单）: " CHOICE
        [ -z "$CHOICE" ] && break
        case "$CHOICE" in
            1) add_user ;;
            2) renew_user ;;
            3) view_links ;;
            4) list_users ;;
            5) delete_user ;;
            6) disable_expired_users ;;
            7) break ;;
            *) echo -e "${RED}无效选项!${NC}" ;;
        esac
    done
    exec 200>&-
}

add_user() {
    echo -e "${GREEN}=== 新建用户流程 ===${NC}"
    [ ${#PROTOCOLS[@]} -eq 0 ] || [ ! -f "$XRAY_CONFIG" ] || ! jq -e '.inbounds | length > 0' "$XRAY_CONFIG" >/dev/null 2>&1 && { echo -e "${RED}未检测到 Xray 配置${NC}"; return; }
    flock -x 200
    cp "$XRAY_CONFIG" "$XRAY_CONFIG.bak.$(date +%F_%H%M%S)"
    cp "$USER_DATA" "$USER_DATA.bak.$(date +%F_%H%M%S)"
    read -p "输入用户名: " USERNAME
    UUID=$(uuidgen)
    while jq -r ".users[] | .uuid" "$USER_DATA" | grep -q "$UUID"; do UUID=$(uuidgen); done
    echo -e "1. 月费 (默认)\n2. 年费\n3. 永久\n4. 自定义时间"
    read -p "请选择 [默认1]: " EXPIRE_TYPE
    EXPIRE_TYPE=${EXPIRE_TYPE:-1}
    case "$EXPIRE_TYPE" in
        1) EXPIRE_DATE=$(date -d "+1 month" "+%Y-%m-%d %H:%M:%S") ;;
        2) EXPIRE_DATE=$(date -d "+1 year" "+%Y-%m-%d %H:%M:%S") ;;
        3) EXPIRE_DATE="永久" ;;
        4) read -p "请输入自定义时间 (如 1h/10m/200d): " CUSTOM_TIME
           if [[ "$CUSTOM_TIME" =~ ^([0-9]+)([hmd])$ ]]; then
               NUM=${BASH_REMATCH[1]}
               UNIT=${BASH_REMATCH[2]}
               case "$UNIT" in
                   h) EXPIRE_DATE=$(date -d "+${NUM} hours" "+%Y-%m-%d %H:%M:%S") ;;
                   m) EXPIRE_DATE=$(date -d "+${NUM} minutes" "+%Y-%m-%d %H:%M:%S") ;;
                   d) EXPIRE_DATE=$(date -d "+${NUM} days" "+%Y-%m-%d %H:%M:%S") ;;
               esac
           else
               echo -e "${RED}无效格式! 请使用如 1h、10m、200d${NC}"
               exit 1
           fi
           ;;
        *) EXPIRE_DATE=$(date -d "+1 month" "+%Y-%m-%d %H:%M:%S") ;;
    esac
    jq --arg name "$USERNAME" --arg uuid "$UUID" --arg expire "$EXPIRE_DATE" \
       '.users += [{"id": (.users | length + 1), "name": $name, "uuid": $uuid, "expire": $expire, "used_traffic": 0, "status": "启用"}]' \
       "$USER_DATA" > tmp.json && mv tmp.json "$USER_DATA" || { cp "$USER_DATA.bak.$(date +%F_%H%M%S)" "$USER_DATA"; exit 1; }
    [ ! -e "$USER_DATA" ] || ! jq -e . "$USER_DATA" >/dev/null 2>&1 && { cp "$USER_DATA.bak.$(date +%F_%H%M%S)" "$USER_DATA"; exit 1; }
    for i in $(seq 0 $((${#PROTOCOLS[@]} - 1))); do
        jq --arg uuid "$UUID" ".inbounds[$i].settings.clients += [{\"id\": \$uuid$(if [ \"${PROTOCOLS[$i]}\" = \"2\" ]; then echo \", \\\"alterId\\\": 0\"; fi)}]" "$XRAY_CONFIG" > tmp.json && mv tmp.json "$XRAY_CONFIG"
    done
    [ ! -e "$XRAY_CONFIG" ] || ! jq -e . "$XRAY_CONFIG" >/dev/null 2>&1 && { cp "$XRAY_CONFIG.bak.$(date +%F_%H%M%S)" "$XRAY_CONFIG"; exit 1; }
    $XRAY_BIN -test -config "$XRAY_CONFIG" >/dev/null 2>&1 || { $XRAY_BIN -test -config "$XRAY_CONFIG"; exit 1; }
    chmod 600 "$XRAY_CONFIG" "$USER_DATA"
    chown root:root "$XRAY_CONFIG" "$USER_DATA"
    SUBSCRIPTION_FILE="$SUBSCRIPTION_DIR/$USERNAME.yml"
    CLASH_FILE="$CLASH_DIR/$USERNAME.yml"
    > "$SUBSCRIPTION_FILE"
    > "$CLASH_FILE"
    for PROTOCOL in "${PROTOCOLS[@]}"; do
        case "$PROTOCOL" in
            1) echo "vless://$UUID@$DOMAIN:443?encryption=none&security=tls&type=ws&path=$WS_PATH&sni=$DOMAIN&host=$DOMAIN#$USERNAME" >> "$SUBSCRIPTION_FILE"
               cat >> "$CLASH_FILE" <<EOF
proxies:
  - name: "$USERNAME"
    type: vless
    server: $DOMAIN
    port: 443
    uuid: $UUID
    network: ws
    tls: true
    udp: true
    sni: $DOMAIN
    ws-opts:
      path: $WS_PATH
      headers:
        Host: $DOMAIN
EOF
               ;;
            2) echo "vmess://$(echo -n '{\"v\":\"2\",\"ps\":\"$USERNAME\",\"add\":\"$DOMAIN\",\"port\":\"443\",\"id\":\"$UUID\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"$DOMAIN\",\"path\":\"$VMESS_PATH\",\"tls\":\"tls\",\"sni\":\"$DOMAIN\"}' | base64 -w 0)" >> "$SUBSCRIPTION_FILE"
               cat >> "$CLASH_FILE" <<EOF
proxies:
  - name: "$USERNAME"
    type: vmess
    server: $DOMAIN
    port: 443
    uuid: $UUID
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    udp: true
    sni: $DOMAIN
    ws-opts:
      path: $VMESS_PATH
      headers:
        Host: $DOMAIN
EOF
               ;;
            3) echo "vless://$UUID@$DOMAIN:443?encryption=none&security=tls&type=grpc&serviceName=$GRPC_SERVICE&sni=$DOMAIN#$USERNAME" >> "$SUBSCRIPTION_FILE"
               cat >> "$CLASH_FILE" <<EOF
proxies:
  - name: "$USERNAME"
    type: vless
    server: $DOMAIN
    port: 443
    uuid: $UUID
    network: grpc
    tls: true
    udp: true
    sni: $DOMAIN
    grpc-opts:
      grpc-service-name: $GRPC_SERVICE
EOF
               ;;
            4) echo "vless://$UUID@$DOMAIN:443?encryption=none&security=tls&type=http&path=$TCP_PATH&sni=$DOMAIN&host=$DOMAIN#$USERNAME" >> "$SUBSCRIPTION_FILE"
               cat >> "$CLASH_FILE" <<EOF
proxies:
  - name: "$USERNAME"
    type: vless
    server: $DOMAIN
    port: 443
    uuid: $UUID
    network: http
    tls: true
    udp: true
    sni: $DOMAIN
    http-opts:
      path: $TCP_PATH
      headers:
        Host: $DOMAIN
EOF
               ;;
        esac
    done
    chmod 644 "$SUBSCRIPTION_FILE" "$CLASH_FILE"
    chown www-data:www-data "$SUBSCRIPTION_FILE" "$CLASH_FILE"
    systemctl restart "$XRAY_SERVICE_NAME" || { systemctl status "$XRAY_SERVICE_NAME"; cat "$LOG_DIR/error.log"; exit 1; }
    check_subscription
    show_user_link
    flock -u 200
}

list_users() {
    echo -e "${BLUE}用户列表:${NC}"
    printf "| %-4s | %-16s | %-36s | %-20s | %-12s | %-6s |\n" "ID" "用户名" "UUID" "过期时间" "已用流量" "状态"
    printf "|------|------------------|--------------------------------------|----------------------|--------------|--------|\n"
    jq -r '.users[] | [.id, .name, .uuid, .expire, .used_traffic, .status] | join("\t")' "$USER_DATA" | \
    while IFS=$'\t' read -r id name uuid expire used status; do
        used_fmt=$(awk "BEGIN {printf \"%.2fG\", $used/1073741824}")
        printf "| %-4s | %-16.16s | %-36.36s | %-20.20s | %-12.12s | %-6.6s |\n" "$id" "$name" "$uuid" "$expire" "$used_fmt" "$status"
    done
}

renew_user() {
    echo -e "${GREEN}=== 用户续期流程 ===${NC}"
    flock -x 200
    read -p "输入要续期的用户名或 UUID: " INPUT
    CURRENT_EXPIRE=$(jq -r ".users[] | select(.name == \"$INPUT\" or .uuid == \"$INPUT\") | .expire" "$USER_DATA")
    USERNAME=$(jq -r ".users[] | select(.name == \"$INPUT\" or .uuid == \"$INPUT\") | .name" "$USER_DATA")
    if [ -z "$CURRENT_EXPIRE" ]; then
        echo -e "${RED}用户 $INPUT 不存在!${NC}"
        flock -u 200
        return
    fi
    echo "当前有效期: $CURRENT_EXPIRE"
    echo -e "1. 月费 (+1个月)\n2. 年费 (+1年)\n3. 永久\n4. 自定义时间"
    read -p "请选择 [默认1]: " RENEW_TYPE
    RENEW_TYPE=${RENEW_TYPE:-1}
    case "$RENEW_TYPE" in
        1) NEW_EXPIRE=$(date -d "$CURRENT_EXPIRE +1 month" "+%Y-%m-%d %H:%M:%S") ;;
        2) NEW_EXPIRE=$(date -d "$CURRENT_EXPIRE +1 year" "+%Y-%m-%d %H:%M:%S") ;;
        3) NEW_EXPIRE="永久" ;;
        4) read -p "请输入自定义时间 (如 1h/10m/200d): " CUSTOM_TIME
           if [[ "$CUSTOM_TIME" =~ ^([0-9]+)([hmd])$ ]]; then
               NUM=${BASH_REMATCH[1]}
               UNIT=${BASH_REMATCH[2]}
               case "$UNIT" in
                   h) NEW_EXPIRE=$(date -d "$CURRENT_EXPIRE +${NUM} hours" "+%Y-%m-%d %H:%M:%S") ;;
                   m) NEW_EXPIRE=$(date -d "$CURRENT_EXPIRE +${NUM} minutes" "+%Y-%m-%d %H:%M:%S") ;;
                   d) NEW_EXPIRE=$(date -d "$CURRENT_EXPIRE +${NUM} days" "+%Y-%m-%d %H:%M:%S") ;;
               esac
           else
               echo -e "${RED}无效格式! 请使用如 1h、10m、200d${NC}"
               flock -u 200
               return
           fi
           ;;
        *) NEW_EXPIRE=$(date -d "$CURRENT_EXPIRE +1 month" "+%Y-%m-%d %H:%M:%S") ;;
    esac
    jq --arg name "$USERNAME" --arg expire "$NEW_EXPIRE" '(.users[] | select(.name == $name)).expire = $expire' "$USER_DATA" > tmp.json && mv tmp.json "$USER_DATA"
    chmod 600 "$USER_DATA"
    chown root:root "$USER_DATA"
    echo "用户 $USERNAME 已续期至: $NEW_EXPIRE"
    flock -u 200
}

view_links() {
    echo -e "${GREEN}=== 查看链接 ===${NC}"
    RETRY_COUNT=0
    MAX_RETRIES=3
    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        read -p "请输入用户名或 UUID（剩余 $((MAX_RETRIES - RETRY_COUNT)) 次，回车返回）: " INPUT
        [ -z "$INPUT" ] && return
        USER_INFO=$(jq -r ".users[] | select(.name == \"$INPUT\" or .uuid == \"$INPUT\") | [.name, .uuid, .expire, .status] | join(\"\t\")" "$USER_DATA")
        if [ -z "$USER_INFO" ]; then
            echo "用户不存在或用户名错误，请重新输入"
            RETRY_COUNT=$((RETRY_COUNT + 1))
            [ $RETRY_COUNT -eq $MAX_RETRIES ] && { echo "达到最大重试次数，返回菜单"; return; }
        else
            IFS=$'\t' read -r USERNAME UUID EXPIRE STATUS <<< "$USER_INFO"
            TODAY=$(date +%s)
            [ "$STATUS" = "禁用" ] || { [ "$EXPIRE" != "永久" ] && [ $(date -d "$EXPIRE" +%s) -lt $TODAY ]; } && { echo "此用户已过期或被禁用，续费后可查看"; return; }
            SUBSCRIPTION_FILE="$SUBSCRIPTION_DIR/$USERNAME.yml"
            CLASH_FILE="$CLASH_DIR/$USERNAME.yml"
            > "$SUBSCRIPTION_FILE"
            > "$CLASH_FILE"
            for PROTOCOL in "${PROTOCOLS[@]}"; do
                case "$PROTOCOL" in
                    1) echo "vless://$UUID@$DOMAIN:443?encryption=none&security=tls&type=ws&path=$WS_PATH&sni=$DOMAIN&host=$DOMAIN#$USERNAME" >> "$SUBSCRIPTION_FILE"
                       cat >> "$CLASH_FILE" <<EOF
proxies:
  - name: "$USERNAME"
    type: vless
    server: $DOMAIN
    port: 443
    uuid: $UUID
    network: ws
    tls: true
    udp: true
    sni: $DOMAIN
    ws-opts:
      path: $WS_PATH
      headers:
        Host: $DOMAIN
EOF
                       ;;
                    2) echo "vmess://$(echo -n '{\"v\":\"2\",\"ps\":\"$USERNAME\",\"add\":\"$DOMAIN\",\"port\":\"443\",\"id\":\"$UUID\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"$DOMAIN\",\"path\":\"$VMESS_PATH\",\"tls\":\"tls\",\"sni\":\"$DOMAIN\"}' | base64 -w 0)" >> "$SUBSCRIPTION_FILE"
                       cat >> "$CLASH_FILE" <<EOF
proxies:
  - name: "$USERNAME"
    type: vmess
    server: $DOMAIN
    port: 443
    uuid: $UUID
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    udp: true
    sni: $DOMAIN
    ws-opts:
      path: $VMESS_PATH
      headers:
        Host: $DOMAIN
EOF
                       ;;
                    3) echo "vless://$UUID@$DOMAIN:443?encryption=none&security=tls&type=grpc&serviceName=$GRPC_SERVICE&sni=$DOMAIN#$USERNAME" >> "$SUBSCRIPTION_FILE"
                       cat >> "$CLASH_FILE" <<EOF
proxies:
  - name: "$USERNAME"
    type: vless
    server: $DOMAIN
    port: 443
    uuid: $UUID
    network: grpc
    tls: true
    udp: true
    sni: $DOMAIN
    grpc-opts:
      grpc-service-name: $GRPC_SERVICE
EOF
                       ;;
                    4) echo "vless://$UUID@$DOMAIN:443?encryption=none&security=tls&type=http&path=$TCP_PATH&sni=$DOMAIN&host=$DOMAIN#$USERNAME" >> "$SUBSCRIPTION_FILE"
                       cat >> "$CLASH_FILE" <<EOF
proxies:
  - name: "$USERNAME"
    type: vless
    server: $DOMAIN
    port: 443
    uuid: $UUID
    network: http
    tls: true
    udp: true
    sni: $DOMAIN
    http-opts:
      path: $TCP_PATH
      headers:
        Host: $DOMAIN
EOF
                       ;;
                esac
            done
            chmod 644 "$SUBSCRIPTION_FILE" "$CLASH_FILE"
            chown www-data:www-data "$SUBSCRIPTION_FILE" "$CLASH_FILE"
            show_user_link
            break
        fi
    done
}

delete_user() {
    echo -e "${GREEN}=== 删除用户流程 ===${NC}"
    [ ${#PROTOCOLS[@]} -eq 0 ] || [ ! -f "$XRAY_CONFIG" ] && { echo -e "${RED}未检测到 Xray 配置${NC}"; return; }
    flock -x 200
    read -p "输入要删除的用户名或 UUID: " INPUT
    UUID=$(jq -r ".users[] | select(.name == \"$INPUT\" or .uuid == \"$INPUT\") | .uuid" "$USER_DATA")
    USERNAME=$(jq -r ".users[] | select(.name == \"$INPUT\" or .uuid == \"$INPUT\") | .name" "$USER_DATA")
    if [ -n "$UUID" ]; then
        jq "del(.users[] | select(.name == \"$USERNAME\"))" "$USER_DATA" > tmp.json && mv tmp.json "$USER_DATA" || { cp "$USER_DATA.bak.$(date +%F_%H%M%S)" "$USER_DATA"; exit 1; }
        for i in $(seq 0 $((${#PROTOCOLS[@]} - 1))); do jq --arg uuid "$UUID" ".inbounds[$i].settings.clients -= [{\"id\": \$uuid}]" "$XRAY_CONFIG" > tmp.json && mv tmp.json "$XRAY_CONFIG"; done
        [ ! -e "$XRAY_CONFIG" ] || ! jq -e . "$XRAY_CONFIG" >/dev/null 2>&1 && { cp "$XRAY_CONFIG.bak.$(date +%F_%H%M%S)" "$XRAY_CONFIG"; exit 1; }
        $XRAY_BIN -test -config "$XRAY_CONFIG" >/dev/null 2>&1 || { $XRAY_BIN -test -config "$XRAY_CONFIG"; exit 1; }
        chmod 600 "$XRAY_CONFIG" "$USER_DATA"
        chown root:root "$XRAY_CONFIG" "$USER_DATA"
        systemctl restart "$XRAY_SERVICE_NAME" || { systemctl status "$XRAY_SERVICE_NAME"; cat "$LOG_DIR/error.log"; exit 1; }
        echo "用户 $USERNAME 已删除并重启 Xray。"
    else
        echo -e "${RED}用户 $INPUT 不存在!${NC}"
    fi
    flock -u 200
}

protocol_management() {
    check_and_set_domain
    echo -e "${GREEN}=== 协议管理 ===${NC}"
    echo -e "1. VLESS+WS+TLS (推荐)\n2. VMess+WS+TLS\n3. VLESS+gRPC+TLS\n4. VLESS+TCP+TLS (HTTP/2)"
    read -p "请选择 (多选用空格分隔, 默认1，回车返回): " -a PROTOCOLS
    [ ${#PROTOCOLS[@]} -eq 0 ] && return
    check_ports
    configure_nginx
    configure_xray
    systemctl restart nginx "$XRAY_SERVICE_NAME" || exit 1
}

traffic_stats() {
    echo -e "${BLUE}=== 流量统计 ===${NC}"
    printf "| %-16s | %-12s | %-8s | %-8s |\n" "用户名" "已用流量" "总流量" "状态"
    printf "|------------------|--------------|--------|--------|\n"
    jq -r '.users[] | [.name, .used_traffic, .status] | join("\t")' "$USER_DATA" | while IFS=$'\t' read -r name used status; do
        used_fmt=$(awk "BEGIN {printf \"%.2fG\", $used/1073741824}")
        printf "| %-16.16s | %-12.12s | %-8s | %-8.8s |\n" "$name" "$used_fmt" "无限" "$status"
    done
    [ -f "$LOG_DIR/access.log" ] && {
        TOTAL_BYTES=$(awk -v uuid="$UUID" '$0 ~ uuid {sum += $NF} END {print sum}' "$LOG_DIR/access.log" || echo "0")
        [ "$TOTAL_BYTES" != "0" ] && jq --arg uuid "$UUID" --arg bytes "$TOTAL_BYTES" '.users[] | select(.uuid == $uuid) | .used_traffic = ($bytes | tonumber)' "$USER_DATA" > tmp.json && mv tmp.json "$USER_DATA"
    }
    (crontab -l 2>/dev/null; echo "0 */8 * * * bash -c 'if [ -f $LOG_DIR/access.log ]; then for uuid in \$(jq -r \".users[] | .uuid\" $USER_DATA); do TOTAL_BYTES=\$(awk -v uuid=\"\$uuid\" \"\\\$0 ~ uuid {sum += \\\$NF} END {print sum}\" $LOG_DIR/access.log || echo 0); jq --arg uuid \"\$uuid\" --arg bytes \"\$TOTAL_BYTES\" \".users[] | select(.uuid == \\\$uuid) | .used_traffic = (\\\$bytes | tonumber)\" $USER_DATA > tmp.json && mv tmp.json $USER_DATA; done; fi'") | crontab -
}

backup_restore() {
    echo -e "${GREEN}=== 备份管理 ===${NC}"
    echo -e "1. 创建备份\n2. 恢复备份\n3. 返回主菜单"
    read -p "请选择（回车返回主菜单）: " CHOICE
    [ -z "$CHOICE" ] && return
    case "$CHOICE" in
        1) BACKUP_FILE="$BACKUP_DIR/xray_backup_$(date +%F).tar.gz"; tar -czf "$BACKUP_FILE" "$XRAY_CONFIG" "$USER_DATA" "$CERTS_DIR" >/dev/null 2>&1; chmod 600 "$BACKUP_FILE"; chown root:root "$BACKUP_FILE"; echo "备份已创建至: $BACKUP_FILE" ;;
        2) ls -lh "$BACKUP_DIR" | awk '/xray_backup/{print "- " $9 " (" $6 " " $7 " " $8 ")"}'
           read -p "输入要恢复的备份文件名: " BACKUP_FILE
           [ -f "$BACKUP_DIR/$BACKUP_FILE" ] && {
               tar -xzf "$BACKUP_DIR/$BACKUP_FILE" -C / >/dev/null 2>&1
               chmod 600 "$XRAY_CONFIG" "$USER_DATA"
               chown root:root "$XRAY_CONFIG" "$USER_DATA"
               read -p "是否更换域名? [y/N]: " CHANGE_DOMAIN
               [[ "$CHANGE_DOMAIN" =~ ^[Yy] ]] && { read -p "输入新域名: " NEW_DOMAIN; sed -i "s/$DOMAIN/$NEW_DOMAIN/g" "$XRAY_CONFIG" "$NGINX_CONF"; certbot certonly --nginx -d "$NEW_DOMAIN" --non-interactive --agree-tos -m "admin@$NEW_DOMAIN" >/dev/null 2>&1; DOMAIN="$NEW_DOMAIN"; }
               systemctl restart nginx "$XRAY_SERVICE_NAME" || exit 1
               echo "备份恢复完成!"
           } || echo -e "${RED}备份文件不存在!${NC}" ;;
        3) return ;;
        *) echo -e "${RED}无效选择!${NC}" ;;
    esac
}

view_certificates() {
    echo -e "${GREEN}=== 查看证书信息 ===${NC}"
    check_and_set_domain
    CERT_INFO=$(certbot certificates --cert-name "$DOMAIN" 2>/dev/null)
    [ $? -ne 0 ] || [ -z "$CERT_INFO" ] && { echo "未找到 $DOMAIN 的证书信息"; return; }
    EXPIRY_DATE=$(echo "$CERT_INFO" | grep -oP "Expiry Date: \K.*?(?= \(VALID:)" | head -n 1)
    VALID_DAYS=$(echo "$CERT_INFO" | grep -oP "VALID: \K\d+" | head -n 1)
    ISSUE_DATE=$(date -d "$EXPIRY_DATE - $VALID_DAYS days" "+%Y-%m-%d %H:%M:%S")
    echo -e "- 证书域名: $DOMAIN\n- 申请时间: $ISSUE_DATE\n- 到期时间: $EXPIRY_DATE\n- 剩余有效期: $VALID_DAYS 天"
}

uninstall_script() {
    echo -e "${GREEN}=== 卸载脚本 ===${NC}"
    read -p "确定要卸载? (y/N): " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy] ]] && { echo "取消卸载"; return; }
    systemctl stop "$XRAY_SERVICE_NAME" "$SCRIPT_NAME" >/dev/null 2>&1
    systemctl disable "$XRAY_SERVICE_NAME" "$SCRIPT_NAME" >/dev/null 2>&1
    rm -f "/etc/systemd/system/$XRAY_SERVICE_NAME.service" "/etc/systemd/system/$SCRIPT_NAME.service"
    systemctl daemon-reload
    systemctl reset-failed
    rm -rf "$INSTALL_DIR" /usr/local/bin/v "$XRAY_BIN" /usr/local/etc/xray "$LOG_DIR" "$NGINX_CONF" "$SUBSCRIPTION_DIR" "$CLASH_DIR" "$BACKUP_DIR" "$LOCK_FILE"
    systemctl restart nginx >/dev/null 2>&1
    crontab -l 2>/dev/null | grep -v "xray-install.sh" | crontab -
    crontab -l 2>/dev/null | grep -v "access.log" | crontab -
    echo -e "${YELLOW}卸载完成！SSL 证书未删除，可手动运行 'certbot delete'${NC}"
    exit 0
}

install_script() {
    [ "$EUID" -ne 0 ] && { echo -e "${RED}请以 root 运行!${NC}"; exit 1; }
    if [ ! -f "$SCRIPT_PATH" ]; then
        echo -e "${GREEN}首次运行，安装脚本...${NC}"
        mkdir -p "$INSTALL_DIR" || exit 1
        cp "$0" "$SCRIPT_PATH" || exit 1
        chmod 700 "$SCRIPT_PATH"
        chown root:root "$SCRIPT_PATH"
        ln -sf "$SCRIPT_PATH" /usr/local/bin/v || exit 1
        cat > /etc/systemd/system/$SCRIPT_NAME.service <<EOF
[Unit]
Description=Xray Management Script
After=network.target
[Service]
Type=simple
ExecStart=/bin/bash $SCRIPT_PATH
ExecStop=/bin/kill -TERM \$MAINPID
Restart=always
RestartSec=5
User=root
[Install]
WantedBy=multi-user.target
EOF
        chmod 644 /etc/systemd/system/$SCRIPT_NAME.service
        systemctl daemon-reload
        systemctl enable "$SCRIPT_NAME.service" || exit 1
    fi
    main_menu
}

install_script "$@"

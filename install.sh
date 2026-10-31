#!/bin/bash

set -euo pipefail

APP_DIR="/opt/pingmonitor"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================="
echo " PingMonitor 安装开始"
echo "=============================="
echo "源目录: $SCRIPT_DIR"
echo "工作目录: $APP_DIR"
echo ""

apt update -y

apt install -y \
    python3 \
    python3-pip \
    iputils-ping \
    sudo \
    rsync

echo "安装 Python 依赖"
pip3 install flask requests --break-system-packages || pip3 install flask requests

echo ""
echo "同步完整 GitHub 仓库到 $APP_DIR"

mkdir -p "$APP_DIR"

# /opt/pingmonitor 直接作为 GitHub 仓库工作目录。
# 保留 .git，这样以后可以直接：
#   cd /opt/pingmonitor && git pull
#
# 运行时产生的文件不属于 Git 仓库，由安装脚本单独保留。
if [[ "$SCRIPT_DIR" != "$APP_DIR" ]]; then
    rsync -a --delete \
        --exclude 'logs/' \
        --exclude 'status.json' \
        --exclude 'status.json.tmp' \
        --exclude 'last_action.json' \
        --exclude 'last_action.json.tmp' \
        --exclude 'ip_cache.json' \
        --exclude 'ip_cache.json.tmp' \
        --exclude '__pycache__/' \\
        --exclude '.session_secret' \\
        "$SCRIPT_DIR/" "$APP_DIR/"
fi

# 首次安装时复制默认配置；已有安装则保留现有 config.json，
# 其中可能包含通过控制面板设置的 Web 密码哈希。
if [[ ! -f "$APP_DIR/config.json" ]]; then
    cp "$SCRIPT_DIR/config.json" "$APP_DIR/config.json"
fi

echo "设置运行目录和文件权限"

# Git 仓库文件由 root 管理；Web 服务以 www-data 运行。
chown -R root:root "$APP_DIR"

# 普通程序文件、模板、静态资源和 Git 元数据保持 root 管理。
find "$APP_DIR" -type d -exec chmod 755 {} \;
find "$APP_DIR" -type f -exec chmod 644 {} \;
chmod +x "$APP_DIR/install.sh"

# Session 密钥只允许 root 和 Web 服务用户读取。
if [[ -f "$APP_DIR/.session_secret" ]]; then
    chown www-data:www-data "$APP_DIR/.session_secret"
    chmod 640 "$APP_DIR/.session_secret"
fi

# web.py 和 monitor.py 都会使用“临时文件 + os.replace()”原子写入 JSON。
# 因此 /opt/pingmonitor 本身必须允许 www-data 创建/替换运行时 JSON 临时文件。
# 文件本身仍保持 root:www-data，代码文件仍保持 root 管理。
chown root:www-data "$APP_DIR"
chmod 2775 "$APP_DIR"

# 运行时日志目录：monitor.py 以 root 运行，web.py 以 www-data 运行。
mkdir -p "$APP_DIR/logs"
chown root:www-data "$APP_DIR/logs"
chmod 2775 "$APP_DIR/logs"

touch "$APP_DIR/logs/monitor.log"
chown root:www-data "$APP_DIR/logs/monitor.log"
chmod 666 "$APP_DIR/logs/monitor.log"

# Web 端可能直接维护这些运行时 JSON 文件。
for file in \
    "$APP_DIR/config.json" \
    "$APP_DIR/status.json" \
    "$APP_DIR/last_action.json" \
    "$APP_DIR/ip_cache.json"; do
    if [[ -f "$file" ]]; then
        chown root:www-data "$file"
        chmod 664 "$file"
    fi
done

# 系统服务文件仍然安装到标准 systemd 目录。
install -o root -g root -m 644 \
    "$APP_DIR/pingmonitor.service" \
    /etc/systemd/system/pingmonitor.service

install -o root -g root -m 644 \
    "$APP_DIR/pingmonitor-web.service" \
    /etc/systemd/system/pingmonitor-web.service

# sudoers 必须由 root 管理，权限保持 440。
mkdir -p /etc/sudoers.d
install -o root -g root -m 440 \
    "$APP_DIR/sudoers/pingmonitor" \
    /etc/sudoers.d/pingmonitor

# 检查 sudoers 语法，避免错误配置导致 sudo 异常。
visudo -cf /etc/sudoers.d/pingmonitor

echo "验证 www-data 的运行目录写权限"
sudo -u www-data sh -c 'tmp="/opt/pingmonitor/.pingmonitor-permission-test.tmp"; printf "%s" "ok" > "$tmp" && rm -f "$tmp"'

echo "启动服务"
systemctl daemon-reload
systemctl enable pingmonitor
systemctl enable pingmonitor-web
systemctl restart pingmonitor
systemctl restart pingmonitor-web

IP=$(hostname -I | awk '{print $1}')

echo ""
echo "=============================="
echo "安装完成"
echo ""
echo "GitHub 工作目录:"
echo "$APP_DIR"
echo ""
echo "以后更新程序:"
echo "cd $APP_DIR && git pull"
echo ""
echo "Web 管理地址:"
echo "http://${IP}:5000"
echo "初始登录密码: 123456"
echo "修改密码: 编辑 /opt/pingmonitor/pingmonitor-web.service 中的 PINGMONITOR_PASSWORD 后执行 systemctl restart pingmonitor-web"
echo "=============================="

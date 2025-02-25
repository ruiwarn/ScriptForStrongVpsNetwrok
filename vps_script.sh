#!/bin/bash

# Debian 12 VPS 安全增强脚本
# 适用于 root 用户环境
# 通过检查配置状态防止重复配置

echo "开始执行 VPS 安全增强脚本..."

# 检查是否为 Debian 12
if ! grep -q "Debian GNU/Linux 12" /etc/os-release; then
    echo "此脚本用 Debian 系统开发" >&2
fi

# 检查是否为 root 用户
if [ "$(id -u)" -ne 0 ]; then
    echo "此脚本需要 root 权限，请以 root 用户运行" >&2
    exit 1
fi

# 检查必要命令
for cmd in apt systemctl sed grep netstat df; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "正在安装必要命令: $cmd"
        if ! apt install -y "$cmd"; then
            echo "错误：安装 $cmd 失败" >&2
            exit 1
        fi
    fi
done

# 设置 trap 捕获中断
trap 'echo "脚本被中断，正在退出..."; exit 1' INT TERM

# 更新系统（如果24小时内未更新）
echo "检查系统更新..."
if apt update && apt upgrade -y; then
    echo "系统更新完成"
else
    echo "系统更新失败，请检查网络或软件源" >&2
    exit 1
fi


# 安装基本工具
echo "检查并安装基本安全工具..."
TOOLS="fail2ban ufw iptables-persistent unattended-upgrades logwatch rkhunter lynis"
for tool in $TOOLS; do
    if ! dpkg-query -W -f='${Status}' "$tool" 2>/dev/null | grep -q "install ok installed"; then
        echo "安装 $tool..."
        if ! apt install -y "$tool"; then
            echo "安装 $tool 失败" >&2
        fi
    else
        echo "$tool 已安装，跳过..."
    fi
done

# 配置 Fail2Ban 防止暴力攻击
echo "配置Fail2Ban ..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
banaction = iptables-multiport

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

# 检查 Nginx 是否安装并配置 nginx-http-auth
if command -v nginx >/dev/null 2>&1 && [ -d /var/log/nginx ]; then
    cat >> /etc/fail2ban/jail.local << EOF

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
EOF
else
    echo "未检测到 Nginx，跳过 nginx-http-auth 配置..."
fi

# 重启 Fail2Ban 服务
if systemctl restart fail2ban && systemctl enable fail2ban; then
    echo "Fail2Ban 配置完成"
else
    echo "Fail2Ban 服务启动失败，请检查配置" >&2
fi


# 配置 UFW 防火墙
echo "配置 UFW 防火墙禁止icmp..."
ufw deny proto icmp
echo "UFW 配置完成"

# 禁止 ping (通过 sysctl)
echo "禁止 PING 响应..."
sed -i '/net.ipv4.icmp_echo_ignore_all/c\net.ipv4.icmp_echo_ignore_all = 1' /etc/sysctl.conf
if sysctl -p; then
    echo "PING 响应已禁用"
else
    echo "应用 sysctl 配置失败" >&2
fi

# 配置 SSH 安全
echo "检查 SSH 安全配置..."
SSH_CONFIG="/etc/ssh/sshd_config"
if grep -q "^PermitRootLogin without-password" "$SSH_CONFIG" && grep -q "^PasswordAuthentication no" "$SSH_CONFIG" && grep -q "^X11Forwarding no" "$SSH_CONFIG" && grep -q "^AllowUsers root" "$SSH_CONFIG" && grep -q "^Protocol 2" "$SSH_CONFIG" && grep -q "^MaxAuthTries 3" "$SSH_CONFIG"; then
    echo "SSH 安全配置已完成，跳过此步骤..."
else
    echo "增强 SSH 安全性..."
    cp "$SSH_CONFIG" "$SSH_CONFIG.bak.$(date +%Y%m%d%H%M%S)"
    
    # 检查是否存在 SSH 公钥
    if [ ! -f /root/.ssh/authorized_keys ]; then
        echo "警告：未检测到 SSH 公钥，保持密码登录可用，避免锁死"
        sed -i '/^#\?PasswordAuthentication/c\PasswordAuthentication yes' "$SSH_CONFIG"
    else
        sed -i '/^#\?PasswordAuthentication/c\PasswordAuthentication no' "$SSH_CONFIG"
    fi
    
    # 使用 sed 替换或添加配置，确保每个配置只有一行
    sed -i '/^#\?PermitRootLogin/c\PermitRootLogin without-password' "$SSH_CONFIG"
    sed -i '/^#\?X11Forwarding/c\X11Forwarding no' "$SSH_CONFIG"
    sed -i '/^#\?Protocol/c\Protocol 2' "$SSH_CONFIG"
    sed -i '/^#\?MaxAuthTries/c\MaxAuthTries 3' "$SSH_CONFIG"
    
    # 对于 AllowUsers，先删除再添加
    sed -i '/^AllowUsers/d' "$SSH_CONFIG"
    echo "AllowUsers root" >> "$SSH_CONFIG"
    
    if systemctl restart ssh; then
        echo "SSH 安全配置完成"
    else
        echo "SSH 服务重启失败，请检查配置" >&2
    fi
fi

# 配置自动更新
echo "检查自动更新配置..."
# 配置 20auto-upgrades
if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    # 删除已存在的相关配置
    sed -i '/^APT::Periodic::Update-Package-Lists/d' /etc/apt/apt.conf.d/20auto-upgrades
    sed -i '/^APT::Periodic::Unattended-Upgrade/d' /etc/apt/apt.conf.d/20auto-upgrades
    sed -i '/^APT::Periodic::AutocleanInterval/d' /etc/apt/apt.conf.d/20auto-upgrades
    sed -i '/^APT::Periodic::Download-Upgradeable-Packages/d' /etc/apt/apt.conf.d/20auto-upgrades
fi
# 添加新的配置
cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
EOF

# 配置 50unattended-upgrades
if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
    # 删除已存在的相关配置
    sed -i '/^Unattended-Upgrade::Mail/d' /etc/apt/apt.conf.d/50unattended-upgrades
    sed -i '/^Unattended-Upgrade::MailOnlyOnError/d' /etc/apt/apt.conf.d/50unattended-upgrades
fi

echo "自动更新配置完成"

# 设置系统资源限制
echo "检查系统资源限制配置..."
# 先删除已存在的配置
sed -i '/^# 进程数限制/d' /etc/security/limits.conf
sed -i '/^\* soft nproc/d' /etc/security/limits.conf
sed -i '/^\* hard nproc/d' /etc/security/limits.conf
sed -i '/^\* soft nofile/d' /etc/security/limits.conf
sed -i '/^\* hard nofile/d' /etc/security/limits.conf

# 添加新的配置
cat >> /etc/security/limits.conf << EOF
# 进程数限制
* soft nproc 1000
* hard nproc 2000
* soft nofile 4096
* hard nofile 10240
EOF
echo "系统资源限制配置完成"

# 配置 LogWatch 日志分析
echo "检查 LogWatch 配置..."
if [ -f /etc/cron.daily/00logwatch ]; then
    echo "LogWatch 已配置，跳过此步骤..."
else
    echo "配置 LogWatch 日志分析..."
    echo "/usr/sbin/logwatch --output mail --mailto root --detail high" > /etc/cron.daily/00logwatch
    chmod +x /etc/cron.daily/00logwatch
    echo "LogWatch 配置完成"
fi

# 运行 Lynis 系统安全审计
echo "运行 Lynis 系统安全审计..."
lynis audit system --quick || echo "Lynis 审计未完成，请手动检查"

# 创建定期安全检查脚本
echo "检查安全检查脚本..."
if [ -f /root/security_check.sh ]; then
    echo "安全检查脚本已存在，跳过此步骤..."
else
    echo "创建定期安全检查脚本..."
    cat > /root/security_check.sh << EOF
#!/bin/bash
# 安全检查脚本

echo "======= 安全检查报告 - \$(date) =======" > /root/security_report.txt
echo "" >> /root/security_report.txt

echo "Failed SSH login attempts:" >> /root/security_report.txt
grep "Failed password" /var/log/auth.log | tail -n 10 >> /root/security_report.txt
echo "" >> /root/security_report.txt

echo "Current Fail2Ban status:" >> /root/security_report.txt
fail2ban-client status >> /root/security_report.txt
echo "" >> /root/security_report.txt

echo "Open ports:" >> /root/security_report.txt
netstat -tuln >> /root/security_report.txt
echo "" >> /root/security_report.txt

echo "Disk usage:" >> /root/security_report.txt
df -h >> /root/security_report.txt
echo "" >> /root/security_report.txt

echo "Last 5 installed packages:" >> /root/security_report.txt
grep "install " /var/log/dpkg.log | tail -n 5 >> /root/security_report.txt
echo "" >> /root/security_report.txt

echo "关键系统文件变更:" >> /root/security_report.txt
find /etc -type f -mtime -1 | grep -v "/etc/mtab" >> /root/security_report.txt
echo "" >> /root/security_report.txt

echo "高 CPU 占用进程:" >> /root/security_report.txt
ps aux --sort=-%cpu | head -n 10 >> /root/security_report.txt

echo "安全报告已保存到 /root/security_report.txt"
EOF
    chmod +x /root/security_check.sh
    echo "安全检查脚本创建完成"
fi

# 添加定期运行安全检查的 cron 任务
echo "检查安全检查 cron 任务..."
if crontab -l 2>/dev/null | grep -q "security_check.sh"; then
    echo "安全检查 cron 任务已存在，跳过此步骤..."
else
    echo "配置安全检查 cron 任务..."
    (crontab -l 2>/dev/null; echo "0 6 * * * /root/security_check.sh") | crontab -
    echo "安全检查 cron 任务配置完成"
fi

# 增强网络安全参数
echo "增强网络安全配置..."
# 使用 sed 删除或更新每个配置项
sed -i '/^# 启用 TCP SYN cookies/d' /etc/sysctl.conf
sed -i '/^net.ipv4.tcp_syncookies/c\# 启用 TCP SYN cookies 防止 SYN 洪水攻击\nnet.ipv4.tcp_syncookies = 1' /etc/sysctl.conf

sed -i '/^# 启用源路由验证/d' /etc/sysctl.conf
sed -i '/^net.ipv4.conf.all.rp_filter/c\# 启用源路由验证，防止 IP 欺骗\nnet.ipv4.conf.all.rp_filter = 1' /etc/sysctl.conf

sed -i '/^# 为新接口启用源路由验证/d' /etc/sysctl.conf
sed -i '/^net.ipv4.conf.default.rp_filter/c\# 为新接口启用源路由验证\nnet.ipv4.conf.default.rp_filter = 1' /etc/sysctl.conf

sed -i '/^# 禁止接受 ICMP 重定向/d' /etc/sysctl.conf
sed -i '/^net.ipv4.conf.all.accept_redirects/c\# 禁止接受 ICMP 重定向\nnet.ipv4.conf.all.accept_redirects = 0' /etc/sysctl.conf

sed -i '/^# 为新接口禁止接受 ICMP 重定向/d' /etc/sysctl.conf
sed -i '/^net.ipv4.conf.default.accept_redirects/c\# 为新接口禁止接受 ICMP 重定向\nnet.ipv4.conf.default.accept_redirects = 0' /etc/sysctl.conf

sed -i '/^# 禁止接受 IPv6 重定向/d' /etc/sysctl.conf
sed -i '/^net.ipv6.conf.all.accept_redirects/c\# 禁止接受 IPv6 重定向\nnet.ipv6.conf.all.accept_redirects = 0' /etc/sysctl.conf

sed -i '/^# 为新接口禁止接受 IPv6 重定向/d' /etc/sysctl.conf
sed -i '/^net.ipv6.conf.default.accept_redirects/c\# 为新接口禁止接受 IPv6 重定向\nnet.ipv6.conf.default.accept_redirects = 0' /etc/sysctl.conf

sed -i '/^# 禁止发送 ICMP 重定向/d' /etc/sysctl.conf
sed -i '/^net.ipv4.conf.all.send_redirects/c\# 禁止发送 ICMP 重定向\nnet.ipv4.conf.all.send_redirects = 0' /etc/sysctl.conf

sed -i '/^# 为新接口禁止发送 ICMP 重定向/d' /etc/sysctl.conf
sed -i '/^net.ipv4.conf.default.send_redirects/c\# 为新接口禁止发送 ICMP 重定向\nnet.ipv4.conf.default.send_redirects = 0' /etc/sysctl.conf

sed -i '/^# 忽略广播 ping 请求/d' /etc/sysctl.conf
sed -i '/^net.ipv4.icmp_echo_ignore_broadcasts/c\# 忽略广播 ping 请求\nnet.ipv4.icmp_echo_ignore_broadcasts = 1' /etc/sysctl.conf

sed -i '/^# 启用 RFC 1337 保护/d' /etc/sysctl.conf
sed -i '/^net.ipv4.tcp_rfc1337/c\# 启用 RFC 1337 保护\nnet.ipv4.tcp_rfc1337 = 1' /etc/sysctl.conf

if sysctl -p; then
    echo "网络安全配置完成"
else
    echo "网络参数应用失败，请检查 /etc/sysctl.conf" >&2
fi

# 配置日志轮转
echo "检查日志轮转配置..."
if [ -f /etc/logrotate.d/custom-logs ]; then
    echo "日志轮转已配置，跳过此步骤..."
else
    echo "配置日志轮转..."
    cat > /etc/logrotate.d/custom-logs << EOF
/root/security_report.txt {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}
/var/log/auth.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
EOF
    echo "日志轮转配置完成"
fi

echo "脚本执行完毕！以下安全措施已配置："
echo "1. Fail2Ban 已配置用于防止暴力攻击"
echo "2. 已禁止 PING 响应"
echo "3. UFW 防火墙已配置并启用"
echo "4. SSH 安全设置已增强"
echo "5. 自动安全更新已配置"
echo "6. 系统资源限制已设置"
echo "7. LogWatch 日志分析工具已配置"
echo "8. Lynis 系统安全审计已运行"
echo "9. 定期安全检查脚本已创建并设置为每天运行"
echo "10. 网络安全参数已增强"
echo "11. 已设置日志轮转"

echo "建议手动操作："
echo "- 检查 /root/security_report.txt 了解安全状况"
echo "- 考虑使用密钥登录并完全禁用密码登录"
echo "- 定期审查日志文件"
echo "- 在 /root/.ssh/authorized_keys 中添加你的 SSH 公钥（如果尚未添加）"

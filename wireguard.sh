#!/bin/bash
# 安全的WireGuard服务器安装脚本
# https://github.com/angristan/wireguard-install
RED='\033[0;31m'          # 定义红色文本颜色代码
ORANGE='\033[0;33m'       # 定义橙色文本颜色代码
NC='\033[0m'              # 定义正常（无颜色）文本颜色代码

# 检查是否以root权限运行
function isRoot() {
    if [ "${EUID}" -ne 0 ]; then
        echo "您需要以root权限运行此脚本"
        exit 1
    fi
}

# 检查虚拟化环境
function checkVirt() {
    if [ "$(systemd-detect-virt)" == "openvz" ]; then
        echo "OpenVZ不被支持"
        exit 1
    fi
    if [ "$(systemd-detect-virt)" == "lxc" ]; then
        echo "LXC目前不被支持。"
        echo "从技术上讲，WireGuard可以在LXC容器中运行，"
        echo "但内核模块必须在主机上安装，"
        echo "容器需要以特定参数运行"
        echo "且仅需在容器中安装工具。"
        exit 1
    fi
}

# 检查操作系统版本
function checkOS() {
    if [[ -e /etc/debian_version ]]; then
        source /etc/os-release
        OS="${ID}" # debian 或者 ubuntu
        if [[ ${ID} == "debian" || ${ID} == "raspbian" ]]; then
            if [[ ${VERSION_ID} -lt 10 ]]; then
                echo "您的Debian版本 (${VERSION_ID}) 不被支持。请使用 Debian 10 Buster 或更高版本"
                exit 1
            fi
            OS=debian # 如果是 raspbian，则覆盖为 debian
        fi
    elif [[ -e /etc/fedora-release ]]; then
        source /etc/os-release
        OS="${ID}"
    elif [[ -e /etc/centos-release ]]; then
        source /etc/os-release
        OS=centos
    elif [[ -e /etc/oracle-release ]]; then
        source /etc/os-release
        OS=oracle
    elif [[ -e /etc/arch-release ]]; then
        OS=arch
    else
        echo "看起来您不是在 Debian、Ubuntu、Fedora、CentOS、Oracle 或 Arch Linux 系统上运行此安装程序"
        exit 1
    fi
}

# 进行初始检查
function initialCheck() {
    isRoot
    checkVirt
    checkOS
}

# 安装前的问题
function installQuestions() {
    echo "欢迎使用 WireGuard 安装程序！"
    echo "GitHub 仓库地址：https://github.com/angristan/wireguard-install"
    echo ""
    echo "我需要在开始设置之前向您询问一些问题。"
    echo "您可以接受默认选项并直接按 Enter 键继续，如果您对它们满意的话。"
    echo ""

    # 检测公共 IPv4 或 IPv6 地址并预填给用户
    SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
    if [[ -z ${SERVER_PUB_IP} ]]; then
        # 检测公共 IPv6 地址
        SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    fi
    read -rp "IPv4 或 IPv6 公共地址: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

    # 检测公共网络接口并预填给用户
    SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
    until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
        read -rp "公共接口: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
    done
    until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
        read -rp "WireGuard 接口名称: " -e -i wg0 SERVER_WG_NIC
    done
    until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
        read -rp "服务器的 WireGuard IPv4 地址: " -e -i 10.66.66.1 SERVER_WG_IPV4
    done
    until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
        read -rp "服务器的 WireGuard IPv6 地址: " -e -i fd42:42:42::1 SERVER_WG_IPV6
    done

    # 生成私有端口范围内的随机数字
    RANDOM_PORT=$(shuf -i49152-65535 -n1)
    until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
        read -rp "服务器的 WireGuard 端口 [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
    done

    # 默认使用 Adguard DNS
    until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "客户端使用的第一个 DNS 解析器: " -e -i 94.140.14.14 CLIENT_DNS_1
    done
    until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "客户端使用的第二个 DNS 解析器 (可选): " -e -i 94.140.15.15 CLIENT_DNS_2
        if [[ ${CLIENT_DNS_2} == "" ]]; then
            CLIENT_DNS_2="${CLIENT_DNS_1}"
        fi
    done

    echo ""
    echo "好的，我已经得到了所有需要的信息。我们现在可以开始设置您的 WireGuard 服务器了。"
    echo "在安装结束后，您将能够生成一个客户端配置文件。"
    read -n1 -r -p "按下任意键继续..."
}

# 安装 WireGuard
function installWireGuard() {
    # 首先进行安装前的问题询问
    installQuestions

    # 安装 WireGuard 工具和模块
    if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
        apt-get update
        apt-get install -y wireguard iptables resolvconf qrencode
    elif [[ ${OS} == 'debian' ]]; then
        if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
            echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
            apt-get update
        fi
        apt-get update
        apt-get install -y iptables resolvconf qrencode
        apt-get install -y -t buster-backports wireguard
    elif [[ ${OS} == 'fedora' ]]; then
        if [[ ${VERSION_ID} -lt 32 ]]; then
            dnf install -y dnf-plugins-core
            dnf copr enable -y jdoss/wireguard
            dnf install -y wireguard-dkms
        fi
        dnf install -y wireguard-tools iptables qrencode
    elif [[ ${OS} == 'centos' ]]; then
        yum -y install epel-release elrepo-release
        if [[ ${VERSION_ID} -eq 7 ]]; then
            yum -y install yum-plugin-elrepo
        fi
        yum -y install kmod-wireguard wireguard-tools iptables qrencode
    elif [[ ${OS} == 'oracle' ]]; then
        dnf install -y oraclelinux-developer-release-el8
        dnf config-manager --disable -y ol8_developer
        dnf config-manager --enable -y ol8_developer_UEKR6
        dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
        dnf install -y wireguard-tools qrencode iptables
    elif [[ ${OS} == 'arch' ]]; then
        pacman -S --needed --noconfirm wireguard-tools qrencode
    fi

    # 确保目录存在（在 Fedora 上可能不存在）
    mkdir /etc/wireguard >/dev/null 2>&1
    chmod 600 -R /etc/wireguard/

    # 生成服务器密钥对
    SERVER_PRIV_KEY=$(wg genkey)
    SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

    # 保存 WireGuard 设置
    echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}" >/etc/wireguard/params

    # 添加服务器接口配置
    echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" > "/etc/wireguard/${SERVER_WG_NIC}.conf"

    if pgrep firewalld; then
        FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
        FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
        echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >> "/etc/wireguard/${SERVER_WG_NIC}.conf"
    else
        echo "PostUp = iptables -A FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >> "/etc/wireguard/${SERVER_WG_NIC}.conf"
    fi

    # 启用服务器上的路由功能
    echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf
    sysctl --system

    # 启动并设置 WireGuard 服务
    systemctl start "wg-quick@${SERVER_WG_NIC}"
    systemctl enable "wg-quick@${SERVER_WG_NIC}"

    # 创建新客户端
    newClient

    echo "如果您想添加更多客户端，只需再次运行此脚本即可！"

    # 检查 WireGuard 是否正在运行
    systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
    WG_RUNNING=$?

    # 如果更新了内核，WireGuard 可能无法工作。提示用户重启
    if [[ ${WG_RUNNING} -ne 0 ]]; then
        echo -e "\n${RED}警告: WireGuard 似乎没有运行。${NC}"
        echo -e "${ORANGE}您可以使用以下命令检查 WireGuard 是否运行: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
        echo -e "${ORANGE}如果显示类似 \"找不到设备 ${SERVER_WG_NIC}\"，请重启！${NC}"
    fi
}

# 创建新客户端
function newClient() {
    ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"
    echo ""
    echo "请输入客户端的名称。"
    echo "名称只能包含字母数字字符。还可以包括下划线或破折号，并且不能超过 15 个字符。"
    until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
        read -rp "客户端名称: " -e CLIENT_NAME
        CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")
        if [[ ${CLIENT_EXISTS} == '1' ]]; then
            echo ""
            echo "已存在指定名称的客户端，请选择另一个名称。"
            echo ""
        fi
    done

    for DOT_IP in {2..254}; do
        DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
        if [[ ${DOT_EXISTS} == '0' ]]; then
            break
        fi
    done

    if [[ ${DOT_EXISTS} == '1' ]]; then
        echo ""
        echo "配置的子网仅支持 253 个客户端。"
        exit 1
    fi

    BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
    until [[ ${IPV4_EXISTS} == '0' ]]; do
        read -rp "客户端的 WireGuard IPv4 地址: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
        CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
        IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/24" "/etc/wireguard/${SERVER_WG_NIC}.conf")
        if [[ ${IPV4_EXISTS} == '1' ]]; then
            echo ""
            echo "已存在指定 IPv4 的客户端，请选择另一个 IPv4。"
            echo ""
        fi
    done

    BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
    until [[ ${IPV6_EXISTS} == '0' ]]; do
        read -rp "客户端的 WireGuard IPv6 地址: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
        CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
        IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/64" "/etc/wireguard/${SERVER_WG_NIC}.conf")
        if [[ ${IPV6_EXISTS} == '1' ]]; then
            echo ""
            echo "已存在指定 IPv6 的客户端，请选择另一个 IPv6。"
            echo ""
        fi
    done

    # 为客户端生成密钥对
    CLIENT_PRIV_KEY=$(wg genkey)
    CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
    CLIENT_PRE_SHARED_KEY=$(wg genpsk)

    # 用户主目录，客户端配置文件将写入此处
    if [ -e "/home/${CLIENT_NAME}" ]; then
        # 如果 $1 是用户名
        HOME_DIR="/home/${CLIENT_NAME}"
    elif [ "${SUDO_USER}" ]; then
        # 如果不是用户名，则使用 SUDO_USER
        if [ "${SUDO_USER}" == "root" ]; then
            # 如果使用 sudo 作为 root
            HOME_DIR="/root"
        else
            HOME_DIR="/home/${SUDO_USER}"
        fi
    else
        # 如果没有 SUDO_USER，则使用 /root
        HOME_DIR="/root"
    fi

    # 创建客户端文件并添加服务器为对等方
    echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}
[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = 0.0.0.0/0,::/0" >> "${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

    # 将客户端添加为服务器的对等方
    echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >> "/etc/wireguard/${SERVER_WG_NIC}.conf"

    wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

    echo -e "\n这是您的客户端配置文件的二维码："
    qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
    echo "它也可以在 ${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf 中找到"
}

# 删除客户端
function revokeClient() {
    NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
        echo ""
        echo "您没有任何现有客户端！"
        exit 1
    fi
    echo ""
    echo "请选择要撤销的现有客户端"
    grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
        if [[ ${CLIENT_NUMBER} == '1' ]]; then
            read -rp "选择一个客户端 [1]: " CLIENT_NUMBER
        else
            read -rp "选择一个客户端 [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
        fi
    done

    # 匹配选定的编号到客户端名称
    CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

    # 移除与 $CLIENT_NAME 匹配的 [Peer] 块
    sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

    # 移除生成的客户端文件
    rm -f "${HOME}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

    # 重启 WireGuard 应用更改
    wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
}

# 卸载 WireGuard
function uninstallWg() {
    echo ""
    read -rp "您真的要移除 WireGuard 吗？ [y/n]: " -e -i n REMOVE
    if [[ $REMOVE == 'y' ]]; then
        checkOS
        systemctl stop "wg-quick@${SERVER_WG_NIC}"
        systemctl disable "wg-quick@${SERVER_WG_NIC}"
        if [[ ${OS} == 'ubuntu' ]]; then
            apt-get autoremove --purge -y wireguard qrencode
        elif [[ ${OS} == 'debian' ]]; then
            apt-get autoremove --purge -y wireguard qrencode
        elif [[ ${OS} == 'fedora' ]]; then
            dnf remove -y wireguard-tools qrencode
            if [[ ${VERSION_ID} -lt 32 ]]; then
                dnf remove -y wireguard-dkms
                dnf copr disable -y jdoss/wireguard
            fi
            dnf autoremove -y
        elif [[ ${OS} == 'centos' ]]; then
            yum -y remove kmod-wireguard wireguard-tools qrencode
            yum -y autoremove
        elif [[ ${OS} == 'oracle' ]]; then
            yum -y remove wireguard-tools qrencode
            yum -y autoremove
        elif [[ ${OS} == 'arch' ]]; then
            pacman -Rs --noconfirm wireguard-tools qrencode
        fi

        rm -rf /etc/wireguard
        rm -f /etc/sysctl.d/wg.conf

        # 重新加载 sysctl
        sysctl --system

        # 检查 WireGuard 是否还在运行
        systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
        WG_RUNNING=$?

        if [[ ${WG_RUNNING} -eq 0 ]]; then
            echo "WireGuard 卸载失败。"
            exit 1
        else
            echo "WireGuard 成功卸载。"
            exit 0
        fi
    else
        echo ""
        echo "卸载已取消！"
    fi
}

# 管理菜单
function manageMenu() {
    echo "欢迎使用 WireGuard-install！"
    echo "GitHub 仓库地址：https://github.com/angristan/wireguard-install"
    echo ""
    echo "看起来 WireGuard 已经安装好了。"
    echo ""
    echo "您想要做什么？"
    echo " 1) 添加新用户"
    echo " 2) 撤销现有用户"
    echo " 3) 卸载 WireGuard"
    echo " 4) 退出"
    until [[ ${MENU_OPTION} =~ ^[1-4]$ ]]; do
        read -rp "选择一个选项 [1-4]: " MENU_OPTION
    done
    case "${MENU_OPTION}" in
        1)
            newClient
            ;;
        2)
            revokeClient
            ;;
        3)
            uninstallWg
            ;;
        4)
            exit 0
            ;;
    esac
}

# 进行初始检查
initialCheck

# 检查 WireGuard 是否已经安装并加载参数
if [[ -e /etc/wireguard/params ]]; then
    source /etc/wireguard/params
    manageMenu
else
    installWireGuard
fi
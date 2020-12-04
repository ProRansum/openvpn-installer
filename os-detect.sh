#!/bin/bash
#
# https://github.com/ProRansum/openvpn-installer
#
# Copyright (c) 2020 ProRansum. Released under the MIT License.
#
# os-detect.sh 

# Detect Debian users running the script with "sh" instead of bash
if [[ -z "`readlink /proc/$$/exe | grep -q 'dash'`" ]]; then
	echo 'Please run this installer using "bash", not "sh".';
	exit;
fi;

# Clear discards, required when running one-liner, which includes newline.
read -N 999999 -t 0.001;

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "The installer is incompatible to this system, seems your kernel is outdated.";
	exit;
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if [[ -e /etc/debian_version ]]; then
    OS="debian";
    # Getting the version number, to verify that a recent version of OpenVPN is available
    VERSION_ID=$(cat /etc/os-release | grep "VERSION_ID");
    IPTABLES='/etc/iptables/iptables.rules';
    SYSCTL='/etc/sysctl.conf';
    if [[ "$VERSION_ID" != 'VERSION_ID="7"' ]] || [[ "$VERSION_ID" != 'VERSION_ID="8"' ]] || [[ "$VERSION_ID" != 'VERSION_ID="9"' ]] || [[ "$VERSION_ID" != 'VERSION_ID="14.04"' ]] || [[ "$VERSION_ID" != 'VERSION_ID="16.04"' ]] || [[ "$VERSION_ID" != 'VERSION_ID="17.10"' ]] || [[ "$VERSION_ID" != 'VERSION_ID="18.04"' ]]; then
        echo "${RED}Your version of Debian/Ubuntu is not supported.${NC}";
        echo "${RED}I can't install a recent version of OpenVPN on your system.${NC}";
        echo;
        echo "${WHITE}However, if you're using Debian unstable/testing, or Ubuntu beta,";
        echo "then you can continue, a recent version of OpenVPN is available on these.";
        echo "Keep in mind they are not supported, though.${YELLOW}";
		
        while [[ $CONTINUE != "y" && $CONTINUE != "n" ]]; do
            read -p "Continue? [y/n]: " -e CONTINUE;
        done
        if [[ "$CONTINUE" = "n" ]]; then
            echo -e "\n${CYAN}Okay, Goodbye!\n\n${WHITE}";
            exit 4;
        fi;
    fi;
elif [[ -e /etc/fedora-release ]]; then
    OS='fedora';
    IPTABLES='/etc/iptables/iptables.rules';
    SYSCTL='/etc/sysctl.d/openvpn.conf';
elif [[ -e /etc/centos-release || -e /etc/redhat-release || -e /etc/system-release ]]; then
    OS='centos';
    IPTABLES='/etc/iptables/iptables.rules';
    SYSCTL='/etc/sysctl.conf';
elif [[ -e /etc/arch-release ]]; then
    OS='arch';
    IPTABLES='/etc/iptables/iptables.rules';
    SYSCTL='/etc/sysctl.d/openvpn.conf';
else
    echo -e "${WHITE}Looks like you aren't running this installer on a Debian, Ubuntu, CentOS or ArchLinux system.";
    exit 4;
fi;





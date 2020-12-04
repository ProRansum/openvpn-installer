  
#!/bin/bash
#
# https://github.com/ProRansum/openvpn-installer
#
# Copyright (c) 2020 ProRansum. Released under the MIT License.

# Set working directory 
WDIR="`dirname "$0"`";

# Initialize config variables 
source "$WDIR/configs";

# Determine OS platform 
$WDIR/os-detect.sh


newclient () {
    # Where to write the custom client.ovpn?
    if [ -e /home/$1 ]; then  # if $1 is a user name
        homeDir="/home/$1"
    elif [ ${SUDO_USER} ]; then   # if not, use SUDO_USER
        homeDir="/home/${SUDO_USER}"
    else  # if not SUDO_USER, use /root
        homeDir="/root"
    fi
	
    # Generates the custom client.ovpn
    cp /etc/openvpn/client-template.txt $homeDir/$1.ovpn
    echo -e "<ca>" >> $homeDir/$1.ovpn
	
    cat /etc/openvpn/easy-rsa/pki/ca.crt >> $homeDir/$1.ovpn
    echo -e "</ca>" >> $homeDir/$1.ovpn
    echo -e "<cert>" >> $homeDir/$1.ovpn
	
    cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> $homeDir/$1.ovpn
    echo -e "</cert>" >> $homeDir/$1.ovpn
    echo -e "<key>" >> $homeDir/$1.ovpn
	
    cat /etc/openvpn/easy-rsa/pki/private/$1.key >> $homeDir/$1.ovpn
    echo -e "</key>" >> $homeDir/$1.ovpn
    echo -e "key-direction 1" >> $homeDir/$1.ovpn
    echo -e "<tls-auth>" >> $homeDir/$1.ovpn
	
    cat /etc/openvpn/tls-auth.key >> $homeDir/$1.ovpn
    echo -e "</tls-auth>" >> $homeDir/$1.ovpn
}

# Get Internet network interface with default route
NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

if [[ -e /etc/openvpn/server.conf ]]; then
    while :
    do
    clear
		echo -e "\n\n"
        echo -e "${WHITE}OpenVPN-install ${YELLOW}(github.com/Angristan/OpenVPN-install)\n"
        echo -e "${WHITE}Looks like OpenVPN is already installed.\n"
        echo -e "${BLUE}What do you want to do?"
        echo -e "${WHITE}   [${CYAN}1${WHITE}.] ${GREEN}Add${WHITE} a cert for a new user."
        echo -e "${WHITE}   [${CYAN}2${WHITE}.] ${YELLOW}Revoke${WHITE} existing user cert."
        echo -e "${WHITE}   [${CYAN}3${WHITE}.] ${RED}Remove${WHITE} OpenVPN."
        echo -e "${WHITE}   [${CYAN}4${WHITE}.] ${RED}Exit.${YELLOW}"
        read -p "Select from Options [1-4]: " option
		
        case $option in
            1)
				echo -e "\n\n${WHITE}Provide a name for the client cert, exclude special characters from the name."
				echo -e "${ORANGE}${RED}Do not use the following special characters ${WHITE}i.e. ${YELLOW}~, !, @, #, $, %, ^, &, *, _, +, (), [], {}${NC}"
				read -p "Create Client Name: " -e -i newclient CLIENT
				cd /etc/openvpn/easy-rsa/
				./easyrsa build-client-full $CLIENT nopass
				# Generates the custom client.ovpn
				newclient "$CLIENT"
				echo -e "\n${WHITE}Client ${YELLOW}$CLIENT${WHITE} added, certs available at ${WHITE}$homeDir/${YELLOW}$CLIENT.ovpn${NC}"
				exit
            ;;
            2)
				NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
				if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
					echo -e "\n${RED}Uh Oh!${ORANGE}You do not have any existing clients!${NC}"
					exit 5
				fi
				echo -e "\n${WHITE}Select one of the following existing client certificate(s) you wish to revoke.${NC}"
				tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
				if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
					read -p "${WHITE}Select a Client [1]: ${YELLOW}" CLIENTNUMBER
				else
					read -p "${WHITE}Select a Client [1-$NUMBEROFCLIENTS]: ${YELLOW}" CLIENTNUMBER
				fi
				CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
				cd /etc/openvpn/easy-rsa/
				./easyrsa --batch revoke $CLIENT
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f pki/reqs/$CLIENT.req
				rm -f pki/private/$CLIENT.key
				rm -f pki/issued/$CLIENT.crt
				rm -f /etc/openvpn/crl.pem
				cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
				chmod 644 /etc/openvpn/crl.pem
				rm -f $(find /home -maxdepth 2 | grep $CLIENT.ovpn) 2>/dev/null
				rm -f /root/$CLIENT.ovpn 2>/dev/null
				echo -e "\nCertificate for client ${YELLOW}$CLIENT revoked${NC}"
				echo -e "${RED}Exiting...${NC}\n"
				exit
            ;;
            3)
				read -p "${RED}Really?${WHITE} Are you sure you want to remove OpenVPN? [${GREEN}y${NC}/${RED}n${WHITE}]: ${YELLOW}" -e -i n REMOVE
				if [[ "$REMOVE" = 'y' ]]; then
					PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
					if pgrep firewalld; then
						# Using both permanent and not permanent rules to avoid a firewalld reload.
						firewall-cmd --zone=public --remove-port=$PORT/udp
						firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
						firewall-cmd --permanent --zone=public --remove-port=$PORT/udp
						firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					fi
					if iptables -L -n | grep -qE 'REJECT|DROP'; then
						if [[ "$PROTOCOL" = 'udp' ]]; then
							iptables -D INPUT -p udp --dport $PORT -j ACCEPT
						else
							iptables -D INPUT -p tcp --dport $PORT -j ACCEPT
						fi
						iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
						iptables-save > $IPTABLES
					fi
					iptables -t nat -D POSTROUTING -o $NIC -s 10.8.0.0/24 -j MASQUERADE
					iptables-save > $IPTABLES
					if hash sestatus 2>/dev/null; then
						if sestatus | grep "Current mode" | grep -qs "enforcing"; then
							if [[ "$PORT" != '1194' ]]; then
								semanage port -d -t openvpn_port_t -p udp $PORT
							fi
						fi
					fi
					if [[ "$OS" = 'debian' ]]; then
						apt-get autoremove --purge -y openvpn
					elif [[ "$OS" = 'arch' ]]; then
						pacman -R openvpn --noconfirm
					else
						yum remove openvpn -y
					fi
					OVPNS=$(ls /etc/openvpn/easy-rsa/pki/issued | awk -F "." {'print $1'})
					for i in $OVPNS
					do
					rm $(find /home -maxdepth 2 | grep $i.ovpn) 2>/dev/null
					rm /root/$i.ovpn 2>/dev/null
					done
					rm -rf /etc/openvpn
					rm -rf /usr/share/doc/openvpn*
					echo -e "\n${GREEN}OpenVPN ${RED}Removed${WHITE}!${NC}"
				else
					echo -e "\N${GREEN}Removal Aborted!${NC}"
				fi
				exit
            ;;
            4) 
				exit
			;;
        esac
    done
else
    clear
    echo -e "${WHITE}Welcome to the ${CYAN}Secure OpenVPN Installer${WHITE}!${WHITE} Go Visit ${YELLOW}github.com/Angristan/OpenVPN-install${WHITE} for More Info."
	
    # OpenVPN setup and first user creation
    echo -e "\nFor this installer we're gonna need some info to properly build your client certificates."
    echo -e "Throughout the installer we provide (${LIGHT_GREY}recommended${WHITE}) default options, though you can change it if you'd prefer your own parameters."
    
    ### Start First Prompt - Set IPv4 Address.
    echo -e "\n${PURPLE} > Setting IPv4 Address - "
    echo -e "${WHITE}I need to know the ${ORANGE}IPv4 Address${WHITE} of the network interfaces you want OpenVPN's listening to."
    echo -e "${RED}Important! ${WHITE} If your server is running behind a ${ORANGE}NAT${WHITE}, ${LIGHT_GREY}(e.g. LowEndSpirit, Scaleway)${WHITE} leave the IPv4 address as is ${LIGHT_GREY}(Local/Private IP).${NC}"
    echo -e "${LIGHT_GREY}If not, it should be your Public IPv4 address.${YELLOW}"
	
    ##  Autodetect Interface IPv4 Address and Pre-Fill as default for the user.
    IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    read -p "Type IPv4 Address: " -e -i $IP IP
    
    ### Start Second Prompt - Set Port.
    echo -e "\n${PURPLE} > Setting  Port - ${WHITE}"
    echo -e "${WHITE}What ${ORANGE}Port${WHITE} do you want for OpenVPN to use? ${LIGHT_GREY}Default: ${GREEN}1194${YELLOW}"
    read -p "Port: " -e -i 1194 PORT
    # If $IP is a private IP address, the server must be behind NAT
    if echo -e "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
        echo -e "${WHITE}\nThis server is behind ${ORANGE}NAT${WHITE}. What is the ${ORANGE}Public IPv4 Address${WHITE} or ${ORANGE}Hostname${WHITE}?${NC}"
        read -p "Public IPv4 Address / Hostname: " -e PUBLICIP
    fi
    
    ### Start Third Prompt - Set UDP/TCP Protocol.
    echo -e "\n${PURPLE} > Setting UDP or TCP Protocol - ${WHITE}"
    echo -e "\nWhat Protocol would you like ${GREEN}OpenVPN${WHITE} to use ${ORANGE}UDP${WHITE} or ${ORANGE}TCP${WHITE}?"
    echo -e "${RED}Important!${WHITE} Unless ${ORANGE}UDP${WHITE} is blocked, you should ${RED}NOT${WHITE} use ${ORANGE}TCP ${LIGHT_GREY}(${RED}unnecessarily slower{LIGHT_GREY}).${YELLOW}"
    while [[ $PROTOCOL != "UDP" && $PROTOCOL != "TCP" ]]; do
        read -p "Type One Protocol from [UDP or TCP]: " -e -i UDP PROTOCOL
    done
    
    ### Start Second Prompt - Set DNS Service Provider.
    echo -e "\n${PURPLE} > Setting DNS Service Provider - ${WHITE}"
    echo -e "${WHITE}What ${ORANGE}DNS${LIGHT_GREY} Service Provider${WHITE} would you like to use with the VPN?"
    echo -e "${WHITE}   [${CYAN}1${WHITE}.] ${LIGHT_BLUE}Current System Resolvers ${LIGHT_GREY}(from /etc/resolv.conf)."
    echo -e "${WHITE}   [${CYAN}2${WHITE}.] ${BLUE}Cloudflare ${LIGHT_GREY}(Anycast: Worldwide).${NC}"
    echo -e "${WHITE}   [${CYAN}3${WHITE}.] ${BLUE}Quad9 ${LIGHT_GREY}(Anycast: worldwide).${NC}"
    echo -e "${WHITE}   [${CYAN}4${WHITE}.] ${BLUE}FDN ${LIGHT_GREY}(France).${NC}"
    echo -e "${WHITE}   [${CYAN}5${WHITE}.] ${BLUE}DNS.WATCH ${LIGHT_GREY}(Germany).${NC}"
    echo -e "${WHITE}   [${CYAN}6${WHITE}.] ${BLUE}OpenDNS ${LIGHT_GREY}(Anycast: worldwide).${NC}"
    echo -e "${WHITE}   [${CYAN}7${WHITE}.] ${BLUE}Google ${LIGHT_GREY}(Anycast: worldwide).${NC}"
    echo -e "${WHITE}   [${CYAN}8${WHITE}.] ${BLUE}Yandex Basic ${LIGHT_GREY}(Russia).${NC}"
    echo -e "${WHITE}   [${CYAN}9${WHITE}.] ${BLUE}AdGuard DNS ${LIGHT_GREY}(Russia).${YELLOW}\n"
	
    # User Input -> DNS Service Provider
    while [[ $DNS != "1" && $DNS != "2" && $DNS != "3" && $DNS != "4" && $DNS != "5" && $DNS != "6" && $DNS != "7" && $DNS != "8" && $DNS != "9" ]]; do
        read -p "Select an DNS Option [1-9]: " -e -i 1 DNS
    done
        echo -e "\n${LIGHT_GREY}See ${YELLOW}https://github.com/Angristan/OpenVPN-install#encryption${LIGHT_GREY} to learn more about the encryption in OpenVPN and the ones I provided in the installer."
    echo -e "${RED}Important!${LIGHT_GREY} Every level of each choice proposed are up-to-date secure and reliable (to there adaquete level of encryption${RED}*${LIGHT_GREY})."
    echo -e "The default options provide in this installer are much viable to date, comparably to OpenVPN's default options...\n"
    
    ### Start Third Prompt - Set Data Channel Cipher.
    echo -e "\n${PURPLE} > Setting Cipher for Data Channel - ${WHITE}"
    echo -e "${WHITE}Choose a ${ORANGE}Cipher${WHITE} you want to use for the ${ORANGE}Data Channel${WHITE}:"
    echo -e "${WHITE}   [${CYAN}1${WHITE}.]${LIGHT_BLUE} AES-128-CBC {LIGHT_GREY}(fastest and sufficiently secure for everyone, recommended)."
    echo -e "${WHITE}   [${CYAN}2${WHITE}.]${LIGHT_BLUE} AES-192-CBC"
    echo -e "${WHITE}   [${CYAN}3${WHITE}.]${LIGHT_BLUE} AES-256-CBC"
	
    # Cipher Alternative Options for Data Channel
    echo -e "${LIGHT_GREY}Alternatives to AES, use only if you know what you're doing. They are relatively ${WHITE}slower${LIGHT_GREY} but as ${WHITE}secure${LIGHT_GREY} as AES."
    echo -e "${WHITE}   [${CYAN}4${WHITE}.]${BLUE} CAMELLIA-128-CBC"
    echo -e "${WHITE}   [${CYAN}5${WHITE}.]${BLUE} CAMELLIA-192-CBC"
    echo -e "${WHITE}   [${CYAN}6${WHITE}.]${BLUE} CAMELLIA-256-CBC"
    echo -e "${WHITE}   [${CYAN}7${WHITE}.]${BLUE} SEED-CBC${YELLOW}\n"
	
    while [[ $CIPHER != "1" && $CIPHER != "2" && $CIPHER != "3" && $CIPHER != "4" && $CIPHER != "5" && $CIPHER != "6" && $CIPHER != "7" ]]; do
        read -p "Select a Cipher Level for the Data Channel from Options [1-7]: " -e -i 1 CIPHER
    done
	
    case $CIPHER in
        1)
        CIPHER="cipher AES-128-CBC"
        ;;
        2)
        CIPHER="cipher AES-192-CBC"
        ;;
        3)
        CIPHER="cipher AES-256-CBC"
        ;;
        4)
        CIPHER="cipher CAMELLIA-128-CBC"
        ;;
        5)
        CIPHER="cipher CAMELLIA-192-CBC"
        ;;
        6)
        CIPHER="cipher CAMELLIA-256-CBC"
        ;;
        7)
        CIPHER="cipher SEED-CBC"
        ;;
    esac
    #
    ### Start  Prompt - Set .
    echo -e "\n${PURPLE} > Setting DH Key Size - ${WHITE}"
    echo -e "Choose what size of Diffie-Hellman key you want to use:"
    echo -e "${WHITE}   [${CYAN}1${WHITE}.]${RED}2048${BLUE} bits ${WHITE}(${GREEN}fastest${WHITE})."
    echo -e "${WHITE}   [${CYAN}2${WHITE}.]${RED}3072${BLUE} bits ${WHITE}(${ORANGE}recommended, best compromise${WHITE})."
    echo -e "${WHITE}   [${CYAN}3${WHITE}.]${RED}4096${BLUE} bits ${WHITE}(${RED}most secure${WHITE}).${YELLOW}\n"
	
    while [[ $DH_KEY_SIZE != "1" && $DH_KEY_SIZE != "2" && $DH_KEY_SIZE != "3" ]]; do
        read -p "Select a DH Key Size from Options [1-3]: " -e -i 2 DH_KEY_SIZE
    done
	
    case $DH_KEY_SIZE in
        1)
        DH_KEY_SIZE="2048"
        ;;
        2)
        DH_KEY_SIZE="3072"
        ;;
        3)
        DH_KEY_SIZE="4096"
        ;;
    esac
	
    ### Start  Prompt - Set .
    echo -e "\n${PURPLE} > Setting RSA Key Size - ${WHITE}"
    echo -e "What Size Would You Like For Your RSA Key?"
    echo -e "${WHITE}   [${CYAN}1${WHITE}.]${RED}2048${BLUE} bits ${WHITE}(${GREEN}fastest${WHITE})."
    echo -e "${WHITE}   [${CYAN}2${WHITE}.]${RED}3072${BLUE} bits ${WHITE}(${ORANGE}recommended, best compromise${WHITE})."
    echo -e "${WHITE}   [${CYAN}3${WHITE}.]${RED}4096${BLUE} bits ${WHITE}(${RED}most secure${WHITE}).${YELLOW}\n"
	
    while [[ $RSA_KEY_SIZE != "1" && $RSA_KEY_SIZE != "2" && $RSA_KEY_SIZE != "3" ]]; do
        read -p "Select an RSA Key Size from Options [1-3]: " -e -i 2 RSA_KEY_SIZE
    done
	
    case $RSA_KEY_SIZE in
        1)
			RSA_KEY_SIZE="2048"
		;;
        2)
			RSA_KEY_SIZE="3072"
		;;
        3)
			RSA_KEY_SIZE="4096"
		;;
    esac;
    #
    ### Start  Prompt - Set .
    echo -e "\n${PURPLE} > Setting Client Name -${WHITE} "
    echo -e "${WHITE}What name would you like to give to your client certificate and configuration?"
    while [[ $CLIENT = "" ]]; do
        echo -e "${LIGHT_GREY}Please, exclude any special characters from the name, so use one word.${YELLOW}\n"
		
        read -p "Type your Client Certificate Name: " -e -i client CLIENT
    done
    #
    ### Finalization of Setup
    echo -e "\n${GREEN}Congrats${WHITE}! You've gotten through the configuration process. Now we can begin the setup of your OpenVPN Server!"
    echo -e "Whenever you're ready, let's begin the setup process!${YELLOW}"
	
    read -n1 -r -p "Press any key to continue..."
    echo -e "${WHITE}"

    if [[ "$OS" = 'debian' ]]; then
        apt-get install ca-certificates gnupg -y
        # We add the OpenVPN repo to get the latest version.
        # Debian 7
        if [[ "$VERSION_ID" = 'VERSION_ID="7"' ]]; then
            echo -e "deb http://build.openvpn.net/debian/openvpn/stable wheezy main" > /etc/apt/sources.list.d/openvpn.list
            wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			
            apt-get update
        fi
        # Debian 8
        if [[ "$VERSION_ID" = 'VERSION_ID="8"' ]]; then
            echo -e "deb http://build.openvpn.net/debian/openvpn/stable jessie main" > /etc/apt/sources.list.d/openvpn.list
            wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			
            apt update
        fi
        # Ubuntu 14.04
        if [[ "$VERSION_ID" = 'VERSION_ID="14.04"' ]]; then
            echo -e "deb http://build.openvpn.net/debian/openvpn/stable trusty main" > /etc/apt/sources.list.d/openvpn.list
            wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			
            apt-get update
        fi
        # Ubuntu >= 16.04 and Debian > 8 have OpenVPN > 2.3.3 without the need of a third party repository.
        # The we install OpenVPN
        apt-get install openvpn iptables openssl wget ca-certificates curl -y
        # Install iptables service
        if [[ ! -e /etc/systemd/system/iptables.service ]]; then
            mkdir /etc/iptables
            iptables-save > /etc/iptables/iptables.rules
            
			echo -e "#!/bin/sh \niptables -F \niptables -X \niptables -t nat -F \niptables -t nat -X \niptables -t mangle -F \niptables -t mangle -X \niptables -P INPUT ACCEPT \niptables -P FORWARD ACCEPT \niptables -P OUTPUT ACCEPT" > /etc/iptables/flush-iptables.sh
            chmod +x /etc/iptables/flush-iptables.sh
			
            echo -e "[Unit] \nDescription=Packet Filtering Framework \nDefaultDependencies=no \nBefore=network-pre.target \nWants=network-pre.target \n[Service] \nType=oneshot \nExecStart=/sbin/iptables-restore /etc/iptables/iptables.rules \nExecReload=/sbin/iptables-restore /etc/iptables/iptables.rules \nExecStop=/etc/iptables/flush-iptables.sh \nRemainAfterExit=yes \n[Install] \nWantedBy=multi-user.target" > /etc/systemd/system/iptables.service
            systemctl daemon-reload
            systemctl enable iptables.service
        fi
    elif [[ "$OS" = 'centos' || "$OS" = 'fedora' ]]; then
        if [[ "$OS" = 'centos' ]]; then
            yum install epel-release -y
        fi
        yum install openvpn iptables openssl wget ca-certificates curl -y
        # Install iptables service
        if [[ ! -e /etc/systemd/system/iptables.service ]]; then
            mkdir /etc/iptables
            iptables-save > /etc/iptables/iptables.rules
            echo -e "#!/bin/sh \niptables -F \niptables -X \niptables -t nat -F \niptables -t nat -X \niptables -t mangle -F \niptables -t mangle -X \niptables -P INPUT ACCEPT \niptables -P FORWARD ACCEPT \niptables -P OUTPUT ACCEPT" > /etc/iptables/flush-iptables.sh
			
            chmod +x /etc/iptables/flush-iptables.sh
            echo -e "[Unit] \nDescription=Packet Filtering Framework \nDefaultDependencies=no \nBefore=network-pre.target \nWants=network-pre.target \n[Service] \nType=oneshot \nExecStart=/sbin/iptables-restore /etc/iptables/iptables.rules \nExecReload=/sbin/iptables-restore /etc/iptables/iptables.rules \nExecStop=/etc/iptables/flush-iptables.sh \nRemainAfterExit=yes \n[Install] \nWantedBy=multi-user.target" > /etc/systemd/system/iptables.service
			
            systemctl daemon-reload
            systemctl enable iptables.service
			
            # Disable firewalld to allow iptables to start upon reboot
            systemctl disable firewalld
            systemctl mask firewalld
        fi
    else
        # Else, the distro is ArchLinux

        echo -e "\n\n${WHITE}As you're using ${YELLOW}ArchLinux${WHITE}, I need to update the packages on your system to install those I need."
        echo -e "Not doing that could cause problems between dependencies, or missing files in repositories."
        echo -e "\n${LIGHT_GREY}Continuing will update your installed packages and install needed ones.${YELLOW}"
        while [[ $CONTINUE != "y" && $CONTINUE != "n" ]]; do
            read -p "Continue ? [y/n]: " -e -i y CONTINUE
        done
        if [[ "$CONTINUE" = "n" ]]; then
            echo -e "\n${CYAN}Okay, Goodbye!${WHITE}\n\n"
            exit 4
        fi

        if [[ "$OS" = 'arch' ]]; then
            # Install dependencies
            pacman -Syu openvpn iptables openssl wget ca-certificates curl --needed --noconfirm
            iptables-save > /etc/iptables/iptables.rules # iptables won't start if this file does not exist
            systemctl daemon-reload
            systemctl enable iptables
            systemctl start iptables
        fi
    fi
    # Find out if the machine uses nogroup or nobody for the permissionless group
    if grep -qs "^nogroup:" /etc/group; then
        NOGROUP=nogroup
    else
        NOGROUP=nobody
    fi

    # An old version of easy-rsa was available by default in some openvpn packages
    if [[ -d /etc/openvpn/easy-rsa/ ]]; then
        rm -rf /etc/openvpn/easy-rsa/
    fi
    # Get easy-rsa
    wget -O ~/EasyRSA-3.0.4.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.tgz
    tar xzf ~/EasyRSA-3.0.4.tgz -C ~/
    mv ~/EasyRSA-3.0.4/ /etc/openvpn/
    mv /etc/openvpn/EasyRSA-3.0.4/ /etc/openvpn/easy-rsa/
    chown -R root:root /etc/openvpn/easy-rsa/
    rm -f ~/EasyRSA-3.0.4.tgz
    cd /etc/openvpn/easy-rsa/
	
    # Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
    SERVER_CN="cn_$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
    SERVER_NAME="server_$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	
    echo -e "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" > vars
    echo -e "set_var EASYRSA_REQ_CN $SERVER_CN" >> vars
    # Create the PKI, set up the CA, the DH params and the server + client certificates
    ./easyrsa init-pki
    ./easyrsa --batch build-ca nopass
    openssl dhparam -out dh.pem $DH_KEY_SIZE
    ./easyrsa build-server-full $SERVER_NAME nopass
    ./easyrsa build-client-full $CLIENT nopass
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
    # generate tls-auth key
    openvpn --genkey --secret /etc/openvpn/tls-auth.key
    # Move all the generated files
    cp pki/ca.crt pki/private/ca.key dh.pem pki/issued/$SERVER_NAME.crt pki/private/$SERVER_NAME.key /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
    # Make cert revocation list readable for non-root
    chmod 644 /etc/openvpn/crl.pem

    # Generate server.conf
    echo -e "port $PORT" > /etc/openvpn/server.conf
    if [[ "$PROTOCOL" = 'UDP' ]]; then
        echo -e "proto udp" >> /etc/openvpn/server.conf
    elif [[ "$PROTOCOL" = 'TCP' ]]; then
        echo -e "proto tcp" >> /etc/openvpn/server.conf
    fi
    echo -e "dev tun \nuser nobody \ngroup $NOGROUP \npersist-key \npersist-tun \nkeepalive 10 120 \ntopology subnet \nserver 10.8.0.0 255.255.255.0 \nifconfig-pool-persist ipp.txt" >> /etc/openvpn/server.conf
    # DNS resolvers
    case $DNS in
        1)
        # Locate the proper resolv.conf
        # Needed for systems running systemd-resolved
        if grep -q "127.0.0.53" "/etc/resolv.conf"; then
            RESOLVCONF='/run/systemd/resolve/resolv.conf'
        else
            RESOLVCONF='/etc/resolv.conf'
        fi
        # Obtain the resolvers from resolv.conf and use them for OpenVPN
        grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
            echo -e "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
        done
        ;;
        2) # Cloudflare
        echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
        echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
        ;;
        3) # Quad9
        echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server.conf
        ;;
        4) # FDN
        echo 'push "dhcp-option DNS 80.67.169.40"' >> /etc/openvpn/server.conf
        echo 'push "dhcp-option DNS 80.67.169.12"' >> /etc/openvpn/server.conf
        ;;
        5) # DNS.WATCH
        echo 'push "dhcp-option DNS 84.200.69.80"' >> /etc/openvpn/server.conf
        echo 'push "dhcp-option DNS 84.200.70.40"' >> /etc/openvpn/server.conf
        ;;
        6) # OpenDNS
        echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
        echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
        ;;
        7) # Google
        echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
        echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
        ;;
        8) # Yandex Basic
        echo 'push "dhcp-option DNS 77.88.8.8"' >> /etc/openvpn/server.conf
        echo 'push "dhcp-option DNS 77.88.8.1"' >> /etc/openvpn/server.conf
        ;;
        9) # AdGuard DNS
        echo 'push "dhcp-option DNS 176.103.130.130"' >> /etc/openvpn/server.conf
        echo 'push "dhcp-option DNS 176.103.130.131"' >> /etc/openvpn/server.conf
        ;;
    esac
	
	echo 'push "redirect-gateway def1 bypass-dhcp" '>> /etc/openvpn/server.conf
	echo -e "crl-verify crl.pem \nca ca.crt \ncert $SERVER_NAME.crt \nkey $SERVER_NAME.key \ntls-auth tls-auth.key 0 \ndh dh.pem \nauth SHA256 \n$CIPHER \ntls-server \ntls-version-min 1.2 \ntls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256 \nstatus openvpn.log \nverb 3" >> /etc/openvpn/server.conf

    # Create the sysctl configuration file if needed (mainly for Arch Linux)
    if [[ ! -e $SYSCTL ]]; then
        touch $SYSCTL
    fi

    # Enable net.ipv4.ip_forward for the system
    sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' $SYSCTL
    if ! grep -q "\<net.ipv4.ip_forward\>" $SYSCTL; then
        echo 'net.ipv4.ip_forward=1' >> $SYSCTL
    fi
    # Avoid an unneeded reboot
    echo 1 > /proc/sys/net/ipv4/ip_forward
    # Set NAT for the VPN subnet
    iptables -t nat -A POSTROUTING -o $NIC -s 10.8.0.0/24 -j MASQUERADE
    # Save persitent iptables rules
    iptables-save > $IPTABLES
    if pgrep firewalld; then
        # We don't use --add-service=openvpn because that would only work with
        # the default port. Using both permanent and not permanent rules to
        # avoid a firewalld reload.
        if [[ "$PROTOCOL" = 'UDP' ]]; then
            firewall-cmd --zone=public --add-port=$PORT/udp
            firewall-cmd --permanent --zone=public --add-port=$PORT/udp
        elif [[ "$PROTOCOL" = 'TCP' ]]; then
            firewall-cmd --zone=public --add-port=$PORT/tcp
            firewall-cmd --permanent --zone=public --add-port=$PORT/tcp
        fi
        firewall-cmd --zone=trusted --add-source=10.8.0.0/24
        firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
    fi
    if iptables -L -n | grep -qE 'REJECT|DROP'; then
        # If iptables has at least one REJECT rule, we asume this is needed.
        # Not the best approach but I can't think of other and this shouldn't
        # cause problems.
        if [[ "$PROTOCOL" = 'UDP' ]]; then
            iptables -I INPUT -p udp --dport $PORT -j ACCEPT
        elif [[ "$PROTOCOL" = 'TCP' ]]; then
            iptables -I INPUT -p tcp --dport $PORT -j ACCEPT
        fi
        iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
        iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        # Save persitent OpenVPN rules
        iptables-save > $IPTABLES
    fi
    # If SELinux is enabled and a custom port was selected, we need this
    if hash sestatus 2>/dev/null; then
        if sestatus | grep "Current mode" | grep -qs "enforcing"; then
            if [[ "$PORT" != '1194' ]]; then
                # semanage isn't available in CentOS 6 by default
                if ! hash semanage 2>/dev/null; then
                    yum install policycoreutils-python -y
                fi
                if [[ "$PROTOCOL" = 'UDP' ]]; then
                    semanage port -a -t openvpn_port_t -p udp $PORT
                elif [[ "$PROTOCOL" = 'TCP' ]]; then
                    semanage port -a -t openvpn_port_t -p tcp $PORT
                fi
            fi
        fi
    fi
    # And finally, restart OpenVPN
    if [[ "$OS" = 'debian' ]]; then
        # Little hack to check for systemd
        if pgrep systemd-journal; then
                #Workaround to fix OpenVPN service on OpenVZ
                sed -i 's|LimitNPROC|#LimitNPROC|' /lib/systemd/system/openvpn\@.service
                sed -i 's|/etc/openvpn/server|/etc/openvpn|' /lib/systemd/system/openvpn\@.service
                sed -i 's|%i.conf|server.conf|' /lib/systemd/system/openvpn\@.service
                systemctl daemon-reload
                systemctl restart openvpn
                systemctl enable openvpn
        else
            /etc/init.d/openvpn restart
        fi
    else
        if pgrep systemd-journal; then
            if [[ "$OS" = 'arch' || "$OS" = 'fedora' ]]; then
                #Workaround to avoid rewriting the entire script for Arch & Fedora
                sed -i 's|/etc/openvpn/server|/etc/openvpn|' /usr/lib/systemd/system/openvpn-server@.service
                sed -i 's|%i.conf|server.conf|' /usr/lib/systemd/system/openvpn-server@.service
                systemctl daemon-reload
                systemctl restart openvpn-server@openvpn.service
                systemctl enable openvpn-server@openvpn.service
            else
                systemctl restart openvpn@server.service
                systemctl enable openvpn@server.service
            fi
        else
            service openvpn restart
            chkconfig openvpn on
        fi
    fi
    # If the server is behind a NAT, use the correct IP address
    if [[ "$PUBLICIP" != "" ]]; then
        IP=$PUBLICIP
    fi
    # client-template.txt is created so we have a template to add further users later
    echo -e "client" > /etc/openvpn/client-template.txt
    if [[ "$PROTOCOL" = 'UDP' ]]; then
        echo -e "proto udp" >> /etc/openvpn/client-template.txt
    elif [[ "$PROTOCOL" = 'TCP' ]]; then
        echo -e "proto tcp-client" >> /etc/openvpn/client-template.txt
    fi
    echo -e "remote $IP $PORT \ndev tun \nresolv-retry infinite \nnobind \npersist-key \npersist-tun \nremote-cert-tls server \nverify-x509-name $SERVER_NAME name \nauth SHA256 \nauth-nocache \n$CIPHER \ntls-client \ntls-version-min 1.2 \ntls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256 \nsetenv opt block-outside-dns \nverb 3" >> /etc/openvpn/client-template.txt

    # Generate the custom client.ovpn
    newclient "$CLIENT"
    echo -e ""
    echo -e "${GREEN}Finished!${WHITE}"
    echo -e "\nYour client config is available at ${CYAN}$homeDir/${YELLOW}$CLIENT.ovpn${WHITE}"
    echo -e "If you want to add more clients, you simply need to run this script another time!"
fi;

exit 0;

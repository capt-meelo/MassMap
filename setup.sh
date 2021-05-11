#!/bin/bash

VERSION="2.0"

WORKING_DIR="$(cd "$(dirname "$0")" ; pwd -P)"
RESULTS_PATH="$WORKING_DIR/results"

RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

displayLogo(){
echo -e "${GREEN}                               
 _______                     _______              
|   |   |.---.-.-----.-----.|   |   |.---.-.-----.
|       ||  _  |__ --|__ --||       ||  _  |  _  |
|__|_|__||___._|_____|_____||__|_|__||___._|   __|${RESET} ${RED}v$VERSION${RESET}  
                                           ${GREEN}|__|${RESET}    by ${YELLOW}@CaptMeelo${RESET}\n
"
}

setupTools(){
    echo -e "${GREEN}[+] Setting things up.${RESET}"
    sudo apt update -y
    sudo apt install -y gcc g++ make libpcap-dev xsltproc jq
    
    if [ -d $RESULTS_PATH ]
    then
        echo -e "${BLUE}[-] Directory already exists. Skipping...${RESET}"
    else
        echo -e "${GREEN}[+] Creating results directory.${RESET}"
        mkdir -p $RESULTS_PATH
    fi
}


installTools(){
    LATEST_MASSCAN="$(curl --silent "https://api.github.com/repos/robertdavidgraham/masscan/releases/latest" | jq -r .tag_name)"
    
    if [ ! -x "$(command -v masscan)" ]; then
        echo -e "${GREEN}[+] Installing Masscan.${RESET}"
        wget https://github.com/robertdavidgraham/masscan/archive/refs/tags/$LATEST_MASSCAN.tar.gz
        tar -xf $LATEST_MASSCAN.tar.gz
        cd masscan-$LATEST_MASSCAN
        make -j
        sudo make -j install
        cd $WORKING_DIR
        rm -rf $LATEST_MASSCAN.tar.gz masscan-$LATEST_MASSCAN
    else
        if [ "$LATEST_MASSCAN" == "$(masscan -V | grep "Masscan version" | cut -d " " -f 3)" ]; then
            echo -e "${BLUE}[-] Latest version of Masscan already installed. Skipping...${RESET}"
        else
            echo -e "${GREEN}[+] Upgrading Masscan to the latest version.${RESET}"
            wget https://github.com/robertdavidgraham/masscan/archive/refs/tags/$LATEST_MASSCAN.tar.gz
            tar -xf $LATEST_MASSCAN.tar.gz
            cd masscan-$LATEST_MASSCAN
            make -j
            sudo make -j install
            cd $WORKING_DIR
            rm -rf $LATEST_MASSCAN.tar.gz masscan-$LATEST_MASSCAN
        fi
    fi

    LATEST_NMAP="$(wget -qO- https://nmap.org/dist/ | grep -oP 'nmap-([0-9\.]+)\.tar\.bz2'| tail -n 1 | grep -oP 'nmap-[0-9\.]+' | grep -oP '[0-9\.]+' | head -c -2)"
    
    if [ ! -x "$(command -v nmap)" ]; then
        echo -e "${GREEN}[+] Installing Nmap.${RESET}"
        wget https://nmap.org/dist/nmap-$LATEST_NMAP.tar.bz2
        bzip2 -cd nmap-$LATEST_NMAP.tar.bz2 | tar xvf -
        cd nmap-$LATEST_NMAP
        ./configure
        make -j
        sudo make -j install
        cd $WORKING_DIR
        rm -rf nmap-$LATEST_NMAP*
    else 
        if [ "$LATEST_NMAP" == "$(nmap -V | grep "Nmap version" | cut -d " " -f 3)" ]; then
            echo -e "${BLUE}[-] Latest version of Nmap already installed. Skipping...${RESET}"
        else
            echo -e "${GREEN}[+] Upgrading Nmap to the latest version.${RESET}"
            wget https://nmap.org/dist/nmap-$LATEST_NMAP.tar.bz2
            bzip2 -cd nmap-$LATEST_NMAP.tar.bz2 | tar xvf -
            cd nmap-$LATEST_NMAP
            ./configure
            make -j
            sudo make -j install
            cd $WORKING_DIR
            rm -rf nmap-$LATEST_NMAP*
        fi 
    fi
}

displayLogo
setupTools
installTools
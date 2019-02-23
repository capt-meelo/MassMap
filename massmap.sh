#!/bin/bash

VERSION="1.0"

TARGET="$1"

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


checkArgs(){
    if [[ $# -eq 0 ]]; then
        echo -e "\t${RED}[!] ERROR:${RESET} Invalid argument!\n"
        echo -e "\t${GREEN}[+] USAGE:${RESET}$0 <list-of-IP/CIDR>\n"
        exit 1
    elif [ ! -s $1 ]; then
        echo -e "\t${RED}[!] ERROR:${RESET} File is empty and/or does not exists!\n"
        echo -e "\t${GREEN}[+] USAGE:${RESET}$0 <list-of-IP/CIDR>\n"
        exit 1
    fi
}


setupTools(){
    echo -e "${GREEN}[+] Setting things up.${RESET}"
    sudo apt update -y
    sudo apt upgrade -y
    sudo apt autoremove -y
    sudo apt clean
    sudo apt install -y gcc g++ make libpcap-dev xsltproc
    
    echo -e "${GREEN}[+] Creating results directory.${RESET}"
    mkdir -p $RESULTS_PATH
}


installTools(){
    LATEST_MASSCAN="1.0.6"
    if [ ! -x "$(command -v masscan)" ]; then
        echo -e "${GREEN}[+] Installing Masscan.${RESET}"
        git clone https://github.com/robertdavidgraham/masscan
        cd masscan
        make -j
        sudo make -j install
        cd $WORKING_DIR
        rm -rf masscan
    else
        if [ "$LATEST_MASSCAN" == "$(masscan -V | grep "Masscan version" | cut -d " " -f 3)" ]; then
            echo -e "${BLUE}[-] Latest version of Masscan already installed. Skipping...${RESET}"
        else
            echo -e "${GREEN}[+] Upgrading Masscan to the latest version.${RESET}"
            git clone https://github.com/robertdavidgraham/masscan
            cd masscan
            make -j
            sudo make -j install
            cd $WORKING_DIR
            rm -rf masscan*
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


portScan(){
    echo -e "${GREEN}[+] Running Masscan.${RESET}"
    sudo masscan -p 1-65535 --rate 10000 --wait 0 --open -iL $TARGET -oX $RESULTS_PATH/masscan.xml
    sudo rm $WORKING_DIR/paused.conf
    xsltproc -o $RESULTS_PATH/masscan.html $WORKING_DIR/bootstrap-masscan.xsl $RESULTS_PATH/masscan.xml
    open_ports=$(cat $RESULTS_PATH/masscan.xml | grep portid | cut -d "\"" -f 10 | sort -n | uniq | paste -sd,)
    cat $RESULTS_PATH/masscan.xml | grep portid | cut -d "\"" -f 4 | sort -V | uniq > $WORKING_DIR/nmap_targets.tmp
    echo -e "${RED}[*] Masscan Done! View the HTML report at $RESULTS_PATH${RESET}"

    echo -e "${GREEN}[+] Running Nmap.${RESET}"
    sudo nmap -sVC -p $open_ports --open -v -Pn -n -T4 -iL $WORKING_DIR/nmap_targets.tmp -oX $RESULTS_PATH/nmap.xml
    sudo rm $WORKING_DIR/nmap_targets.tmp
    xsltproc -o $RESULTS_PATH/nmap-native.html $RESULTS_PATH/nmap.xml
    xsltproc -o $RESULTS_PATH/nmap-bootstrap.html $WORKING_DIR/bootstrap-nmap.xsl $RESULTS_PATH/nmap.xml
    echo -e "${RED}[*] Nmap Done! View the HTML reports at $RESULTS_PATH${RESET}"
}


displayLogo
checkArgs $TARGET
setupTools
installTools
portScan
